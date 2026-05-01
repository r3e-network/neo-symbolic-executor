using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

/// <summary>
/// The symbolic execution driver. Owns the worklist and runs Step() per state until terminal.
///
/// Design choices reflecting prior audit findings:
///  - State cloning is deep (Heap.Clone, Telemetry.Clone, frame Clone). No shallow leaks.
///  - Witness model is symbolic (audit HIGH-3): CheckWitness pushes a fresh symbolic Bool
///    that the engine tracks for enforcement consistency on the consuming branch only.
///  - PUSHA target uses the resolved Target field (audit CRIT-1): never falls back to the raw
///    operand delta when target == 0.
///  - Cross-type equality (audit HIGH-2) is handled in <see cref="Expr.Eq"/> via canonical bytes.
///  - Unknown opcodes terminate the state explicitly rather than silently no-op (audit symbolic
///    engine HIGH severity).
///
/// This file contains the core dispatch + the most common opcodes. Less-common opcodes
/// (compound types, splice, advanced math) are layered in via partial classes.
/// </summary>
public sealed partial class SymbolicEngine
{
    private readonly NeoProgram _program;
    private readonly ExecutionOptions _options;
    private readonly List<ExecutionState> _finalStates = new();
    private readonly Queue<ExecutionState> _worklist = new();
    private int _statesExplored;
    private int _stepsExecuted;
    private bool _budgetExceeded;
    private string? _budgetReason;

    public SymbolicEngine(NeoProgram program, ExecutionOptions? options = null)
    {
        _program = program;
        _options = options ?? ExecutionOptions.Default;
    }

    public ExecutionResult Run(ExecutionState? initial = null)
    {
        var start = initial ?? CreateInitialState();
        _worklist.Enqueue(start);

        // Audit fix (iter-2 wakeup-2 mem bomb): wall-clock deadline. A single state's fork
        // point can spawn many heap clones in a single step (each path forks a new heap); none
        // of those steps individually exceeds MaxSteps, but the aggregate memory pressure can
        // jump 3 GB in a few hundred ms. Track an absolute deadline at engine entry and drain
        // the worklist when it fires — the next step boundary picks it up.
        var deadline = _options.PerRunDeadline is { } d ? System.DateTime.UtcNow + d : (System.DateTime?)null;

        while (_worklist.Count > 0)
        {
            if (_finalStates.Count >= _options.MaxPaths)
            {
                DrainWorklist("max paths reached");
                break;
            }

            // Worklist cap: deeply-forking symbolic loops can fill the worklist with millions
            // of states before any of them terminates (and thus before MaxPaths fires). When the
            // worklist itself blows past its budget, drain it. Without this, path-explosion
            // attacks would burn unbounded CPU before the engine returns.
            if (_options.MaxQueuedStates > 0 && _worklist.Count >= _options.MaxQueuedStates)
            {
                DrainWorklist("max queued states reached");
                break;
            }

            if (deadline is { } dl && System.DateTime.UtcNow > dl)
            {
                DrainWorklist("per-run wall-clock deadline exceeded");
                break;
            }

            var state = _worklist.Dequeue();
            _statesExplored++;

            if (state.Status != TerminalStatus.Running)
            {
                _finalStates.Add(state);
                continue;
            }

            try
            {
                var produced = StepBounded(state);
                foreach (var s in produced)
                {
                    if (s.Status == TerminalStatus.Running)
                        _worklist.Enqueue(s);
                    else
                        _finalStates.Add(s);
                }
            }
            catch (AnalysisBudgetException bex)
            {
                state.Telemetry.Truncated = true;
                state.Terminate(TerminalStatus.Stopped, "budget: " + bex.Message);
                _finalStates.Add(state);
                _budgetExceeded = true;
                _budgetReason ??= bex.Message;
            }
            catch (VmFaultException vex)
            {
                state.Terminate(TerminalStatus.Faulted, vex.Message);
                _finalStates.Add(state);
            }
            catch (CatchableVmException cex)
            {
                // A NeoVM-catchable exception bubbled up out of the dispatch path. Treat it like
                // a THROW: route through the active TRY/CATCH stack, faulting the state if no
                // handler is found. Without this catch, the exception leaks out of Run() and
                // crashes the caller (audit lesson: every VM exception must have a destination).
                state.UncaughtException = SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes(cex.Message));
                state.Telemetry.ExceptionsThrown.Add(state.Pc);
                foreach (var s in PropagateException(state))
                {
                    if (s.Status == TerminalStatus.Running) _worklist.Enqueue(s);
                    else _finalStates.Add(s);
                }
            }
            catch (System.OverflowException oex)
            {
                // BigInteger -> int cast overflow on a runtime-supplied index. Per NeoVM semantics
                // an out-of-range index is a CatchableException; we surface as a faulted terminal.
                state.Terminate(TerminalStatus.Faulted, $"index out of Int32 range: {oex.Message}");
                _finalStates.Add(state);
            }
        }

        return new ExecutionResult(
            _finalStates.ToImmutableArray(),
            _statesExplored,
            _stepsExecuted,
            _budgetExceeded,
            _budgetReason);
    }

    private void DrainWorklist(string reason)
    {
        _budgetExceeded = true;
        _budgetReason = reason;
        while (_worklist.TryDequeue(out var leftover))
        {
            leftover.Telemetry.Truncated = true;
            leftover.Terminate(TerminalStatus.Stopped, "budget: " + reason);
            _finalStates.Add(leftover);
        }
    }

    private ExecutionState CreateInitialState() => BuildEntryState(pc: 0);

    /// <summary>
    /// Build an entry state for analyzing a specific manifest method. Real DevPack contracts
    /// dispatch on a string method name argument, so running from offset 0 with empty stack
    /// faults at INITSLOT before any user code executes — the detectors see nothing. This
    /// helper seeds the eval stack with one fresh symbolic value per declared parameter and
    /// jumps directly to the method's body offset, so each per-method analysis produces real
    /// telemetry. NeoVM INITSLOT pops args in stack order so arg[0] sits on top: we push in
    /// reverse so positional order is preserved (param[0] -> Args[0]).
    /// </summary>
    public ExecutionState CreateMethodEntryState(int offset, IReadOnlyList<ContractParameterDefinition>? parameters)
    {
        var state = BuildEntryState(offset);
        if (parameters is { Count: > 0 } pars)
        {
            for (int i = pars.Count - 1; i >= 0; i--)
            {
                var p = pars[i];
                string symbolName = string.IsNullOrEmpty(p.Name) ? $"arg{i}" : $"arg_{p.Name}";
                state.Push(SymbolicValue.Symbol(SortForParameterType(p.Type), symbolName));
            }
        }
        return state;
    }

    // Audit fix (iter-2 wakeup-2 memory bomb): construct the Heap with the engine's budgets
    // rather than letting it default to 1 MiB × 4096 objects. Without this plumbing a single
    // pathological iteration could allocate ~3 GB before any cap fired, freezing all six
    // workers on that iteration.
    private ExecutionState BuildEntryState(int pc)
    {
        var state = new ExecutionState
        {
            Heap = new Heap(_options.MaxHeapObjects, _options.MaxItemSize, _options.MaxCollectionSize),
        };
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = pc;
        return state;
    }

    private static Sort SortForParameterType(string type) => type switch
    {
        "Integer" => Sort.Int,
        "Boolean" => Sort.Bool,
        // ByteString, String, Hash160, Hash256, PublicKey, Signature, Array, Map, Struct,
        // InteropInterface, Any, Void all flow through Sort.Bytes — the engine's coercion
        // primitives (ConcreteInt, GetInteger, GetByteString) keep that conservative.
        _ => Sort.Bytes,
    };

    private IEnumerable<ExecutionState> StepBounded(ExecutionState state)
    {
        if (state.Steps >= _options.MaxSteps)
        {
            state.Telemetry.Truncated = true;
            state.Terminate(TerminalStatus.Stopped, "budget: max steps reached");
            return new[] { state };
        }
        state.Steps++;
        _stepsExecuted++;

        if (state.EvaluationStack.Count > _options.MaxStackSize)
            throw new VmFaultException("evaluation stack overflow");

        if (!state.VisitCounts.TryGetValue(state.Pc, out int visits)) visits = 0;
        if (visits >= _options.MaxVisitsPerOffset)
        {
            state.Telemetry.Truncated = true;
            state.Telemetry.LoopsDetected.Add(state.Pc);
            state.Terminate(TerminalStatus.Stopped, "budget: visit cap at offset");
            return new[] { state };
        }
        state.VisitCounts[state.Pc] = visits + 1;
        state.Path.Add(state.Pc);

        // Audit fix (iter-2 wakeup-4 differential): match Neo.VM by JIT-decoding the
        // instruction at PC if the linear-scan index has no entry. NeoVM happily executes
        // a JMP whose target lands inside the operand of a prior instruction; our engine
        // used to fault on "unaligned offset" — a structural divergence the differential
        // target found within 10 seconds.
        var inst = _program.AtOffsetOrDecode(state.Pc);
        if (inst is null)
        {
            state.Terminate(TerminalStatus.Faulted, $"PC at unaligned offset 0x{state.Pc:X4}");
            return new[] { state };
        }

        return Dispatch(state, inst);
    }
}
