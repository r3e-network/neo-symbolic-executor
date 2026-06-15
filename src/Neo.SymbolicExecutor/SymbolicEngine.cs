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
    private const int MethodEntryCollectionSeedSize = 4;

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
            catch (ModelingLimitException mex)
            {
                state.Terminate(TerminalStatus.Stopped, "modeling limit: " + mex.Message);
                _finalStates.Add(state);
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

        var finalStates = _finalStates.ToImmutableArray();
        var coverageReasons = finalStates
            .Where(IsCoverageLimitingStop)
            .Select(s => s.TerminationReason ?? "stopped")
            .Distinct(System.StringComparer.Ordinal)
            .Order(System.StringComparer.Ordinal)
            .ToList();

        // Review fix (#1/#9): SMT operand concretization (PICK/ROLL/XDROP/NEWBUFFER/NEWARRAY_T)
        // pins a symbolic index to a single feasible value and constrains the path, silently
        // abandoning the other feasible values and the out-of-bounds fault branch. The state stays
        // Running, so it never reaches the Stopped set above. The verifier already downgrades on
        // SmtConcretizations>0; surface it here too so the bug-finder's CoverageIncomplete flag is
        // not falsely clean and the default analyze coverage gate fails closed.
        if (finalStates.Any(s => s.Telemetry.SmtConcretizations > 0))
            coverageReasons.Add(
                "SMT concretization pinned a symbolic operand to a single value; other feasible operand values were not explored");

        return new ExecutionResult(
            finalStates,
            _statesExplored,
            _stepsExecuted,
            _budgetExceeded,
            _budgetReason,
            coverageReasons.Count > 0,
            coverageReasons.Count > 0
                ? "symbolic execution stopped before full coverage: " + string.Join("; ", coverageReasons)
                : null);
    }

    private static bool IsCoverageLimitingStop(ExecutionState state)
    {
        if (state.Status != TerminalStatus.Stopped) return false;
        string reason = state.TerminationReason ?? "";
        if (reason.StartsWith("budget:", System.StringComparison.Ordinal)) return false;
        if (string.Equals(reason, "both branches unsatisfiable", System.StringComparison.Ordinal)) return false;
        return true;
    }

    private void DrainWorklist(string reason)
    {
        MarkBudgetExceeded(reason);
        while (_worklist.TryDequeue(out var leftover))
        {
            leftover.Telemetry.Truncated = true;
            leftover.Terminate(TerminalStatus.Stopped, "budget: " + reason);
            _finalStates.Add(leftover);
        }
    }

    private void MarkBudgetExceeded(string reason)
    {
        _budgetExceeded = true;
        _budgetReason ??= reason;
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
                state.Push(CreateMethodEntryArgument(state, p, i));
            }
        }
        return state;
    }

    /// <summary>
    /// Build one or more entry states for proof-oriented method analysis. ABI <c>Any</c>
    /// parameters range over all NeoVM stack-item families, so the verifier uses this overload
    /// to cover representative primitive, compound, and interop shapes instead of silently
    /// treating <c>Any</c> as ByteString-only.
    /// </summary>
    public IReadOnlyList<ExecutionState> CreateMethodEntryStates(
        int offset,
        IReadOnlyList<ContractParameterDefinition>? parameters)
    {
        var states = new List<ExecutionState> { BuildEntryState(offset) };
        if (parameters is not { Count: > 0 } pars)
            return states;

        for (int i = pars.Count - 1; i >= 0; i--)
        {
            var next = new List<ExecutionState>();
            foreach (var state in states)
            {
                foreach (var expanded in CreateMethodEntryArgumentStates(state, pars[i], i))
                    next.Add(expanded);
            }
            states = next;
        }

        return states;
    }

    /// <summary>
    /// Canonical symbol-name shape for a method-entry argument: <c>arg_&lt;name&gt;</c> when the
    /// manifest declares a parameter name, <c>arg&lt;i&gt;</c> otherwise. Detectors reading
    /// path-condition free symbols must use this exact shape to match the engine — see
    /// <c>ProtocolRiskHelpers.MethodArgSymbolName</c>.
    /// </summary>
    public static string MethodEntryArgSymbolName(string? declaredName, int positionalIndex) =>
        string.IsNullOrEmpty(declaredName) ? $"arg{positionalIndex}" : $"arg_{declaredName}";

    // Audit fix (iter-2 wakeup-2 memory bomb): construct the Heap with the engine's budgets
    // rather than letting it default to 1 MiB × 4096 objects. Without this plumbing a single
    // pathological iteration could allocate ~3 GB before any cap fired, freezing all six
    // workers on that iteration.
    private ExecutionState BuildEntryState(int pc)
    {
        var state = new ExecutionState
        {
            Heap = new Heap(_options.MaxHeapObjects, _options.MaxItemSize, _options.MaxCollectionSize, _options.MaxStackSize),
            CurrentCallFlags = _options.InitialCallFlags,
            RuntimeTrigger = _options.RuntimeTrigger,
        };
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = pc;
        return state;
    }

    private static SymbolicValue CreateMethodEntryArgument(
        ExecutionState state,
        ContractParameterDefinition parameter,
        int positionalIndex)
    {
        string name = MethodEntryArgSymbolName(parameter.Name, positionalIndex);
        string type = parameter.Type ?? "Any";
        string taint = name;

        if (string.Equals(type, "Integer", System.StringComparison.OrdinalIgnoreCase))
        {
            var value = MethodEntrySymbol(Sort.Int, name, taint);
            state.PathConditions = state.PathConditions
                .Add(Expr.Ge(value.Expression, Expr.Int(Expr.NeoVmIntegerMin)))
                .Add(Expr.Le(value.Expression, Expr.Int(Expr.NeoVmIntegerMax)));
            return value;
        }
        if (string.Equals(type, "Boolean", System.StringComparison.OrdinalIgnoreCase))
            return MethodEntrySymbol(Sort.Bool, name, taint);
        if (string.Equals(type, "InteropInterface", System.StringComparison.OrdinalIgnoreCase))
            return MethodEntrySymbol(Sort.InteropInterface, name, taint);

        if (TryGetFixedByteLengthAbiType(type, out int fixedByteLength))
        {
            var value = MethodEntrySymbol(Sort.Bytes, name, taint);
            state.PathConditions = state.PathConditions.Add(Expr.Eq(
                new UnaryExpr(Sort.Int, "size", value.Expression),
                Expr.Int(fixedByteLength)));
            if (string.Equals(type, "PublicKey", System.StringComparison.OrdinalIgnoreCase))
                state.PathConditions = state.PathConditions.Add(Expr.IsValidEcPoint(value.Expression));
            return value;
        }

        if (IsVariableByteAbiType(type))
        {
            var value = MethodEntrySymbol(Sort.Bytes, name, taint);
            var size = new UnaryExpr(Sort.Int, "size", value.Expression);
            state.PathConditions = state.PathConditions
                .Add(Expr.Ge(size, Expr.Int(0)))
                .Add(Expr.Le(size, Expr.Int(state.Heap.MaxItemSize)));
            if (string.Equals(type, "String", System.StringComparison.OrdinalIgnoreCase))
                state.PathConditions = state.PathConditions.Add(Expr.IsStrictUtf8(value.Expression));
            return value;
        }

        if (string.Equals(type, "Buffer", System.StringComparison.OrdinalIgnoreCase))
            return CreateBufferMethodEntrySymbol(state, name, taint);

        if (string.Equals(type, "Array", System.StringComparison.OrdinalIgnoreCase))
        {
            int count = MethodEntryCollectionSeedCount(state);
            var array = state.Heap.NewArray(Enumerable.Range(0, count)
                .Select(i => MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)),
                isSymbolicOpen: true,
                minCount: 0);
            return SymbolicValue.HeapRef(Sort.Array, array.Id).WithTaint(taint);
        }

        if (string.Equals(type, "Struct", System.StringComparison.OrdinalIgnoreCase))
        {
            int count = MethodEntryCollectionSeedCount(state);
            var structure = state.Heap.NewStruct(Enumerable.Range(0, count)
                .Select(i => MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)),
                isSymbolicOpen: true,
                minCount: 0);
            return SymbolicValue.HeapRef(Sort.Struct, structure.Id).WithTaint(taint);
        }

        if (string.Equals(type, "Map", System.StringComparison.OrdinalIgnoreCase))
        {
            int count = MethodEntryCollectionSeedCount(state);
            var entries = new List<(SymbolicValue Key, SymbolicValue Value)>(count);
            if (count > 0)
                entries.Add((SymbolicValue.Int(0), MethodEntrySymbol(Sort.Bytes, $"{name}[0]", taint)));
            if (count > 1)
                entries.Add((SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("key")),
                    MethodEntrySymbol(Sort.Bytes, $"{name}[key]", taint)));
            if (count > 2)
                entries.Add((SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes(name)),
                    MethodEntrySymbol(Sort.Bytes, $"{name}[{name}]", taint)));
            for (int i = 3; i < count; i++)
                entries.Add((SymbolicValue.Int(i), MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)));

            var map = state.Heap.NewMap(entries, isSymbolicOpen: true);
            return SymbolicValue.HeapRef(Sort.Map, map.Id).WithTaint(taint);
        }

        // Any and unfamiliar manifest strings flow through Bytes. NeoVM's GetInteger/GetBoolean
        // and ByteString conversions keep those primitive parameters conservative and useful.
        return MethodEntrySymbol(Sort.Bytes, name, taint);
    }

    private static IEnumerable<ExecutionState> CreateMethodEntryArgumentStates(
        ExecutionState state,
        ContractParameterDefinition parameter,
        int positionalIndex)
    {
        string type = parameter.Type ?? "Any";
        if (!string.Equals(type, "Any", System.StringComparison.OrdinalIgnoreCase))
        {
            state.Push(CreateMethodEntryArgument(state, parameter, positionalIndex));
            yield return state;
            yield break;
        }

        string name = MethodEntryArgSymbolName(parameter.Name, positionalIndex);
        string taint = name;
        for (int variant = 0; variant < MethodEntryAnyVariantCount; variant++)
        {
            var target = state.Clone();
            target.Push(CreateAnyMethodEntryArgument(target, name, taint, variant));
            yield return target;
        }
    }

    private const int MethodEntryAnyVariantCount = 9;

    private static SymbolicValue CreateAnyMethodEntryArgument(
        ExecutionState state,
        string name,
        string taint,
        int variant) =>
        variant switch
        {
            0 => SymbolicValue.Null().WithTaint(taint),
            1 => MethodEntrySymbol(Sort.Bool, name, taint),
            2 => CreateIntegerMethodEntrySymbol(state, name, taint),
            3 => CreateVariableByteMethodEntrySymbol(state, name, taint),
            4 => CreateBufferMethodEntrySymbol(state, name, taint),
            5 => CreateArrayMethodEntrySymbol(state, name, taint),
            6 => CreateStructMethodEntrySymbol(state, name, taint),
            7 => CreateMapMethodEntrySymbol(state, name, taint),
            8 => MethodEntrySymbol(Sort.InteropInterface, name, taint),
            _ => throw new System.ArgumentOutOfRangeException(nameof(variant), variant, null),
        };

    private static SymbolicValue CreateIntegerMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        var value = MethodEntrySymbol(Sort.Int, name, taint);
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(value.Expression, Expr.Int(Expr.NeoVmIntegerMin)))
            .Add(Expr.Le(value.Expression, Expr.Int(Expr.NeoVmIntegerMax)));
        return value;
    }

    private static SymbolicValue CreateVariableByteMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        var value = MethodEntrySymbol(Sort.Bytes, name, taint);
        var size = new UnaryExpr(Sort.Int, "size", value.Expression);
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(size, Expr.Int(0)))
            .Add(Expr.Le(size, Expr.Int(state.Heap.MaxItemSize)));
        return value;
    }

    private static SymbolicValue CreateBufferMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        int count = MethodEntryCollectionSeedCount(state);
        var cells = new List<Expression>(count);
        for (int i = 0; i < count; i++)
        {
            var cell = Expr.Sym(Sort.Int, $"{name}[{i}]");
            state.PathConditions = state.PathConditions
                .Add(Expr.Ge(cell, Expr.Int(0)))
                .Add(Expr.Le(cell, Expr.Int(byte.MaxValue)));
            cells.Add(cell);
        }

        var runtimeLength = Expr.Sym(Sort.Int, $"{name}_size");
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(runtimeLength, Expr.Int(0)))
            .Add(Expr.Le(runtimeLength, Expr.Int(state.Heap.MaxItemSize)));

        var buffer = state.Heap.Allocate(id => new BufferObject(
            id,
            cells,
            isSymbolicOpen: true,
            minLength: 0,
            symbolicLength: runtimeLength));
        return SymbolicValue.HeapRef(Sort.Buffer, buffer.Id).WithTaint(taint);
    }

    private static SymbolicValue CreateArrayMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        int count = MethodEntryCollectionSeedCount(state);
        var array = state.Heap.NewArray(Enumerable.Range(0, count)
            .Select(i => MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)),
            isSymbolicOpen: true,
            minCount: 0);
        return SymbolicValue.HeapRef(Sort.Array, array.Id).WithTaint(taint);
    }

    private static SymbolicValue CreateStructMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        int count = MethodEntryCollectionSeedCount(state);
        var structure = state.Heap.NewStruct(Enumerable.Range(0, count)
            .Select(i => MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)),
            isSymbolicOpen: true,
            minCount: 0);
        return SymbolicValue.HeapRef(Sort.Struct, structure.Id).WithTaint(taint);
    }

    private static SymbolicValue CreateMapMethodEntrySymbol(ExecutionState state, string name, string taint)
    {
        int count = MethodEntryCollectionSeedCount(state);
        var entries = new List<(SymbolicValue Key, SymbolicValue Value)>(count);
        if (count > 0)
            entries.Add((SymbolicValue.Int(0), MethodEntrySymbol(Sort.Bytes, $"{name}[0]", taint)));
        if (count > 1)
            entries.Add((SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("key")),
                MethodEntrySymbol(Sort.Bytes, $"{name}[key]", taint)));
        if (count > 2)
            entries.Add((SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes(name)),
                MethodEntrySymbol(Sort.Bytes, $"{name}[{name}]", taint)));
        for (int i = 3; i < count; i++)
            entries.Add((SymbolicValue.Int(i), MethodEntrySymbol(Sort.Bytes, $"{name}[{i}]", taint)));

        var map = state.Heap.NewMap(entries, isSymbolicOpen: true);
        return SymbolicValue.HeapRef(Sort.Map, map.Id).WithTaint(taint);
    }

    private static bool TryGetFixedByteLengthAbiType(string type, out int length)
    {
        if (string.Equals(type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "UInt160", System.StringComparison.OrdinalIgnoreCase))
        {
            length = Hash160Length;
            return true;
        }

        if (string.Equals(type, "Hash256", System.StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "UInt256", System.StringComparison.OrdinalIgnoreCase))
        {
            length = Hash256Length;
            return true;
        }

        if (string.Equals(type, "PublicKey", System.StringComparison.OrdinalIgnoreCase))
        {
            length = CompressedPublicKeyLength;
            return true;
        }

        if (string.Equals(type, "Signature", System.StringComparison.OrdinalIgnoreCase))
        {
            length = SignatureLength;
            return true;
        }

        length = 0;
        return false;
    }

    private static bool IsVariableByteAbiType(string type) =>
        string.Equals(type, "ByteString", System.StringComparison.OrdinalIgnoreCase)
        || string.Equals(type, "ByteArray", System.StringComparison.OrdinalIgnoreCase)
        || string.Equals(type, "String", System.StringComparison.OrdinalIgnoreCase);

    private static SymbolicValue MethodEntrySymbol(Sort sort, string name, string taint) =>
        SymbolicValue.Symbol(sort, name).WithTaint(taint);

    private static int MethodEntryCollectionSeedCount(ExecutionState state) =>
        System.Math.Max(0, System.Math.Min(MethodEntryCollectionSeedSize, state.Heap.MaxCollectionSize));

    /// <summary>
    /// The top-level reference contribution: the evaluation stack plus every static/local/argument slot.
    /// The full NeoVM reference count (the quantity <c>ExecutionEngineLimits.MaxStackSize</c> = 2048 bounds,
    /// asserted in <c>PostExecuteInstruction</c>) also includes the subitems of every reachable compound,
    /// added on top of this base by <see cref="EnforceReferenceCount"/>.
    /// </summary>
    private static int ReferenceLoad(ExecutionState state)
    {
        int load = state.EvaluationStack.Count + state.StaticFields.Count;
        foreach (var frame in state.CallStack)
            load += frame.Locals.Count + frame.Args.Count;
        return load;
    }

    /// <summary>
    /// NeoVM's <c>ReferenceCounter.Count</c> (bounded by MaxStackSize = 2048) is the evaluation stack and
    /// slots PLUS the subitems of every reachable compound, counted once per distinct object via
    /// <c>AddStackReference</c>: Array/Struct items and Map keys+values (Buffer is not a CompoundType, so its
    /// cells do not count). <see cref="ReferenceLoad"/> alone misses a subitem-driven overflow (e.g. several
    /// 512-cell arrays held live, where no single collection exceeds MaxCollectionSize), which NeoVM faults
    /// on but the engine used to prove fault-free. A cheap all-heap upper bound short-circuits the common
    /// safe case; only when it exceeds the limit do we walk the reachable object graph to count precisely.
    /// A concrete over-limit count faults; a reachable OPEN (unknown-length) collection that could push the
    /// total past the limit routes to a modeling limit (CoverageIncomplete) — never a false fault.
    /// </summary>
    private void EnforceReferenceCount(ExecutionState state)
    {
        int baseLoad = ReferenceLoad(state);
        if (baseLoad > _options.MaxStackSize)
            throw new VmFaultException("evaluation stack overflow");

        long upper = baseLoad;
        foreach (var obj in state.Heap.Objects.Values)
            upper += CompoundSubitemCount(obj);
        if (upper <= _options.MaxStackSize)
            return;

        var (count, sawOpen) = ReachableReferenceCount(state, _options.MaxStackSize);
        if (count > _options.MaxStackSize)
            throw new VmFaultException(
                $"reference count {count} exceeds NeoVM MaxStackSize {_options.MaxStackSize}");
        if (sawOpen)
            throw new ModelingLimitException(
                "a reachable open symbolic collection may push the reference count past NeoVM MaxStackSize");
    }

    private static int CompoundSubitemCount(HeapObject obj) => obj switch
    {
        StructObject s => s.Fields.Count,    // Struct : Array, subitems are its fields
        ArrayObject a => a.Items.Count,
        MapObject m => m.Entries.Count * 2,  // NeoVM Map.SubItems = Keys.Concat(Values)
        _ => 0,                              // Buffer is not a CompoundType
    };

    /// <summary>
    /// Precise NeoVM reference count: the top-level <see cref="ReferenceLoad"/> plus the subitems of every
    /// compound reachable from the stack/slot roots, each distinct object counted once (matching
    /// AddStackReference's tracked-set dedup). Stops early once <paramref name="cap"/> is exceeded.
    /// <c>SawOpen</c> is set when a reachable collection has unknown (symbolic-open) length, so its true
    /// subitem count may exceed the seeded prefix counted here.
    /// </summary>
    private static (int Count, bool SawOpen) ReachableReferenceCount(ExecutionState state, int cap)
    {
        int count = ReferenceLoad(state);
        bool sawOpen = false;
        var visited = new HashSet<int>();
        var queue = new Queue<int>();
        void Enqueue(IEnumerable<SymbolicValue?> items)
        {
            foreach (var v in items)
                if (v?.Expression is HeapRef href)
                    queue.Enqueue(href.ObjectId);
        }
        Enqueue(state.EvaluationStack);
        Enqueue(state.StaticFields);
        foreach (var frame in state.CallStack)
        {
            Enqueue(frame.Locals);
            Enqueue(frame.Args);
        }
        while (queue.Count > 0 && count <= cap)
        {
            int id = queue.Dequeue();
            if (!visited.Add(id)) continue;
            if (!state.Heap.Objects.TryGetValue(id, out var obj)) continue;
            switch (obj)
            {
                case StructObject s:
                    count += s.Fields.Count;
                    if (s.IsSymbolicOpen) sawOpen = true;
                    Enqueue(s.Fields);
                    break;
                case ArrayObject a:
                    count += a.Items.Count;
                    if (a.IsSymbolicOpen) sawOpen = true;
                    Enqueue(a.Items);
                    break;
                case MapObject m:
                    count += m.Entries.Count * 2;
                    if (m.IsSymbolicOpen) sawOpen = true;
                    Enqueue(m.Entries.Select(e => e.Value));
                    break;
            }
        }
        return (count, sawOpen);
    }

    private IEnumerable<ExecutionState> StepBounded(ExecutionState state)
    {
        if (state.Steps >= _options.MaxSteps)
        {
            state.Telemetry.Truncated = true;
            const string reason = "max steps reached";
            MarkBudgetExceeded(reason);
            state.Terminate(TerminalStatus.Stopped, "budget: " + reason);
            return new[] { state };
        }
        state.Steps++;
        _stepsExecuted++;

        EnforceReferenceCount(state);

        if (!state.VisitCounts.TryGetValue(state.Pc, out int visits)) visits = 0;
        if (visits >= _options.MaxVisitsPerOffset)
        {
            state.Telemetry.Truncated = true;
            // Record under VisitCapsHit, not LoopsDetected. LoopsDetected is the back-edge
            // target set populated by JMP*/branch sites; the cap-hit PC is not necessarily a
            // back-edge target. Polluting LoopsDetected with cap-hit offsets caused detectors
            // to surface non-loop offsets as "loop sites".
            state.Telemetry.VisitCapsHit.Add(state.Pc);
            const string reason = "visit cap at offset";
            MarkBudgetExceeded(reason);
            state.Terminate(TerminalStatus.Stopped, "budget: " + reason);
            return new[] { state };
        }
        state.VisitCounts[state.Pc] = visits + 1;
        state.Path.Add(state.Pc);

        // Audit fix (iter-2 wakeup-4 differential): match Neo.VM by JIT-decoding the
        // instruction at PC if the linear-scan index has no entry. NeoVM happily executes
        // a JMP whose target lands inside the operand of a prior instruction; our engine
        // used to fault on "unaligned offset" — a structural divergence the differential
        // target found within 10 seconds.
        // Round-3 audit fix: NeoVM performs an IMPLICIT RET when the program counter reaches (or
        // passes) the end of the script — falling off the end is a clean HALT/return, not a fault
        // (verified on the real VM: a script `PUSH1` with no RET HALTs with 1 on the stack). The prior
        // code faulted here, pruning that feasible terminal path.
        if (state.Pc >= _program.Bytes.Length)
            return ImplicitReturn(state, "implicit RET at end of script");

        var inst = _program.AtOffsetOrDecode(state.Pc);
        if (inst is null)
        {
            state.Terminate(TerminalStatus.Faulted, $"PC at unaligned offset 0x{state.Pc:X4}");
            return new[] { state };
        }

        return Dispatch(state, inst);
    }
}
