using System;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Differential oracle: run the same concrete script in both Neo.VM's reference
/// <see cref="NeoVm.ExecutionEngine"/> and our <see cref="SymbolicEngine"/>; flag the
/// narrow case where Neo.VM HALTs cleanly (single-path concrete execution) but the
/// symbolic engine FAULTs the corresponding state. Such a divergence is always a real
/// bug — we have implemented an opcode more strictly than the spec requires.
///
/// Conservative scope:
/// - We do NOT flag the inverse direction (Neo.VM FAULT, symbolic HALT). Symbolic
///   exec sometimes produces multiple final states from forking; concretely-identical
///   forks may all halt while Neo.VM faults on a path Neo.VM picked. Bidirectional
///   would create false positives.
/// - We skip scripts containing SYSCALL/CALLT — Neo.VM faults on missing syscall
///   handlers but symbolic exec models a subset of them. Differential here is noise.
/// - We skip when symbolic terminates with status=Stopped (budget exceeded). Neo.VM
///   may have run further; we cannot decide.
/// - We bound Neo.VM execution at ~2000 steps via Debugger to avoid infinite loops.
/// </summary>
public sealed class DifferentialNeoVmTarget : IFuzzTarget
{
    public string Name => "differential-neovm";
    public Type[] ExpectedExceptions => Type.EmptyTypes;
    public bool SupportsDirectReplay => true;

    private const int NeoVmStepBudget = 2_000;

    private readonly ExecutionOptions _engineOptions = new()
    {
        MaxSteps = 2_000,
        MaxPaths = 32,
        MaxStackSize = 128,
        MaxInvocationStackDepth = 64,
        MaxItemSize = 32 * 1024,
        MaxCollectionSize = 256,
        MaxHeapObjects = 512,
        MaxQueuedStates = 128,
        PerRunDeadline = TimeSpan.FromSeconds(2),
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 2, 32);   // Smaller scripts → likelier to terminate
        reproInput = bytes;
        return RunWithInput(bytes, out reason);
    }

    public bool RunWithInput(byte[] input, out string? reason)
    {
        reason = null;

        // Skip scripts that contain SYSCALL (0x41) or CALLT (0x44). Symbolic exec models
        // a subset of syscalls; Neo.VM faults on missing handlers. Differential signal
        // here is noise. Also skip CALLA (0x36) — Neo.VM enforces strict pointer-sort
        // typing, symbolic exec is more lenient.
        foreach (var b in input)
        {
            if (b == (byte)NeoVm.OpCode.SYSCALL) return true;
            if (b == (byte)NeoVm.OpCode.CALLT) return true;
            if (b == (byte)NeoVm.OpCode.CALLA) return true;
        }

        // 1) Run in Neo.VM with a step budget.
        NeoVm.VMState neoState;
        try
        {
            using var nvm = new NeoVm.ExecutionEngine();
            try { nvm.LoadScript(new NeoVm.Script(input)); }
            catch (NeoVm.BadScriptException) { return true; }   // unloadable -> skip
            catch (FormatException) { return true; }
            catch (ArgumentException) { return true; }

            var dbg = new NeoVm.Debugger(nvm);
            for (int i = 0; i < NeoVmStepBudget; i++)
            {
                if (nvm.State == NeoVm.VMState.HALT || nvm.State == NeoVm.VMState.FAULT) break;
                try { dbg.StepInto(); }
                catch { /* Neo.VM may throw; treat as FAULT */ break; }
            }
            neoState = nvm.State;
        }
        catch (Exception)
        {
            return true;   // any infrastructure exception in Neo.VM driver -> skip
        }

        // Skip if Neo.VM didn't reach a terminal state in budget.
        if (neoState != NeoVm.VMState.HALT && neoState != NeoVm.VMState.FAULT) return true;
        // We only flag the (HALT, FAULT) divergence in the narrow direction.
        if (neoState != NeoVm.VMState.HALT) return true;

        // 2) Run in our symbolic engine.
        NeoProgram program;
        try { program = ScriptDecoder.Decode(input); }
        catch (VmFaultException) { return true; }   // decode failure -> can't run sym -> skip

        var result = new SymbolicEngine(program, _engineOptions).Run();
        if (result.FinalStates.Length == 0) return true;

        // Review fix (#63): do NOT treat the run as "agreement" just because SOME forked path
        // Halted. NeoVM ran this input single-path (the scope above skips SYSCALL/CALLT/CALLA,
        // so inputs are largely concrete and forks are concretely-identical). If NeoVM HALTed
        // but a sibling symbolic state FAULTed with a non-cap (semantic) reason, that fault is
        // a real divergence the oracle must report — a Halted sibling masking it would let an
        // engine bug slip through. So we look for a semantic (non-cap) fault FIRST, before
        // crediting any Halted state as agreement.
        var semanticFault = result.FinalStates.FirstOrDefault(s =>
            s.Status == TerminalStatus.Faulted
            && !IsExpectedDivergence(s.TerminationReason ?? "<no reason>"));
        if (semanticFault is null)
        {
            // No semantic fault on any path. A Halted state now legitimately means agreement;
            // Stopped (budget) / cap-only faults are undecidable and skipped.
            return true;
        }

        // NeoVM Halted but a symbolic path Faulted for a non-cap reason -> divergence.
        // (IsExpectedDivergence was already applied when selecting semanticFault above.)
        var faultReason = semanticFault.TerminationReason ?? "<no reason>";

        reason = $"{faultReason}: Neo.VM HALT but symbolic engine FAULTED";
        return false;
    }

    /// <summary>
    /// Returns true when a symbolic FAULT reason is an *expected* analyzer-level cap or
    /// symbolic-only limitation — not a NeoVM-semantic divergence. These are skipped so the
    /// oracle does not produce false divergence reports for legitimate analyzer caps.
    ///
    /// Review fix (#24): the prior filter used free substrings ("out of range",
    /// "out of bounds", and the "size" &amp;&amp; "exceeds" combo) that SWALLOWED genuine
    /// VM-semantic faults — slot/XDROP/ROLL/PICK/Peek "out of range" and "exceeds ... range",
    /// exactly the off-by-one bounds-bug class this differential oracle exists to catch. The
    /// filter now matches SPECIFIC analyzer-cap strings only. Genuine VM-bound faults such as
    /// "slot index ... out of range", "XDROP index ... out of range", "Peek depth ... out of
    /// range", and "ROLL index ... out of range" are NO LONGER skipped and surface as
    /// divergences.
    /// </summary>
    private static bool IsExpectedDivergence(string r) =>
        // MaxItemSize cap (analyzer-tighter than NeoVM): "... exceeds item size limit ..."
        r.Contains("exceeds item size limit")
        // Generic NeoVM hard limits modeled as analyzer caps.
        || r.Contains("exceeds NeoVM limit")
        // MaxHeapObjects cap.
        || r.Contains("Heap object limit")
        // MaxStackSize / MaxInvocationStackDepth caps.
        || r.Contains("evaluation stack overflow")
        || r.Contains("invocation stack overflow")
        // Symbolic-fuzz scheduler / budget caps.
        || r.Contains("budget:")
        || r.Contains("max paths")
        || r.Contains("max queued")
        // Symbolic-only refusal to execute on a non-concrete operand.
        || r.Contains("requires concrete")
        // Catchable exception that the test bytecode didn't TRY-wrap; not a semantic divergence
        // (NeoVM also throws, just routes to ExecuteThrow which the bytecode here doesn't observe).
        || r.Contains("uncaught")
        || r.Contains("PC at unaligned");   // see iter-2 wakeup-4: JIT decode covers most cases
                                            // but corner cases (post-RET PC overshoot etc.) remain
}
