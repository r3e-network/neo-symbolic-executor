using System.Collections.Immutable;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Per-run analysis budgets. These are analyzer concerns (not NeoVM rules) and are surfaced
/// distinctly from VM faults so detectors can downgrade findings on truncated paths
/// (audit C7: detectors must not trust telemetry from cap-truncated states).
/// </summary>
public sealed record ExecutionOptions
{
    public int MaxSteps { get; init; } = 200_000;
    public int MaxPaths { get; init; } = 512;
    public int MaxVisitsPerOffset { get; init; } = 16;
    public int MaxStackSize { get; init; } = 2_048;
    public int MaxInvocationStackDepth { get; init; } = 1_024;
    public int MaxTryDepth { get; init; } = 16;
    // Audit fix (iter-2 wakeup-2): tighter heap defaults to bound peak memory under fuzz-style
    // path explosion. NeoVM's max stack item size is 1 MiB, but allowing every analyzer state to
    // independently allocate a 1 MiB buffer × up to 4096 objects, then cloning that across 32+
    // forked paths and 256+ queued states, produces multi-GB peaks before any cap fires. The
    // analyzer doesn't need full NeoVM-scale buffers for symbolic exploration; 64 KiB items × 1024
    // objects is a more realistic ceiling that still covers every Neo DevPack contract we've
    // observed in practice. The CLI can still raise these via explicit --max-* flags if needed.
    public int MaxItemSize { get; init; } = 65_536;
    public int MaxCollectionSize { get; init; } = 512;
    public int MaxHeapObjects { get; init; } = 1_024;
    public int MaxShiftCount { get; init; } = 256;
    public int MaxPowExponent { get; init; } = 256;
    public int InitialCallFlags { get; init; } = NeoCallFlags.All;
    public int RuntimeTrigger { get; init; } = NeoTriggerTypes.Application;
    public ImmutableArray<byte> CurrentScriptHash { get; init; } = ImmutableArray<byte>.Empty;

    /// <summary>
    /// Cap on worklist size. Without this, deeply-forking symbolic loops can drive worklist
    /// occupancy into the millions before any path terminates (and thus before MaxPaths fires).
    /// When the cap is reached, queued states are drained as Stopped (Truncated). 0 disables.
    /// </summary>
    public int MaxQueuedStates { get; init; } = 4_096;

    /// <summary>
    /// When the analysis budget is exceeded, mark the state truncated and emit it as a stopped
    /// terminal rather than discarding it. Detectors should respect <see cref="Telemetry.Truncated"/>.
    /// </summary>
    public bool MarkTruncatedOnBudget { get; init; } = true;

    /// <summary>
    /// Optional SMT backend for solver-backed path pruning. When null, the engine falls back to
    /// syntactic-only branch handling (constant folding via the simplifier). Enabled via
    /// <c>--smt</c> on the CLI.
    /// </summary>
    public Smt.ISmtBackend? SmtBackend { get; init; }

    /// <summary>
    /// Per-state cap on SMT concretizations of symbolic operands (PICK/ROLL/CALLA/NEWARRAY).
    /// Each concretization adds an `expr == value` constraint, which can fork the path space
    /// quickly; this cap prevents runaway exploration. 0 disables concretization entirely.
    /// </summary>
    public int MaxConcretizations { get; init; } = 8;

    /// <summary>
    /// Wall-clock deadline for a single Run() call. When set and exceeded, the engine drains
    /// the worklist as Stopped (Truncated) on the next step boundary. This is the only bound
    /// that catches per-iteration memory bombs caused by path-fork explosion of heap allocations
    /// — `MaxSteps` accounts work-per-state, not aggregate wall-clock, and a single state's
    /// fork point can spawn 256+ clones each with their own heap before any of them advances
    /// step-counted work. Default zero (disabled); fuzz targets set ~1-5 seconds.
    /// </summary>
    public System.TimeSpan? PerRunDeadline { get; init; }

    /// <summary>
    /// Optional manifest-aware resolver for same-contract <c>System.Contract.Call</c> targets.
    /// The core engine stays manifest-agnostic by default; formal verification supplies a
    /// resolver so concrete self-calls can execute the callee body instead of becoming opaque
    /// external proof surface.
    /// </summary>
    public ContractSelfCallResolver? SelfCallResolver { get; init; }

    public static ExecutionOptions Default { get; } = new();
}

public sealed record ContractSelfCallTarget(
    string Method,
    int Offset,
    int ParameterCount,
    bool HasReturnValue,
    bool Safe);

public delegate ContractSelfCallTarget? ContractSelfCallResolver(string method, int argumentCount);
