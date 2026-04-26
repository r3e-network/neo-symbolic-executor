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
    public int MaxDepth { get; init; } = 256;
    public int MaxVisitsPerOffset { get; init; } = 16;
    public int MaxStackSize { get; init; } = 2_048;
    public int MaxInvocationStackDepth { get; init; } = 1_024;
    public int MaxTryDepth { get; init; } = 16;
    public int MaxItemSize { get; init; } = 1_048_576;
    public int MaxCollectionSize { get; init; } = 2_048;
    public int MaxHeapObjects { get; init; } = 4_096;
    public int MaxShiftCount { get; init; } = 256;
    public int MaxPowExponent { get; init; } = 256;

    /// <summary>
    /// When the analysis budget is exceeded, mark the state truncated and emit it as a stopped
    /// terminal rather than discarding it. Detectors should respect <see cref="Telemetry.Truncated"/>.
    /// </summary>
    public bool MarkTruncatedOnBudget { get; init; } = true;

    public static ExecutionOptions Default { get; } = new();
}
