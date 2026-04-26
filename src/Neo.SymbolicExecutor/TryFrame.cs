namespace Neo.SymbolicExecutor;

public enum TryFrameState
{
    Try,
    Catch,
    Finally,
}

/// <summary>
/// A live TRY/CATCH/FINALLY frame. Mutable fields are reassigned via clone-on-write
/// to avoid the in-place mutation bug fixed in the prior Python audit.
/// </summary>
public sealed class TryFrame
{
    public int CatchOffset { get; init; }
    public int FinallyOffset { get; init; }
    public int EndOffset { get; init; }
    public TryFrameState State { get; set; }
    public int InitialStackDepth { get; init; }
    public int InitialCallDepth { get; init; }

    /// <summary>
    /// PC to resume at after the FINALLY block runs. Set by ENDTRY when transitioning
    /// Try→Finally. Audit C# #1: without this, ENDFINALLY would silently fall through to
    /// the byte after itself, mis-positioning execution after `try {} finally {}` blocks.
    /// </summary>
    public int PostFinallyPc { get; set; } = -1;

    public bool HasCatch => CatchOffset >= 0;
    public bool HasFinally => FinallyOffset >= 0;

    public TryFrame Clone() => new()
    {
        CatchOffset = CatchOffset,
        FinallyOffset = FinallyOffset,
        EndOffset = EndOffset,
        State = State,
        InitialStackDepth = InitialStackDepth,
        InitialCallDepth = InitialCallDepth,
        PostFinallyPc = PostFinallyPc,
    };
}
