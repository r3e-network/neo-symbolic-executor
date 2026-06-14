using System;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Raised on a NeoVM hard fault that cannot be caught by user TRY/CATCH (e.g. ABORT, divide-by-zero
/// at evaluation time, stack overflow). Distinct from <see cref="CatchableVmException"/>.
/// </summary>
public sealed class VmFaultException : Exception
{
    public VmFaultException(string message) : base(message) { }
    public VmFaultException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Raised on a NeoVM exception that user TRY/CATCH can catch (e.g. PICKITEM out of range,
/// missing map key per NeoVM CatchableException sites).
/// </summary>
public sealed class CatchableVmException : Exception
{
    public CatchableVmException(string message) : base(message) { }
}

/// <summary>
/// Raised when an analysis budget is exceeded (max paths, max depth, max heap items, etc.).
/// Distinct from VM faults: this is an analyzer concern, not contract behavior.
/// </summary>
public sealed class AnalysisBudgetException : Exception
{
    public AnalysisBudgetException(string message) : base(message) { }
}

/// <summary>
/// Raised when a runtime-feasible operation reaches a modeling surface the analyzer cannot yet
/// over-approximate soundly. Distinct from VM faults: callers must treat this as incomplete
/// coverage, not as contract behavior.
/// </summary>
public sealed class ModelingLimitException : Exception
{
    public ModelingLimitException(string message) : base(message) { }
}
