using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor;

public sealed record ExecutionResult(
    ImmutableArray<ExecutionState> FinalStates,
    int StatesExplored,
    int StepsExecuted,
    bool BudgetExceeded,
    string? BudgetReason)
{
    public IEnumerable<ExecutionState> Halted => FinalStates.Where(s => s.Status == TerminalStatus.Halted);
    public IEnumerable<ExecutionState> Faulted => FinalStates.Where(s => s.Status == TerminalStatus.Faulted);
    public IEnumerable<ExecutionState> Stopped => FinalStates.Where(s => s.Status == TerminalStatus.Stopped);
    public bool AnyFaulted => FinalStates.Any(s => s.Status == TerminalStatus.Faulted);
}
