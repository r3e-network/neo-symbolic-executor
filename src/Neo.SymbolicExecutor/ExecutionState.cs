using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor;

public enum TerminalStatus
{
    Running,
    Halted,
    Faulted,
    Stopped,
}

/// <summary>
/// One symbolic execution state. A state is a single concrete (-ish) "execution context";
/// branching forks the state, and clones must be deep enough that no branch sees another's writes.
///
/// The audit identified shallow-clone leaks as a critical class of bugs (Python C1, C6).
/// In C# we use Clone() everywhere and lean on records / List ctor copies for correctness.
/// </summary>
public sealed class ExecutionState
{
    public int Pc { get; set; }
    public List<SymbolicValue> EvaluationStack { get; init; }
    public List<CallFrame> CallStack { get; init; }
    public List<SymbolicValue?> StaticFields { get; init; }
    public Heap Heap { get; init; }
    public ImmutableList<Expression> PathConditions { get; set; } = ImmutableList<Expression>.Empty;
    public Telemetry Telemetry { get; init; }
    public TerminalStatus Status { get; set; } = TerminalStatus.Running;
    public string? TerminationReason { get; set; }
    public int Steps { get; set; }
    public Dictionary<int, int> VisitCounts { get; init; }
    public List<int> Path { get; init; }
    public SymbolicValue? UncaughtException { get; set; }
    public Dictionary<string, SymbolicValue> InteropContext { get; init; }
    public Dictionary<Expression, SymbolicValue> StorageValues { get; init; }
    public Dictionary<int, int> UnknownStorageReadCounts { get; init; }
    public int CurrentCallFlags { get; set; } = NeoCallFlags.All;
    public int RuntimeTrigger { get; set; } = NeoTriggerTypes.Application;
    public int FreshSymbolCounter { get; set; }

    public ExecutionState()
    {
        EvaluationStack = new List<SymbolicValue>();
        CallStack = new List<CallFrame>();
        StaticFields = new List<SymbolicValue?>();
        Heap = new Heap();
        Telemetry = new Telemetry();
        Telemetry.BindPathConditions(() => PathConditions.ToImmutableArray());
        VisitCounts = new Dictionary<int, int>();
        Path = new List<int>();
        InteropContext = new Dictionary<string, SymbolicValue>();
        StorageValues = new Dictionary<Expression, SymbolicValue>();
        UnknownStorageReadCounts = new Dictionary<int, int>();
    }

    private ExecutionState(
        int pc,
        List<SymbolicValue> stack,
        List<CallFrame> callStack,
        List<SymbolicValue?> statics,
        Heap heap,
        ImmutableList<Expression> conditions,
        Telemetry telemetry,
        TerminalStatus status,
        string? reason,
        int steps,
        Dictionary<int, int> visits,
        List<int> path,
        SymbolicValue? exception,
        Dictionary<string, SymbolicValue> interop,
        Dictionary<Expression, SymbolicValue> storageValues,
        Dictionary<int, int> unknownStorageReadCounts,
        int currentCallFlags,
        int runtimeTrigger,
        int freshSymbolCounter)
    {
        Pc = pc;
        EvaluationStack = stack;
        CallStack = callStack;
        StaticFields = statics;
        Heap = heap;
        PathConditions = conditions;
        Telemetry = telemetry;
        Telemetry.BindPathConditions(() => PathConditions.ToImmutableArray());
        Status = status;
        TerminationReason = reason;
        Steps = steps;
        VisitCounts = visits;
        Path = path;
        UncaughtException = exception;
        InteropContext = interop;
        StorageValues = storageValues;
        UnknownStorageReadCounts = unknownStorageReadCounts;
        CurrentCallFlags = currentCallFlags;
        RuntimeTrigger = runtimeTrigger;
        FreshSymbolCounter = freshSymbolCounter;
    }

    public ExecutionState Clone() => new(
        Pc,
        new List<SymbolicValue>(EvaluationStack),
        CallStack.Select(f => f.Clone()).ToList(),
        new List<SymbolicValue?>(StaticFields),
        Heap.Clone(),
        PathConditions,                    // ImmutableList: safe to share
        Telemetry.Clone(),
        Status,
        TerminationReason,
        Steps,
        new Dictionary<int, int>(VisitCounts),
        new List<int>(Path),
        UncaughtException,
        new Dictionary<string, SymbolicValue>(InteropContext),
        new Dictionary<Expression, SymbolicValue>(StorageValues),
        new Dictionary<int, int>(UnknownStorageReadCounts),
        CurrentCallFlags,
        RuntimeTrigger,
        FreshSymbolCounter);

    public string NextFreshSymbolName(string prefix) =>
        $"{prefix}_{FreshSymbolCounter++}";

    public CallFrame CurrentFrame =>
        CallStack.Count == 0
            ? throw new VmFaultException("No active call frame")
            : CallStack[^1];

    public void Push(SymbolicValue value) => EvaluationStack.Add(value);

    public SymbolicValue Pop()
    {
        if (EvaluationStack.Count == 0)
            throw new VmFaultException("Stack underflow");
        var top = EvaluationStack[^1];
        EvaluationStack.RemoveAt(EvaluationStack.Count - 1);
        return top;
    }

    public SymbolicValue Peek(int back = 0)
    {
        if (back < 0 || back >= EvaluationStack.Count)
            throw new VmFaultException($"Peek depth {back} out of range (stack size {EvaluationStack.Count})");
        return EvaluationStack[^(back + 1)];
    }

    public ExecutionState WithPc(int newPc)
    {
        Pc = newPc;
        return this;
    }

    public ExecutionState Terminate(TerminalStatus status, string? reason = null)
    {
        Status = status;
        TerminationReason = reason;
        return this;
    }

    public ExecutionState AddCondition(Expression condition)
    {
        PathConditions = PathConditions.Add(condition);
        return this;
    }

    public override string ToString() =>
        $"State(pc=0x{Pc:X4}, status={Status}, stack={EvaluationStack.Count}, calls={CallStack.Count})";
}
