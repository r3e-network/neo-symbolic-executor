using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Telemetry collected per-state during symbolic exploration. Detectors consume these fields.
///
/// All collections are mutable lists/dicts owned by the state. <see cref="Clone"/> performs a
/// deep copy so cloned states do not alias each other (audit C1, C6 lessons).
/// </summary>
public sealed class Telemetry
{
    public List<StorageOp> StorageOps { get; } = new();
    public List<ExternalCall> ExternalCalls { get; } = new();
    public ArithmeticOpCollection ArithmeticOps { get; } = new();
    public FaultConditionCollection FaultConditions { get; } = new();
    public List<int> WitnessChecks { get; } = new();
    public List<WitnessCheckOp> WitnessCheckOps { get; } = new();
    public HashSet<int> WitnessChecksEnforced { get; } = new();
    public HashSet<string> WitnessCheckResultsEnforced { get; } = new();
    public List<int> CallerHashChecks { get; } = new();
    public List<CallerHashCheckOp> CallerHashCheckOps { get; } = new();
    public List<int> SignatureChecks { get; } = new();
    public List<SignatureCheckOp> SignatureCheckOps { get; } = new();
    public HashSet<int> SignatureChecksEnforced { get; } = new();
    public HashSet<string> SignatureCheckResultsEnforced { get; } = new();
    public List<int> TimeAccesses { get; } = new();
    public List<int> RandomnessAccesses { get; } = new();
    public List<int> EventsEmitted { get; } = new();
    public List<RuntimeNotification> Notifications { get; } = new();
    public List<ContractExistenceQuery> ContractExistenceQueries { get; } = new();
    /// <summary>
    /// Set of back-edge target offsets — populated at JMP*/branch sites when the resolved target
    /// is a lower offset than the current PC. Each entry is a *loop-header offset*, not the
    /// jumping instruction.
    /// </summary>
    public HashSet<int> LoopsDetected { get; } = new();
    /// <summary>
    /// Set of PCs where the per-offset visit cap fired. Distinct from <see cref="LoopsDetected"/>
    /// because a cap-hit PC is not necessarily a back-edge target — any opcode revisited beyond
    /// the cap (e.g. an unrolled tight switch tail) ends up here. The DOS detector consumes both
    /// as evidence of a loop-shaped truncation.
    /// </summary>
    public HashSet<int> VisitCapsHit { get; } = new();
    public HashSet<int> IteratorLoops { get; } = new();
    public List<int> ExceptionsThrown { get; } = new();
    public List<int> UnknownSyscalls { get; } = new();
    public List<int> UnknownOpcodes { get; } = new();
    public int MaxCallStackDepth { get; set; }
    public long GasCost { get; set; }
    public bool Truncated { get; set; }
    public bool ReentrancyGuard { get; set; }
    public HashSet<int> SmtUnknownOffsets { get; } = new();
    public int SmtPrunedBranches { get; set; }
    public int SmtConcretizations { get; set; }

    internal void BindPathConditions(Func<ImmutableArray<Expression>> currentPathSnapshot)
    {
        ArithmeticOps.BindPathConditions(currentPathSnapshot);
        FaultConditions.BindPathConditions(currentPathSnapshot);
    }

    public Telemetry Clone()
    {
        var copy = new Telemetry();
        copy.StorageOps.AddRange(StorageOps);
        copy.ExternalCalls.AddRange(ExternalCalls.Select(c => c.Clone()));
        copy.ArithmeticOps.AddRange(ArithmeticOps);
        copy.FaultConditions.AddRange(FaultConditions);
        copy.WitnessChecks.AddRange(WitnessChecks);
        copy.WitnessCheckOps.AddRange(WitnessCheckOps);
        foreach (var w in WitnessChecksEnforced) copy.WitnessChecksEnforced.Add(w);
        foreach (var w in WitnessCheckResultsEnforced) copy.WitnessCheckResultsEnforced.Add(w);
        copy.CallerHashChecks.AddRange(CallerHashChecks);
        copy.CallerHashCheckOps.AddRange(CallerHashCheckOps);
        copy.SignatureChecks.AddRange(SignatureChecks);
        copy.SignatureCheckOps.AddRange(SignatureCheckOps);
        foreach (var s in SignatureChecksEnforced) copy.SignatureChecksEnforced.Add(s);
        foreach (var s in SignatureCheckResultsEnforced) copy.SignatureCheckResultsEnforced.Add(s);
        copy.TimeAccesses.AddRange(TimeAccesses);
        copy.RandomnessAccesses.AddRange(RandomnessAccesses);
        copy.EventsEmitted.AddRange(EventsEmitted);
        copy.Notifications.AddRange(Notifications);
        copy.ContractExistenceQueries.AddRange(ContractExistenceQueries);
        foreach (var l in LoopsDetected) copy.LoopsDetected.Add(l);
        foreach (var v in VisitCapsHit) copy.VisitCapsHit.Add(v);
        foreach (var l in IteratorLoops) copy.IteratorLoops.Add(l);
        copy.ExceptionsThrown.AddRange(ExceptionsThrown);
        copy.UnknownSyscalls.AddRange(UnknownSyscalls);
        copy.UnknownOpcodes.AddRange(UnknownOpcodes);
        copy.MaxCallStackDepth = MaxCallStackDepth;
        copy.GasCost = GasCost;
        copy.Truncated = Truncated;
        copy.ReentrancyGuard = ReentrancyGuard;
        foreach (var off in SmtUnknownOffsets) copy.SmtUnknownOffsets.Add(off);
        copy.SmtPrunedBranches = SmtPrunedBranches;
        copy.SmtConcretizations = SmtConcretizations;
        return copy;
    }

    public bool IsWitnessCheckResultEnforced(WitnessCheckOp op) =>
        WitnessCheckResultsEnforced.Contains(op.ResultSymbol)
        || (WitnessCheckResultsEnforced.Count == 0 && WitnessChecksEnforced.Contains(op.Offset));

    public bool IsSignatureCheckResultEnforced(SignatureCheckOp op) =>
        SignatureCheckResultsEnforced.Contains(op.ResultSymbol)
        || (SignatureCheckResultsEnforced.Count == 0 && SignatureChecksEnforced.Contains(op.Offset));
}

public sealed class FaultConditionCollection : IReadOnlyList<FaultConditionOp>
{
    private readonly List<FaultConditionOp> items = new();
    private Func<ImmutableArray<Expression>> currentPathSnapshot = static () => ImmutableArray<Expression>.Empty;

    public int Count => items.Count;

    public FaultConditionOp this[int index] => items[index];

    internal void BindPathConditions(Func<ImmutableArray<Expression>> snapshot) =>
        currentPathSnapshot = snapshot;

    public void Add(FaultConditionOp item)
    {
        if (item.PathConditions.IsDefault)
            item = item with { PathConditions = currentPathSnapshot() };
        items.Add(item);
    }

    public void AddRange(IEnumerable<FaultConditionOp> source)
    {
        foreach (var item in source)
            Add(item);
    }

    public IEnumerator<FaultConditionOp> GetEnumerator() => items.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public sealed class ArithmeticOpCollection : IReadOnlyList<ArithmeticOp>
{
    private readonly List<ArithmeticOp> items = new();
    private Func<ImmutableArray<Expression>> currentPathSnapshot = static () => ImmutableArray<Expression>.Empty;

    public int Count => items.Count;

    public ArithmeticOp this[int index] => items[index];

    internal void BindPathConditions(Func<ImmutableArray<Expression>> snapshot) =>
        currentPathSnapshot = snapshot;

    public void Add(ArithmeticOp item)
    {
        if (item.PathConditions.IsDefault)
            item = item with { PathConditions = currentPathSnapshot() };
        items.Add(item);
    }

    public void AddRange(IEnumerable<ArithmeticOp> source)
    {
        foreach (var item in source)
            Add(item);
    }

    public IEnumerator<ArithmeticOp> GetEnumerator() => items.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public sealed record StorageOp(
    int Offset,
    StorageOpKind Kind,
    SymbolicValue Key,
    SymbolicValue? Value,
    bool ContextDynamic,
    bool ContextReadOnly);

public enum StorageOpKind { Get, Put, Delete, Find }

public sealed record FaultConditionOp(
    int Offset,
    string Operation,
    Expression FaultCondition,
    string Reason,
    string FailedCondition,
    ImmutableArray<Expression> PathConditions = default);

public sealed record WitnessCheckOp(
    int Offset,
    SymbolicValue Target,
    string ResultSymbol = "");

public sealed record CallerHashCheckOp(
    int Offset,
    SymbolicValue Target);

public sealed record SignatureCheckOp(
    int Offset,
    SymbolicValue PublicKeyOrKeys,
    SymbolicValue SignatureOrSignatures,
    string ResultSymbol = "",
    bool IsMultisig = false,
    SymbolicValue? Message = null);

public sealed record RuntimeNotification(
    int Offset,
    SymbolicValue ScriptHash,
    SymbolicValue Name,
    SymbolicValue State,
    string? ConcreteName);

public sealed record ContractExistenceQuery(
    int Offset,
    SymbolicValue Target,
    bool Exists);

public sealed class ExternalCall
{
    public int Offset { get; init; }
    public string Method { get; set; } = "";
    public SymbolicValue? TargetHash { get; set; }
    public SymbolicValue? MethodArg { get; set; }
    public bool TargetHashDynamic { get; set; }
    public bool MethodDynamic { get; set; }
    public int CallFlags { get; set; }
    public bool CallFlagsDynamic { get; set; }
    public bool HasReturnValue { get; set; }
    public bool ReturnValueDeclaredByMethodToken { get; set; }
    public bool ReturnModeledNative { get; set; }
    public bool ModeledSelfCall { get; set; }
    public bool ReturnChecked { get; set; }
    public bool ArgumentsDynamic { get; set; }
    public List<SymbolicValue> Args { get; init; } = new();

    public ExternalCall Clone() => new()
    {
        Offset = Offset,
        Method = Method,
        TargetHash = TargetHash,
        MethodArg = MethodArg,
        TargetHashDynamic = TargetHashDynamic,
        MethodDynamic = MethodDynamic,
        CallFlags = CallFlags,
        CallFlagsDynamic = CallFlagsDynamic,
        HasReturnValue = HasReturnValue,
        ReturnValueDeclaredByMethodToken = ReturnValueDeclaredByMethodToken,
        ReturnModeledNative = ReturnModeledNative,
        ModeledSelfCall = ModeledSelfCall,
        ReturnChecked = ReturnChecked,
        ArgumentsDynamic = ArgumentsDynamic,
        Args = new List<SymbolicValue>(Args),
    };
}

public sealed record ArithmeticOp(
    int Offset,
    string Operation,
    SymbolicValue? Left,
    SymbolicValue? Right,
    bool OverflowPossible,
    bool DivisorMaybeZero,
    bool Checked,
    int? MaxRight = null,
    SymbolicValue? Third = null,
    SymbolicValue? Result = null,
    ImmutableArray<Expression> PathConditions = default);
