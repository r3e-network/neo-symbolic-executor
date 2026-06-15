using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Telemetry collected per-state during symbolic exploration. Detectors consume these fields.
///
/// Collections holding IMMUTABLE elements (records, ints, strings) are <see cref="CowList{T}"/> /
/// <see cref="CowSet{T}"/>: <see cref="Clone"/> forks them in O(1) and the backing storage is copied
/// only on the first write after a fork (audit C1, C6: cloned states must never alias each other's
/// writes — the copy-before-write discipline guarantees this). <see cref="ExternalCalls"/> holds MUTABLE
/// <see cref="ExternalCall"/> objects (their fields are set in place), so it is still eagerly deep-copied.
/// </summary>
public sealed class Telemetry
{
    public CowList<StorageOp> StorageOps { get; private set; } = new();
    public List<ExternalCall> ExternalCalls { get; } = new();
    public ArithmeticOpCollection ArithmeticOps { get; private set; } = new();
    public FaultConditionCollection FaultConditions { get; private set; } = new();
    public CowList<int> WitnessChecks { get; private set; } = new();
    public CowList<WitnessCheckOp> WitnessCheckOps { get; private set; } = new();
    public CowSet<int> WitnessChecksEnforced { get; private set; } = new();
    public CowSet<string> WitnessCheckResultsEnforced { get; private set; } = new();
    public CowList<int> CallerHashChecks { get; private set; } = new();
    public CowList<CallerHashCheckOp> CallerHashCheckOps { get; private set; } = new();
    public CowList<int> SignatureChecks { get; private set; } = new();
    public CowList<SignatureCheckOp> SignatureCheckOps { get; private set; } = new();
    public CowSet<int> SignatureChecksEnforced { get; private set; } = new();
    public CowSet<string> SignatureCheckResultsEnforced { get; private set; } = new();
    public CowList<int> TimeAccesses { get; private set; } = new();
    public CowList<int> RandomnessAccesses { get; private set; } = new();
    public CowList<int> EventsEmitted { get; private set; } = new();
    public CowList<RuntimeNotification> Notifications { get; private set; } = new();
    public CowList<ContractExistenceQuery> ContractExistenceQueries { get; private set; } = new();
    /// <summary>
    /// Set of back-edge target offsets — populated at JMP*/branch sites when the resolved target
    /// is a lower offset than the current PC. Each entry is a *loop-header offset*, not the
    /// jumping instruction.
    /// </summary>
    public CowSet<int> LoopsDetected { get; private set; } = new();
    /// <summary>
    /// Set of PCs where the per-offset visit cap fired. Distinct from <see cref="LoopsDetected"/>
    /// because a cap-hit PC is not necessarily a back-edge target — any opcode revisited beyond
    /// the cap (e.g. an unrolled tight switch tail) ends up here. The DOS detector consumes both
    /// as evidence of a loop-shaped truncation.
    /// </summary>
    public CowSet<int> VisitCapsHit { get; private set; } = new();
    public CowSet<int> IteratorLoops { get; private set; } = new();
    public CowList<int> ExceptionsThrown { get; private set; } = new();
    public CowList<int> UnknownSyscalls { get; private set; } = new();
    public CowList<int> UnknownOpcodes { get; private set; } = new();
    public int MaxCallStackDepth { get; set; }
    public long GasCost { get; set; }
    public bool Truncated { get; set; }
    public bool ReentrancyGuard { get; set; }
    public CowSet<int> SmtUnknownOffsets { get; private set; } = new();
    public int SmtPrunedBranches { get; set; }
    public int SmtConcretizations { get; set; }

    internal void BindPathConditions(Func<ImmutableArray<Expression>> currentPathSnapshot)
    {
        ArithmeticOps.BindPathConditions(currentPathSnapshot);
        FaultConditions.BindPathConditions(currentPathSnapshot);
    }

    public Telemetry Clone()
    {
        var copy = new Telemetry
        {
            // Copy-on-write fork: O(1), the backing storage is copied only on the first write in either
            // state. Sound because every element here is immutable.
            StorageOps = StorageOps.Fork(),
            ArithmeticOps = ArithmeticOps.Fork(),
            FaultConditions = FaultConditions.Fork(),
            WitnessChecks = WitnessChecks.Fork(),
            WitnessCheckOps = WitnessCheckOps.Fork(),
            WitnessChecksEnforced = WitnessChecksEnforced.Fork(),
            WitnessCheckResultsEnforced = WitnessCheckResultsEnforced.Fork(),
            CallerHashChecks = CallerHashChecks.Fork(),
            CallerHashCheckOps = CallerHashCheckOps.Fork(),
            SignatureChecks = SignatureChecks.Fork(),
            SignatureCheckOps = SignatureCheckOps.Fork(),
            SignatureChecksEnforced = SignatureChecksEnforced.Fork(),
            SignatureCheckResultsEnforced = SignatureCheckResultsEnforced.Fork(),
            TimeAccesses = TimeAccesses.Fork(),
            RandomnessAccesses = RandomnessAccesses.Fork(),
            EventsEmitted = EventsEmitted.Fork(),
            Notifications = Notifications.Fork(),
            ContractExistenceQueries = ContractExistenceQueries.Fork(),
            LoopsDetected = LoopsDetected.Fork(),
            VisitCapsHit = VisitCapsHit.Fork(),
            IteratorLoops = IteratorLoops.Fork(),
            ExceptionsThrown = ExceptionsThrown.Fork(),
            UnknownSyscalls = UnknownSyscalls.Fork(),
            UnknownOpcodes = UnknownOpcodes.Fork(),
            SmtUnknownOffsets = SmtUnknownOffsets.Fork(),
            MaxCallStackDepth = MaxCallStackDepth,
            GasCost = GasCost,
            Truncated = Truncated,
            ReentrancyGuard = ReentrancyGuard,
            SmtPrunedBranches = SmtPrunedBranches,
            SmtConcretizations = SmtConcretizations,
        };
        // ExternalCall objects are mutated in place (ReturnChecked, Method, …) after recording, so the
        // list cannot be COW-shared — deep-copy each entry as before.
        copy.ExternalCalls.AddRange(ExternalCalls.Select(c => c.Clone()));
        return copy;
    }

    public bool IsWitnessCheckResultEnforced(WitnessCheckOp op) =>
        WitnessCheckResultsEnforced.Contains(op.ResultSymbol)
        || (WitnessCheckResultsEnforced.Count == 0 && WitnessChecksEnforced.Contains(op.Offset));

    public bool IsSignatureCheckResultEnforced(SignatureCheckOp op) =>
        SignatureCheckResultsEnforced.Contains(op.ResultSymbol)
        || (SignatureCheckResultsEnforced.Count == 0 && SignatureChecksEnforced.Contains(op.Offset));
}

/// <summary>
/// Fault-condition list with two extra responsibilities over a plain <see cref="CowList{T}"/>: it stamps
/// each added op with the current path-condition snapshot, and it is copy-on-write so a state fork shares
/// the backing storage until the first subsequent write (see <see cref="Telemetry"/>).
/// </summary>
public sealed class FaultConditionCollection : IReadOnlyList<FaultConditionOp>
{
    private List<FaultConditionOp> items;
    private bool shared;
    private Func<ImmutableArray<Expression>> currentPathSnapshot = static () => ImmutableArray<Expression>.Empty;

    public FaultConditionCollection() => items = new List<FaultConditionOp>();

    private FaultConditionCollection(List<FaultConditionOp> items)
    {
        this.items = items;
        shared = true;
    }

    public int Count => items.Count;

    public FaultConditionOp this[int index] => items[index];

    internal void BindPathConditions(Func<ImmutableArray<Expression>> snapshot) =>
        currentPathSnapshot = snapshot;

    /// <summary>Fork sharing the backing list; both sides copy before their next write.</summary>
    public FaultConditionCollection Fork()
    {
        shared = true;
        return new FaultConditionCollection(items);
    }

    private void EnsureWritable()
    {
        if (shared)
        {
            items = new List<FaultConditionOp>(items);
            shared = false;
        }
    }

    public void Add(FaultConditionOp item)
    {
        if (item.PathConditions.IsDefault)
            item = item with { PathConditions = currentPathSnapshot() };
        EnsureWritable();
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

/// <summary>
/// Arithmetic-op list, the path-condition-stamping copy-on-write sibling of
/// <see cref="FaultConditionCollection"/>.
/// </summary>
public sealed class ArithmeticOpCollection : IReadOnlyList<ArithmeticOp>
{
    private List<ArithmeticOp> items;
    private bool shared;
    private Func<ImmutableArray<Expression>> currentPathSnapshot = static () => ImmutableArray<Expression>.Empty;

    public ArithmeticOpCollection() => items = new List<ArithmeticOp>();

    private ArithmeticOpCollection(List<ArithmeticOp> items)
    {
        this.items = items;
        shared = true;
    }

    public int Count => items.Count;

    public ArithmeticOp this[int index] => items[index];

    internal void BindPathConditions(Func<ImmutableArray<Expression>> snapshot) =>
        currentPathSnapshot = snapshot;

    public ArithmeticOpCollection Fork()
    {
        shared = true;
        return new ArithmeticOpCollection(items);
    }

    private void EnsureWritable()
    {
        if (shared)
        {
            items = new List<ArithmeticOp>(items);
            shared = false;
        }
    }

    public void Add(ArithmeticOp item)
    {
        if (item.PathConditions.IsDefault)
            item = item with { PathConditions = currentPathSnapshot() };
        EnsureWritable();
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
