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
    public List<ArithmeticOp> ArithmeticOps { get; } = new();
    public List<int> WitnessChecks { get; } = new();
    public HashSet<int> WitnessChecksEnforced { get; } = new();
    public List<int> CallerHashChecks { get; } = new();
    public List<int> SignatureChecks { get; } = new();
    public List<int> TimeAccesses { get; } = new();
    public List<int> RandomnessAccesses { get; } = new();
    public List<int> EventsEmitted { get; } = new();
    public HashSet<int> LoopsDetected { get; } = new();
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

    public Telemetry Clone()
    {
        var copy = new Telemetry();
        copy.StorageOps.AddRange(StorageOps);
        copy.ExternalCalls.AddRange(ExternalCalls.Select(c => c.Clone()));
        copy.ArithmeticOps.AddRange(ArithmeticOps);
        copy.WitnessChecks.AddRange(WitnessChecks);
        foreach (var w in WitnessChecksEnforced) copy.WitnessChecksEnforced.Add(w);
        copy.CallerHashChecks.AddRange(CallerHashChecks);
        copy.SignatureChecks.AddRange(SignatureChecks);
        copy.TimeAccesses.AddRange(TimeAccesses);
        copy.RandomnessAccesses.AddRange(RandomnessAccesses);
        copy.EventsEmitted.AddRange(EventsEmitted);
        foreach (var l in LoopsDetected) copy.LoopsDetected.Add(l);
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
        return copy;
    }
}

public sealed record StorageOp(
    int Offset,
    StorageOpKind Kind,
    SymbolicValue Key,
    SymbolicValue? Value,
    bool ContextDynamic,
    bool ContextReadOnly);

public enum StorageOpKind { Get, Put, Delete, Find }

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
    public bool ReturnChecked { get; set; }
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
        ReturnChecked = ReturnChecked,
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
    bool Checked);
