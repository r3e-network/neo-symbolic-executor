using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects calls to <c>StdLib.deserialize</c> / <c>StdLib.jsonDeserialize</c> where the input
/// flows from an untrusted source (method argument, storage value, prior external call return,
/// iterator value). NeoVM deserialization reconstructs arbitrary StackItems — feeding it
/// attacker-controlled bytes can:
///   - cause type confusion (a callsite that expects an Integer receives a Map/Struct)
///   - trigger nested allocations that blow past the heap budget
///   - reconstruct Pointers / InteropInterfaces with unexpected sort
///
/// Mitigations: validate the input length / type / shape before calling deserialize, or only
/// deserialize values originating from trusted contract-controlled storage.
///
/// Detection signal: an <see cref="ExternalCall"/> entry with method "deserialize" /
/// "jsonDeserialize" whose first argument's expression references a free symbol typical of
/// untrusted sources.
/// </summary>
public sealed class UnsafeDeserializationDetector : BaseDetector
{
    public override string Name => "unsafe_deserialization";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.7;

    private static readonly System.Collections.Generic.HashSet<string> DeserializeMethods =
        new(System.StringComparer.OrdinalIgnoreCase) { "deserialize", "jsonDeserialize" };

    private static readonly string[] UntrustedPrefixes =
    {
        "arg",            // method argument (arg0..argN, arg_<name>)
        "storage_value_", // value pulled from Storage.Get
        "iterator_value_", // value yielded from Iterator.Next + Iterator.Value
        "ext_ret_",       // return value from a prior external Contract.Call
    };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var call in state.Telemetry.ExternalCalls)
            {
                if (call.ModeledSelfCall) continue;
                if (!DeserializeMethods.Contains(call.Method)) continue;
                // Restrict to StdLib. DApps occasionally implement their own contract method
                // also named "deserialize" that already validates input; surfacing every such
                // call would over-report. A symbolic target hash (dynamic call) is included
                // because we cannot rule out StdLib at static-analysis time.
                if (call.TargetHash is not null)
                {
                    var hashBytes = call.TargetHash.AsConcreteBytes();
                    if (hashBytes is not null)
                    {
                        var native = context.Natives.ByHashBytes(hashBytes);
                        if (native is null) continue;
                        if (!string.Equals(native.Name, "StdLib", System.StringComparison.OrdinalIgnoreCase))
                            continue;
                    }
                }
                if (call.Args.Count == 0) continue;

                var sources = UntrustedSources(call.Args[0]);
                if (sources.Count == 0) continue;

                yield return MakeFinding(
                    title: $"StdLib.{call.Method} on potentially attacker-controlled input",
                    description: $"StdLib.{call.Method} at 0x{call.Offset:X4} receives a value derived from "
                               + $"{string.Join(", ", sources.OrderBy(s => s, System.StringComparer.Ordinal))}. "
                               + "Validate length, type, and shape of the input before deserializing, or restrict to values "
                               + "sourced exclusively from contract-controlled storage.",
                    offset: call.Offset,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "unsafe-deserialization", "stdlib", "input-validation" });
            }
        }
    }

    private static IReadOnlyCollection<string> UntrustedSources(SymbolicValue arg)
    {
        var found = new SortedSet<string>(System.StringComparer.Ordinal);
        foreach (var name in arg.Expression.FreeSymbols())
        {
            foreach (var prefix in UntrustedPrefixes)
            {
                if (name.StartsWith(prefix, System.StringComparison.Ordinal))
                {
                    found.Add(LabelFor(prefix));
                    break;
                }
            }
        }
        return found;
    }

    private static string LabelFor(string prefix) => prefix switch
    {
        "arg" => "method argument",
        "storage_value_" => "storage value",
        "iterator_value_" => "iterator value",
        "ext_ret_" => "external call return",
        _ => prefix,
    };
}
