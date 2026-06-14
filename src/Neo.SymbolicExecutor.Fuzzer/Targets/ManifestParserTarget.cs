using System;
using System.Text;
using System.Text.Json;
using Neo.SymbolicExecutor.Fuzzer.Generators;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

public sealed class ManifestParserTarget : IFuzzTarget
{
    public string Name => "manifest";
    public Type[] ExpectedExceptions => new[]
    {
        typeof(FormatException),
        typeof(JsonException),
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        string json = ManifestJsonGen.RandomManifest(rng);
        reproInput = Encoding.UTF8.GetBytes(json);
        reason = null;
        try { _ = ContractManifest.FromJson(json); return true; }
        catch (FormatException) { return true; }
        catch (JsonException) { return true; }
    }
}
