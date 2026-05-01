using System;
using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Per-manifest-entrypoint analysis target. Exercises
/// <see cref="SymbolicEngine.CreateMethodEntryState"/> with synthetic ABI methods that point
/// at random offsets in a random script with random parameter counts and types. Property:
/// no FAULTed/HALTed state ever leaks Running back to the worklist drain, and no exception
/// outside the expected fault path escapes.
///
/// This is the fuzz coverage for the analyze-CLI per-entrypoint code path that no other
/// target reaches: the offset-0 + empty-stack regime is covered by engine-seeded /
/// engine-cov / decoder etc., but those never seed args from a manifest.
/// </summary>
public sealed class MethodEntryStateTarget : IFuzzTarget
{
    public string Name => "method-entry";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    private static readonly string[] ParamTypes =
    {
        "Integer", "Boolean", "ByteString", "Hash160", "Hash256", "PublicKey",
        "Signature", "Array", "Map", "Any", "String", "Void",
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var script = OpCodeGen.RandomScript(rng, 4, 64);
        reproInput = script;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(script); }
        catch (VmFaultException) { return true; }

        int methodCount = rng.Next(1, 8);
        var methods = new List<ContractMethodDescriptor>();
        for (int i = 0; i < methodCount; i++)
        {
            int offset = rng.Next(0, Math.Max(1, program.Bytes.Length));
            int paramCount = rng.Next(0, 6);
            var parameters = new List<ContractParameterDefinition>();
            for (int p = 0; p < paramCount; p++)
                parameters.Add(new ContractParameterDefinition(
                    Name: $"p{p}",
                    Type: ParamTypes[rng.Next(ParamTypes.Length)]));
            methods.Add(new ContractMethodDescriptor
            {
                Name = $"method{i}",
                Offset = offset,
                Parameters = parameters,
            });
        }

        var options = new ExecutionOptions
        {
            MaxSteps = 2_000,
            MaxPaths = 32,
            MaxStackSize = 256,
            MaxInvocationStackDepth = 32,
            MaxItemSize = 16 * 1024,
            MaxCollectionSize = 128,
            MaxHeapObjects = 256,
            MaxQueuedStates = 128,
            PerRunDeadline = TimeSpan.FromSeconds(2),
        };

        foreach (var m in methods)
        {
            var engine = new SymbolicEngine(program, options);
            var entry = engine.CreateMethodEntryState(m.Offset, m.Parameters);
            var result = engine.Run(entry);
            if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
            {
                reason = $"method-entry: method {m.Name} at 0x{m.Offset:X4} left a Running state after Run()";
                return false;
            }
        }
        return true;
    }
}
