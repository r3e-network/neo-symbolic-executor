using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Structure-aware mutation: take a structurally-valid script, then mutate it semantically
/// — swap two opcodes, delete an instruction, change an operand byte. This reaches deeper
/// engine paths than purely-random byte streams, because the result is far more likely to
/// decode and run than to fail at a magic check.
/// </summary>
public sealed class StructureAwareMutationTarget : IFuzzTarget
{
    public string Name => "structured-mutation";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 4, 64);
        // Apply 1-3 mutations.
        int n = rng.Next(1, 4);
        for (int i = 0; i < n; i++)
            bytes = ApplyMutation(rng, bytes);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000,
            MaxPaths = 32,
            MaxQueuedStates = 256,
            MaxStackSize = 128,
            MaxInvocationStackDepth = 64,
            MaxItemSize = 64 * 1024,
            MaxCollectionSize = 256,
        }).Run();

        if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "structured-mutation: state with status=Running after Run()";
            return false;
        }
        return true;
    }

    private static byte[] ApplyMutation(Random rng, byte[] bytes)
    {
        if (bytes.Length < 2) return bytes;
        switch (rng.Next(5))
        {
            case 0:  // Replace one byte with random
                {
                    var copy = (byte[])bytes.Clone();
                    copy[rng.Next(copy.Length)] = (byte)rng.Next(0, 256);
                    return copy;
                }
            case 1:  // Replace one byte with a known opcode
                {
                    var copy = (byte[])bytes.Clone();
                    copy[rng.Next(copy.Length)] = (byte)OpCodeGen.DefaultMix[rng.Next(OpCodeGen.DefaultMix.Length)];
                    return copy;
                }
            case 2:  // Delete a byte
                {
                    int idx = rng.Next(bytes.Length);
                    var copy = new byte[bytes.Length - 1];
                    Buffer.BlockCopy(bytes, 0, copy, 0, idx);
                    Buffer.BlockCopy(bytes, idx + 1, copy, idx, bytes.Length - idx - 1);
                    return copy;
                }
            case 3:  // Insert a random byte
                {
                    int idx = rng.Next(bytes.Length + 1);
                    var copy = new byte[bytes.Length + 1];
                    Buffer.BlockCopy(bytes, 0, copy, 0, idx);
                    copy[idx] = (byte)OpCodeGen.DefaultMix[rng.Next(OpCodeGen.DefaultMix.Length)];
                    Buffer.BlockCopy(bytes, idx, copy, idx + 1, bytes.Length - idx);
                    return copy;
                }
            case 4:  // Swap two adjacent bytes
                {
                    var copy = (byte[])bytes.Clone();
                    if (copy.Length >= 2)
                    {
                        int idx = rng.Next(copy.Length - 1);
                        (copy[idx], copy[idx + 1]) = (copy[idx + 1], copy[idx]);
                    }
                    return copy;
                }
        }
        return bytes;
    }
}
