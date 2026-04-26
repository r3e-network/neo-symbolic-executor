using System;
using System.Linq;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Property-based regression: same script + same options must produce byte-identical
/// engine results. Determinism is foundational — detectors and gates rely on stable
/// state ordering, and CI artifacts must be diffable across runs.
/// </summary>
public class DeterminismTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(42)]
    [InlineData(0x1AFEBABE)]
    [InlineData(int.MaxValue)]
    public void Engine_RandomScript_DeterministicAcrossRuns(int seed)
    {
        var rng1 = new Random(seed);
        var bytes = BuildRandomScript(rng1, opCount: 32);

        var program = ScriptDecoder.Decode(bytes);
        var opts = new ExecutionOptions
        {
            MaxSteps = 1_000,
            MaxPaths = 16,
            MaxStackSize = 64,
            MaxQueuedStates = 128,
        };
        var r1 = new SymbolicEngine(program, opts).Run();
        var r2 = new SymbolicEngine(program, opts).Run();

        r1.FinalStates.Length.Should().Be(r2.FinalStates.Length);
        r1.StatesExplored.Should().Be(r2.StatesExplored);
        r1.StepsExecuted.Should().Be(r2.StepsExecuted);
        for (int i = 0; i < r1.FinalStates.Length; i++)
        {
            r1.FinalStates[i].Status.Should().Be(r2.FinalStates[i].Status);
            r1.FinalStates[i].Pc.Should().Be(r2.FinalStates[i].Pc);
            r1.FinalStates[i].EvaluationStack.Count.Should().Be(r2.FinalStates[i].EvaluationStack.Count);
        }
    }

    private static byte[] BuildRandomScript(Random rng, int opCount)
    {
        var ops = new[]
        {
            NeoVm.OpCode.NOP, NeoVm.OpCode.PUSH0, NeoVm.OpCode.PUSH1, NeoVm.OpCode.PUSH7,
            NeoVm.OpCode.DUP, NeoVm.OpCode.DROP, NeoVm.OpCode.SWAP, NeoVm.OpCode.OVER,
            NeoVm.OpCode.ADD, NeoVm.OpCode.SUB, NeoVm.OpCode.MUL,
            NeoVm.OpCode.AND, NeoVm.OpCode.OR, NeoVm.OpCode.XOR,
            NeoVm.OpCode.NUMEQUAL, NeoVm.OpCode.NUMNOTEQUAL,
            NeoVm.OpCode.NEWARRAY0, NeoVm.OpCode.NEWMAP, NeoVm.OpCode.SIZE,
        };
        var bytes = new System.Collections.Generic.List<byte>();
        for (int i = 0; i < opCount; i++)
            bytes.Add((byte)ops[rng.Next(ops.Length)]);
        bytes.Add((byte)NeoVm.OpCode.RET);
        return bytes.ToArray();
    }

    [Fact]
    public void Detectors_DeterministicOnSameStates()
    {
        // Same input states -> same finding list (in the same order, with same dedupe key).
        var script = new byte[]
        {
            (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var states = new SymbolicEngine(program).Run().FinalStates;

        var d = new Detectors.DetectorEngine(Detectors.DefaultDetectorSet.All());
        var ctx = new Detectors.AnalysisContext { States = states };
        var f1 = d.Run(ctx);
        var f2 = d.Run(ctx);

        f1.Length.Should().Be(f2.Length);
        for (int i = 0; i < f1.Length; i++)
            f1[i].DedupeKey.Should().Be(f2[i].DedupeKey);
    }
}
