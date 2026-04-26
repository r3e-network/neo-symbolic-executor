using System;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Coverage;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Coverage-guided engine target. Picks an interesting prior input ~70% of the time and
/// mutates it; otherwise generates fresh random bytes. Tracks every offset visited across
/// final states; an input that opens *any* previously-unseen offset is added to the corpus
/// for future mutation. This is the standard greybox-fuzzing loop adapted to symbolic
/// execution: instead of branch coverage from instrumentation, we use the engine's
/// state.Path as the coverage signal.
///
/// Why a separate target instead of folding it into <see cref="EngineRandomScriptTarget"/>:
/// the corpus + tracker are stateful and are reused across iterations and workers. Keeping
/// the dependency local to one target means other engine targets can stay stateless and
/// remain reproducible from a single seed.
/// </summary>
public sealed class CoverageGuidedEngineTarget : IFuzzTarget
{
    public string Name => "engine-cov";
    public Type[] ExpectedExceptions => Type.EmptyTypes;
    public bool SupportsDirectReplay => true;

    private static readonly CoverageTracker GlobalTracker = new();
    private static readonly InterestingCorpus GlobalCorpus = new(capacity: 4096);

    public static long UniqueEdges => GlobalTracker.UniqueEdges;
    public static int CorpusSize => GlobalCorpus.Count;

    private readonly ExecutionOptions _engineOptions = new()
    {
        MaxSteps = 4_000,
        MaxPaths = 32,
        MaxStackSize = 128,
        MaxInvocationStackDepth = 64,
        MaxItemSize = 64 * 1024,
        MaxCollectionSize = 256,
        MaxQueuedStates = 256,
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        byte[] bytes;

        // 70% prefer mutation of an existing interesting input — once we have one.
        var seedInput = rng.NextDouble() < 0.7 ? GlobalCorpus.PickRandom(rng) : null;
        bytes = seedInput is not null
            ? Mutate(rng, seedInput)
            : OpCodeGen.RandomScript(rng, 4, 80);

        reproInput = bytes;
        reason = null;
        return RunWithInput(bytes, out reason);
    }

    public bool RunWithInput(byte[] input, out string? reason)
    {
        reason = null;
        NeoProgram program;
        try { program = ScriptDecoder.Decode(input); }
        catch (VmFaultException) { return true; }

        var result = new SymbolicEngine(program, _engineOptions).Run();

        // Property: every final state has a terminal status.
        if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "engine-cov produced state with status=Running after Run()";
            return false;
        }

        // Aggregate visited offsets and report to the global tracker.
        int newEdges = 0;
        foreach (var s in result.FinalStates)
            newEdges += GlobalTracker.RecordPath(Name, s.Path);

        if (newEdges > 0) GlobalCorpus.Add(input);
        return true;
    }

    /// <summary>
    /// Stack of small structural mutations: byte flip, opcode swap, byte insertion, byte
    /// deletion, splice (take half from another corpus input). Each iteration applies 1-3
    /// mutations to keep delta small enough that coverage signal is meaningful.
    /// </summary>
    private static byte[] Mutate(Random rng, byte[] src)
    {
        if (src.Length == 0) return OpCodeGen.RandomScript(rng, 2, 32);
        byte[] cur = (byte[])src.Clone();
        int n = rng.Next(1, 4);
        for (int i = 0; i < n; i++)
        {
            switch (rng.Next(6))
            {
                case 0:  // flip a byte to a random opcode from the curated mix
                    if (cur.Length > 0)
                        cur[rng.Next(cur.Length)] = (byte)OpCodeGen.DefaultMix[rng.Next(OpCodeGen.DefaultMix.Length)];
                    break;
                case 1:  // flip a byte to fully random
                    if (cur.Length > 0)
                        cur[rng.Next(cur.Length)] = (byte)rng.Next(0, 256);
                    break;
                case 2:  // insert a byte
                    {
                        int idx = rng.Next(cur.Length + 1);
                        var copy = new byte[cur.Length + 1];
                        Buffer.BlockCopy(cur, 0, copy, 0, idx);
                        copy[idx] = (byte)OpCodeGen.DefaultMix[rng.Next(OpCodeGen.DefaultMix.Length)];
                        Buffer.BlockCopy(cur, idx, copy, idx + 1, cur.Length - idx);
                        cur = copy;
                        break;
                    }
                case 3:  // delete a byte
                    if (cur.Length > 1)
                    {
                        int idx = rng.Next(cur.Length);
                        var copy = new byte[cur.Length - 1];
                        Buffer.BlockCopy(cur, 0, copy, 0, idx);
                        Buffer.BlockCopy(cur, idx + 1, copy, idx, cur.Length - idx - 1);
                        cur = copy;
                    }
                    break;
                case 4:  // swap two adjacent bytes
                    if (cur.Length >= 2)
                    {
                        int idx = rng.Next(cur.Length - 1);
                        (cur[idx], cur[idx + 1]) = (cur[idx + 1], cur[idx]);
                    }
                    break;
                case 5:  // splice: replace a window with a window from another corpus input
                    {
                        var donor = GlobalCorpus.PickRandom(rng);
                        if (donor is null || donor.Length < 2 || cur.Length < 2) break;
                        int aLen = rng.Next(1, Math.Min(cur.Length, 32));
                        int aStart = rng.Next(cur.Length - aLen + 1);
                        int bLen = rng.Next(1, Math.Min(donor.Length, 32));
                        int bStart = rng.Next(donor.Length - bLen + 1);
                        var copy = new byte[cur.Length - aLen + bLen];
                        Buffer.BlockCopy(cur, 0, copy, 0, aStart);
                        Buffer.BlockCopy(donor, bStart, copy, aStart, bLen);
                        Buffer.BlockCopy(cur, aStart + aLen, copy, aStart + bLen, cur.Length - (aStart + aLen));
                        cur = copy;
                        break;
                    }
            }
        }
        // Bound length to keep iterations cheap.
        if (cur.Length > 4096) cur = cur[..4096];
        return cur;
    }
}
