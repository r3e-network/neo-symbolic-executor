using System;

namespace Neo.SymbolicExecutor.Fuzzer.Generators;

/// <summary>Random byte producer with bounded length.</summary>
public static class ByteGen
{
    public static byte[] RandomBytes(Random rng, int minLen = 0, int maxLen = 256)
    {
        int len = rng.Next(minLen, maxLen + 1);
        byte[] b = new byte[len];
        rng.NextBytes(b);
        return b;
    }

    public static byte[] WeightedBytes(Random rng, int minLen, int maxLen, double zeroBias = 0.0)
    {
        int len = rng.Next(minLen, maxLen + 1);
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++)
            b[i] = rng.NextDouble() < zeroBias ? (byte)0 : (byte)rng.Next(0, 256);
        return b;
    }
}
