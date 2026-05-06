using System;
using System.Diagnostics;
using System.Text;
using Neo.SymbolicExecutor.Detectors;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Fuzzes <see cref="SourceHints.FromText"/> + <see cref="SourceHints.MethodContainsAny"/> with
/// random C#-shaped fragments to flush out regex-engine hangs (catastrophic backtracking) and
/// uncaught exceptions on adversarial layouts. The arity-aware overload disambiguation, the
/// [DisplayName] alias resolution, and the brace-tracking masker are the surfaces this target
/// stresses; all three involve hand-rolled lexical scanning that benefits from broad input.
/// </summary>
public sealed class SourceHintsTarget : IFuzzTarget
{
    public string Name => "source-hints";
    public Type[] ExpectedExceptions => Array.Empty<Type>();

    // Generous per-iteration cap — the regex paths should be near-linear in input size, so any
    // multi-second iteration on a small input is a real signal of a backtracking pathology.
    private static readonly TimeSpan PerIterationBudget = TimeSpan.FromMilliseconds(500);

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        string source = GenerateRandomSource(rng);
        reproInput = Encoding.UTF8.GetBytes(source);
        reason = null;

        var sw = Stopwatch.StartNew();
        var hints = SourceHints.FromText(source);
        sw.Stop();

        if (sw.Elapsed > PerIterationBudget)
        {
            reason = $"FromText exceeded {PerIterationBudget.TotalMilliseconds:0}ms (took {sw.Elapsed.TotalMilliseconds:0}ms)";
            return false;
        }

        // Probe a handful of lookups — the matching path also runs Fold and the body masker,
        // so we want to hit them on adversarial bodies.
        for (int i = 0; i < 4; i++)
        {
            string name = RandomIdentifier(rng);
            int? parameterCount = rng.Next(3) == 0 ? null : rng.Next(0, 6);
            string[] hintNeedles = new[] { RandomIdentifier(rng), RandomIdentifier(rng) };

            sw.Restart();
            _ = hints.MethodContainsAny(name, parameterCount, hintNeedles, includeStringLiterals: rng.Next(2) == 0);
            sw.Stop();
            if (sw.Elapsed > PerIterationBudget)
            {
                reason = $"MethodContainsAny exceeded {PerIterationBudget.TotalMilliseconds:0}ms (took {sw.Elapsed.TotalMilliseconds:0}ms) on name={name}";
                return false;
            }
        }

        return true;
    }

    private static string GenerateRandomSource(Random rng)
    {
        var sb = new StringBuilder();
        int chunks = rng.Next(1, 12);
        for (int i = 0; i < chunks; i++)
            EmitChunk(rng, sb);
        return sb.ToString();
    }

    private static void EmitChunk(Random rng, StringBuilder sb)
    {
        switch (rng.Next(10))
        {
            case 0: sb.Append("[DisplayName(\"").Append(RandomIdentifier(rng)).Append("\")]\n"); break;
            case 1: sb.Append("[Safe]\n"); break;
            case 2: sb.Append("public class ").Append(RandomIdentifier(rng)).Append(" {\n"); break;
            case 3: sb.Append("// ").Append(RandomFreeText(rng)).Append('\n'); break;
            case 4: sb.Append("/* ").Append(RandomFreeText(rng)).Append(" */\n"); break;
            case 5: sb.Append('"').Append(RandomFreeText(rng)).Append("\"\n"); break;
            case 6: sb.Append("@\"").Append(RandomFreeText(rng)).Append("\"\n"); break;
            case 7:
                sb.Append("public ").Append(RandomTypeName(rng)).Append(' ')
                  .Append(RandomIdentifier(rng)).Append('(');
                int args = rng.Next(0, 5);
                for (int i = 0; i < args; i++)
                {
                    if (i > 0) sb.Append(", ");
                    sb.Append(RandomTypeName(rng)).Append(' ').Append(RandomIdentifier(rng));
                }
                sb.Append(") {\n  ").Append(RandomIdentifier(rng)).Append(" = 1;\n}\n");
                break;
            case 8: sb.Append("}\n"); break;
            default:
                int k = rng.Next(1, 12);
                for (int j = 0; j < k; j++)
                    sb.Append(RandomChar(rng));
                sb.Append('\n');
                break;
        }
    }

    private static string RandomIdentifier(Random rng)
    {
        const string head = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        const string tail = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
        int len = rng.Next(1, 8);
        var sb = new StringBuilder(len);
        sb.Append(head[rng.Next(head.Length)]);
        for (int i = 1; i < len; i++) sb.Append(tail[rng.Next(tail.Length)]);
        return sb.ToString();
    }

    private static string RandomTypeName(Random rng) =>
        new[] { "int", "BigInteger", "byte[]", "UInt160", "UInt256", "string", "bool", "object?" }[rng.Next(8)];

    private static string RandomFreeText(Random rng)
    {
        int len = rng.Next(0, 32);
        var sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.Append(RandomChar(rng));
        return sb.ToString();
    }

    private static char RandomChar(Random rng)
    {
        // Bias toward ASCII characters that the lexer cares about: braces, parens, quotes,
        // angle brackets, attribute brackets, semicolons, commas, line breaks, identifiers.
        const string interesting = "{}()[]<>;,\"'\\\n\t /*+-=. ABCDxy0123";
        return interesting[rng.Next(interesting.Length)];
    }
}
