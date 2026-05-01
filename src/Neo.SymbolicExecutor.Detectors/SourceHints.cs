using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Optional source-text hints for protocol detectors. NEF bytecode does not preserve local
/// variable names or collection/member names, so callers can pass source files to let detectors
/// recover method-local intent such as "reserve", "amountOutMin", or "owners[tokenId]".
/// </summary>
public sealed class SourceHints
{
    private static readonly HashSet<string> ControlKeywords = new(StringComparer.Ordinal)
    {
        "if", "for", "foreach", "while", "switch", "catch", "using", "lock", "return", "new"
    };

    private static readonly HashSet<string> IgnoredSourceDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".omx", ".vs", "bin", "obj", "node_modules", "packages"
    };

    private readonly IReadOnlyDictionary<string, string> _methodBodies;

    private SourceHints(IReadOnlyDictionary<string, string> methodBodies)
    {
        _methodBodies = methodBodies;
    }

    public static SourceHints FromText(string text) =>
        new(ExtractMethodBodies(text ?? string.Empty));

    public static SourceHints FromPaths(IEnumerable<string> paths)
    {
        var texts = new List<string>();
        foreach (string path in paths)
        {
            if (File.Exists(path))
            {
                texts.Add(File.ReadAllText(path));
            }
            else if (Directory.Exists(path))
            {
                foreach (string file in EnumerateProjectSourceFiles(path).OrderBy(p => p, StringComparer.Ordinal))
                    texts.Add(File.ReadAllText(file));
            }
            else
            {
                throw new ArgumentException($"source path does not exist: {path}");
            }
        }

        return FromText(string.Join(Environment.NewLine, texts));
    }

    private static IEnumerable<string> EnumerateProjectSourceFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            string current = pending.Pop();

            foreach (string file in Directory.EnumerateFiles(current, "*.cs"))
                yield return file;

            foreach (string directory in Directory.EnumerateDirectories(current))
            {
                string name = Path.GetFileName(directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                if (!IgnoredSourceDirectories.Contains(name))
                    pending.Push(directory);
            }
        }
    }

    public bool MethodContainsAny(string? methodName, IEnumerable<string> hints)
    {
        if (methodName is null) return false;
        if (!_methodBodies.TryGetValue(methodName, out string? body)) return false;
        string folded = Fold(body);
        return hints.Any(h => folded.Contains(Fold(h), StringComparison.Ordinal));
    }

    private static Dictionary<string, string> ExtractMethodBodies(string text)
    {
        var methods = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(text, @"\b(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"))
        {
            string name = match.Groups["name"].Value;
            if (ControlKeywords.Contains(name)) continue;

            int openBrace = text.IndexOf('{', match.Index + match.Length - 1);
            if (openBrace < 0) continue;
            int closeBrace = FindMatchingBrace(text, openBrace);
            if (closeBrace < 0) continue;

            methods[name] = text.Substring(openBrace, closeBrace - openBrace + 1);
        }

        return methods;
    }

    private static int FindMatchingBrace(string text, int openBrace)
    {
        int depth = 0;
        for (int i = openBrace; i < text.Length; i++)
        {
            if (text[i] == '{') depth++;
            else if (text[i] == '}')
            {
                depth--;
                if (depth == 0) return i;
            }
        }

        return -1;
    }

    private static string Fold(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            if (char.IsLetterOrDigit(c))
                sb.Append(char.ToLowerInvariant(c));
        return sb.ToString();
    }
}
