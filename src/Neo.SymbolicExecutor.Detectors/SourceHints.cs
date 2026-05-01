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

    public bool MethodContainsAny(string? methodName, IEnumerable<string> hints, bool includeStringLiterals = true)
    {
        if (methodName is null) return false;
        if (!_methodBodies.TryGetValue(methodName, out string? body)) return false;
        string searchableBody = includeStringLiterals ? body : MaskNonCodeText(body, maskStringAndCharLiterals: true);
        string folded = Fold(searchableBody);
        return hints.Any(h => folded.Contains(Fold(h), StringComparison.Ordinal));
    }

    private static Dictionary<string, string> ExtractMethodBodies(string text)
    {
        string textWithoutComments = MaskNonCodeText(text, maskStringAndCharLiterals: false);
        string structuralText = MaskNonCodeText(text, maskStringAndCharLiterals: true);
        var methods = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(structuralText, @"\b(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"))
        {
            string name = match.Groups["name"].Value;
            if (ControlKeywords.Contains(name)) continue;

            int openBrace = structuralText.IndexOf('{', match.Index + match.Length - 1);
            if (openBrace < 0) continue;
            int closeBrace = FindMatchingBrace(structuralText, openBrace);
            if (closeBrace < 0) continue;

            methods[name] = textWithoutComments.Substring(openBrace, closeBrace - openBrace + 1);
        }

        return methods;
    }

    private static string MaskNonCodeText(string text, bool maskStringAndCharLiterals)
    {
        char[] chars = text.ToCharArray();
        int i = 0;
        while (i < text.Length)
        {
            if (i + 1 < text.Length && text[i] == '/' && text[i + 1] == '/')
            {
                int end = i + 2;
                while (end < text.Length && text[end] != '\r' && text[end] != '\n')
                    end++;
                MaskRange(chars, i, end);
                i = end;
                continue;
            }

            if (i + 1 < text.Length && text[i] == '/' && text[i + 1] == '*')
            {
                int end = i + 2;
                while (end + 1 < text.Length && !(text[end] == '*' && text[end + 1] == '/'))
                    end++;
                end = Math.Min(end + 2, text.Length);
                MaskRange(chars, i, end);
                i = end;
                continue;
            }

            if (TryGetStringStart(text, i, out int quoteIndex))
            {
                int end = FindStringEnd(text, quoteIndex);
                if (maskStringAndCharLiterals)
                    MaskRange(chars, i, end);
                i = end;
                continue;
            }

            if (text[i] == '\'')
            {
                int end = FindCharLiteralEnd(text, i);
                if (maskStringAndCharLiterals)
                    MaskRange(chars, i, end);
                i = end;
                continue;
            }

            i++;
        }

        return new string(chars);
    }

    private static bool TryGetStringStart(string text, int index, out int quoteIndex)
    {
        quoteIndex = index;
        if (text[index] == '"')
            return true;

        if ((text[index] == '@' || text[index] == '$') && index + 1 < text.Length && text[index + 1] == '"')
        {
            quoteIndex = index + 1;
            return true;
        }

        if ((text[index] == '@' || text[index] == '$')
            && index + 2 < text.Length
            && (text[index + 1] == '@' || text[index + 1] == '$')
            && text[index + 1] != text[index]
            && text[index + 2] == '"')
        {
            quoteIndex = index + 2;
            return true;
        }

        return false;
    }

    private static int FindStringEnd(string text, int quoteIndex)
    {
        int quoteRunLength = CountQuoteRun(text, quoteIndex);
        if (quoteRunLength >= 3)
            return FindRawStringEnd(text, quoteIndex, quoteRunLength);

        bool verbatim = quoteIndex > 0 && text[quoteIndex - 1] == '@'
            || quoteIndex > 1 && text[quoteIndex - 2] == '@';
        if (verbatim)
            return FindVerbatimStringEnd(text, quoteIndex);

        return FindRegularStringEnd(text, quoteIndex);
    }

    private static int FindRegularStringEnd(string text, int quoteIndex)
    {
        bool escaped = false;
        for (int i = quoteIndex + 1; i < text.Length; i++)
        {
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (text[i] == '\\')
            {
                escaped = true;
                continue;
            }

            if (text[i] == '"')
                return i + 1;
        }

        return text.Length;
    }

    private static int FindVerbatimStringEnd(string text, int quoteIndex)
    {
        for (int i = quoteIndex + 1; i < text.Length; i++)
        {
            if (text[i] != '"') continue;
            if (i + 1 < text.Length && text[i + 1] == '"')
            {
                i++;
                continue;
            }

            return i + 1;
        }

        return text.Length;
    }

    private static int FindRawStringEnd(string text, int quoteIndex, int quoteRunLength)
    {
        string terminator = new('"', quoteRunLength);
        int end = text.IndexOf(terminator, quoteIndex + quoteRunLength, StringComparison.Ordinal);
        return end < 0 ? text.Length : end + quoteRunLength;
    }

    private static int CountQuoteRun(string text, int quoteIndex)
    {
        int count = 0;
        while (quoteIndex + count < text.Length && text[quoteIndex + count] == '"')
            count++;
        return count;
    }

    private static int FindCharLiteralEnd(string text, int quoteIndex)
    {
        bool escaped = false;
        for (int i = quoteIndex + 1; i < text.Length; i++)
        {
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (text[i] == '\\')
            {
                escaped = true;
                continue;
            }

            if (text[i] == '\'')
                return i + 1;
        }

        return text.Length;
    }

    private static void MaskRange(char[] chars, int start, int end)
    {
        for (int i = start; i < end; i++)
            if (chars[i] is not '\r' and not '\n')
                chars[i] = ' ';
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
