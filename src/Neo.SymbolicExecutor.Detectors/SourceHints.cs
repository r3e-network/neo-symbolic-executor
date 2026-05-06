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

    // ReDoS guard. The patterns are linear in input size by construction (no nested
    // quantifiers over overlapping alternatives), but defending against a future regex tweak
    // costs nothing: a regex that takes longer than this on any plausible source input is
    // already a bug. The fuzzer's per-iteration budget is 500ms, so this is well below that.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    private static readonly Regex DisplayNameAttribute = new(
        @"\[\s*(?:System\.ComponentModel\.)?DisplayName\s*\(\s*""(?<alias>[^""\r\n]+)""\s*\)\s*\]",
        RegexOptions.Compiled,
        RegexTimeout);

    // Type-declaration keywords that disqualify an upstream [DisplayName] from binding to the
    // next method — e.g. a class-level DisplayName must not alias the first method below it.
    private static readonly Regex BlockingDeclaration = new(
        @"\b(?:class|struct|interface|enum|namespace|record)\b",
        RegexOptions.Compiled,
        RegexTimeout);

    // The parameter group forbids '(' and ')' so attribute applications like
    // [DisplayName("transfer")] do not swallow the following method signature into one
    // greedy match (which would record name="DisplayName" with the real signature as params).
    // This is strict enough for Neo contract ABI shapes; default values with parenthesised
    // expressions (e.g. casts) won't be matched, but those don't appear in DevPack contracts.
    private static readonly Regex MethodDeclaration = new(
        @"\b(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?<parameters>[^;(){}]*)\)\s*\{",
        RegexOptions.Compiled,
        RegexTimeout);

    private sealed record MethodBody(int ParameterCount, string Body);

    private readonly IReadOnlyDictionary<string, IReadOnlyList<MethodBody>> _methodBodies;

    private SourceHints(IReadOnlyDictionary<string, IReadOnlyList<MethodBody>> methodBodies)
    {
        _methodBodies = methodBodies;
    }

    public static SourceHints FromText(string text) =>
        new(ExtractMethodBodies(text ?? string.Empty));

    public static SourceHints FromPaths(IEnumerable<string> paths)
    {
        // Scan each source file independently and merge the resulting method dictionaries.
        // Concatenating files first would let attribute scopes (e.g. [DisplayName]) and
        // unmatched braces leak across file boundaries, leading to wrong aliases or stray
        // method bodies.
        var merged = new Dictionary<string, List<MethodBody>>(StringComparer.OrdinalIgnoreCase);
        foreach (string source in EnumerateSourceTexts(paths))
        {
            foreach (var entry in ExtractMethodBodies(source))
            {
                if (!merged.TryGetValue(entry.Key, out var bodies))
                {
                    bodies = new List<MethodBody>();
                    merged[entry.Key] = bodies;
                }
                bodies.AddRange(entry.Value);
            }
        }

        return new(merged.ToDictionary(
            kvp => kvp.Key,
            kvp => (IReadOnlyList<MethodBody>)kvp.Value,
            StringComparer.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> EnumerateSourceTexts(IEnumerable<string> paths)
    {
        foreach (string path in paths)
        {
            if (File.Exists(path))
            {
                yield return File.ReadAllText(path);
            }
            else if (Directory.Exists(path))
            {
                foreach (string file in EnumerateProjectSourceFiles(path).OrderBy(p => p, StringComparer.Ordinal))
                    yield return File.ReadAllText(file);
            }
            else
            {
                throw new ArgumentException($"source path does not exist: {path}");
            }
        }
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

    public bool MethodContainsAny(string? methodName, IEnumerable<string> hints, bool includeStringLiterals = true) =>
        MethodContainsAny(methodName, parameterCount: null, hints, includeStringLiterals);

    public bool MethodContainsAny(
        string? methodName,
        int? parameterCount,
        IEnumerable<string> hints,
        bool includeStringLiterals = true)
    {
        if (methodName is null) return false;
        if (!_methodBodies.TryGetValue(methodName, out var bodies)) return false;

        var foldedHints = hints.Select(Fold).ToArray();
        foreach (var methodBody in bodies)
        {
            if (parameterCount is int count && methodBody.ParameterCount != count)
                continue;

            string searchableBody = includeStringLiterals
                ? methodBody.Body
                : MaskNonCodeText(methodBody.Body, maskStringAndCharLiterals: true);
            string folded = Fold(searchableBody);
            if (foldedHints.Any(h => folded.Contains(h, StringComparison.Ordinal)))
                return true;
        }

        return false;
    }

    private static Dictionary<string, IReadOnlyList<MethodBody>> ExtractMethodBodies(string text)
    {
        string textWithoutComments = MaskNonCodeText(text, maskStringAndCharLiterals: false);
        string structuralText = MaskNonCodeText(text, maskStringAndCharLiterals: true);

        // [DisplayName("foo")] aliases a method's ABI name — Neo DevPack contracts use this
        // when the C# identifier differs from the manifest entrypoint name. Without aliasing,
        // SourceHints lookups by ABI name would miss the implementation body. We scan
        // textWithoutComments so the literal alias survives (structuralText masks string
        // literals away). Tracked in source order so the assignment loop below can advance an
        // index pointer instead of re-scanning per method.
        var displayNameAttrs = new List<(int End, string Alias)>();
        foreach (Match dn in DisplayNameAttribute.Matches(textWithoutComments))
            displayNameAttrs.Add((dn.Index + dn.Length, dn.Groups["alias"].Value));

        var methods = new Dictionary<string, List<MethodBody>>(StringComparer.OrdinalIgnoreCase);
        int attrCursor = 0;
        foreach (Match match in MethodDeclaration.Matches(structuralText))
        {
            string name = match.Groups["name"].Value;
            if (ControlKeywords.Contains(name)) continue;

            int openBrace = structuralText.IndexOf('{', match.Index + match.Length - 1);
            if (openBrace < 0) continue;
            int closeBrace = FindMatchingBrace(structuralText, openBrace);
            if (closeBrace < 0) continue;

            var body = new MethodBody(
                CountParameters(match.Groups["parameters"].Value),
                textWithoutComments.Substring(openBrace, closeBrace - openBrace + 1));
            AddMethodBody(methods, name, body);

            // Consume any DisplayName attributes that precede this method declaration. The
            // cursor only moves forward, so each attribute binds to at most one method.
            string? alias = null;
            int aliasEnd = -1;
            while (attrCursor < displayNameAttrs.Count
                   && displayNameAttrs[attrCursor].End <= match.Index)
            {
                alias = displayNameAttrs[attrCursor].Alias;
                aliasEnd = displayNameAttrs[attrCursor].End;
                attrCursor++;
            }

            // Reject the alias if a type declaration (class/struct/interface/etc.) sits
            // between the attribute and the method — in that case the attribute targets the
            // type, not this method. structuralText has comments and string literals masked
            // so the keyword check is not fooled by them.
            if (alias is not null
                && BlockingDeclaration.Match(structuralText, aliasEnd, match.Index - aliasEnd).Success)
            {
                alias = null;
            }

            if (alias is not null && !string.Equals(alias, name, StringComparison.Ordinal))
                AddMethodBody(methods, alias, body);
        }

        return methods.ToDictionary(
            kvp => kvp.Key,
            kvp => (IReadOnlyList<MethodBody>)kvp.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static void AddMethodBody(
        Dictionary<string, List<MethodBody>> methods,
        string name,
        MethodBody body)
    {
        if (!methods.TryGetValue(name, out var bodies))
        {
            bodies = new List<MethodBody>();
            methods[name] = bodies;
        }
        bodies.Add(body);
    }

    private static int CountParameters(string parameters)
    {
        string trimmed = parameters.Trim();
        if (trimmed.Length == 0) return 0;

        // The MethodDeclaration regex forbids '(' and ')' in the captured parameter group, so
        // only generic and array depth need to be tracked here to avoid splitting on commas
        // inside Func<int, int> or int[,] declarations.
        int count = 1;
        int angleDepth = 0;
        int bracketDepth = 0;
        foreach (char c in trimmed)
        {
            switch (c)
            {
                case '<':
                    angleDepth++;
                    break;
                case '>':
                    if (angleDepth > 0) angleDepth--;
                    break;
                case '[':
                    bracketDepth++;
                    break;
                case ']':
                    if (bracketDepth > 0) bracketDepth--;
                    break;
                case ',' when angleDepth == 0 && bracketDepth == 0:
                    count++;
                    break;
            }
        }

        return count;
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
