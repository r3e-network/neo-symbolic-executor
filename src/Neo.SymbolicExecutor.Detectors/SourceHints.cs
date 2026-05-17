using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Optional source-text hints for protocol detectors. NEF bytecode does not preserve local
/// variable names or collection/member names, so callers can pass source files to let detectors
/// recover method-local intent such as "reserve", "amountOutMin", or "owners[tokenId]".
///
/// As of v0.7.0 the extractor uses the Roslyn syntax tree (CSharpSyntaxTree.ParseText) rather
/// than the previous regex-based scanner. The public API and matching semantics are unchanged.
/// Benefits of the syntactic upgrade:
///   - Correct brace / string / comment boundary detection for every C# syntax including
///     raw strings, interpolated verbatim strings, and nested generic angle brackets.
///   - [DisplayName] attribute aliasing reads from the attribute lists of the method symbol
///     itself, so a type-level [DisplayName] never accidentally binds to the first method
///     below it (the prior regex implementation depended on a textual "blocking declaration"
///     check between attribute and method).
///   - No regex / ReDoS surface; the parser is a deterministic recursive-descent.
/// SemanticModel is intentionally NOT used — the lexical matching semantics is what detector
/// callers want today, and skipping the semantic layer keeps the cost to syntax parsing only
/// (no References resolution, no Workspaces dependency).
/// </summary>
public sealed class SourceHints
{
    private static readonly HashSet<string> IgnoredSourceDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".omx", ".vs", "bin", "obj", "node_modules", "packages"
    };

    private sealed record MethodBody(int ParameterCount, string Body);

    private readonly IReadOnlyDictionary<string, IReadOnlyList<MethodBody>> _methodBodies;

    private SourceHints(IReadOnlyDictionary<string, IReadOnlyList<MethodBody>> methodBodies)
    {
        _methodBodies = methodBodies;
    }

    /// <summary>
    /// Number of distinct method names indexed (counting each name once even if it has
    /// multiple overload bodies). Surfaced for CLI diagnostics — a value of 0 after passing
    /// <c>--source</c> usually means the path didn't contain any matching .cs files.
    /// </summary>
    public int MethodNameCount => _methodBodies.Count;

    /// <summary>
    /// Total number of method bodies indexed across every name (each overload counted).
    /// </summary>
    public int MethodBodyCount
    {
        get
        {
            int total = 0;
            foreach (var bodies in _methodBodies.Values) total += bodies.Count;
            return total;
        }
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
                : StripStringAndCharLiterals(methodBody.Body);
            string folded = Fold(searchableBody);
            if (foldedHints.Any(h => folded.Contains(h, StringComparison.Ordinal)))
                return true;
        }

        return false;
    }

    private static Dictionary<string, IReadOnlyList<MethodBody>> ExtractMethodBodies(string text)
    {
        var methods = new Dictionary<string, List<MethodBody>>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text))
            return Materialize(methods);

        // Test inputs (and unusual user files) sometimes contain bare method declarations at
        // file scope. C# does not allow top-level MethodDeclarationSyntax outside a type, so
        // Roslyn parses such input either with diagnostics or as LocalFunctionStatementSyntax
        // depending on shape. Wrapping in a synthetic class produces a single canonical AST
        // shape (Type → Method) that the rest of the walker can rely on, and preserves
        // source-offset semantics for the body-text substring lookup because the wrapper
        // prefix has a fixed length.
        string wrappedText = WrapIfTopLevel(text);

        // Parse with a permissive LangVersion so files using C# 12+ syntax (raw strings,
        // primary constructors, collection expressions) are accepted. Diagnostic-free parse
        // is not required — we only walk the tree's surface syntax.
        var parseOptions = CSharpParseOptions.Default
            .WithLanguageVersion(LanguageVersion.Latest);
        var tree = CSharpSyntaxTree.ParseText(wrappedText, parseOptions);
        var root = tree.GetRoot();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            string body = MethodBodyText(method, wrappedText);
            int paramCount = method.ParameterList.Parameters.Count;
            var record = new MethodBody(paramCount, body);

            AddMethodBody(methods, method.Identifier.Text, record);

            foreach (string alias in DisplayNameAliases(method))
            {
                if (string.Equals(alias, method.Identifier.Text, StringComparison.Ordinal))
                    continue;
                AddMethodBody(methods, alias, record);
            }
        }

        // Also surface local functions (top-level methods in some test inputs parse as these).
        foreach (var local in root.DescendantNodes().OfType<LocalFunctionStatementSyntax>())
        {
            string body = LocalFunctionBodyText(local, wrappedText);
            int paramCount = local.ParameterList.Parameters.Count;
            var record = new MethodBody(paramCount, body);
            AddMethodBody(methods, local.Identifier.Text, record);
        }

        return Materialize(methods);
    }

    /// <summary>
    /// If <paramref name="text"/> contains no top-level type or namespace, wrap it in a
    /// synthetic class so Roslyn parses bare method declarations as
    /// <see cref="MethodDeclarationSyntax"/>. Returns the (possibly-wrapped) text.
    /// </summary>
    private static string WrapIfTopLevel(string text)
    {
        // Cheap heuristic: if the text already declares a type or a namespace, leave it alone.
        // Roslyn will parse those forms correctly. Otherwise wrap. The wrapper class name is
        // deliberately uncommon so it never collides with detector hint terms.
        if (ContainsTypeOrNamespaceKeyword(text)) return text;
        return "class __SourceHintsWrapper { " + text + " }";
    }

    private static bool ContainsTypeOrNamespaceKeyword(string text)
    {
        // Reuse a tiny Roslyn pass: tokenize and look for keywords. This is exact (handles
        // strings, comments, identifiers named "class") and cheap (tokenization is linear).
        var tree = CSharpSyntaxTree.ParseText(text);
        foreach (var token in tree.GetRoot().DescendantTokens())
        {
            if (token.IsKind(SyntaxKind.ClassKeyword)
                || token.IsKind(SyntaxKind.StructKeyword)
                || token.IsKind(SyntaxKind.InterfaceKeyword)
                || token.IsKind(SyntaxKind.RecordKeyword)
                || token.IsKind(SyntaxKind.EnumKeyword)
                || token.IsKind(SyntaxKind.NamespaceKeyword))
                return true;
        }
        return false;
    }

    private static string LocalFunctionBodyText(LocalFunctionStatementSyntax local, string source)
    {
        if (local.Body is { } block)
            return MaskComments(source.Substring(block.FullSpan.Start, block.FullSpan.Length));
        if (local.ExpressionBody is { } expr)
            return MaskComments(source.Substring(expr.Expression.FullSpan.Start, expr.Expression.FullSpan.Length));
        return string.Empty;
    }

    /// <summary>
    /// Mask single-line and multi-line comments in <paramref name="text"/> by replacing each
    /// comment character with a space (newlines preserved). Uses Roslyn's lexer to get exact
    /// boundaries — single-line comment to EOL, multi-line comment to the matching `*/`.
    /// </summary>
    private static string MaskComments(string text)
    {
        var tree = CSharpSyntaxTree.ParseText(text);
        var root = tree.GetRoot();
        var commentSpans = new List<TextSpan>();
        foreach (var trivia in root.DescendantTrivia(descendIntoTrivia: true))
        {
            if (trivia.IsKind(SyntaxKind.SingleLineCommentTrivia)
                || trivia.IsKind(SyntaxKind.MultiLineCommentTrivia)
                || trivia.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia)
                || trivia.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia))
                commentSpans.Add(trivia.Span);
        }
        if (commentSpans.Count == 0) return text;
        return MaskSpans(text, commentSpans);
    }

    private static string MaskSpans(string text, List<TextSpan> spans)
    {
        var chars = text.ToCharArray();
        foreach (var span in spans)
        {
            int start = Math.Max(0, span.Start);
            int end = Math.Min(chars.Length, span.End);
            for (int i = start; i < end; i++)
                if (chars[i] is not '\r' and not '\n')
                    chars[i] = ' ';
        }
        return new string(chars);
    }

    private static Dictionary<string, IReadOnlyList<MethodBody>> Materialize(Dictionary<string, List<MethodBody>> methods) =>
        methods.ToDictionary(
            kvp => kvp.Key,
            kvp => (IReadOnlyList<MethodBody>)kvp.Value,
            StringComparer.OrdinalIgnoreCase);

    private static string MethodBodyText(MethodDeclarationSyntax method, string source)
    {
        // Prefer the block body when present; expression-bodied methods retain just the
        // expression text (no surrounding braces). Comments are always masked at extraction
        // time so MethodContainsAny does not match a hint word that only appears in a
        // `// TODO` line — preserving the prior implementation's contract.
        if (method.Body is { } block)
            return MaskComments(source.Substring(block.FullSpan.Start, block.FullSpan.Length));
        if (method.ExpressionBody is { } expr)
            return MaskComments(source.Substring(expr.Expression.FullSpan.Start, expr.Expression.FullSpan.Length));
        return string.Empty;
    }

    private static IEnumerable<string> DisplayNameAliases(MethodDeclarationSyntax method)
    {
        foreach (var list in method.AttributeLists)
        {
            // Attribute lists on a type/property/etc. parent don't reach this loop — Roslyn
            // attaches each attribute list to its actual target, so a class-level
            // [DisplayName] is on the class and never on its methods. This naturally fixes
            // the prior regex implementation's "blocking declaration" bug class.
            foreach (var attribute in list.Attributes)
            {
                if (!IsDisplayNameAttribute(attribute)) continue;
                if (attribute.ArgumentList is null) continue;
                var firstArg = attribute.ArgumentList.Arguments.FirstOrDefault();
                if (firstArg?.Expression is LiteralExpressionSyntax { Token.Value: string alias }
                    && !string.IsNullOrEmpty(alias))
                {
                    yield return alias;
                }
            }
        }
    }

    private static bool IsDisplayNameAttribute(AttributeSyntax attribute)
    {
        // Honor both `[DisplayName(...)]` and the fully-qualified
        // `[System.ComponentModel.DisplayName(...)]` form.
        string name = attribute.Name switch
        {
            QualifiedNameSyntax qualified => qualified.Right.Identifier.Text,
            IdentifierNameSyntax ident => ident.Identifier.Text,
            _ => attribute.Name.ToString(),
        };
        return string.Equals(name, "DisplayName", StringComparison.Ordinal)
            || string.Equals(name, "DisplayNameAttribute", StringComparison.Ordinal);
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

    /// <summary>
    /// Strip string and char literal contents from <paramref name="body"/> for the
    /// <c>includeStringLiterals=false</c> matching mode. Uses the syntax tree so all C# 12+
    /// literal shapes (regular, verbatim, interpolated, raw single-line, raw multi-line) are
    /// handled identically — including the run-counted closing-quote logic for raw strings
    /// that previously had its own bespoke regex.
    /// </summary>
    private static string StripStringAndCharLiterals(string body)
    {
        var tree = CSharpSyntaxTree.ParseText(body);
        var root = tree.GetRoot();
        var spansToMask = new List<TextSpan>();
        foreach (var node in root.DescendantNodes())
        {
            switch (node)
            {
                case LiteralExpressionSyntax lit when
                    lit.Token.IsKind(SyntaxKind.StringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.SingleLineRawStringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.MultiLineRawStringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.Utf8StringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.Utf8SingleLineRawStringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.Utf8MultiLineRawStringLiteralToken)
                    || lit.Token.IsKind(SyntaxKind.CharacterLiteralToken):
                    spansToMask.Add(lit.Span);
                    break;
                case InterpolatedStringExpressionSyntax interp:
                    foreach (var content in interp.Contents)
                        if (content is InterpolatedStringTextSyntax txt)
                            spansToMask.Add(txt.Span);
                    break;
            }
        }
        return MaskSpans(body, spansToMask);
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
