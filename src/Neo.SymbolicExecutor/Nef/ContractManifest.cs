using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Neo.SymbolicExecutor.Nef;

/// <summary>
/// Neo N3 contract manifest, parsed from the JSON sidecar (`*.manifest.json`).
/// </summary>
public sealed class ContractManifest
{
    public const int MaxManifestBytes = 1_048_576;
    public const int MaxAbiMethods = 1_024;
    public const int MaxParametersPerMethod = 64;
    public const int MaxEvents = 1_024;
    public const int MaxPermissions = 1_024;
    public const int MaxSupportedStandards = 128;

    public string Name { get; init; } = "";
    public IReadOnlyList<ContractGroup> Groups { get; init; } = Array.Empty<ContractGroup>();
    public IReadOnlyDictionary<string, JsonNode?> Features { get; init; } =
        new Dictionary<string, JsonNode?>();
    public IReadOnlyList<string> SupportedStandards { get; init; } = Array.Empty<string>();
    public ContractAbi Abi { get; init; } = new();
    public IReadOnlyList<ContractPermission> Permissions { get; init; } = Array.Empty<ContractPermission>();
    public WildCard<string> Trusts { get; init; } = WildCard<string>.Empty;
    public JsonNode? Extra { get; init; }

    public static ContractManifest FromJson(string json)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxManifestBytes)
            throw new FormatException($"Manifest size exceeds max {MaxManifestBytes} bytes");

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException jex)
        {
            // Wrap the underlying parser's message so the CLI surfaces "manifest" as the failing
            // input instead of leaking raw "input does not contain any JSON tokens" stack noise
            // — the user has no way to know which sidecar file failed otherwise.
            throw new FormatException($"Manifest is not valid JSON: {jex.Message}", jex);
        }
        return FromJson(node ?? throw new FormatException("Manifest is not valid JSON"));
    }

    public static ContractManifest FromJson(JsonNode node)
    {
        if (node is not JsonObject obj)
            throw new FormatException("Manifest root must be a JSON object");

        var groups = new List<ContractGroup>();
        if (OptionalArray(obj["groups"], "groups") is { } g)
        {
            for (int i = 0; i < g.Count; i++)
                groups.Add(ContractGroup.FromJson(RequireObject(g[i], $"groups[{i}]")));
        }
        RejectDuplicateStrings(
            groups.Select(group => group.PubKey).Where(pubKey => !string.IsNullOrEmpty(pubKey)),
            "groups[].pubkey");

        var standards = new List<string>();
        if (OptionalArray(obj["supportedstandards"], "supportedstandards") is { } s)
        {
            if (s.Count > MaxSupportedStandards)
                throw new FormatException($"Manifest supportedstandards count {s.Count} exceeds max {MaxSupportedStandards}");
            for (int i = 0; i < s.Count; i++)
            {
                string str = RequireString(s[i], $"supportedstandards[{i}]");
                if (string.IsNullOrEmpty(str))
                    throw new FormatException("Manifest 'supportedstandards' must not contain empty strings");
                standards.Add(str);
            }
        }
        RejectDuplicateStrings(standards, "supportedstandards", NormalizeStandardTag);

        var permissions = new List<ContractPermission>();
        if (OptionalArray(obj["permissions"], "permissions") is { } p)
        {
            if (p.Count > MaxPermissions)
                throw new FormatException($"Manifest permissions count {p.Count} exceeds max {MaxPermissions}");
            for (int i = 0; i < p.Count; i++)
                permissions.Add(ContractPermission.FromJson(RequireObject(p[i], $"permissions[{i}]"), $"permissions[{i}]"));
        }
        RejectDuplicateStrings(permissions.Select(permission => permission.Contract), "permissions[].contract");

        var trusts = ParseWildCardOfString(obj["trusts"]);
        if (!trusts.IsWildcard)
            RejectDuplicateStrings(trusts.Items, "trusts");

        var features = new Dictionary<string, JsonNode?>();
        if (obj["features"] is JsonObject fo)
        {
            if (fo.Count != 0)
                throw new FormatException("Manifest 'features' must be an empty object");
            foreach (var kv in fo) features[kv.Key] = kv.Value;
        }
        else if (obj["features"] is not null)
        {
            throw new FormatException("Manifest 'features' must be an empty object");
        }

        string name = OptionalString(obj, "name", "name") ?? "";
        if (obj.ContainsKey("name") && string.IsNullOrEmpty(name))
            throw new FormatException("Manifest 'name' must be non-empty when present");

        return new ContractManifest
        {
            Name = name,
            Groups = groups,
            Features = features,
            SupportedStandards = standards,
            Abi = ContractAbi.FromJson(obj["abi"]),
            Permissions = permissions,
            Trusts = trusts,
            Extra = obj["extra"],
        };
    }

    public static ContractManifest FromFile(string path)
    {
        var info = new System.IO.FileInfo(path);
        if (info.Length > MaxManifestBytes)
            throw new FormatException($"Manifest file '{path}' is {info.Length} bytes, exceeds max {MaxManifestBytes} bytes");
        return FromJson(System.IO.File.ReadAllText(path));
    }

    /// <summary>Quick lookup: is this a "*" trust grant (max-broad)?</summary>
    public bool TrustsWildcard => Trusts.IsWildcard;

    /// <summary>Quick lookup: any permission with wildcard contract?</summary>
    public bool HasWildcardPermission =>
        Permissions.Any(p => p.Contract == "*" || p.Methods.IsWildcard);

    public ContractMethodDescriptor? FindMethod(string name) =>
        Abi.Methods.FirstOrDefault(m => m.Name == name);

    public ContractMethodDescriptor? FindMethodAtOffset(int offset) =>
        Abi.Methods.FirstOrDefault(m => m.Offset == offset);

    /// <summary>
    /// Case-insensitive membership test for a NEP standard tag (e.g. "NEP-17", "NEP-11"). Manifest
    /// authors sometimes write "nep-17" / "Nep17"; normalizing separators keeps detectors
    /// deterministic while honoring those common variants.
    /// </summary>
    public bool DeclaresStandard(string standard) =>
        SupportedStandards.Any(s => string.Equals(
            NormalizeStandardTag(s),
            NormalizeStandardTag(standard),
            StringComparison.Ordinal));

    private static string NormalizeStandardTag(string standard) =>
        new(standard.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static void RejectDuplicateStrings(
        IEnumerable<string> values,
        string path,
        Func<string, string>? keySelector = null)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            string key = keySelector?.Invoke(value) ?? value;
            if (!seen.Add(key))
                throw new FormatException($"Manifest '{path}' contains duplicate value '{value}'");
        }
    }

    private static WildCard<string> ParseWildCardOfString(JsonNode? node, string path = "trusts")
    {
        if (node is null) return WildCard<string>.Empty;
        if (node is JsonValue jv && jv.TryGetValue<string>(out string? s) && s == "*")
            return WildCard<string>.Wildcard;
        if (node is JsonArray ja)
        {
            var list = new List<string>();
            for (int i = 0; i < ja.Count; i++)
                list.Add(RequireString(ja[i], $"{path}[{i}]"));
            return WildCard<string>.From(list);
        }
        throw new FormatException($"Manifest '{path}' must be '*' or an array of strings");
    }

    internal static JsonArray? OptionalArray(JsonNode? node, string path)
    {
        if (node is null)
            return null;
        if (node is JsonArray array)
            return array;
        throw new FormatException($"Manifest '{path}' must be an array");
    }

    internal static JsonObject RequireObject(JsonNode? node, string path)
    {
        if (node is JsonObject obj)
            return obj;
        throw new FormatException($"Manifest '{path}' must be an object");
    }

    internal static string RequireString(JsonNode? node, string path) =>
        OptionalString(node, path) ?? throw new FormatException($"Manifest '{path}' must be a string");

    internal static string RequireNonEmptyString(JsonNode? node, string path)
    {
        string value = RequireString(node, path);
        if (string.IsNullOrEmpty(value))
            throw new FormatException($"Manifest '{path}' must be non-empty");
        return value;
    }

    internal static string? OptionalString(JsonNode? node, string path)
    {
        if (node is null)
            return null;
        if (node is JsonValue value && value.TryGetValue<string>(out string? result))
            return result;
        throw new FormatException($"Manifest '{path}' must be a string");
    }

    internal static string? OptionalString(JsonObject obj, string key, string path)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node))
            return null;
        return RequireString(node, path);
    }

    internal static int OptionalInt(JsonNode? node, string path, int defaultValue)
    {
        if (node is null)
            return defaultValue;
        if (node is JsonValue value && value.TryGetValue<int>(out int result))
            return result;
        throw new FormatException($"Manifest '{path}' must be an integer");
    }

    internal static int RequireInt(JsonNode? node, string path)
    {
        if (node is null)
            throw new FormatException($"Manifest '{path}' must be an integer");
        return OptionalInt(node, path, defaultValue: 0);
    }

    internal static int OptionalInt(JsonObject obj, string key, string path, int defaultValue)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node))
            return defaultValue;
        if (node is null)
            throw new FormatException($"Manifest '{path}' must be an integer");
        return OptionalInt(node, path, defaultValue);
    }

    internal static bool OptionalBool(JsonNode? node, string path, bool defaultValue)
    {
        if (node is null)
            return defaultValue;
        if (node is JsonValue value && value.TryGetValue<bool>(out bool result))
            return result;
        throw new FormatException($"Manifest '{path}' must be a boolean");
    }

    internal static bool OptionalBool(JsonObject obj, string key, string path, bool defaultValue)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node))
            return defaultValue;
        if (node is null)
            throw new FormatException($"Manifest '{path}' must be a boolean");
        return OptionalBool(node, path, defaultValue);
    }
}

public sealed class ContractAbi
{
    public IReadOnlyList<ContractMethodDescriptor> Methods { get; init; } = Array.Empty<ContractMethodDescriptor>();
    public IReadOnlyList<ContractEventDescriptor> Events { get; init; } = Array.Empty<ContractEventDescriptor>();

    // Review note (#51/#53/#54): this parser is intentionally MORE LENIENT than Neo's official
    // deserializer on non-proof-critical fields — it accepts an empty/missing abi.methods (Neo
    // throws "Methods in ContractAbi is empty"), permission descriptors with unusual contract
    // strings or duplicate method names, and non-enum returntypes / duplicate parameter names. This
    // never narrows the analyzed surface (a parse that accepts more inputs only widens it) and is
    // NOT a soundness gap: every field that affects a verification verdict is re-validated downstream
    // and a malformed value is surfaced as Incomplete / Violated / FormatException by the verifier
    // and the call-permission matcher (which fails closed/Denied on malformed descriptors). The
    // duplicate-selector and duplicate-event-name checks that DO affect dispatch are enforced (see
    // ContractManifest.FromJson). Tightening these to exactly match Neo's acceptance semantics would
    // improve fidelity but is not required for sound analysis.
    public static ContractAbi FromJson(JsonNode? node)
    {
        if (node is null) return new();
        var obj = ContractManifest.RequireObject(node, "abi");
        var methods = new List<ContractMethodDescriptor>();
        if (ContractManifest.OptionalArray(obj["methods"], "abi.methods") is { } m)
        {
            if (m.Count > ContractManifest.MaxAbiMethods)
                throw new FormatException($"Manifest ABI methods count {m.Count} exceeds max {ContractManifest.MaxAbiMethods}");
            for (int i = 0; i < m.Count; i++)
                methods.Add(ContractMethodDescriptor.FromJson(
                    ContractManifest.RequireObject(m[i], $"abi.methods[{i}]"),
                    $"abi.methods[{i}]"));
        }
        RejectDuplicateMethodSelectors(methods);
        var events = new List<ContractEventDescriptor>();
        if (ContractManifest.OptionalArray(obj["events"], "abi.events") is { } e)
        {
            if (e.Count > ContractManifest.MaxEvents)
                throw new FormatException($"Manifest ABI events count {e.Count} exceeds max {ContractManifest.MaxEvents}");
            for (int i = 0; i < e.Count; i++)
                events.Add(ContractEventDescriptor.FromJson(
                    ContractManifest.RequireObject(e[i], $"abi.events[{i}]"),
                    $"abi.events[{i}]"));
        }
        RejectDuplicateEventNames(events);
        return new ContractAbi { Methods = methods, Events = events };
    }

    private static void RejectDuplicateMethodSelectors(IEnumerable<ContractMethodDescriptor> methods)
    {
        var seen = new HashSet<(string Name, int Arity)>();
        foreach (var method in methods)
        {
            var key = (method.Name, method.Parameters.Count);
            if (!seen.Add(key))
            {
                throw new FormatException(
                    $"Manifest 'abi.methods' contains duplicate method selector '{method.Name}/{method.Parameters.Count}'");
            }
        }
    }

    private static void RejectDuplicateEventNames(IEnumerable<ContractEventDescriptor> events)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var abiEvent in events)
        {
            if (!seen.Add(abiEvent.Name))
            {
                throw new FormatException(
                    $"Manifest 'abi.events' contains duplicate event name '{abiEvent.Name}'");
            }
        }
    }
}

public sealed class ContractMethodDescriptor
{
    public string Name { get; init; } = "";
    public IReadOnlyList<ContractParameterDefinition> Parameters { get; init; } = Array.Empty<ContractParameterDefinition>();
    public string ReturnType { get; init; } = "Void";
    public int Offset { get; init; }
    public bool Safe { get; init; }

    public static ContractMethodDescriptor FromJson(JsonObject node, string path = "abi.methods[]")
    {
        var parameters = new List<ContractParameterDefinition>();
        if (ContractManifest.OptionalArray(node["parameters"], $"{path}.parameters") is { } p)
        {
            if (p.Count > ContractManifest.MaxParametersPerMethod)
                throw new FormatException($"Manifest ABI method parameter count {p.Count} exceeds max {ContractManifest.MaxParametersPerMethod}");
            for (int i = 0; i < p.Count; i++)
                parameters.Add(ContractParameterDefinition.FromJson(
                    ContractManifest.RequireObject(p[i], $"{path}.parameters[{i}]"),
                    $"{path}.parameters[{i}]"));
        }
        return new ContractMethodDescriptor
        {
            Name = ContractManifest.RequireNonEmptyString(node["name"], $"{path}.name"),
            Parameters = parameters,
            ReturnType = ContractManifest.RequireNonEmptyString(node["returntype"], $"{path}.returntype"),
            Offset = ContractManifest.RequireInt(node["offset"], $"{path}.offset"),
            Safe = ContractManifest.OptionalBool(node, "safe", $"{path}.safe", false),
        };
    }
}

public sealed class ContractEventDescriptor
{
    public string Name { get; init; } = "";
    public IReadOnlyList<ContractParameterDefinition> Parameters { get; init; } = Array.Empty<ContractParameterDefinition>();

    public static ContractEventDescriptor FromJson(JsonObject node, string path = "abi.events[]")
    {
        var parameters = new List<ContractParameterDefinition>();
        if (ContractManifest.OptionalArray(node["parameters"], $"{path}.parameters") is { } p)
        {
            if (p.Count > ContractManifest.MaxParametersPerMethod)
                throw new FormatException($"Manifest ABI event parameter count {p.Count} exceeds max {ContractManifest.MaxParametersPerMethod}");
            for (int i = 0; i < p.Count; i++)
                parameters.Add(ContractParameterDefinition.FromJson(
                    ContractManifest.RequireObject(p[i], $"{path}.parameters[{i}]"),
                    $"{path}.parameters[{i}]"));
        }
        return new ContractEventDescriptor
        {
            Name = ContractManifest.RequireNonEmptyString(node["name"], $"{path}.name"),
            Parameters = parameters,
        };
    }
}

public sealed record ContractParameterDefinition(string Name, string Type)
{
    public static ContractParameterDefinition FromJson(JsonObject node, string path = "abi.parameters[]") =>
        new(
            ContractManifest.OptionalString(node, "name", $"{path}.name") ?? "",
            ContractManifest.RequireNonEmptyString(node["type"], $"{path}.type"));
}

public sealed class ContractGroup
{
    public string PubKey { get; init; } = "";
    public string Signature { get; init; } = "";

    public static ContractGroup FromJson(JsonObject node) =>
        new()
        {
            PubKey = ContractManifest.OptionalString(node, "pubkey", "groups[].pubkey") ?? "",
            Signature = ContractManifest.OptionalString(node, "signature", "groups[].signature") ?? "",
        };
}

public sealed class ContractPermission
{
    public string Contract { get; init; } = "*";
    public WildCard<string> Methods { get; init; } = WildCard<string>.Wildcard;

    public static ContractPermission FromJson(JsonObject node, string path = "permissions[]")
    {
        string contract = ContractManifest.OptionalString(node, "contract", $"{path}.contract") ?? "*";
        var methodsNode = node["methods"];
        WildCard<string> methods;
        if (methodsNode is JsonValue jv && jv.TryGetValue<string>(out string? s) && s == "*")
            methods = WildCard<string>.Wildcard;
        else if (methodsNode is JsonArray ja)
        {
            var list = new List<string>();
            for (int i = 0; i < ja.Count; i++)
            {
                list.Add(ContractManifest.RequireString(ja[i], $"{path}.methods[{i}]"));
            }
            methods = WildCard<string>.From(list);
        }
        else if (methodsNode is null)
            methods = WildCard<string>.Empty;
        else
            throw new FormatException($"Manifest '{path}.methods' must be '*' or an array of strings");

        return new ContractPermission { Contract = contract, Methods = methods };
    }
}

/// <summary>
/// "WildcardContainer" semantics: either a wildcard ("*") or an explicit list. Per the audit
/// detector findings, partial wildcards must be flagged separately from full wildcards.
/// </summary>
public sealed class WildCard<T>
{
    public static readonly WildCard<T> Wildcard = new(isWildcard: true, items: Array.Empty<T>());
    public static readonly WildCard<T> Empty = new(isWildcard: false, items: Array.Empty<T>());

    public bool IsWildcard { get; }
    public IReadOnlyList<T> Items { get; }

    private WildCard(bool isWildcard, IReadOnlyList<T> items)
    {
        IsWildcard = isWildcard;
        Items = items;
    }

    public static WildCard<T> From(IEnumerable<T> items) =>
        new(isWildcard: false, items: items.ToList());

    public bool Contains(T value) =>
        IsWildcard || Items.Contains(value);

    public int Count => IsWildcard ? -1 : Items.Count;
}
