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
        var node = JsonNode.Parse(json) ?? throw new FormatException("Manifest is not valid JSON");
        return FromJson(node);
    }

    public static ContractManifest FromJson(JsonNode node)
    {
        var groups = new List<ContractGroup>();
        if (node["groups"] is JsonArray g)
            foreach (var item in g) if (item is not null) groups.Add(ContractGroup.FromJson(item));

        var standards = new List<string>();
        if (node["supportedstandards"] is JsonArray s)
            foreach (var item in s) if (item is not null) standards.Add(item.GetValue<string>());

        var permissions = new List<ContractPermission>();
        if (node["permissions"] is JsonArray p)
            foreach (var item in p) if (item is not null) permissions.Add(ContractPermission.FromJson(item));

        var trusts = ParseWildCardOfString(node["trusts"]);

        var features = new Dictionary<string, JsonNode?>();
        if (node["features"] is JsonObject fo)
            foreach (var kv in fo) features[kv.Key] = kv.Value;

        return new ContractManifest
        {
            Name = node["name"]?.GetValue<string>() ?? "",
            Groups = groups,
            Features = features,
            SupportedStandards = standards,
            Abi = ContractAbi.FromJson(node["abi"]),
            Permissions = permissions,
            Trusts = trusts,
            Extra = node["extra"],
        };
    }

    public static ContractManifest FromFile(string path) => FromJson(System.IO.File.ReadAllText(path));

    /// <summary>Quick lookup: is this a "*" trust grant (max-broad)?</summary>
    public bool TrustsWildcard => Trusts.IsWildcard;

    /// <summary>Quick lookup: any permission with wildcard contract?</summary>
    public bool HasWildcardPermission =>
        Permissions.Any(p => p.Contract == "*" || p.Methods.IsWildcard);

    public ContractMethodDescriptor? FindMethod(string name) =>
        Abi.Methods.FirstOrDefault(m => m.Name == name);

    public ContractMethodDescriptor? FindMethodAtOffset(int offset) =>
        Abi.Methods.FirstOrDefault(m => m.Offset == offset);

    private static WildCard<string> ParseWildCardOfString(JsonNode? node)
    {
        if (node is null) return WildCard<string>.Empty;
        if (node is JsonValue jv && jv.TryGetValue<string>(out string? s) && s == "*")
            return WildCard<string>.Wildcard;
        if (node is JsonArray ja)
        {
            var list = new List<string>();
            foreach (var x in ja) if (x is not null) list.Add(x.GetValue<string>());
            return WildCard<string>.From(list);
        }
        return WildCard<string>.Empty;
    }
}

public sealed class ContractAbi
{
    public IReadOnlyList<ContractMethodDescriptor> Methods { get; init; } = Array.Empty<ContractMethodDescriptor>();
    public IReadOnlyList<ContractEventDescriptor> Events { get; init; } = Array.Empty<ContractEventDescriptor>();

    public static ContractAbi FromJson(JsonNode? node)
    {
        if (node is null) return new();
        var methods = new List<ContractMethodDescriptor>();
        if (node["methods"] is JsonArray m)
            foreach (var item in m) if (item is not null) methods.Add(ContractMethodDescriptor.FromJson(item));
        var events = new List<ContractEventDescriptor>();
        if (node["events"] is JsonArray e)
            foreach (var item in e) if (item is not null) events.Add(ContractEventDescriptor.FromJson(item));
        return new ContractAbi { Methods = methods, Events = events };
    }
}

public sealed class ContractMethodDescriptor
{
    public string Name { get; init; } = "";
    public IReadOnlyList<ContractParameterDefinition> Parameters { get; init; } = Array.Empty<ContractParameterDefinition>();
    public string ReturnType { get; init; } = "Void";
    public int Offset { get; init; }
    public bool Safe { get; init; }

    public static ContractMethodDescriptor FromJson(JsonNode node)
    {
        var parameters = new List<ContractParameterDefinition>();
        if (node["parameters"] is JsonArray p)
            foreach (var item in p) if (item is not null) parameters.Add(ContractParameterDefinition.FromJson(item));
        return new ContractMethodDescriptor
        {
            Name = node["name"]?.GetValue<string>() ?? "",
            Parameters = parameters,
            ReturnType = node["returntype"]?.GetValue<string>() ?? "Void",
            Offset = node["offset"]?.GetValue<int>() ?? 0,
            Safe = node["safe"]?.GetValue<bool>() ?? false,
        };
    }
}

public sealed class ContractEventDescriptor
{
    public string Name { get; init; } = "";
    public IReadOnlyList<ContractParameterDefinition> Parameters { get; init; } = Array.Empty<ContractParameterDefinition>();

    public static ContractEventDescriptor FromJson(JsonNode node)
    {
        var parameters = new List<ContractParameterDefinition>();
        if (node["parameters"] is JsonArray p)
            foreach (var item in p) if (item is not null) parameters.Add(ContractParameterDefinition.FromJson(item));
        return new ContractEventDescriptor
        {
            Name = node["name"]?.GetValue<string>() ?? "",
            Parameters = parameters,
        };
    }
}

public sealed record ContractParameterDefinition(string Name, string Type)
{
    public static ContractParameterDefinition FromJson(JsonNode node) =>
        new(
            node["name"]?.GetValue<string>() ?? "",
            node["type"]?.GetValue<string>() ?? "Any");
}

public sealed class ContractGroup
{
    public string PubKey { get; init; } = "";
    public string Signature { get; init; } = "";

    public static ContractGroup FromJson(JsonNode node) =>
        new()
        {
            PubKey = node["pubkey"]?.GetValue<string>() ?? "",
            Signature = node["signature"]?.GetValue<string>() ?? "",
        };
}

public sealed class ContractPermission
{
    public string Contract { get; init; } = "*";
    public WildCard<string> Methods { get; init; } = WildCard<string>.Wildcard;

    public static ContractPermission FromJson(JsonNode node)
    {
        string contract = node["contract"]?.GetValue<string>() ?? "*";
        var methodsNode = node["methods"];
        WildCard<string> methods;
        if (methodsNode is JsonValue jv && jv.TryGetValue<string>(out string? s) && s == "*")
            methods = WildCard<string>.Wildcard;
        else if (methodsNode is JsonArray ja)
        {
            var list = new List<string>();
            foreach (var x in ja) if (x is not null) list.Add(x.GetValue<string>());
            methods = WildCard<string>.From(list);
        }
        else
            methods = WildCard<string>.Empty;

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
