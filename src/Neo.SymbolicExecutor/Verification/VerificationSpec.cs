using System.Collections.Immutable;
using System.Numerics;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Verification;

public sealed record VerificationSpec(
    int Version,
    ImmutableArray<string> Profiles,
    ImmutableArray<VerificationProperty> Properties)
{
    public const int MaxSpecBytes = 1_048_576;
    public const int MaxProfiles = 16;
    public const int MaxProperties = 256;
    public const int MaxConditionsPerProperty = 128;

    public static VerificationSpec Empty { get; } =
        new(Version: 1, Profiles: ImmutableArray<string>.Empty, Properties: ImmutableArray<VerificationProperty>.Empty);

    public static VerificationSpec FromFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxSpecBytes)
            throw new FormatException($"Verification spec file '{path}' is {info.Length} bytes, exceeds max {MaxSpecBytes} bytes");
        var root = JsonNode.Parse(File.ReadAllText(path))
            ?? throw new FormatException("verification spec is empty");
        return FromJson(root);
    }

    public static VerificationSpec FromJson(JsonNode root)
    {
        if (root is not JsonObject rootObject)
            throw new FormatException("verification spec root must be an object");
        RejectUnknownFields(
            rootObject,
            "verification spec",
            ImmutableHashSet.Create(StringComparer.Ordinal, "version", "profiles", "properties"));
        int version = OptionalSpecVersion(rootObject, "version");
        if (version != 1)
            throw new FormatException($"verification spec version {version} is not supported; supported version is 1");
        var profiles = ParseProfiles(root["profiles"]);
        var properties = ImmutableArray.CreateBuilder<VerificationProperty>();
        if (root["properties"] is { } propertiesNode)
        {
            if (propertiesNode is not JsonArray propertiesArray)
                throw new FormatException("verification spec 'properties' must be an array");
            if (propertiesArray.Count > MaxProperties)
                throw new FormatException($"verification spec properties count {propertiesArray.Count} exceeds max {MaxProperties}");
            for (int i = 0; i < propertiesArray.Count; i++)
            {
                var item = propertiesArray[i];
                if (item is not JsonObject obj)
                    throw new FormatException("verification property entries must be objects");
                properties.Add(VerificationProperty.FromJson(obj, $"properties[{i}]"));
            }
        }

        if (properties.Count == 0 && profiles.IsDefaultOrEmpty)
            throw new FormatException("verification spec must declare at least one property or profile");
        return new VerificationSpec(version, profiles, properties.ToImmutable());
    }

    public VerificationSpec WithAdditionalProfiles(IEnumerable<string> profileNames)
    {
        var merged = Profiles
            .Concat(profileNames.Select(NormalizeProfileName))
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToImmutableArray();
        return this with { Profiles = merged };
    }

    internal static string NormalizeProfileName(string profileName) =>
        profileName.Trim().ToLowerInvariant();

    private static ImmutableArray<string> ParseProfiles(JsonNode? node)
    {
        if (node is null) return ImmutableArray<string>.Empty;

        var profiles = ImmutableArray.CreateBuilder<string>();
        if (node is JsonValue one && one.TryGetValue<string>(out var oneName))
        {
            AddProfile(profiles, oneName);
        }
        else if (node is JsonArray arr)
        {
            if (arr.Count > MaxProfiles)
                throw new FormatException($"verification spec profiles count {arr.Count} exceeds max {MaxProfiles}");
            foreach (var item in arr)
            {
                if (item is not JsonValue value || !value.TryGetValue<string>(out var name))
                    throw new FormatException("verification profile entries must be strings");
                AddProfile(profiles, name);
            }
        }
        else
        {
            throw new FormatException("verification spec 'profiles' must be a string or array");
        }

        return profiles
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToImmutableArray();
    }

    private static void AddProfile(ImmutableArray<string>.Builder profiles, string profileName)
    {
        string normalized = NormalizeProfileName(profileName);
        if (string.IsNullOrWhiteSpace(normalized))
            throw new FormatException("verification profile names must be non-empty strings");
        profiles.Add(normalized);
    }

    internal static void RejectUnknownFields(
        JsonObject obj,
        string scope,
        IImmutableSet<string> allowedFields,
        string? path = null)
    {
        foreach (var field in obj)
        {
            if (!allowedFields.Contains(field.Key))
            {
                string display = path is null
                    ? field.Key
                    : $"{path}.{field.Key}";
                throw new FormatException($"unknown {scope} field '{display}'");
            }
        }
    }

    private static int OptionalSpecVersion(JsonObject obj, string name)
    {
        if (obj[name] is null) return 1;
        if (obj[name] is JsonValue value && value.TryGetValue<int>(out int version))
            return version;
        throw new FormatException($"verification spec '{name}' must be an integer");
    }
}

public sealed record VerificationProperty(
    string Id,
    string Method,
    string? Description,
    bool ForbidFaults,
    ImmutableArray<VerificationCondition> Requires,
    ImmutableArray<VerificationCondition> Ensures,
    int? MethodOffset = null,
    ImmutableArray<string> ParameterTypes = default,
    bool RequireExternalCallCompleteness = true,
    bool ForbidStorageMutation = false,
    bool ForbidExternalCalls = false,
    bool ForbidNotifications = false)
{
    public bool HasForbiddenSideEffectObligations =>
        ForbidStorageMutation || ForbidExternalCalls || ForbidNotifications;

    public bool HasPostconditionObligations =>
        !Ensures.IsDefaultOrEmpty || HasForbiddenSideEffectObligations;

    public static VerificationProperty FromJson(JsonObject obj)
    {
        return FromJson(obj, "properties[]");
    }

    internal static VerificationProperty FromJson(JsonObject obj, string path)
    {
        VerificationSpec.RejectUnknownFields(
            obj,
            "verification property",
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "id",
                "method",
                "description",
                "forbid_faults",
                "forbid_storage_mutation",
                "forbid_external_calls",
                "forbid_notifications",
                "requires",
                "ensures",
                "method_offset",
                "parameter_types",
                "require_external_call_completeness"),
            path);
        string id = RequiredString(obj, "id");
        string method = RequiredString(obj, "method");
        string? description = OptionalString(obj, "description", allowEmpty: true);
        int? methodOffset = OptionalInt(obj, "method_offset");
        var parameterTypes = ParseParameterTypes(obj["parameter_types"]);
        bool forbidFaults = OptionalBool(obj, "forbid_faults");
        bool forbidStorageMutation = OptionalBool(obj, "forbid_storage_mutation");
        bool forbidExternalCalls = OptionalBool(obj, "forbid_external_calls");
        bool forbidNotifications = OptionalBool(obj, "forbid_notifications");
        bool requireExternalCallCompleteness = obj["require_external_call_completeness"] is null
            ? true
            : OptionalBool(obj, "require_external_call_completeness");
        var requires = ParseConditionList(obj["requires"], $"{path}.requires");
        var ensures = ParseConditionList(obj["ensures"], $"{path}.ensures");
        if (requires.Any(c => c.StoragePutOffset.HasValue))
            throw new FormatException($"verification property '{id}' may use 'storage_put' conditions only in ensures");
        if (requires.Any(c => c.NotificationName is not null))
            throw new FormatException($"verification property '{id}' may use 'notification' conditions only in ensures");
        if (requires.Any(c => c.IsExternalCallTelemetryCondition))
            throw new FormatException($"verification property '{id}' may use 'external_call' conditions only in ensures");
        if (ensures.IsDefaultOrEmpty
            && !forbidFaults
            && !forbidStorageMutation
            && !forbidExternalCalls
            && !forbidNotifications)
        {
            throw new FormatException(
                $"verification property '{id}' requires at least one ensures condition, forbid_faults=true, or a forbidden side-effect obligation");
        }
        return new VerificationProperty(
            id,
            method,
            description,
            forbidFaults,
            requires,
            ensures,
            methodOffset,
            parameterTypes,
            requireExternalCallCompleteness,
            forbidStorageMutation,
            forbidExternalCalls,
            forbidNotifications);
    }

    private static ImmutableArray<string> ParseParameterTypes(JsonNode? node)
    {
        if (node is null) return ImmutableArray<string>.Empty;
        if (node is not JsonArray arr)
            throw new FormatException("verification property 'parameter_types' must be an array");

        var types = ImmutableArray.CreateBuilder<string>(arr.Count);
        foreach (var item in arr)
        {
            if (item is not JsonValue value
                || !value.TryGetValue<string>(out var type)
                || string.IsNullOrWhiteSpace(type))
            {
                throw new FormatException("verification property 'parameter_types' entries must be non-empty strings");
            }
            types.Add(type.Trim());
        }
        return types.ToImmutable();
    }

    private static ImmutableArray<VerificationCondition> ParseConditionList(JsonNode? node, string path)
    {
        if (node is null) return ImmutableArray<VerificationCondition>.Empty;
        if (node is JsonObject one)
            return ImmutableArray.Create(VerificationCondition.FromJson(one, path));
        if (node is not JsonArray arr)
            throw new FormatException("condition list must be an object or array");
        if (arr.Count > VerificationSpec.MaxConditionsPerProperty)
            throw new FormatException($"verification property condition count {arr.Count} exceeds max {VerificationSpec.MaxConditionsPerProperty}");

        var conditions = ImmutableArray.CreateBuilder<VerificationCondition>();
        for (int i = 0; i < arr.Count; i++)
        {
            var item = arr[i];
            if (item is not JsonObject obj)
                throw new FormatException("condition entries must be objects");
            conditions.Add(VerificationCondition.FromJson(obj, $"{path}[{i}]"));
        }
        return conditions.ToImmutable();
    }

    private static string RequiredString(JsonObject obj, string name)
    {
        if (obj[name] is not JsonValue jsonValue || !jsonValue.TryGetValue<string>(out string? value))
            throw new FormatException($"verification property '{name}' must be a non-empty string");
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"verification property requires non-empty '{name}'");
        return value;
    }

    private static string? OptionalString(JsonObject obj, string name, bool allowEmpty = false)
    {
        if (obj[name] is null) return null;
        if (obj[name] is JsonValue value && value.TryGetValue<string>(out string? text))
        {
            if (allowEmpty || !string.IsNullOrWhiteSpace(text))
                return text;
        }
        throw new FormatException($"verification property '{name}' must be a string");
    }

    private static bool OptionalBool(JsonObject obj, string name)
    {
        if (obj[name] is null) return false;
        if (obj[name] is JsonValue value && value.TryGetValue(out bool boolean))
            return boolean;
        throw new FormatException($"verification property '{name}' must be boolean");
    }

    private static int? OptionalInt(JsonObject obj, string name)
    {
        if (obj[name] is null) return null;
        if (obj[name] is JsonValue value && value.TryGetValue(out int integer))
            return integer;
        throw new FormatException($"verification property '{name}' must be integer");
    }
}

public sealed record VerificationCondition(
    string Arg,
    string Op,
    BigInteger? IntegerValue,
    bool? BooleanValue,
    bool IsReturn = false,
    string? Metric = null,
    int? StorageReadOffset = null,
    int? StoragePutOffset = null,
    string? NotificationName = null,
    string? ExternalCallMethod = null,
    ImmutableArray<byte> ByteValue = default,
    bool HasByteValue = false,
    string? WitnessTarget = null,
    ImmutableArray<byte> WitnessByteTarget = default,
    bool HasWitnessByteTarget = false,
    string? CallerHashTarget = null,
    ImmutableArray<byte> CallerHashByteTarget = default,
    bool HasCallerHashByteTarget = false,
    string? SignatureCheckTarget = null,
    ImmutableArray<byte> SignatureCheckByteTarget = default,
    bool HasSignatureCheckByteTarget = false,
    string? ValueArg = null,
    string? NotificationArgumentName = null,
    int? NotificationArgumentIndex = null,
    string? NotificationEmitter = null,
    ImmutableArray<byte> NotificationEmitterHash = default,
    bool HasNotificationEmitterHash = false,
    bool NotificationEmitterCurrent = false,
    string? ExternalCallTargetMethod = null,
    string? ExternalCallArgumentMethod = null,
    int? ExternalCallArgumentIndex = null,
    string? ExternalCallAfterNotificationMethod = null,
    string? NotificationBeforeName = null,
    string? ExternalCallContract = null,
    ImmutableArray<byte> ExternalCallContractHash = default,
    bool HasExternalCallContractHash = false,
    bool ExternalCallContractCurrent = false)
{
    private enum ScriptHashSelectorMatch
    {
        Match,
        NoMatch,
        Unknown,
    }

    public static VerificationCondition FromJson(JsonObject obj)
    {
        return FromJson(obj, "condition");
    }

    public bool RequiresExecutionState =>
        IsReturn
        || StoragePutOffset.HasValue
        || NotificationName is not null
        || NotificationArgumentName is not null
        || IsExternalCallTelemetryCondition
        || WitnessTarget is not null
        || CallerHashTarget is not null
        || SignatureCheckTarget is not null;

    public bool IsExternalCallTelemetryCondition =>
        ExternalCallMethod is not null
        || ExternalCallTargetMethod is not null
        || ExternalCallArgumentMethod is not null
        || ExternalCallAfterNotificationMethod is not null;

    internal static VerificationCondition FromJson(JsonObject obj, string path)
    {
        VerificationSpec.RejectUnknownFields(
            obj,
            "verification condition",
            ImmutableHashSet.Create(
                StringComparer.Ordinal,
                "arg",
                "return",
                "target",
                "storage_read",
                "storage_get",
                "storage_put",
                "storage_write",
                "storage_offset",
                "notification",
                "notification_arg",
                "notification_emitter",
                "notification_script_hash",
                "notification_index",
                "index",
                "external_call",
                "external_call_target",
                "external_call_arg",
                "external_call_index",
                "external_call_after_notification",
                "external_call_contract",
                "external_call_script_hash",
                "notification_before",
                "witness",
                "check_witness",
                "caller_hash",
                "calling_script_hash",
                "signature_check",
                "check_sig",
                "signature_public_key",
                "metric",
                "measure",
                "op",
                "value",
                "value_arg"),
            path);
        bool isReturn = IsReturnTarget(obj);
        string? arg = OptionalString(obj, "arg");
        string? notificationName = OptionalString(obj, "notification");
        string? notificationArgumentName = OptionalString(obj, "notification_arg")?.Trim();
        string? notificationEmitterField = OptionalString(obj, "notification_emitter");
        string? notificationScriptHashField = OptionalString(obj, "notification_script_hash");
        if (notificationEmitterField is not null && notificationScriptHashField is not null)
            throw new FormatException("verification condition supports only one of 'notification_emitter' or 'notification_script_hash'");
        string? notificationEmitter = notificationEmitterField ?? notificationScriptHashField;
        int? sharedIndex = OptionalInt(obj, "index");
        int? notificationIndexField = OptionalInt(obj, "notification_index");
        int? externalCallIndexField = OptionalInt(obj, "external_call_index");
        int? notificationArgumentIndex = notificationIndexField ?? (notificationArgumentName is not null ? sharedIndex : null);
        string? externalCallMethod = OptionalString(obj, "external_call");
        string? externalCallTargetMethod = OptionalString(obj, "external_call_target")?.Trim();
        string? externalCallArgumentMethod = OptionalString(obj, "external_call_arg")?.Trim();
        int? externalCallArgumentIndex = externalCallIndexField ?? (externalCallArgumentMethod is not null ? sharedIndex : null);
        string? externalCallAfterNotificationMethod = OptionalString(obj, "external_call_after_notification")?.Trim();
        string? externalCallContractField = OptionalString(obj, "external_call_contract");
        string? externalCallScriptHashField = OptionalString(obj, "external_call_script_hash");
        if (externalCallContractField is not null && externalCallScriptHashField is not null)
            throw new FormatException("verification condition supports only one of 'external_call_contract' or 'external_call_script_hash'");
        string? externalCallContract = externalCallContractField ?? externalCallScriptHashField;
        string externalCallContractFieldName = externalCallContractField is not null
            ? "external_call_contract"
            : "external_call_script_hash";
        string? notificationBeforeName = OptionalString(obj, "notification_before")?.Trim();
        string? witnessTarget = OptionalString(obj, "witness") ?? OptionalString(obj, "check_witness");
        witnessTarget = witnessTarget?.Trim();
        string? callerHashTarget = OptionalString(obj, "caller_hash") ?? OptionalString(obj, "calling_script_hash");
        callerHashTarget = callerHashTarget?.Trim();
        string? signatureCheckTarget =
            OptionalString(obj, "signature_check")
            ?? OptionalString(obj, "check_sig")
            ?? OptionalString(obj, "signature_public_key");
        signatureCheckTarget = signatureCheckTarget?.Trim();
        int? storageReadOffset =
            OptionalInt(obj, "storage_read")
            ?? OptionalInt(obj, "storage_get")
            ?? OptionalInt(obj, "storage_offset");
        int? storagePutOffset =
            OptionalInt(obj, "storage_put")
            ?? OptionalInt(obj, "storage_write");
        int targetCount =
            (isReturn ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(arg) ? 1 : 0)
            + (storageReadOffset.HasValue ? 1 : 0)
            + (storagePutOffset.HasValue ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(notificationName) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(notificationArgumentName) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(externalCallMethod) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(externalCallTargetMethod) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(externalCallArgumentMethod) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(externalCallAfterNotificationMethod) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(witnessTarget) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(callerHashTarget) ? 1 : 0)
            + (!string.IsNullOrWhiteSpace(signatureCheckTarget) ? 1 : 0);
        if (targetCount != 1)
            throw new FormatException("verification condition requires exactly one target: 'arg', 'return': true, 'storage_read', 'storage_put', 'notification', 'notification_arg', 'external_call', 'external_call_target', 'external_call_arg', 'external_call_after_notification', 'witness', 'caller_hash', or 'signature_check'");
        if (storageReadOffset is < 0)
            throw new FormatException("verification condition 'storage_read' must be a non-negative instruction offset");
        if (storagePutOffset is < 0)
            throw new FormatException("verification condition 'storage_put' must be a non-negative instruction offset");
        if (notificationArgumentIndex is < 0)
            throw new FormatException("verification condition 'notification_arg' index must be non-negative");
        if (externalCallArgumentIndex is < 0)
            throw new FormatException("verification condition 'external_call_arg' index must be non-negative");
        if (notificationArgumentName is not null && notificationArgumentIndex is null)
            throw new FormatException("verification condition 'notification_arg' requires an integer 'index'");
        if (externalCallArgumentMethod is not null && externalCallArgumentIndex is null)
            throw new FormatException("verification condition 'external_call_arg' requires an integer 'index'");
        if (externalCallAfterNotificationMethod is not null && string.IsNullOrWhiteSpace(notificationBeforeName))
            throw new FormatException("verification condition 'external_call_after_notification' requires non-empty 'notification_before'");
        if (notificationBeforeName is not null && string.IsNullOrWhiteSpace(externalCallAfterNotificationMethod))
            throw new FormatException("verification condition 'notification_before' is only valid with 'external_call_after_notification'");
        if (notificationIndexField is not null && notificationArgumentName is null)
            throw new FormatException("verification condition 'notification_index' is only valid with 'notification_arg'");
        if (externalCallIndexField is not null && externalCallArgumentMethod is null)
            throw new FormatException("verification condition 'external_call_index' is only valid with 'external_call_arg'");
        if (sharedIndex is not null && notificationArgumentName is null && externalCallArgumentMethod is null)
            throw new FormatException("verification condition 'index' is only valid with 'notification_arg' or 'external_call_arg'");
        if (notificationEmitter is not null
            && notificationName is null
            && notificationArgumentName is null
            && externalCallAfterNotificationMethod is null)
        {
            throw new FormatException("verification condition 'notification_emitter' is only valid with 'notification', 'notification_arg', or 'external_call_after_notification'");
        }
        if (externalCallContract is not null
            && externalCallMethod is null
            && externalCallTargetMethod is null
            && externalCallArgumentMethod is null
            && externalCallAfterNotificationMethod is null)
        {
            throw new FormatException("verification condition 'external_call_contract' is only valid with 'external_call', 'external_call_target', 'external_call_arg', or 'external_call_after_notification'");
        }

        string? metric = NormalizeMetric(OptionalString(obj, "metric") ?? OptionalString(obj, "measure"));
        bool notificationEmitterCurrent = false;
        ImmutableArray<byte> notificationEmitterHash = default;
        bool hasNotificationEmitterHash = false;
        if (notificationEmitter is not null)
        {
            ParseScriptHashSelector(
                notificationEmitter,
                "notification_emitter",
                out notificationEmitter,
                out notificationEmitterCurrent,
                out notificationEmitterHash,
                out hasNotificationEmitterHash);
        }
        bool externalCallContractCurrent = false;
        ImmutableArray<byte> externalCallContractHash = default;
        bool hasExternalCallContractHash = false;
        if (externalCallContract is not null)
        {
            ParseScriptHashSelector(
                externalCallContract,
                externalCallContractFieldName,
                out externalCallContract,
                out externalCallContractCurrent,
                out externalCallContractHash,
                out hasExternalCallContractHash);
        }
        ImmutableArray<byte> witnessByteTarget = default;
        bool hasWitnessByteTarget = witnessTarget is not null && TryParseBytesLiteral(witnessTarget, out witnessByteTarget);
        ImmutableArray<byte> callerHashByteTarget = default;
        bool hasCallerHashByteTarget = callerHashTarget is not null && TryParseBytesLiteral(callerHashTarget, out callerHashByteTarget);
        if (hasCallerHashByteTarget && callerHashByteTarget.Length != 20)
            throw new FormatException("caller_hash target byte literal must be a 20-byte UInt160 script hash");
        ImmutableArray<byte> signatureCheckByteTarget = default;
        bool hasSignatureCheckByteTarget = signatureCheckTarget is not null && TryParseBytesLiteral(signatureCheckTarget, out signatureCheckByteTarget);
        if (hasSignatureCheckByteTarget && !IsSignatureCheckByteTarget(signatureCheckByteTarget))
            throw new FormatException("signature_check target byte literal must be a valid 33-byte compressed or 65-byte uncompressed ECPoint public key, or a 32-byte Ed25519 public key");

        string? op = OptionalString(obj, "op");
        if (op is not ("==" or "!=" or ">" or ">=" or "<" or "<="))
            throw new FormatException($"unsupported verification condition operator '{op}'");

        string? valueArg = OptionalString(obj, "value_arg")?.Trim();
        bool hasLiteralValue = obj["value"] is not null;
        if (hasLiteralValue == (valueArg is not null))
            throw new FormatException("verification condition requires exactly one of 'value' or 'value_arg'");
        string targetName = ConditionTargetName(
            arg,
            isReturn,
            storageReadOffset,
            storagePutOffset,
            notificationName,
            externalCallMethod,
            witnessTarget,
            callerHashTarget,
            signatureCheckTarget,
            notificationArgumentName,
            notificationArgumentIndex,
            notificationEmitter,
            externalCallContract,
            externalCallTargetMethod,
            externalCallArgumentMethod,
            externalCallArgumentIndex,
            externalCallAfterNotificationMethod,
            notificationBeforeName);

        if (valueArg is not null)
        {
            return new VerificationCondition(
                targetName,
                op,
                null,
                null,
                isReturn,
                metric,
                storageReadOffset,
                storagePutOffset,
                notificationName,
                externalCallMethod,
                WitnessTarget: witnessTarget,
                WitnessByteTarget: witnessByteTarget,
                HasWitnessByteTarget: hasWitnessByteTarget,
                CallerHashTarget: callerHashTarget,
                CallerHashByteTarget: callerHashByteTarget,
                HasCallerHashByteTarget: hasCallerHashByteTarget,
                SignatureCheckTarget: signatureCheckTarget,
                SignatureCheckByteTarget: signatureCheckByteTarget,
                HasSignatureCheckByteTarget: hasSignatureCheckByteTarget,
                ValueArg: valueArg,
                NotificationArgumentName: notificationArgumentName,
                NotificationArgumentIndex: notificationArgumentIndex,
                NotificationEmitter: notificationEmitter,
                NotificationEmitterHash: notificationEmitterHash,
                HasNotificationEmitterHash: hasNotificationEmitterHash,
                NotificationEmitterCurrent: notificationEmitterCurrent,
                ExternalCallTargetMethod: externalCallTargetMethod,
                ExternalCallArgumentMethod: externalCallArgumentMethod,
                ExternalCallArgumentIndex: externalCallArgumentIndex,
                ExternalCallAfterNotificationMethod: externalCallAfterNotificationMethod,
                NotificationBeforeName: notificationBeforeName,
                ExternalCallContract: externalCallContract,
                ExternalCallContractHash: externalCallContractHash,
                HasExternalCallContractHash: hasExternalCallContractHash,
                ExternalCallContractCurrent: externalCallContractCurrent);
        }

        var valueNode = obj["value"]!;
        if (TryReadBool(valueNode, out bool boolValue))
        {
            if (metric is not null)
                throw new FormatException("verification condition metrics require an integer 'value'");
            if (!string.IsNullOrWhiteSpace(notificationName))
                throw new FormatException("notification verification conditions require an integer count value");
            if (!string.IsNullOrWhiteSpace(externalCallMethod))
                throw new FormatException("external_call verification conditions require an integer count value");
            if (!string.IsNullOrWhiteSpace(witnessTarget))
                throw new FormatException("witness verification conditions require an integer enforced_count value");
            if (!string.IsNullOrWhiteSpace(callerHashTarget))
                throw new FormatException("caller_hash verification conditions require an integer enforced_count value");
            if (!string.IsNullOrWhiteSpace(signatureCheckTarget))
                throw new FormatException("signature_check verification conditions require an integer enforced_count value");
            return new VerificationCondition(
                targetName,
                op,
                null,
                boolValue,
                isReturn,
                metric,
                storageReadOffset,
                storagePutOffset,
                notificationName,
                externalCallMethod,
                NotificationArgumentName: notificationArgumentName,
                NotificationArgumentIndex: notificationArgumentIndex,
                NotificationEmitter: notificationEmitter,
                NotificationEmitterHash: notificationEmitterHash,
                HasNotificationEmitterHash: hasNotificationEmitterHash,
                NotificationEmitterCurrent: notificationEmitterCurrent,
                ExternalCallTargetMethod: externalCallTargetMethod,
                ExternalCallArgumentMethod: externalCallArgumentMethod,
                ExternalCallArgumentIndex: externalCallArgumentIndex,
                ExternalCallAfterNotificationMethod: externalCallAfterNotificationMethod,
                NotificationBeforeName: notificationBeforeName,
                ExternalCallContract: externalCallContract,
                ExternalCallContractHash: externalCallContractHash,
                HasExternalCallContractHash: hasExternalCallContractHash,
                ExternalCallContractCurrent: externalCallContractCurrent);
        }
        if (TryReadBytes(valueNode, out var byteValue))
        {
            if (metric is not null)
                throw new FormatException("byte-string verification conditions cannot use a metric");
            if (!string.IsNullOrWhiteSpace(notificationName))
                throw new FormatException("notification verification conditions require an integer count value");
            if (!string.IsNullOrWhiteSpace(externalCallMethod))
                throw new FormatException("external_call verification conditions require an integer count value");
            if (!string.IsNullOrWhiteSpace(witnessTarget))
                throw new FormatException("witness verification conditions require an integer enforced_count value");
            if (!string.IsNullOrWhiteSpace(callerHashTarget))
                throw new FormatException("caller_hash verification conditions require an integer enforced_count value");
            if (!string.IsNullOrWhiteSpace(signatureCheckTarget))
                throw new FormatException("signature_check verification conditions require an integer enforced_count value");
            return new VerificationCondition(
                targetName,
                op,
                null,
                null,
                isReturn,
                metric,
                storageReadOffset,
                storagePutOffset,
                notificationName,
                externalCallMethod,
                byteValue,
                HasByteValue: true,
                NotificationArgumentName: notificationArgumentName,
                NotificationArgumentIndex: notificationArgumentIndex,
                NotificationEmitter: notificationEmitter,
                NotificationEmitterHash: notificationEmitterHash,
                HasNotificationEmitterHash: hasNotificationEmitterHash,
                NotificationEmitterCurrent: notificationEmitterCurrent,
                ExternalCallTargetMethod: externalCallTargetMethod,
                ExternalCallArgumentMethod: externalCallArgumentMethod,
                ExternalCallArgumentIndex: externalCallArgumentIndex,
                ExternalCallAfterNotificationMethod: externalCallAfterNotificationMethod,
                NotificationBeforeName: notificationBeforeName,
                ExternalCallContract: externalCallContract,
                ExternalCallContractHash: externalCallContractHash,
                HasExternalCallContractHash: hasExternalCallContractHash,
                ExternalCallContractCurrent: externalCallContractCurrent);
        }
        return new VerificationCondition(
            targetName,
            op,
            ReadInteger(valueNode),
            null,
            isReturn,
            metric,
            storageReadOffset,
            storagePutOffset,
            notificationName,
            externalCallMethod,
            WitnessTarget: witnessTarget,
            WitnessByteTarget: witnessByteTarget,
            HasWitnessByteTarget: hasWitnessByteTarget,
            CallerHashTarget: callerHashTarget,
            CallerHashByteTarget: callerHashByteTarget,
            HasCallerHashByteTarget: hasCallerHashByteTarget,
            SignatureCheckTarget: signatureCheckTarget,
            SignatureCheckByteTarget: signatureCheckByteTarget,
            HasSignatureCheckByteTarget: hasSignatureCheckByteTarget,
            NotificationArgumentName: notificationArgumentName,
            NotificationArgumentIndex: notificationArgumentIndex,
            NotificationEmitter: notificationEmitter,
            NotificationEmitterHash: notificationEmitterHash,
            HasNotificationEmitterHash: hasNotificationEmitterHash,
            NotificationEmitterCurrent: notificationEmitterCurrent,
            ExternalCallTargetMethod: externalCallTargetMethod,
            ExternalCallArgumentMethod: externalCallArgumentMethod,
            ExternalCallArgumentIndex: externalCallArgumentIndex,
            ExternalCallAfterNotificationMethod: externalCallAfterNotificationMethod,
            NotificationBeforeName: notificationBeforeName,
            ExternalCallContract: externalCallContract,
            ExternalCallContractHash: externalCallContractHash,
            HasExternalCallContractHash: hasExternalCallContractHash,
            ExternalCallContractCurrent: externalCallContractCurrent);
    }

    public Expression ToExpression(
        ContractMethodDescriptor method,
        ExecutionState? state = null,
        ImmutableArray<byte> currentScriptHash = default)
    {
        if (NotificationArgumentName is not null)
            return ToNotificationArgumentConditionExpression(method, state, currentScriptHash);
        if (ExternalCallTargetMethod is not null || ExternalCallArgumentMethod is not null)
            return ToExternalCallFieldConditionExpression(method, state, currentScriptHash);
        if (ExternalCallAfterNotificationMethod is not null)
            return ToComparisonExpression(method, ResolveExternalCallAfterNotificationExpression(state, currentScriptHash));

        Expression left = IsReturn
            ? ResolveReturnExpression(method, state)
            : StorageReadOffset is int
                    ? ResolveStorageReadExpression()
                    : StoragePutOffset is int
                        ? ResolveStoragePutExpression(method, state)
                        : NotificationName is not null
                            ? ResolveNotificationCountExpression(state, currentScriptHash)
                        : ExternalCallMethod is not null
                            ? ResolveExternalCallCountExpression(state, currentScriptHash)
                            : WitnessTarget is not null
                                ? ResolveWitnessEnforcedCountExpression(method, state)
                                : CallerHashTarget is not null
                                    ? ResolveCallerHashEnforcedCountExpression(method, state)
                                    : SignatureCheckTarget is not null
                                        ? ResolveSignatureCheckEnforcedCountExpression(method, state)
                                        : ResolveConditionLeftExpression(method);
        return ToComparisonExpression(method, left);
    }

    private Expression ToComparisonExpression(ContractMethodDescriptor method, Expression left)
    {
        if (BooleanValue.HasValue && Op is not ("==" or "!="))
            throw new FormatException("boolean verification conditions only support == or !=");
        if (ValueArg is not null)
            return ToValueArgExpression(method, left);
        if (BooleanValue.HasValue)
            left = Expr.ToBool(left);
        if (HasByteValue)
        {
            if (Op is not ("==" or "!="))
                throw new FormatException("byte-string verification conditions only support == or !=");
            if (Metric is not null)
                throw new FormatException("byte-string verification conditions cannot use a metric");
            var equality = ExactBytesEqual(left, ByteValue);
            return Op == "==" ? equality : Expr.Not(equality);
        }
        Expression right = BooleanValue.HasValue
            ? Expr.Bool(BooleanValue.Value)
            : Expr.Int(IntegerValue ?? BigInteger.Zero);
        return Op switch
        {
            "==" => Expr.Eq(left, right),
            "!=" => Expr.Ne(left, right),
            ">" => Expr.Gt(left, right),
            ">=" => Expr.Ge(left, right),
            "<" => Expr.Lt(left, right),
            "<=" => Expr.Le(left, right),
            _ => throw new InvalidOperationException($"validated operator '{Op}' unexpectedly reached expression generation"),
        };
    }

    public string Display(ContractMethodDescriptor method) =>
        $"{DisplayLeft(method)} {Op} {DisplayValue()}";

    private Expression ResolveStorageReadExpression()
    {
        if ((HasByteValue || ValueArg is not null) && Metric is null)
            return Expr.Sym(Sort.Bytes, StorageReadSymbolName(StorageReadOffset
                ?? throw new FormatException("storage_read verification condition is missing an instruction offset")));
        if (BooleanValue.HasValue)
            throw new FormatException("storage_read verification conditions require an integer metric value");
        if (Metric is null)
            throw new FormatException("storage_read verification conditions require a metric such as 'size'");
        int offset = StorageReadOffset
            ?? throw new FormatException("storage_read verification condition is missing an instruction offset");
        var storageValue = Expr.Sym(Sort.Bytes, StorageReadSymbolName(offset));
        return Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", storageValue),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", storageValue, Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
    }

    private Expression ResolveStoragePutExpression(ContractMethodDescriptor method, ExecutionState? state)
    {
        if (state is null)
            throw new FormatException("storage_put verification conditions require an execution state");
        int offset = StoragePutOffset
            ?? throw new FormatException("storage_put verification condition is missing an instruction offset");
        var writes = state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Put && op.Offset == offset)
            .ToArray();
        if (writes.Length == 0)
            throw new FormatException($"storage_put verification condition references unobserved Storage.Put offset {FormatOffset(offset)}");
        if (writes.Length > 1)
            throw new FormatException($"storage_put verification condition references Storage.Put offset {FormatOffset(offset)} more than once on one path; the write value is ambiguous");
        if (writes[0].Value is not { } value)
            throw new FormatException($"storage_put verification condition references Storage.Put offset {FormatOffset(offset)} without a recorded value");

        if (Metric is null)
        {
            if (HasByteValue)
                return NormalizeStoragePutBytesExpression(value);
            if (BooleanValue.HasValue)
            {
                if (value.Sort != Sort.Bool)
                    throw new FormatException($"storage_put verification condition at {FormatOffset(offset)} compares a non-Boolean write value to a boolean");
                return Expr.ToBool(value.Expression);
            }
            if (ValueArg is not null)
            {
                var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
                string valueArgType = valueArgParameter.Type ?? "Any";
                if (IsByteStringLikeAbiType(valueArgType))
                    return NormalizeStoragePutBytesExpression(value);
                if (IsAbiType(valueArgType, "Boolean"))
                {
                    if (value.Sort != Sort.Bool)
                        throw new FormatException($"storage_put verification condition at {FormatOffset(offset)} compares a non-Boolean write value to value_arg ABI parameter '{ValueArg}'");
                    return Expr.ToBool(value.Expression);
                }
                if (!IsAbiType(valueArgType, "Integer"))
                    throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' and cannot be used as a verification RHS");
            }

            if (value.Sort != Sort.Int)
                throw new FormatException($"storage_put verification condition at {FormatOffset(offset)} requires an Integer write value or a metric such as 'size'");
            return value.Expression;
        }

        if (BooleanValue.HasValue)
            throw new FormatException("storage_put verification condition metrics require an integer 'value'");

        Expression storageValue = NormalizeStoragePutBytesExpression(value);
        return Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", storageValue),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", storageValue, Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
    }

    private Expression ResolveConditionLeftExpression(ContractMethodDescriptor method)
    {
        var (parameter, symbol) = ResolveArgument(method);
        string parameterType = parameter.Type ?? "Any";
        if (Metric is null)
        {
            if (ValueArg is not null)
            {
                var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
                string valueArgType = valueArgParameter.Type ?? "Any";
                if (IsAbiType(valueArgType, "Boolean"))
                {
                    if (!IsAbiType(parameterType, "Boolean"))
                        throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to Boolean value_arg ABI parameter '{ValueArg}'");
                    return Expr.Sym(Sort.Bool, symbol);
                }
                if (IsAbiType(valueArgType, "Integer"))
                {
                    if (!IsAbiType(parameterType, "Integer"))
                    {
                        if (IsByteStringLikeAbiType(parameterType))
                            throw new FormatException($"{parameterType} ABI parameter '{Arg}' requires a metric for integer value_arg comparisons");
                        throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to Integer value_arg ABI parameter '{ValueArg}'");
                    }
                    return Expr.Sym(Sort.Int, symbol);
                }
                if (IsByteStringLikeAbiType(valueArgType))
                {
                    if (!IsByteStringLikeAbiType(parameterType))
                        throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to ByteString-like value_arg ABI parameter '{ValueArg}'");
                    return Expr.Sym(Sort.Bytes, symbol);
                }
                throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' and cannot be used as a verification RHS");
            }
            if (HasByteValue)
            {
                if (!IsByteStringLikeAbiType(parameterType))
                    throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to a byte-string value");
                return Expr.Sym(Sort.Bytes, symbol);
            }
            if (BooleanValue.HasValue)
            {
                if (!IsAbiType(parameterType, "Boolean"))
                    throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to a boolean value");
                return Expr.Sym(Sort.Bool, symbol);
            }

            if (!IsAbiType(parameterType, "Integer"))
            {
                if (IsByteStringLikeAbiType(parameterType))
                    throw new FormatException($"{parameterType} ABI parameter '{Arg}' requires a metric for integer conditions");
                throw new FormatException($"ABI parameter '{Arg}' has type '{parameterType}' and cannot be compared to an integer value");
            }

            return Expr.Sym(Sort.Int, symbol);
        }

        if (BooleanValue.HasValue)
            throw new FormatException("verification condition metrics require an integer 'value'");
        if (ValueArg is not null)
        {
            var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
            string valueArgType = valueArgParameter.Type ?? "Any";
            if (!IsAbiType(valueArgType, "Integer"))
                throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' but metric comparisons require an Integer RHS");
        }
        if (!IsByteStringLikeAbiType(parameterType))
            throw new FormatException($"verification condition metric '{Metric}' is only supported for ByteString-like ABI parameters; '{Arg}' has type '{parameterType}'");

        return Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, symbol)),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", Expr.Sym(Sort.Bytes, symbol), Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
    }

    private Expression ToValueArgExpression(ContractMethodDescriptor method, Expression left)
    {
        string valueArg = ValueArg
            ?? throw new InvalidOperationException("value_arg expression generation requires a value_arg");
        var (parameter, symbol) = ResolveArgument(method, valueArg);
        string parameterType = parameter.Type ?? "Any";

        if (IsAbiType(parameterType, "Boolean"))
        {
            if (Metric is not null)
                throw new FormatException($"value_arg ABI parameter '{valueArg}' has type '{parameterType}' but metric comparisons require an Integer RHS");
            if (Op is not ("==" or "!="))
                throw new FormatException("boolean value_arg verification conditions only support == or !=");
            EnsureValueArgTargetSort(valueArg, parameterType, left, Sort.Bool);
            var right = Expr.Sym(Sort.Bool, symbol);
            return Op == "==" ? Expr.Eq(left, right) : Expr.Ne(left, right);
        }

        if (IsAbiType(parameterType, "Integer"))
        {
            EnsureValueArgTargetSort(valueArg, parameterType, left, Sort.Int);
            var right = Expr.Sym(Sort.Int, symbol);
            return Op switch
            {
                "==" => Expr.Eq(left, right),
                "!=" => Expr.Ne(left, right),
                ">" => Expr.Gt(left, right),
                ">=" => Expr.Ge(left, right),
                "<" => Expr.Lt(left, right),
                "<=" => Expr.Le(left, right),
                _ => throw new InvalidOperationException($"validated operator '{Op}' unexpectedly reached value_arg expression generation"),
            };
        }

        if (IsByteStringLikeAbiType(parameterType))
        {
            if (Metric is not null)
                throw new FormatException($"value_arg ABI parameter '{valueArg}' has type '{parameterType}' but metric comparisons require an Integer RHS");
            if (Op is not ("==" or "!="))
                throw new FormatException("byte-string value_arg verification conditions only support == or !=");
            EnsureValueArgTargetSort(valueArg, parameterType, left, Sort.Bytes);
            var equality = ExactBytesEqual(left, Expr.Sym(Sort.Bytes, symbol));
            return Op == "==" ? equality : Expr.Not(equality);
        }

        throw new FormatException($"value_arg ABI parameter '{valueArg}' has type '{parameterType}' and cannot be used as a verification RHS");
    }

    private static void EnsureValueArgTargetSort(
        string valueArg,
        string valueArgType,
        Expression left,
        Sort expectedSort)
    {
        if (left.Sort != expectedSort)
            throw new FormatException($"value_arg ABI parameter '{valueArg}' has type '{valueArgType}' but the verification target has runtime sort {left.Sort}");
    }

    private string DisplayLeft(ContractMethodDescriptor method)
    {
        if (IsReturn)
        {
            return Metric switch
            {
                null => "$return",
                "size" => "size($return)",
                "first_byte" => "first_byte($return)",
                _ => $"{Metric}($return)",
            };
        }
        if (StorageReadOffset is int offset)
        {
            string storageSymbol = StorageReadSymbolName(offset);
            return Metric switch
            {
                null => storageSymbol,
                "size" => $"size({storageSymbol})",
                "first_byte" => $"first_byte({storageSymbol})",
                _ => $"{Metric}({storageSymbol})",
            };
        }
        if (StoragePutOffset is int putOffset)
        {
            string storageSymbol = StoragePutSymbolName(putOffset);
            return Metric switch
            {
                null => storageSymbol,
                "size" => $"size({storageSymbol})",
                "first_byte" => $"first_byte({storageSymbol})",
                _ => $"{Metric}({storageSymbol})",
            };
        }
        if (NotificationName is not null)
            return NotificationCountSymbolName(NotificationName, NotificationEmitter);
        if (NotificationArgumentName is not null)
            return NotificationArgumentSymbolName(NotificationArgumentName, NotificationArgumentIndex ?? 0, NotificationEmitter);
        if (ExternalCallMethod is not null)
            return ExternalCallCountSymbolName(ExternalCallMethod, ExternalCallContract);
        if (ExternalCallTargetMethod is not null)
            return ExternalCallTargetSymbolName(ExternalCallTargetMethod, ExternalCallContract);
        if (ExternalCallArgumentMethod is not null)
            return ExternalCallArgumentSymbolName(ExternalCallArgumentMethod, ExternalCallArgumentIndex ?? 0, ExternalCallContract);
        if (ExternalCallAfterNotificationMethod is not null)
            return ExternalCallAfterNotificationSymbolName(ExternalCallAfterNotificationMethod, NotificationBeforeName ?? "", NotificationEmitter, ExternalCallContract);
        if (WitnessTarget is not null)
            return WitnessEnforcedCountSymbolName(WitnessTarget);
        if (CallerHashTarget is not null)
            return CallerHashEnforcedCountSymbolName(CallerHashTarget);
        if (SignatureCheckTarget is not null)
            return SignatureCheckEnforcedCountSymbolName(SignatureCheckTarget);
        var (_, symbol) = ResolveArgument(method);
        return Metric switch
        {
            null => symbol,
            "size" => $"size({symbol})",
            "first_byte" => $"first_byte({symbol})",
            _ => $"{Metric}({symbol})",
        };
    }

    private static string StorageReadSymbolName(int offset) =>
        $"storage_value_{offset}";

    private static string StoragePutSymbolName(int offset) =>
        $"storage_put_value_{offset}";

    private static string NotificationNameWithEmitter(string notificationName, string? notificationEmitter) =>
        string.IsNullOrWhiteSpace(notificationEmitter)
            ? notificationName
            : $"{notificationName}@{notificationEmitter}";

    private static string NotificationCountSymbolName(string notificationName, string? notificationEmitter = null) =>
        $"notification_count({NotificationNameWithEmitter(notificationName, notificationEmitter)})";

    private static string NotificationArgumentSymbolName(string notificationName, int index, string? notificationEmitter = null) =>
        $"notification_arg({NotificationNameWithEmitter(notificationName, notificationEmitter)}, {index})";

    private static string ExternalCallNameWithContract(string methodName, string? externalCallContract) =>
        string.IsNullOrWhiteSpace(externalCallContract)
            ? methodName
            : $"{methodName}@{externalCallContract}";

    private static string ExternalCallCountSymbolName(string methodName, string? externalCallContract = null) =>
        $"external_call_count({ExternalCallNameWithContract(methodName, externalCallContract)})";

    private static string ExternalCallTargetSymbolName(string methodName, string? externalCallContract = null) =>
        $"external_call_target({ExternalCallNameWithContract(methodName, externalCallContract)})";

    private static string ExternalCallArgumentSymbolName(string methodName, int index, string? externalCallContract = null) =>
        $"external_call_arg({ExternalCallNameWithContract(methodName, externalCallContract)}, {index})";

    private static string ExternalCallAfterNotificationSymbolName(
        string methodName,
        string notificationName,
        string? notificationEmitter = null,
        string? externalCallContract = null) =>
        $"external_call_after_notification({ExternalCallNameWithContract(methodName, externalCallContract)}, {NotificationNameWithEmitter(notificationName, notificationEmitter)})";

    private static string WitnessEnforcedCountSymbolName(string target) =>
        $"witness_enforced_count({target})";

    private static string CallerHashEnforcedCountSymbolName(string target) =>
        $"caller_hash_enforced_count({target})";

    private static string SignatureCheckEnforcedCountSymbolName(string target) =>
        $"signature_check_enforced_count({target})";

    private static string ConditionTargetName(
        string? arg,
        bool isReturn,
        int? storageReadOffset,
        int? storagePutOffset = null,
        string? notificationName = null,
        string? externalCallMethod = null,
        string? witnessTarget = null,
        string? callerHashTarget = null,
        string? signatureCheckTarget = null,
        string? notificationArgumentName = null,
        int? notificationArgumentIndex = null,
        string? notificationEmitter = null,
        string? externalCallContract = null,
        string? externalCallTargetMethod = null,
        string? externalCallArgumentMethod = null,
        int? externalCallArgumentIndex = null,
        string? externalCallAfterNotificationMethod = null,
        string? notificationBeforeName = null) =>
        isReturn
            ? "$return"
            : storageReadOffset is int offset
                ? StorageReadSymbolName(offset)
                : storagePutOffset is int putOffset
                    ? StoragePutSymbolName(putOffset)
                    : notificationName is not null
                        ? NotificationCountSymbolName(notificationName, notificationEmitter)
                        : notificationArgumentName is not null
                            ? NotificationArgumentSymbolName(notificationArgumentName, notificationArgumentIndex ?? 0, notificationEmitter)
                            : externalCallMethod is not null
                                ? ExternalCallCountSymbolName(externalCallMethod, externalCallContract)
                                : externalCallTargetMethod is not null
                                    ? ExternalCallTargetSymbolName(externalCallTargetMethod, externalCallContract)
                                    : externalCallArgumentMethod is not null
                                        ? ExternalCallArgumentSymbolName(externalCallArgumentMethod, externalCallArgumentIndex ?? 0, externalCallContract)
                                        : externalCallAfterNotificationMethod is not null
                                            ? ExternalCallAfterNotificationSymbolName(externalCallAfterNotificationMethod, notificationBeforeName ?? "", notificationEmitter, externalCallContract)
                                            : witnessTarget is not null
                                                ? WitnessEnforcedCountSymbolName(witnessTarget)
                                                : callerHashTarget is not null
                                                    ? CallerHashEnforcedCountSymbolName(callerHashTarget)
                                                    : signatureCheckTarget is not null
                                                        ? SignatureCheckEnforcedCountSymbolName(signatureCheckTarget)
                                                        : arg!;

    private static Expression NormalizeStoragePutBytesExpression(SymbolicValue value) =>
        value.Sort switch
        {
            Sort.Int => new UnaryExpr(Sort.Bytes, "i2b", value.Expression),
            Sort.Bool => Expr.Ite(value.Expression, Expr.Bytes(new byte[] { 1 }), Expr.Bytes(Array.Empty<byte>())),
            _ => value.Expression,
        };

    private string DisplayValue()
    {
        if (ValueArg is not null)
            return $"arg({ValueArg})";
        if (BooleanValue.HasValue)
            return BooleanValue.Value.ToString().ToLowerInvariant();
        if (HasByteValue)
            return FormatByteValue(ByteValue);
        return IntegerValue?.ToString() ?? "null";
    }

    private static string FormatByteValue(ImmutableArray<byte> bytes) =>
        "0x" + Convert.ToHexString(bytes.IsDefault ? Array.Empty<byte>() : bytes.ToArray()).ToLowerInvariant();

    private static void ParseScriptHashSelector(
        string raw,
        string fieldName,
        out string display,
        out bool isCurrent,
        out ImmutableArray<byte> hash,
        out bool hasHash)
    {
        raw = raw.Trim();
        display = raw;
        isCurrent = false;
        hash = default;
        hasHash = false;

        string normalized = raw.ToLowerInvariant();
        if (normalized is "current" or "self" or "executing" or "executing_script_hash")
        {
            display = "current";
            isCurrent = true;
            return;
        }

        if (normalized is "gas" or "gas_token" or "gas-token" or "native:gas" or "native_gas")
        {
            display = "gas";
            hash = NeoNativeContractHashes.FromHex(NeoNativeContractHashes.GasToken).ToImmutableArray();
            hasHash = true;
            return;
        }

        if (normalized is "neo" or "neo_token" or "neo-token" or "native:neo" or "native_neo")
        {
            display = "neo";
            hash = NeoNativeContractHashes.FromHex(NeoNativeContractHashes.NeoToken).ToImmutableArray();
            hasHash = true;
            return;
        }

        if (TryParseBytesLiteral(raw, out hash))
        {
            if (hash.Length != NeoNativeContractHashes.HashLength)
                throw new FormatException($"{fieldName} byte literal must be a 20-byte UInt160 script hash");

            display = FormatByteValue(hash);
            hasHash = true;
            return;
        }

        throw new FormatException($"verification condition '{fieldName}' must be 'current', 'self', 'neo', 'gas', or a 20-byte 0x... / hex:... script hash");
    }

    private static Expression ExactBytesEqual(Expression left, ImmutableArray<byte> bytes)
    {
        byte[] value = bytes.IsDefault ? Array.Empty<byte>() : bytes.ToArray();
        var sizeMatches = Expr.Eq(new UnaryExpr(Sort.Int, "size", left), Expr.Int(value.Length));
        var valueMatches = Expr.Eq(new UnaryExpr(Sort.Int, "b2i", left), Expr.Int(Expr.BytesToInteger(value)));
        return Expr.BoolAnd(sizeMatches, valueMatches);
    }

    private static Expression ExactBytesEqual(Expression left, Expression right)
    {
        var sizeMatches = Expr.Eq(new UnaryExpr(Sort.Int, "size", left), new UnaryExpr(Sort.Int, "size", right));
        var valueMatches = Expr.Eq(new UnaryExpr(Sort.Int, "b2i", left), new UnaryExpr(Sort.Int, "b2i", right));
        return Expr.BoolAnd(sizeMatches, valueMatches);
    }

    private static string FormatOffset(int offset) =>
        $"0x{offset:X4}";

    private static string? NormalizeMetric(string? metric)
    {
        if (string.IsNullOrWhiteSpace(metric))
            return null;

        string normalized = metric.Trim().ToLowerInvariant();
        return normalized switch
        {
            "size" or "length" => "size",
            "first" or "firstbyte" or "first_byte" or "first-byte" or "byte0" => "first_byte",
            "count" => "count",
            "enforced" or "enforced_count" or "enforced-count" or "witness_enforced_count" => "enforced_count",
            _ => throw new FormatException($"unsupported verification condition metric '{metric}'"),
        };
    }

    private static bool IsReturnTarget(JsonObject obj)
    {
        if (obj["return"] is JsonValue returnValue && returnValue.TryGetValue(out bool enabled))
            return enabled;
        if (obj["target"] is JsonValue targetValue
            && targetValue.TryGetValue<string>(out var target)
            && string.Equals(target, "return", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static int? OptionalInt(JsonObject obj, string name)
    {
        if (obj[name] is null) return null;
        if (obj[name] is JsonValue value)
        {
            if (value.TryGetValue(out int integer))
                return integer;
            if (value.TryGetValue<string>(out var raw))
            {
                raw = raw.Trim();
                if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(
                        raw[2..],
                        System.Globalization.NumberStyles.AllowHexSpecifier,
                        System.Globalization.CultureInfo.InvariantCulture,
                        out var hex))
                {
                    return hex;
                }
                if (int.TryParse(
                    raw,
                    System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var parsed))
                {
                    return parsed;
                }
            }
        }
        throw new FormatException($"verification condition '{name}' must be an integer offset");
    }

    private static string? OptionalString(JsonObject obj, string name)
    {
        if (obj[name] is null) return null;
        if (obj[name] is JsonValue value
            && value.TryGetValue<string>(out var text)
            && !string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        throw new FormatException($"verification condition '{name}' must be a non-empty string");
    }

    private static bool TryReadBytes(JsonNode node, out ImmutableArray<byte> bytes)
    {
        bytes = default;
        if (node is not JsonValue jsonValue || !jsonValue.TryGetValue<string>(out var raw))
            return false;

        return TryParseBytesLiteral(raw, out bytes);
    }

    private static bool TryParseBytesLiteral(string raw, out ImmutableArray<byte> bytes)
    {
        bytes = default;
        raw = raw.Trim();
        string hex;
        if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hex = raw[2..];
        }
        else if (raw.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
        {
            hex = raw[4..];
        }
        else
        {
            return false;
        }

        if (hex.Length % 2 != 0)
            throw new FormatException($"verification condition byte-string value '{raw}' must have an even number of hex digits");

        try
        {
            bytes = Convert.FromHexString(hex).ToImmutableArray();
            return true;
        }
        catch (FormatException ex)
        {
            throw new FormatException($"verification condition byte-string value '{raw}' is not valid hex", ex);
        }
    }

    private (ContractParameterDefinition Parameter, string Symbol) ResolveArgument(ContractMethodDescriptor method) =>
        ResolveArgument(method, Arg);

    private static (ContractParameterDefinition Parameter, string Symbol) ResolveArgument(
        ContractMethodDescriptor method,
        string argName)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, argName, StringComparison.Ordinal))
                return (
                    method.Parameters[i],
                    SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[i].Name, i));
        }
        throw new FormatException($"method '{method.Name}' has no ABI parameter named '{argName}'");
    }

    private static bool IsAbiType(string type, string expected) =>
        string.Equals(type, expected, StringComparison.OrdinalIgnoreCase);

    private static bool IsByteStringLikeAbiType(string type) =>
        IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray")
        || IsAbiType(type, "String")
        || IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "Hash256")
        || IsAbiType(type, "UInt256")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "Signature");

    private static bool IsSignaturePublicKeyLikeAbiType(string type) =>
        IsAbiType(type, "PublicKey")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool IsSignatureCheckByteTarget(ImmutableArray<byte> bytes) =>
        bytes.Length == 32 || NeoEcPoint.IsValidEncoding(bytes.ToArray());

    private static bool IsWitnessTargetAbiType(string type) =>
        IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool IsCallerHashTargetAbiType(string type) =>
        IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool TryGetCompoundAbiSort(string type, out Sort sort)
    {
        if (IsAbiType(type, "Array"))
        {
            sort = Sort.Array;
            return true;
        }

        if (IsAbiType(type, "Struct"))
        {
            sort = Sort.Struct;
            return true;
        }

        if (IsAbiType(type, "Map"))
        {
            sort = Sort.Map;
            return true;
        }

        sort = Sort.Unknown;
        return false;
    }

    private Expression ResolveReturnExpression(ContractMethodDescriptor method, ExecutionState? state)
    {
        if (state is null)
            throw new FormatException($"method '{method.Name}' return condition requires an execution state");
        if (state.EvaluationStack.Count == 0)
            throw new FormatException($"method '{method.Name}' has no return value on a successful HALT path");
        var returned = state.Peek();
        if (Metric == "count")
            return ResolveReturnCountExpression(method, state, returned);
        if (HasByteValue && Metric is null)
        {
            if (!IsByteStringLikeAbiType(method.ReturnType ?? ""))
                throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but byte-string return conditions require a ByteString-like ABI return");
            if (!TryResolveRuntimeByteStringExpression(state, returned, out var returnedBytes))
                throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {returned.Sort} StackItem; return metric or byte-string condition(s) cannot be evaluated soundly");
            return returnedBytes;
        }
        if (Metric is null)
            return returned.Expression;

        if (!IsByteStringLikeAbiType(method.ReturnType ?? ""))
            throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but return metrics require a ByteString-like ABI return");
        if (!TryResolveRuntimeByteStringExpression(state, returned, out var metricBytes))
            throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {returned.Sort} StackItem; return metric condition(s) cannot be evaluated soundly");

        return Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", metricBytes),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", metricBytes, Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
    }

    private static bool TryResolveRuntimeByteStringExpression(
        ExecutionState state,
        SymbolicValue value,
        out Expression expression)
    {
        if (value.Sort == Sort.Bytes)
        {
            expression = value.Expression;
            return true;
        }

        if (value.Expression is HeapRef { RefSort: Sort.Buffer } href
            && state.Heap.Get(href.ObjectId) is BufferObject buffer)
        {
            if (buffer.SourceBytes is { } sourceBytes)
            {
                expression = sourceBytes;
                return true;
            }

            if (!buffer.IsSymbolicOpen && buffer.Cells.All(cell => cell is IntConst))
            {
                expression = Expr.Bytes(buffer.Cells.Select(cell => (byte)((IntConst)cell).Value).ToArray());
                return true;
            }

            expression = new UnaryExpr(Sort.Bytes, "buf2bytes", value.Expression);
            return true;
        }

        expression = Expr.Bytes(Array.Empty<byte>());
        return false;
    }

    private static Expression ResolveReturnCountExpression(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned)
    {
        if (!TryGetCompoundAbiSort(method.ReturnType ?? "", out var expectedSort))
            throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but return count metrics require an Array, Struct, or Map ABI return");
        if (returned.Expression is not HeapRef { RefSort: var actualSort } href || actualSort != expectedSort)
            throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {returned.Sort} StackItem; return count condition(s) cannot be evaluated soundly");

        var heapObject = state.Heap.Get(href.ObjectId);
        return heapObject switch
        {
            ArrayObject { IsSymbolicOpen: false } array => Expr.Int(array.Items.Count),
            ArrayObject { IsSymbolicOpen: true } => throw new FormatException($"manifest method '{method.Name}' returns an open Array; return count condition(s) cannot be evaluated soundly"),
            StructObject { IsSymbolicOpen: false } structure => Expr.Int(structure.Fields.Count),
            StructObject { IsSymbolicOpen: true } => throw new FormatException($"manifest method '{method.Name}' returns an open Struct; return count condition(s) cannot be evaluated soundly"),
            MapObject { IsSymbolicOpen: false } map => Expr.Int(map.Entries.Count),
            MapObject { IsSymbolicOpen: true } => throw new FormatException($"manifest method '{method.Name}' returns an open Map; return count condition(s) cannot be evaluated soundly"),
            _ => throw new FormatException($"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {returned.Sort} StackItem; return count condition(s) cannot be evaluated soundly"),
        };
    }

    private Expression ResolveNotificationCountExpression(
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash)
    {
        string notificationName = NotificationName
            ?? throw new FormatException("notification verification condition is missing an event name");
        if (BooleanValue.HasValue)
            throw new FormatException("notification verification conditions require an integer count value");
        if (!string.Equals(Metric, "count", StringComparison.Ordinal))
            throw new FormatException("notification verification conditions require metric 'count'");
        if (state is null)
            throw new FormatException("notification verification conditions require an execution state");

        var dynamic = state.Telemetry.Notifications.FirstOrDefault(n =>
            string.IsNullOrWhiteSpace(n.ConcreteName)
            && (NotificationEmitter is null || NotificationEmitterMatches(n, currentScriptHash)));
        if (dynamic is not null)
        {
            throw new FormatException(
                $"notification count condition for '{NotificationNameWithEmitter(notificationName, NotificationEmitter)}' cannot be evaluated because Runtime.Notify at {FormatOffset(dynamic.Offset)} has a dynamic or unknown event name");
        }

        int count = MatchingNotifications(state, notificationName, currentScriptHash).Length;
        return Expr.Int(count);
    }

    private Expression ToNotificationArgumentConditionExpression(
        ContractMethodDescriptor method,
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash)
    {
        return TryResolveNotificationArgumentComparableExpression(method, state, currentScriptHash, out var left)
            ? ToComparisonExpression(method, left)
            : Expr.Bool(false);
    }

    private bool TryResolveNotificationArgumentComparableExpression(
        ContractMethodDescriptor method,
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash,
        out Expression left)
    {
        left = Expr.Bool(false);
        string notificationName = NotificationArgumentName
            ?? throw new FormatException("notification_arg verification condition is missing an event name");
        int index = NotificationArgumentIndex
            ?? throw new FormatException("notification_arg verification condition is missing an index");
        if (state is null)
            throw new FormatException("notification_arg verification conditions require an execution state");

        string displayName = NotificationNameWithEmitter(notificationName, NotificationEmitter);
        var dynamic = state.Telemetry.Notifications.FirstOrDefault(n =>
            string.IsNullOrWhiteSpace(n.ConcreteName)
            && (NotificationEmitter is null || NotificationEmitterMatches(n, currentScriptHash)));
        if (dynamic is not null)
        {
            throw new FormatException(
                $"notification_arg condition for '{displayName}' cannot be evaluated because Runtime.Notify at {FormatOffset(dynamic.Offset)} has a dynamic or unknown event name");
        }

        var matches = MatchingNotifications(state, notificationName, currentScriptHash);
        if (matches.Length == 0)
            return false;
        if (matches.Length > 1)
            throw new FormatException($"notification_arg condition for '{displayName}' is ambiguous because the path emits {matches.Length} matching Runtime.Notify events");

        var notification = matches[0];
        if (notification.State.Expression is not HeapRef href
            || state.Heap.Get(href.ObjectId) is not ArrayObject array)
        {
            return false;
        }

        if (index >= array.Items.Count)
        {
            if (array.IsSymbolicOpen)
                throw new FormatException($"notification_arg condition for '{displayName}' index {index} cannot be evaluated against an open symbolic event payload");
            return false;
        }

        var value = array.Items[index];
        Sort expectedSort = ExpectedNotificationArgumentSort(method);
        if (value.Sort != expectedSort)
            return false;
        if (Metric is null)
        {
            left = value.Expression;
            return true;
        }

        left = Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", value.Expression),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", value.Expression, Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
        return true;
    }

    private RuntimeNotification[] MatchingNotifications(
        ExecutionState state,
        string notificationName,
        ImmutableArray<byte> currentScriptHash)
    {
        var named = state.Telemetry.Notifications
            .Where(n => string.Equals(n.ConcreteName, notificationName, StringComparison.Ordinal))
            .ToArray();
        if (NotificationEmitter is null)
            return named;

        return named
            .Where(n => NotificationEmitterMatches(n, currentScriptHash))
            .ToArray();
    }

    private bool NotificationEmitterMatches(
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash)
    {
        if (NotificationEmitterCurrent)
            return IsCurrentNotificationEmitter(notification.ScriptHash, currentScriptHash);
        if (HasNotificationEmitterHash)
            return NotificationScriptHashEquals(notification.ScriptHash, NotificationEmitterHash, currentScriptHash);
        return true;
    }

    private static bool IsCurrentNotificationEmitter(
        SymbolicValue scriptHash,
        ImmutableArray<byte> currentScriptHash)
    {
        if (scriptHash.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" })
            return true;
        if (!currentScriptHash.IsDefaultOrEmpty
            && scriptHash.AsConcreteBytes() is { Length: NeoNativeContractHashes.HashLength } concrete)
        {
            return BytesEqual(concrete, currentScriptHash);
        }

        return false;
    }

    private static bool NotificationScriptHashEquals(
        SymbolicValue scriptHash,
        ImmutableArray<byte> expected,
        ImmutableArray<byte> currentScriptHash)
    {
        if (scriptHash.AsConcreteBytes() is { Length: NeoNativeContractHashes.HashLength } concrete)
            return BytesEqual(concrete, expected);
        if (scriptHash.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" }
            && !currentScriptHash.IsDefaultOrEmpty)
        {
            return BytesEqual(currentScriptHash, expected);
        }

        return false;
    }

    private static bool BytesEqual(byte[] left, ImmutableArray<byte> right)
    {
        if (right.IsDefault || left.Length != right.Length)
            return false;

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
                return false;
        }

        return true;
    }

    private static bool BytesEqual(ImmutableArray<byte> left, ImmutableArray<byte> right)
    {
        if (left.IsDefault || right.IsDefault || left.Length != right.Length)
            return false;

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
                return false;
        }

        return true;
    }

    private void EnsureExternalCallSelectorAndTargetAreConcrete(
        ExecutionState state,
        string methodName,
        string displayName,
        ImmutableArray<byte> currentScriptHash,
        string conditionKind)
    {
        var dynamicCall = state.Telemetry.ExternalCalls
            .Where(call => !call.ModeledSelfCall)
            .Where(call => ExternalCallContractMayMatch(call, currentScriptHash))
            .FirstOrDefault(call =>
                call.MethodDynamic
                || string.IsNullOrWhiteSpace(call.Method)
                || call.Method == "<dynamic>");
        if (dynamicCall is not null)
        {
            throw new FormatException(
                $"{conditionKind} for '{displayName}' cannot be evaluated because external call at {FormatOffset(dynamicCall.Offset)} has a dynamic or unknown method selector");
        }

        var unknownTarget = state.Telemetry.ExternalCalls
            .Where(call => !call.ModeledSelfCall)
            .Where(call => string.Equals(call.Method, methodName, StringComparison.Ordinal))
            .FirstOrDefault(call => ExternalCallContractMatch(call, currentScriptHash) == ScriptHashSelectorMatch.Unknown);
        if (unknownTarget is not null)
        {
            throw new FormatException(
                $"{conditionKind} for '{displayName}' cannot be evaluated because external call at {FormatOffset(unknownTarget.Offset)} has a dynamic or unknown target contract");
        }
    }

    private ExternalCall[] MatchingExternalCalls(
        ExecutionState state,
        string methodName,
        ImmutableArray<byte> currentScriptHash) =>
        state.Telemetry.ExternalCalls
            .Where(call => !call.ModeledSelfCall)
            .Where(call => string.Equals(call.Method, methodName, StringComparison.Ordinal))
            .Where(call => ExternalCallContractMatch(call, currentScriptHash) == ScriptHashSelectorMatch.Match)
            .ToArray();

    private bool ExternalCallContractMayMatch(
        ExternalCall call,
        ImmutableArray<byte> currentScriptHash) =>
        ExternalCallContractMatch(call, currentScriptHash) is not ScriptHashSelectorMatch.NoMatch;

    private ScriptHashSelectorMatch ExternalCallContractMatch(
        ExternalCall call,
        ImmutableArray<byte> currentScriptHash)
    {
        if (ExternalCallContract is null)
            return ScriptHashSelectorMatch.Match;
        if (call.TargetHash is null)
            return ScriptHashSelectorMatch.Unknown;
        if (ExternalCallContractCurrent)
            return ScriptHashValueMatchesCurrent(call.TargetHash, currentScriptHash);
        if (HasExternalCallContractHash)
            return ScriptHashValueMatches(call.TargetHash, ExternalCallContractHash, currentScriptHash);
        return ScriptHashSelectorMatch.Match;
    }

    private static ScriptHashSelectorMatch ScriptHashValueMatchesCurrent(
        SymbolicValue scriptHash,
        ImmutableArray<byte> currentScriptHash)
    {
        if (scriptHash.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" })
            return ScriptHashSelectorMatch.Match;

        byte[]? concrete = scriptHash.AsConcreteBytes();
        if (concrete is not null && concrete.Length != NeoNativeContractHashes.HashLength)
            return ScriptHashSelectorMatch.NoMatch;
        if (concrete is not null && !currentScriptHash.IsDefaultOrEmpty)
            return BytesEqual(concrete, currentScriptHash)
                ? ScriptHashSelectorMatch.Match
                : ScriptHashSelectorMatch.NoMatch;

        return ScriptHashSelectorMatch.Unknown;
    }

    private static ScriptHashSelectorMatch ScriptHashValueMatches(
        SymbolicValue scriptHash,
        ImmutableArray<byte> expected,
        ImmutableArray<byte> currentScriptHash)
    {
        byte[]? concrete = scriptHash.AsConcreteBytes();
        if (concrete is not null)
        {
            if (concrete.Length != NeoNativeContractHashes.HashLength)
                return ScriptHashSelectorMatch.NoMatch;
            return BytesEqual(concrete, expected)
                ? ScriptHashSelectorMatch.Match
                : ScriptHashSelectorMatch.NoMatch;
        }

        if (scriptHash.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" })
        {
            if (currentScriptHash.IsDefaultOrEmpty)
                return ScriptHashSelectorMatch.Unknown;
            return BytesEqual(currentScriptHash, expected)
                ? ScriptHashSelectorMatch.Match
                : ScriptHashSelectorMatch.NoMatch;
        }

        return ScriptHashSelectorMatch.Unknown;
    }

    private Sort ExpectedNotificationArgumentSort(ContractMethodDescriptor method)
    {
        if (Metric is not null)
        {
            if (BooleanValue.HasValue)
                throw new FormatException("notification_arg verification condition metrics require an integer 'value'");
            if (HasByteValue)
                throw new FormatException("notification_arg byte-string verification conditions cannot use a metric");
            if (ValueArg is not null)
            {
                var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
                string valueArgType = valueArgParameter.Type ?? "Any";
                if (!IsAbiType(valueArgType, "Integer"))
                    throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' but metric comparisons require an Integer RHS");
            }
            return Sort.Bytes;
        }

        if (ValueArg is not null)
        {
            var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
            string valueArgType = valueArgParameter.Type ?? "Any";
            if (IsAbiType(valueArgType, "Boolean"))
                return Sort.Bool;
            if (IsAbiType(valueArgType, "Integer"))
                return Sort.Int;
            if (IsByteStringLikeAbiType(valueArgType))
                return Sort.Bytes;
            throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' and cannot be used as a verification RHS");
        }

        if (HasByteValue)
            return Sort.Bytes;
        if (BooleanValue.HasValue)
            return Sort.Bool;
        return Sort.Int;
    }

    private Expression ResolveExternalCallAfterNotificationExpression(
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash)
    {
        string methodName = ExternalCallAfterNotificationMethod
            ?? throw new FormatException("external_call_after_notification verification condition is missing a method name");
        string notificationName = NotificationBeforeName
            ?? throw new FormatException("external_call_after_notification verification condition is missing notification_before");
        string displayName = NotificationNameWithEmitter(notificationName, NotificationEmitter);
        string callDisplayName = ExternalCallNameWithContract(methodName, ExternalCallContract);
        if (state is null)
            throw new FormatException("external_call_after_notification verification conditions require an execution state");
        if (Metric is not null)
            throw new FormatException("external_call_after_notification verification conditions do not support metrics");
        if (ValueArg is not null || HasByteValue || IntegerValue.HasValue || !BooleanValue.HasValue)
            throw new FormatException("external_call_after_notification verification conditions require a boolean 'value'");

        EnsureExternalCallSelectorAndTargetAreConcrete(
            state,
            methodName,
            callDisplayName,
            currentScriptHash,
            "external_call_after_notification condition");

        var dynamicNotification = state.Telemetry.Notifications.FirstOrDefault(n =>
            string.IsNullOrWhiteSpace(n.ConcreteName)
            && (NotificationEmitter is null || NotificationEmitterMatches(n, currentScriptHash)));
        if (dynamicNotification is not null)
        {
            throw new FormatException(
                $"external_call_after_notification condition for '{methodName}' before '{displayName}' cannot be evaluated because Runtime.Notify at {FormatOffset(dynamicNotification.Offset)} has a dynamic or unknown event name");
        }

        var matchingCalls = MatchingExternalCalls(state, methodName, currentScriptHash);
        if (matchingCalls.Length == 0)
            return Expr.Bool(false);

        var matchingNotifications = MatchingNotifications(state, notificationName, currentScriptHash);
        bool everyMatchingCallHasPriorNotification = matchingCalls.All(call =>
            matchingNotifications.Any(notification => notification.Offset < call.Offset));
        return Expr.Bool(everyMatchingCallHasPriorNotification);
    }

    private Expression ToExternalCallFieldConditionExpression(
        ContractMethodDescriptor method,
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash)
    {
        return TryResolveExternalCallFieldComparableExpression(method, state, currentScriptHash, out var left)
            ? ToComparisonExpression(method, left)
            : Expr.Bool(false);
    }

    private bool TryResolveExternalCallFieldComparableExpression(
        ContractMethodDescriptor method,
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash,
        out Expression left)
    {
        left = Expr.Bool(false);
        string methodName = ExternalCallTargetMethod ?? ExternalCallArgumentMethod
            ?? throw new FormatException("external_call field verification condition is missing a method name");
        string displayName = ExternalCallNameWithContract(methodName, ExternalCallContract);
        if (state is null)
            throw new FormatException("external_call field verification conditions require an execution state");

        EnsureExternalCallSelectorAndTargetAreConcrete(
            state,
            methodName,
            displayName,
            currentScriptHash,
            "external_call field condition");

        var matches = MatchingExternalCalls(state, methodName, currentScriptHash);
        if (matches.Length == 0)
            return false;
        if (matches.Length > 1)
            throw new FormatException($"external_call field condition for '{displayName}' is ambiguous because the path executes {matches.Length} matching external calls");

        var call = matches[0];
        if (ExternalCallTargetMethod is not null)
        {
            if (call.TargetHash is not { } target)
                return false;
            return TryResolveExternalCallValueExpression(
                method,
                "external_call_target",
                methodName,
                target,
                out left,
                requireByteStringWithoutMetric: true);
        }

        int index = ExternalCallArgumentIndex
            ?? throw new FormatException("external_call_arg verification condition is missing an index");
        if (index >= call.Args.Count)
            return false;

        return TryResolveExternalCallValueExpression(
            method,
            "external_call_arg",
            methodName,
            call.Args[index],
            out left,
            requireByteStringWithoutMetric: false);
    }

    private bool TryResolveExternalCallValueExpression(
        ContractMethodDescriptor method,
        string conditionKind,
        string methodName,
        SymbolicValue value,
        out Expression left,
        bool requireByteStringWithoutMetric)
    {
        left = Expr.Bool(false);
        Sort expectedSort = ExpectedExternalCallFieldSort(
            method,
            conditionKind,
            methodName,
            requireByteStringWithoutMetric);
        if (value.Sort != expectedSort)
            return false;
        if (Metric is null)
        {
            left = value.Expression;
            return true;
        }

        left = Metric switch
        {
            "size" => new UnaryExpr(Sort.Int, "size", value.Expression),
            "first_byte" => new BinaryExpr(Sort.Int, "pick", value.Expression, Expr.Int(0)),
            _ => throw new FormatException($"unsupported verification condition metric '{Metric}'"),
        };
        return true;
    }

    private Sort ExpectedExternalCallFieldSort(
        ContractMethodDescriptor method,
        string conditionKind,
        string methodName,
        bool requireByteStringWithoutMetric)
    {
        if (Metric is not null)
        {
            if (BooleanValue.HasValue)
                throw new FormatException($"{conditionKind} verification condition metrics require an integer 'value'");
            if (HasByteValue)
                throw new FormatException($"{conditionKind} byte-string verification conditions cannot use a metric");
            if (ValueArg is not null)
            {
                var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
                string valueArgType = valueArgParameter.Type ?? "Any";
                if (!IsAbiType(valueArgType, "Integer"))
                    throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' but metric comparisons require an Integer RHS");
            }
            return Sort.Bytes;
        }

        if (requireByteStringWithoutMetric)
        {
            if (BooleanValue.HasValue || IntegerValue.HasValue)
                throw new FormatException($"{conditionKind} for '{methodName}' compares a contract hash target and requires a ByteString-like RHS or a metric");
            if (ValueArg is not null)
            {
                var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
                string valueArgType = valueArgParameter.Type ?? "Any";
                if (!IsByteStringLikeAbiType(valueArgType))
                    throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' but {conditionKind} requires a ByteString-like RHS");
            }
            return Sort.Bytes;
        }

        if (ValueArg is not null)
        {
            var (valueArgParameter, _) = ResolveArgument(method, ValueArg);
            string valueArgType = valueArgParameter.Type ?? "Any";
            if (IsAbiType(valueArgType, "Boolean"))
                return Sort.Bool;
            if (IsAbiType(valueArgType, "Integer"))
                return Sort.Int;
            if (IsByteStringLikeAbiType(valueArgType))
                return Sort.Bytes;
            throw new FormatException($"value_arg ABI parameter '{ValueArg}' has type '{valueArgType}' and cannot be used as a verification RHS");
        }

        if (HasByteValue)
            return Sort.Bytes;
        if (BooleanValue.HasValue)
            return Sort.Bool;
        return Sort.Int;
    }

    private Expression ResolveExternalCallCountExpression(
        ExecutionState? state,
        ImmutableArray<byte> currentScriptHash)
    {
        string methodName = ExternalCallMethod
            ?? throw new FormatException("external_call verification condition is missing a method name");
        string displayName = ExternalCallNameWithContract(methodName, ExternalCallContract);
        if (BooleanValue.HasValue)
            throw new FormatException("external_call verification conditions require an integer count value");
        if (!string.Equals(Metric, "count", StringComparison.Ordinal))
            throw new FormatException("external_call verification conditions require metric 'count'");
        if (state is null)
            throw new FormatException("external_call verification conditions require an execution state");

        EnsureExternalCallSelectorAndTargetAreConcrete(
            state,
            methodName,
            displayName,
            currentScriptHash,
            "external_call count condition");

        int count = MatchingExternalCalls(state, methodName, currentScriptHash).Length;
        return Expr.Int(count);
    }

    private Expression ResolveWitnessEnforcedCountExpression(
        ContractMethodDescriptor method,
        ExecutionState? state)
    {
        string target = WitnessTarget
            ?? throw new FormatException("witness verification condition is missing a target");
        if (BooleanValue.HasValue)
            throw new FormatException("witness verification conditions require an integer enforced_count value");
        if (!string.Equals(Metric, "enforced_count", StringComparison.Ordinal))
            throw new FormatException("witness verification conditions require metric 'enforced_count'");
        if (state is null)
            throw new FormatException("witness verification conditions require an execution state");

        Expression? argumentTarget = null;
        if (!HasWitnessByteTarget)
        {
            var (parameter, symbol) = ResolveArgument(method, target);
            string parameterType = parameter.Type ?? "Any";
            if (!IsWitnessTargetAbiType(parameterType))
                throw new FormatException($"witness target ABI parameter '{target}' has type '{parameterType}' and cannot be used as a CheckWitness hash or public key target");
            argumentTarget = Expr.Sym(Sort.Bytes, symbol);
        }

        int count = state.Telemetry.WitnessCheckOps.Count(witness =>
            state.Telemetry.IsWitnessCheckResultEnforced(witness)
            && WitnessTargetMatches(witness.Target.Expression, argumentTarget));
        return Expr.Int(count);
    }

    private bool WitnessTargetMatches(Expression actual, Expression? argumentTarget)
    {
        if (HasWitnessByteTarget)
        {
            return Expr.CanonicalBytes(actual) is { } bytes
                && bytes.AsSpan().SequenceEqual(WitnessByteTarget.AsSpan());
        }

        return argumentTarget is not null && actual.Equals(argumentTarget);
    }

    private Expression ResolveCallerHashEnforcedCountExpression(
        ContractMethodDescriptor method,
        ExecutionState? state)
    {
        string target = CallerHashTarget
            ?? throw new FormatException("caller_hash verification condition is missing a target");
        if (BooleanValue.HasValue)
            throw new FormatException("caller_hash verification conditions require an integer enforced_count value");
        if (!string.Equals(Metric, "enforced_count", StringComparison.Ordinal))
            throw new FormatException("caller_hash verification conditions require metric 'enforced_count'");
        if (state is null)
            throw new FormatException("caller_hash verification conditions require an execution state");

        Expression? argumentTarget = null;
        if (!HasCallerHashByteTarget)
        {
            var (parameter, symbol) = ResolveArgument(method, target);
            string parameterType = parameter.Type ?? "Any";
            if (!IsCallerHashTargetAbiType(parameterType))
                throw new FormatException($"caller_hash target ABI parameter '{target}' has type '{parameterType}' and cannot be used as a UInt160 caller hash target");
            argumentTarget = Expr.Sym(Sort.Bytes, symbol);
        }

        int count = state.Telemetry.CallerHashCheckOps.Count(caller =>
            CallerHashTargetMatches(caller.Target.Expression, argumentTarget));
        return Expr.Int(count);
    }

    private bool CallerHashTargetMatches(Expression actual, Expression? argumentTarget)
    {
        if (HasCallerHashByteTarget)
        {
            return Expr.CanonicalBytes(actual) is { } bytes
                && bytes.AsSpan().SequenceEqual(CallerHashByteTarget.AsSpan());
        }

        return argumentTarget is not null && actual.Equals(argumentTarget);
    }

    private Expression ResolveSignatureCheckEnforcedCountExpression(
        ContractMethodDescriptor method,
        ExecutionState? state)
    {
        string target = SignatureCheckTarget
            ?? throw new FormatException("signature_check verification condition is missing a target");
        if (BooleanValue.HasValue)
            throw new FormatException("signature_check verification conditions require an integer enforced_count value");
        if (!string.Equals(Metric, "enforced_count", StringComparison.Ordinal))
            throw new FormatException("signature_check verification conditions require metric 'enforced_count'");
        if (state is null)
            throw new FormatException("signature_check verification conditions require an execution state");

        Expression? argumentTarget = null;
        if (!HasSignatureCheckByteTarget)
        {
            var (parameter, symbol) = ResolveArgument(method, target);
            string parameterType = parameter.Type ?? "Any";
            if (IsAbiType(parameterType, "Array"))
            {
                argumentTarget = Expr.Sym(Sort.Array, symbol);
            }
            else
            {
                if (!IsSignaturePublicKeyLikeAbiType(parameterType))
                    throw new FormatException($"signature_check target ABI parameter '{target}' has type '{parameterType}' and cannot be used as a CheckSig/CheckMultisig public-key target");
                argumentTarget = Expr.Sym(Sort.Bytes, symbol);
            }
        }

        int count = state.Telemetry.SignatureCheckOps.Count(signature =>
            state.Telemetry.IsSignatureCheckResultEnforced(signature)
            && SignatureCheckTargetMatches(signature, argumentTarget, state));
        return Expr.Int(count);
    }

    private bool SignatureCheckTargetMatches(SignatureCheckOp signature, Expression? argumentTarget, ExecutionState state)
    {
        var actual = signature.PublicKeyOrKeys;
        if (HasSignatureCheckByteTarget)
        {
            if (Expr.CanonicalBytes(actual.Expression) is { } bytes)
                return bytes.AsSpan().SequenceEqual(SignatureCheckByteTarget.AsSpan());

            if (actual.Expression is HeapRef { RefSort: Sort.Array } href
                && state.Heap.Get(href.ObjectId) is ArrayObject array)
            {
                if (array.IsSymbolicOpen)
                    throw new FormatException("signature_check target byte literal cannot be evaluated against an open CheckMultisig public-key array");
                bool targetPresent = array.Items.Any(item =>
                    Expr.CanonicalBytes(item.Expression) is { } itemBytes
                    && itemBytes.AsSpan().SequenceEqual(SignatureCheckByteTarget.AsSpan()));
                if (!targetPresent)
                    return false;

                if (!ClosedMultisigRequiresEveryPublicKey(signature, state))
                {
                    throw new FormatException(
                        "signature_check target byte literal cannot be proved from a partial CheckMultisig public-key array because the current model does not prove which public keys signed");
                }

                return true;
            }

            return false;
        }

        if (argumentTarget is Symbol { Sort: Sort.Array, Name: var arraySymbol })
        {
            return actual.Expression is HeapRef { RefSort: Sort.Array }
                && actual.Taints.Contains(arraySymbol);
        }

        return argumentTarget is not null && actual.Expression.Equals(argumentTarget);
    }

    private static bool ClosedMultisigRequiresEveryPublicKey(SignatureCheckOp signature, ExecutionState state)
    {
        if (!signature.IsMultisig)
            return true;

        if (signature.PublicKeyOrKeys.Expression is not HeapRef { RefSort: Sort.Array } publicKeysRef
            || state.Heap.Get(publicKeysRef.ObjectId) is not ArrayObject publicKeys
            || signature.SignatureOrSignatures.Expression is not HeapRef { RefSort: Sort.Array } signaturesRef
            || state.Heap.Get(signaturesRef.ObjectId) is not ArrayObject signatures
            || publicKeys.IsSymbolicOpen
            || signatures.IsSymbolicOpen)
        {
            throw new FormatException(
                "signature_check target byte literal cannot be evaluated against an open CheckMultisig public-key or signature array");
        }

        return signatures.Items.Count >= publicKeys.Items.Count;
    }

    private static bool TryReadBool(JsonNode node, out bool value)
    {
        if (node is JsonValue jsonValue && jsonValue.TryGetValue(out bool boolean))
        {
            value = boolean;
            return true;
        }
        value = default;
        return false;
    }

    private static BigInteger ReadInteger(JsonNode node)
    {
        if (node is JsonValue jsonValue)
        {
            if (jsonValue.TryGetValue(out int i)) return i;
            if (jsonValue.TryGetValue(out long l)) return l;
            if (jsonValue.TryGetValue(out string? s) && BigInteger.TryParse(s, out var parsed))
                return parsed;
        }

        string raw = node.ToJsonString().Trim('"');
        if (BigInteger.TryParse(raw, out var value))
            return value;
        throw new FormatException($"verification condition value '{raw}' is not an integer or boolean");
    }
}
