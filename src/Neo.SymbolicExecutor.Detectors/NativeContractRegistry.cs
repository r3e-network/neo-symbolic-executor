using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Registry of well-known Neo N3 native contracts and which of their methods are
/// state-changing. Drives precision in the access_control and reentrancy detectors —
/// per the audit, the biggest false-positive source was treating every external call
/// as sensitive (no allowlist for read-only natives).
/// </summary>
public sealed class NativeContractRegistry
{
    public static NativeContractRegistry Default { get; } = BuildDefault();

    private readonly Dictionary<string, NativeContract> _byHash;

    public NativeContractRegistry(IEnumerable<NativeContract> contracts)
    {
        _byHash = contracts.ToDictionary(c => c.Hash, System.StringComparer.OrdinalIgnoreCase);
    }

    public NativeContract? ByHash(string hash) =>
        _byHash.TryGetValue(NormalizeHash(hash), out var c) ? c : null;

    /// <summary>
    /// Look up a native contract by its 20-byte little-endian hash. Returns null when the input
    /// is null or not exactly 20 bytes — non-N3 hash widths cannot designate a real native
    /// contract, and a silent prefix match would let the upgradeability detector misclassify a
    /// short-PUSHDATA value as ContractManagement.
    /// </summary>
    public NativeContract? ByHashBytes(byte[]? hash) =>
        hash is { Length: 20 } ? ByHash(System.Convert.ToHexString(hash)) : null;

    /// <summary>
    /// True when <paramref name="call"/> targets a known native contract and invokes one of its
    /// read-only methods. These calls cannot re-enter the caller's storage, so the access_control
    /// and reentrancy detectors filter them out as benign. Conservative: when the target hash or
    /// method name is symbolic / unresolved we return false.
    /// </summary>
    public bool IsBenignReadOnlyCall(ExternalCall call)
    {
        var native = ByHashBytes(call.TargetHash?.AsConcreteBytes());
        return native is not null
            && native.ReadOnlyMethods.Contains(call.Method, System.StringComparer.OrdinalIgnoreCase);
    }

    private static string NormalizeHash(string hash)
    {
        var s = hash.StartsWith("0x", System.StringComparison.OrdinalIgnoreCase) ? hash[2..] : hash;
        return s.ToLowerInvariant();
    }

    private static NativeContractRegistry BuildDefault()
    {
        return new NativeContractRegistry(new[]
        {
            new NativeContract("ContractManagement", "fffdc93764dbaddd97c48f252a53ea4643faa3fd",
                ReadOnly: new[] { "getContract", "getContractById", "hasMethod", "listContracts", "getContractHashes" },
                Sensitive: new[] { "deploy", "update", "destroy", "setMinimumDeploymentFee" }),
            new NativeContract("StdLib", "acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0",
                ReadOnly: new[] {
                    "atoi", "itoa", "base58Encode", "base58Decode", "base58CheckEncode", "base58CheckDecode",
                    "base64Encode", "base64Decode", "memoryCompare", "memorySearch",
                    "stringSplit", "deserialize", "serialize", "jsonSerialize", "jsonDeserialize",
                },
                Sensitive: System.Array.Empty<string>()),
            new NativeContract("CryptoLib", "726cb6e0cd8628a1350a611384688911ab75f51b",
                ReadOnly: new[] {
                    "sha256", "ripemd160", "murmur32", "verifyWithECDsa", "bls12381Add", "bls12381Mul",
                    "bls12381Pairing", "bls12381Serialize", "bls12381Deserialize", "bls12381Equal",
                },
                Sensitive: System.Array.Empty<string>()),
            new NativeContract("LedgerContract", "da65b600f7124ce6c79950c1772a36403104f2be",
                ReadOnly: new[] {
                    "currentHash", "currentIndex", "getBlock", "getBlockHash", "getTransaction",
                    "getTransactionFromBlock", "getTransactionHeight", "getTransactionVMState",
                    "getTransactionSigners",
                },
                Sensitive: System.Array.Empty<string>()),
            new NativeContract("NeoToken", "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5",
                ReadOnly: new[] { "symbol", "decimals", "totalSupply", "balanceOf", "getCommittee", "getCandidates", "getCommitteeAddress", "getNextBlockValidators", "getRegisterPrice", "getAccountState", "unclaimedGas" },
                Sensitive: new[] { "transfer", "vote", "registerCandidate", "unregisterCandidate", "setRegisterPrice" }),
            new NativeContract("GasToken", "d2a4cff31913016155e38e474a2c06d08be276cf",
                ReadOnly: new[] { "symbol", "decimals", "totalSupply", "balanceOf" },
                Sensitive: new[] { "transfer" }),
            new NativeContract("PolicyContract", "cc5e4edd9f5f8dba8bb65734541df7a1c081c67b",
                ReadOnly: new[] { "getFeePerByte", "getExecFeeFactor", "getStoragePrice", "getAttributeFee", "isBlocked" },
                Sensitive: new[] { "setFeePerByte", "setExecFeeFactor", "setStoragePrice", "setAttributeFee", "blockAccount", "unblockAccount" }),
            new NativeContract("RoleManagement", "49cf4e5378ffcd4dec034fd98a174c5491e395e2",
                ReadOnly: new[] { "getDesignatedByRole" },
                Sensitive: new[] { "designateAsRole" }),
            new NativeContract("OracleContract", "fe924b7cfe89ddd271abaf7210a80a7e11178758",
                ReadOnly: new[] { "getPrice", "verify" },
                Sensitive: new[] { "request", "setPrice", "finish" }),
        });
    }
}

public sealed record NativeContract(
    string Name,
    string Hash,
    IReadOnlyList<string> ReadOnly,
    IReadOnlyList<string> Sensitive)
{
    public IReadOnlyList<string> ReadOnlyMethods => ReadOnly;
    public IReadOnlyList<string> SensitiveMethods => Sensitive;
}
