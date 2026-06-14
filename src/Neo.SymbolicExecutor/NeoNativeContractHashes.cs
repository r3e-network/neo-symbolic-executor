namespace Neo.SymbolicExecutor;

/// <summary>
/// Canonical Neo N3 native contract script hashes, stored as 20-byte little-endian hex strings
/// matching manifest permission descriptors and VM stack ByteString values.
/// </summary>
public static class NeoNativeContractHashes
{
    public const int HashLength = 20;

    public const string ContractManagement = "fffdc93764dbaddd97c48f252a53ea4643faa3fd";
    public const string StdLib = "acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0";
    public const string CryptoLib = "726cb6e0cd8628a1350a611384688911ab75f51b";
    public const string LedgerContract = "da65b600f7124ce6c79950c1772a36403104f2be";
    public const string NeoToken = "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5";
    public const string GasToken = "d2a4cff31913016155e38e474a2c06d08be276cf";
    public const string PolicyContract = "cc5e4edd9f5f8dba8bb65734541df7a1c081c67b";
    public const string RoleManagement = "49cf4e5378ffcd4dec034fd98a174c5491e395e2";
    public const string OracleContract = "fe924b7cfe89ddd271abaf7210a80a7e11178758";

    private static readonly byte[][] KnownHashes =
    {
        FromHex(ContractManagement),
        FromHex(StdLib),
        FromHex(CryptoLib),
        FromHex(LedgerContract),
        FromHex(NeoToken),
        FromHex(GasToken),
        FromHex(PolicyContract),
        FromHex(RoleManagement),
        FromHex(OracleContract),
    };

    public static bool IsKnownNativeContractHash(byte[]? hash)
    {
        if (hash is not { Length: HashLength })
            return false;

        foreach (var known in KnownHashes)
        {
            if (BytesEqual(hash, known))
                return true;
        }

        return false;
    }

    public static byte[] FromHex(string hash) =>
        System.Convert.FromHexString(hash);

    private static bool BytesEqual(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            return false;

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
                return false;
        }

        return true;
    }
}
