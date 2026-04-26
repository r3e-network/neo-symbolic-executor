using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Neo.SymbolicExecutor;

public sealed record SyscallDescriptor(string Name, uint Hash, int PopArgs, bool HasReturnValue, long Price);

/// <summary>
/// Registry of known Neo N3 syscalls. The hash is the first 4 bytes of SHA-256 of the syscall name,
/// little-endian (matches Neo's <c>ApplicationEngine.Register</c>).
///
/// PopArgs and HasReturnValue are best-effort metadata used by the syscall fallback in
/// <see cref="SymbolicEngine"/> to keep the stack aligned even when a specific handler is missing.
/// </summary>
public static class SyscallRegistry
{
    private static readonly Dictionary<uint, SyscallDescriptor> _byHash;
    private static readonly Dictionary<string, SyscallDescriptor> _byName;

    static SyscallRegistry()
    {
        _byHash = new Dictionary<uint, SyscallDescriptor>();
        _byName = new Dictionary<string, SyscallDescriptor>();
        foreach (var d in BuildDescriptors())
        {
            _byHash[d.Hash] = d;
            _byName[d.Name] = d;
        }
    }

    public static SyscallDescriptor? Lookup(uint hash) =>
        _byHash.TryGetValue(hash, out var d) ? d : null;

    public static SyscallDescriptor? LookupByName(string name) =>
        _byName.TryGetValue(name, out var d) ? d : null;

    public static uint ComputeHash(string name)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(name), hash);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(hash);
    }

    private static IEnumerable<SyscallDescriptor> BuildDescriptors()
    {
        // Names mirrored from Neo's ApplicationEngine.* registrations. PopArgs / HasReturn are
        // best-effort — not every modeled syscall has a dedicated handler yet.
        var entries = new (string Name, int Pop, bool Ret, long Price)[]
        {
            ("System.Crypto.CheckSig",                 2, true,  1 << 15),
            ("System.Crypto.CheckMultisig",            2, true,  0),
            ("System.Contract.Call",                   4, true,  1 << 15),
            ("System.Contract.CallNative",             1, true,  0),
            ("System.Contract.GetCallFlags",           0, true,  1 << 10),
            ("System.Contract.CreateStandardAccount",  1, true,  1 << 8),
            ("System.Contract.CreateMultisigAccount",  2, true,  1 << 8),
            ("System.Contract.NativeOnPersist",        0, false, 0),
            ("System.Contract.NativePostPersist",      0, false, 0),
            ("System.Iterator.Next",                   1, true,  1 << 4),
            ("System.Iterator.Value",                  1, true,  1 << 4),
            ("System.Runtime.Platform",                0, true,  1 << 3),
            ("System.Runtime.GetTrigger",              0, true,  1 << 3),
            ("System.Runtime.GetTime",                 0, true,  1 << 3),
            ("System.Runtime.GetScriptContainer",      0, true,  1 << 3),
            ("System.Runtime.GetExecutingScriptHash",  0, true,  1 << 4),
            ("System.Runtime.GetCallingScriptHash",    0, true,  1 << 4),
            ("System.Runtime.GetEntryScriptHash",      0, true,  1 << 4),
            ("System.Runtime.LoadScript",              3, false, 1 << 15),
            ("System.Runtime.CheckWitness",            1, true,  1 << 10),
            ("System.Runtime.GetInvocationCounter",    0, true,  1 << 4),
            ("System.Runtime.GetRandom",               0, true,  0),
            ("System.Runtime.Log",                     1, false, 1 << 15),
            ("System.Runtime.Notify",                  2, false, 1 << 15),
            ("System.Runtime.GetNotifications",        1, true,  1 << 12),
            ("System.Runtime.GasLeft",                 0, true,  1 << 4),
            ("System.Runtime.BurnGas",                 1, false, 1 << 4),
            ("System.Runtime.CurrentSigners",          0, true,  1 << 4),
            ("System.Runtime.GetNetwork",              0, true,  1 << 3),
            ("System.Runtime.GetAddressVersion",       0, true,  1 << 3),
            ("System.Storage.GetContext",              0, true,  1 << 4),
            ("System.Storage.GetReadOnlyContext",      0, true,  1 << 4),
            ("System.Storage.AsReadOnly",              1, true,  1 << 4),
            ("System.Storage.Get",                     2, true,  1 << 15),
            ("System.Storage.Find",                    3, true,  1 << 15),
            ("System.Storage.Put",                     3, false, 1 << 15),
            ("System.Storage.Delete",                  2, false, 1 << 15),
        };
        foreach (var (name, pop, ret, price) in entries)
        {
            yield return new SyscallDescriptor(name, ComputeHash(name), pop, ret, price);
        }
    }
}
