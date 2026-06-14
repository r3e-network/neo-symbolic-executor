using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Neo.SymbolicExecutor;

public sealed record SyscallDescriptor(
    string Name,
    uint Hash,
    int PopArgs,
    bool HasReturnValue,
    long Price,
    int RequiredCallFlags);

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
        var entries = new (string Name, int Pop, bool Ret, long Price, int RequiredFlags)[]
        {
            ("System.Crypto.CheckSig",                 2, true,  1 << 15, NeoCallFlags.None),
            ("System.Crypto.CheckMultisig",            2, true,  0,       NeoCallFlags.None),
            ("System.Contract.Call",                   4, true,  1 << 15, NeoCallFlags.ReadStates | NeoCallFlags.AllowCall),
            ("System.Contract.CallNative",             1, true,  0,       NeoCallFlags.None),
            ("System.Contract.GetCallFlags",           0, true,  1 << 10, NeoCallFlags.None),
            ("System.Contract.CreateStandardAccount",  1, true,  1 << 8,  NeoCallFlags.None),
            ("System.Contract.CreateMultisigAccount",  2, true,  1 << 8,  NeoCallFlags.None),
            ("System.Contract.NativeOnPersist",        0, false, 0,       NeoCallFlags.States),
            ("System.Contract.NativePostPersist",      0, false, 0,       NeoCallFlags.States),
            ("System.Iterator.Next",                   1, true,  1 << 4,  NeoCallFlags.None),
            ("System.Iterator.Value",                  1, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.Platform",                0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Runtime.GetTrigger",              0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Runtime.GetTime",                 0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Runtime.GetScriptContainer",      0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Runtime.GetExecutingScriptHash",  0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.GetCallingScriptHash",    0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.GetEntryScriptHash",      0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.LoadScript",              3, true,  1 << 15, NeoCallFlags.AllowCall),
            ("System.Runtime.CheckWitness",            1, true,  1 << 10, NeoCallFlags.None),
            ("System.Runtime.GetInvocationCounter",    0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.GetRandom",               0, true,  0,       NeoCallFlags.None),
            ("System.Runtime.Log",                     1, false, 1 << 15, NeoCallFlags.AllowNotify),
            ("System.Runtime.Notify",                  2, false, 1 << 15, NeoCallFlags.AllowNotify),
            ("System.Runtime.GetNotifications",        1, true,  1 << 12, NeoCallFlags.None),
            ("System.Runtime.GasLeft",                 0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.BurnGas",                 1, false, 1 << 4,  NeoCallFlags.None),
            ("System.Runtime.CurrentSigners",          0, true,  1 << 4,  NeoCallFlags.None),
            ("System.Runtime.GetNetwork",              0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Runtime.GetAddressVersion",       0, true,  1 << 3,  NeoCallFlags.None),
            ("System.Storage.GetContext",              0, true,  1 << 4,  NeoCallFlags.ReadStates),
            ("System.Storage.GetReadOnlyContext",      0, true,  1 << 4,  NeoCallFlags.ReadStates),
            ("System.Storage.AsReadOnly",              1, true,  1 << 4,  NeoCallFlags.ReadStates),
            ("System.Storage.Get",                     2, true,  1 << 15, NeoCallFlags.ReadStates),
            ("System.Storage.Find",                    3, true,  1 << 15, NeoCallFlags.ReadStates),
            ("System.Storage.Put",                     3, false, 1 << 15, NeoCallFlags.WriteStates),
            ("System.Storage.Delete",                  2, false, 1 << 15, NeoCallFlags.WriteStates),
            ("System.Storage.Local.Get",               1, true,  1 << 15, NeoCallFlags.ReadStates),
            ("System.Storage.Local.Find",              2, true,  1 << 15, NeoCallFlags.ReadStates),
            ("System.Storage.Local.Put",               2, false, 1 << 15, NeoCallFlags.WriteStates),
            ("System.Storage.Local.Delete",            1, false, 1 << 15, NeoCallFlags.WriteStates),
        };
        foreach (var (name, pop, ret, price, requiredFlags) in entries)
        {
            yield return new SyscallDescriptor(name, ComputeHash(name), pop, ret, price, requiredFlags);
        }
    }
}
