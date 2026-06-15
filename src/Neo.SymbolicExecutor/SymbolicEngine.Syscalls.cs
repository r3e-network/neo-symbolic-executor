using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private static readonly byte[] StdLibContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.StdLib);
    private static readonly byte[] CryptoLibContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.CryptoLib);
    private static readonly byte[] ContractManagementHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.ContractManagement);
    private static readonly byte[] LedgerContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.LedgerContract);
    private static readonly byte[] PolicyContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.PolicyContract);
    private static readonly byte[] RoleManagementHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.RoleManagement);
    private static readonly byte[] OracleContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.OracleContract);
    private static readonly int[] ValidLedgerTransactionVmStates =
    {
        0, // NONE
        1, // HALT
        2, // FAULT
        4, // BREAK
    };
    private static readonly int[] ValidPolicyAttributeTypes =
    {
        0x01, // HighPriority
        0x11, // OracleResponse
        0x20, // NotValidBefore
        0x21, // Conflicts
        0x22, // NotaryAssisted
    };
    private static readonly int[] ValidRoleManagementRoles =
    {
        4, // StateValidator
        8, // Oracle
        16, // NeoFSAlphabetNode
        32, // P2PNotary
    };
    private static readonly byte[] NeoTokenContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.NeoToken);
    private static readonly byte[] GasTokenContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.GasToken);
    private const int MaxStorageKeyLength = 64;
    private const int MaxStorageValueLength = 65_535;
    private const int MaxRuntimeEventNameLength = 32;
    private const int MaxRuntimeNotificationSize = 1024;
    private const int MaxOracleUrlLength = 256;
    private const int MaxOracleFilterLength = 128;
    private const int MaxOracleCallbackLength = 32;
    private const int MaxOracleUserDataLength = 512;
    private const int MinOracleGasForResponse = 10_000_000;
    private const byte ContractManagementContractHashPrefix = 12;
    private const int MaxMultisigPublicKeys = 1024;
    private const int MaxContractCallFlags = NeoCallFlags.All;
    private const int Hash160Length = 20;
    private const int Hash256Length = 32;
    private const long Int32MaxValue = int.MaxValue;
    private const long UInt32MaxValue = uint.MaxValue;
    private const int CompressedPublicKeyLength = 33;
    private const int UncompressedPublicKeyLength = 65;
    private const int Ed25519PublicKeyLength = 32;
    private const int SignatureLength = 64;
    private const int RecoverSecp256K1SignatureLength = 65;
    private const int StdLibMaxInputLength = 1024;
    // JavaScript Number.MAX_SAFE_INTEGER (2^53 - 1) — the bound Neo's StdLib.jsonSerialize enforces.
    private static readonly BigInteger JsonMaxSafeInteger = 9007199254740991L;
    private const int MaxRuntimeLoadScriptDepth = 4;
    private const int MaxContractSelfCallDepth = 8;
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string SerializedStackItemSummaryOp = "neo.stackitem.serialized";
    private const string JsonStackItemSummaryOp = "neo.stackitem.json";
    private const string SerializedSummaryNilOp = "neo.stackitem.nil";
    private const string SerializedSummaryConsOp = "neo.stackitem.cons";
    private const string SerializedSummaryNullOp = "neo.stackitem.null";
    private const string SerializedSummaryBoolOp = "neo.stackitem.bool";
    private const string SerializedSummaryIntOp = "neo.stackitem.int";
    private const string SerializedSummaryBytesOp = "neo.stackitem.bytes";
    private const string SerializedSummaryBufferOp = "neo.stackitem.buffer";
    private const string SerializedSummaryArrayOp = "neo.stackitem.array";
    private const string SerializedSummaryStructOp = "neo.stackitem.struct";
    private const string SerializedSummaryMapOp = "neo.stackitem.map";
    private const string SerializedSummaryPairOp = "neo.stackitem.pair";
    private const string RuntimeCallingScriptHashKey = "runtime:calling_script_hash";
    private const string RuntimeExecutingScriptHashKey = "runtime:executing_script_hash";
    private const string RuntimeContractSelfCallDepthKey = "runtime:contract_self_call_depth";
    private const string RuntimeLoadScriptDepthKey = "runtime:loadscript_depth";
    private const int FindOptionsKeysOnly = 1 << 0;
    private const int FindOptionsRemovePrefix = 1 << 1;
    private const int FindOptionsValuesOnly = 1 << 2;
    private const int FindOptionsDeserializeValues = 1 << 3;
    private const int FindOptionsPickField0 = 1 << 4;
    private const int FindOptionsPickField1 = 1 << 5;
    private const int FindOptionsBackwards = 1 << 7;
    private const int FindOptionsAll =
        FindOptionsKeysOnly
        | FindOptionsRemovePrefix
        | FindOptionsValuesOnly
        | FindOptionsDeserializeValues
        | FindOptionsPickField0
        | FindOptionsPickField1
        | FindOptionsBackwards;
    private const int MaxNeoVmIntegerBytes = 32;
    private const int MaxVarIntBytes = 9;
    private static readonly int[] ValidFindOptionsValues = BuildValidFindOptionsValues();
    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static string NextAuthResultSymbol(
        ExecutionState state,
        string prefix,
        int offset,
        Func<ExecutionState, int> occurrenceCounter)
    {
        int occurrence = occurrenceCounter(state);
        return occurrence == 0
            ? $"{prefix}_{offset}"
            : $"{prefix}_{offset}_{occurrence}";
    }

    private readonly record struct NativeTokenInfo(
        string Name,
        string Symbol,
        string SymbolLower,
        int Decimals,
        long? FixedTotalSupply)
    {
        public static NativeTokenInfo Neo { get; } =
            new("neo", "NEO", "neo", 0, 100_000_000);

        public static NativeTokenInfo Gas { get; } =
            new("gas", "GAS", "gas", 8, null);
    }

    private IEnumerable<ExecutionState> HandleSyscall(ExecutionState state, Instruction inst)
    {
        // Operand is a 4-byte little-endian syscall hash (per Neo N3).
        if (inst.Operand.Length != 4)
            throw new VmFaultException("SYSCALL requires 4-byte operand");
        uint hash = BinaryPrimitives.ReadUInt32LittleEndian(inst.Operand.Span);
        var syscall = SyscallRegistry.Lookup(hash);

        if (syscall is null)
        {
            AddUnknownSyscall(state, inst.Offset);
            state.Terminate(
                TerminalStatus.Stopped,
                $"unknown syscall hash 0x{hash:X8} at 0x{inst.Offset:X4}");
            return Single(state);
        }

        // Audit C# #6 fix: accumulate per-syscall gas so GasExhaustionDetector has data to act on.
        state.Telemetry.GasCost += syscall.Price;
        ValidateCurrentCallFlags(state, syscall);
        return DispatchSyscall(state, inst, syscall);
    }

    private IEnumerable<ExecutionState> DispatchSyscall(ExecutionState state, Instruction inst, SyscallDescriptor descriptor)
    {
        switch (descriptor.Name)
        {
            case "System.Runtime.Platform":
                {
                    state.Push(SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("NEO")));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetTrigger":
                {
                    state.Push(SymbolicValue.Int(state.RuntimeTrigger));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetInvocationCounter":
                {
                    // Review fix (#13): the invocation counter is the number of times THIS contract
                    // has been entered in the current execution. At a fresh top-level analysis entry
                    // that count is unknowable (the contract may be the outermost call or already
                    // re-entered), so a concrete 1 wrongly prunes re-entrancy-guard branches such as
                    // `if (Runtime.InvocationCounter > 1) abort`. Model the top-level count as a
                    // path-stable nondeterministic base >= 1, then add the modeled self-call depth so
                    // the deterministic increment across self-calls is preserved (callee == caller+1)
                    // while both guard branches stay feasible at entry.
                    int selfCallDepth = GetContractSelfCallDepth(state);
                    var invocationBase = StableRuntimeInt(state, "invocation_counter_base", min: 1);
                    state.Push(selfCallDepth == 0
                        ? invocationBase
                        : SymbolicValue.Of(Expr.Add(invocationBase.Expression, Expr.Int(selfCallDepth))));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GasLeft":
                {
                    state.Push(RuntimeInt(state, "gas_left", inst.Offset, min: 0));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetNetwork":
                {
                    state.Push(StableRuntimeInt(state, "network", min: 0, max: uint.MaxValue));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetAddressVersion":
                {
                    state.Push(StableRuntimeInt(state, "address_version", min: 0, max: 255));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.BurnGas":
                {
                    var gas = state.Pop();
                    if (Expr.ConcreteInt(gas.Expression) is { } amount)
                    {
                        if (amount.Sign <= 0)
                            throw new VmFaultException($"BurnGas with non-positive amount {amount}");
                        // Round-3 audit fix: Runtime.BurnGas takes a `long` datoshi parameter, so an
                        // amount above long.MaxValue faults at argument binding on the real VM.
                        if (amount > long.MaxValue)
                            throw new VmFaultException($"BurnGas amount {amount} exceeds the long datoshi range");
                    }
                    else
                    {
                        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                            inst.Offset,
                            "BurnGas",
                            Expr.Le(gas.Expression, Expr.Int(0)),
                            "BurnGas amount is non-positive",
                            "VM syscall precondition holds under requires"));
                    }
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.CurrentSigners":
                {
                    state.Push(StableRuntimeValue(
                        state,
                        "runtime:current_signers",
                        () => BuildSignerArray(state, "current_signer", minCount: 1)));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetScriptContainer":
                {
                    state.Push(StableRuntimeValue(
                        state,
                        "runtime:script_container",
                        () => BuildScriptContainerTransaction(state)));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.CheckWitness":
                {
                    var target = state.Pop();
                    EnforceCheckWitnessTarget(state, inst, target);
                    string resultSymbol = NextAuthResultSymbol(
                        state,
                        "witness_ok",
                        inst.Offset,
                        s => s.Telemetry.WitnessCheckOps.Count(op => op.Offset == inst.Offset));
                    state.Telemetry.WitnessChecks.Add(inst.Offset);
                    state.Telemetry.WitnessCheckOps.Add(new WitnessCheckOp(inst.Offset, target, resultSymbol));
                    state.Push(SymbolicValue.Symbol(Sort.Bool, resultSymbol));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetCallingScriptHash":
                {
                    return PushStableNullableCallingScriptHash(state, inst);
                }
            case "System.Runtime.GetExecutingScriptHash":
                {
                    state.Push(ExecutingScriptHash(state));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetEntryScriptHash":
                {
                    state.Push(StableRuntimeBytes(state, "entry_script_hash", exactLength: Hash160Length));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetTime":
                {
                    state.Telemetry.TimeAccesses.Add(inst.Offset);
                    if (state.RuntimeTrigger != NeoTriggerTypes.Application)
                    {
                        throw new VmFaultException(
                            "System.Runtime.GetTime can only be called with Application trigger");
                    }

                    state.Push(StableRuntimeInt(state, "timestamp", min: 0));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetRandom":
                {
                    state.Telemetry.RandomnessAccesses.Add(inst.Offset);
                    state.Push(FreshRuntimeInt(state, "random", inst.Offset, min: 0));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.Notify":
                {
                    var args = state.Pop();
                    var name = state.Pop();
                    EnforceRuntimeNotifyEventName(state, inst, name);
                    EnforceRuntimeNotifyPayloadSize(state, inst, args);
                    state.Telemetry.EventsEmitted.Add(inst.Offset);
                    state.Telemetry.Notifications.Add(new RuntimeNotification(
                        inst.Offset,
                        CurrentExecutingScriptHashValue(state),
                        name,
                        args,
                        TryGetConcreteUtf8(name)));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetNotifications":
                {
                    var filter = state.Pop();
                    if (filter.AsConcreteBytes() is { } bytes && bytes.Length != 20)
                        throw new VmFaultException($"GetNotifications requires a 20-byte script hash, got {bytes.Length}");

                    if (!TryFilterRuntimeNotifications(state, filter, out var filteredNotifications))
                    {
                        state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                        state.Push(SymbolicValue.Symbol(Sort.Array, $"System.Runtime.GetNotifications_ret_{inst.Offset}"));
                        state.Pc = inst.EndOffset;
                        return Single(state);
                    }

                    state.Heap.EnforceCollectionGrowth(filteredNotifications.Count);
                    var notificationRefs = new List<SymbolicValue>(filteredNotifications.Count);
                    foreach (var notification in filteredNotifications)
                    {
                        var item = state.Heap.NewStruct(new[]
                        {
                            notification.ScriptHash,
                            notification.Name,
                            notification.State,
                        });
                        notificationRefs.Add(SymbolicValue.HeapRef(Sort.Struct, item.Id));
                    }

                    var notifications = state.Heap.NewArray(notificationRefs);
                    state.Push(SymbolicValue.HeapRef(Sort.Array, notifications.Id));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.LoadScript":
                {
                    var args = state.Pop();
                    var callFlags = state.Pop();
                    var script = state.Pop();
                    EnforceCallFlagsRange(state, inst, "Runtime.LoadScript", callFlags);
                    if (TryExecuteRuntimeLoadScript(state, inst, script, callFlags, args, out var modeled))
                        return modeled;
                    return ModelRuntimeLoadScriptAsExternal(state, inst, script, callFlags, args);
                }
            case "System.Runtime.Log":
                {
                    var message = state.Pop();
                    EnforceRuntimeLogMessage(state, inst, message);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.GetContext":
            case "System.Storage.GetReadOnlyContext":
                {
                    bool ro = descriptor.Name == "System.Storage.GetReadOnlyContext";
                    state.Push(SymbolicValue.Symbol(Sort.InteropInterface, $"storage_ctx_{(ro ? "ro_" : "")}{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.AsReadOnly":
                {
                    var ctx = state.Pop();
                    ValidateStorageContext(state, inst, "Storage.AsReadOnly", ctx, out _, out _);
                    state.Push(SymbolicValue.Symbol(Sort.InteropInterface, $"storage_ctx_ro_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Get":
                {
                    var key = state.Pop();
                    var ctx = state.Pop();
                    ValidateStorageContext(state, inst, "Storage.Get", ctx, out bool ro, out bool contextDynamic);
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Get", normalizedKey, "key");
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Get, normalizedKey, null,
                        ContextDynamic: contextDynamic, ContextReadOnly: ro));
                    if (!contextDynamic && TryGetPathLocalStorageValue(state, normalizedKey.Expression, out var stored))
                    {
                        state.Push(stored);
                        state.Pc = inst.EndOffset;
                        return Single(state);
                    }

                    state.Pc = inst.EndOffset;
                    return ForkUnknownStorageGet(state, inst, contextDynamic ? null : normalizedKey.Expression);
                }
            case "System.Storage.Local.Get":
                {
                    var key = state.Pop();
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Local.Get", normalizedKey, "key");
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Get, normalizedKey, null,
                        ContextDynamic: false, ContextReadOnly: false));
                    if (TryGetPathLocalStorageValue(state, normalizedKey.Expression, out var stored))
                    {
                        state.Push(stored);
                        state.Pc = inst.EndOffset;
                        return Single(state);
                    }

                    state.Pc = inst.EndOffset;
                    return ForkUnknownStorageGet(state, inst, normalizedKey.Expression);
                }
            case "System.Storage.Put":
                {
                    var value = state.Pop();
                    var key = state.Pop();
                    var ctx = state.Pop();
                    ValidateStorageContext(state, inst, "Storage.Put", ctx, out bool ro, out bool contextDynamic);
                    if (ro) throw new VmFaultException("Storage.Put on read-only context");
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageKeyLength(state, inst, "Storage.Put", normalizedKey);
                    EnforceStorageValueLength(state, inst, "Storage.Put", value);
                    var storedValue = NormalizeStorageBytes(state, value);
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Put, normalizedKey, value,
                        ContextDynamic: contextDynamic, ContextReadOnly: false));
                    if (!contextDynamic)
                        state.StorageValues[normalizedKey.Expression] = storedValue;
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Local.Put":
                {
                    var value = state.Pop();
                    var key = state.Pop();
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageKeyLength(state, inst, "Storage.Local.Put", normalizedKey);
                    EnforceStorageValueLength(state, inst, "Storage.Local.Put", value);
                    var storedValue = NormalizeStorageBytes(state, value);
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Put, normalizedKey, value,
                        ContextDynamic: false, ContextReadOnly: false));
                    state.StorageValues[normalizedKey.Expression] = storedValue;
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Delete":
                {
                    var key = state.Pop();
                    var ctx = state.Pop();
                    ValidateStorageContext(state, inst, "Storage.Delete", ctx, out bool ro, out bool contextDynamic);
                    if (ro) throw new VmFaultException("Storage.Delete on read-only context");
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Delete", normalizedKey, "key");
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Delete, normalizedKey, null,
                        ContextDynamic: contextDynamic, ContextReadOnly: false));
                    if (!contextDynamic)
                        state.StorageValues[normalizedKey.Expression] = SymbolicValue.Null();
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Local.Delete":
                {
                    var key = state.Pop();
                    var normalizedKey = NormalizeStorageKey(state, key);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Local.Delete", normalizedKey, "key");
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Delete, normalizedKey, null,
                        ContextDynamic: false, ContextReadOnly: false));
                    state.StorageValues[normalizedKey.Expression] = SymbolicValue.Null();
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Find":
                {
                    var options = state.Pop();
                    var prefix = state.Pop();
                    var ctx = state.Pop();
                    ValidateStorageContext(state, inst, "Storage.Find", ctx, out bool ro, out bool contextDynamic);
                    var normalizedPrefix = NormalizeStorageKey(state, prefix);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Find", normalizedPrefix, "prefix");
                    EnforceFindOptions(state, inst, "Storage.Find", options);
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Find, normalizedPrefix, null,
                        ContextDynamic: contextDynamic, ContextReadOnly: ro));
                    var iterator = SymbolicValue.Symbol(Sort.InteropInterface, $"iterator_{inst.Offset}");
                    RememberIteratorFind(state, iterator, normalizedPrefix, options,
                        contextDynamic ? System.Array.Empty<(SymbolicValue Key, SymbolicValue Value)>()
                            : FindPathLocalStorageEntries(state, normalizedPrefix));
                    state.Push(iterator);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Local.Find":
                {
                    var options = state.Pop();
                    var prefix = state.Pop();
                    var normalizedPrefix = NormalizeStorageKey(state, prefix);
                    EnforceStorageByteLikeOperand(state, inst, "Storage.Local.Find", normalizedPrefix, "prefix");
                    EnforceFindOptions(state, inst, "Storage.Local.Find", options);
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Find, normalizedPrefix, null,
                        ContextDynamic: false, ContextReadOnly: false));
                    var iterator = SymbolicValue.Symbol(Sort.InteropInterface, $"iterator_{inst.Offset}");
                    RememberIteratorFind(state, iterator, normalizedPrefix, options,
                        FindPathLocalStorageEntries(state, normalizedPrefix));
                    state.Push(iterator);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Iterator.Next":
                {
                    var iterator = state.Pop();
                    state.Telemetry.IteratorLoops.Add(inst.Offset);
                    return ForkIteratorNext(state, inst, iterator);
                }
            case "System.Iterator.Value":
                {
                    var iterator = state.Pop();
                    state.Push(BuildIteratorValue(state, inst, iterator));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Crypto.CheckSig":
                {
                    var signature = state.Pop();
                    var pubKey = state.Pop();
                    EnforcePublicKeyEncoding(state, inst, "CheckSig", pubKey);
                    EnforceSignatureLength(state, inst, "CheckSig", signature);
                    string resultSymbol = NextAuthResultSymbol(
                        state,
                        "sig_ok",
                        inst.Offset,
                        s => s.Telemetry.SignatureCheckOps.Count(op => op.Offset == inst.Offset));
                    state.Telemetry.SignatureChecks.Add(inst.Offset);
                    state.Telemetry.SignatureCheckOps.Add(new SignatureCheckOp(
                        inst.Offset,
                        pubKey,
                        signature,
                        resultSymbol,
                        IsMultisig: false));
                    state.Push(SymbolicValue.Symbol(Sort.Bool, resultSymbol));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Crypto.CheckMultisig":
                {
                    var signatures = state.Pop();
                    var pubKeys = state.Pop();
                    EnforceCheckMultisigArguments(state, inst, pubKeys, signatures);
                    string resultSymbol = NextAuthResultSymbol(
                        state,
                        "multisig_ok",
                        inst.Offset,
                        s => s.Telemetry.SignatureCheckOps.Count(op => op.Offset == inst.Offset));
                    state.Telemetry.SignatureChecks.Add(inst.Offset);
                    state.Telemetry.SignatureCheckOps.Add(new SignatureCheckOp(
                        inst.Offset,
                        pubKeys,
                        signatures,
                        resultSymbol,
                        IsMultisig: true));
                    state.Push(SymbolicValue.Symbol(Sort.Bool, resultSymbol));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Contract.Call":
                return HandleContractCall(state, inst);
            case "System.Contract.CallNative":
                return HandleContractCallNative(state, inst);
            case "System.Contract.GetCallFlags":
                {
                    state.Push(SymbolicValue.Int(state.CurrentCallFlags));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Contract.CreateStandardAccount":
                {
                    var pubKey = state.Pop();
                    EnforcePublicKeyEncoding(state, inst, "CreateStandardAccount", pubKey);
                    state.Push(SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "standard_account", pubKey.Expression),
                        pubKey.Taints));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Contract.CreateMultisigAccount":
                {
                    var pubKeys = state.Pop();
                    var m = state.Pop();
                    if (pubKeys.IsConcreteNull)
                        throw new VmFaultException("CreateMultisigAccount with null public keys");
                    if (pubKeys.Expression is not HeapRef pubKeysRef
                        || state.Heap.Get(pubKeysRef.ObjectId) is not ArrayObject pubKeysArray)
                    {
                        state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                        state.Push(SymbolicValue.Of(
                            new BinaryExpr(Sort.Bytes, "multisig_account", m.Expression, pubKeys.Expression),
                            m.Taints.Union(pubKeys.Taints)));
                        state.Pc = inst.EndOffset;
                        return Single(state);
                    }
                    // Round-2 fix: an open (symbolic-length) public-key array has an unknown true count,
                    // so the seeded-prefix Items.Count would drive the MaxMultisigPublicKeys bound and the
                    // threshold-vs-count fault condition with a wrong length (false negative / unsound
                    // Proved). Terminate as a modeling limit, as the open-collection opcodes do.
                    if (pubKeysArray.IsSymbolicOpen)
                        throw new ModelingLimitException(
                            "CreateMultisigAccount over open symbolic public-key array of unknown length not modeled");
                    int publicKeyCount = pubKeysArray.Items.Count;
                    if (publicKeyCount > MaxMultisigPublicKeys)
                        throw new VmFaultException(
                            $"CreateMultisigAccount with {publicKeyCount} public keys exceeds {MaxMultisigPublicKeys}");
                    if (Expr.ConcreteInt(m.Expression) is { } threshold && threshold < 1)
                        throw new VmFaultException($"CreateMultisigAccount with invalid threshold {threshold}");
                    if (Expr.ConcreteInt(m.Expression) is { } concreteThreshold && concreteThreshold > publicKeyCount)
                        throw new VmFaultException(
                            $"CreateMultisigAccount threshold {concreteThreshold} exceeds public key count {publicKeyCount}");
                    foreach (var pubKey in pubKeysArray.Items)
                        EnforcePublicKeyEncoding(state, inst, "CreateMultisigAccount", pubKey);
                    if (Expr.ConcreteInt(m.Expression) is null)
                    {
                        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                            inst.Offset,
                            "CreateMultisigAccount",
                            Expr.BoolOr(
                                Expr.Lt(m.Expression, Expr.Int(1)),
                                Expr.Gt(m.Expression, Expr.Int(publicKeyCount))),
                            $"threshold must be between 1 and public key count {publicKeyCount}",
                            "VM syscall precondition holds under requires"));
                    }
                    state.Push(SymbolicValue.Of(
                        new BinaryExpr(Sort.Bytes, "multisig_account", m.Expression, pubKeys.Expression),
                        m.Taints.Union(pubKeys.Taints)));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Contract.NativeOnPersist":
            case "System.Contract.NativePostPersist":
                {
                    throw new VmFaultException($"{descriptor.Name} is an internal native-contract hook and requires the matching system trigger");
                }

            default:
                // Modeled descriptor with no specific handler — push a sort-typed symbol if the
                // descriptor declares a return value, otherwise nothing. It is still unmodeled
                // proof surface, so mark it incomplete for formal verification/reporting.
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                for (int i = 0; i < descriptor.PopArgs; i++)
                    state.Pop();
                if (descriptor.HasReturnValue)
                    state.Push(SymbolicValue.Symbol(Sort.Unknown, $"{descriptor.Name}_ret_{inst.Offset}"));
                state.Pc = inst.EndOffset;
                return Single(state);
        }
    }

    private bool TryExecuteRuntimeLoadScript(
        ExecutionState state,
        Instruction inst,
        SymbolicValue script,
        SymbolicValue callFlags,
        SymbolicValue args,
        out IEnumerable<ExecutionState> modeled)
    {
        modeled = System.Array.Empty<ExecutionState>();
        if (script.AsConcreteBytes() is not { } scriptBytes)
            return false;
        if (callFlags.AsConcreteInt() is not { } concreteCallFlags)
            return false;
        if (!TryGetRuntimeLoadScriptArguments(state, args, out var argumentValues))
            return false;

        int depth = GetRuntimeLoadScriptDepth(state);
        if (depth >= MaxRuntimeLoadScriptDepth)
            return false;

        int effectiveCallFlags = (int)concreteCallFlags & state.CurrentCallFlags & NeoCallFlags.ReadOnly;
        var nestedProgram = ScriptDecoder.Decode(scriptBytes);
        var nestedInitial = state.Clone();
        var callerStack = new List<SymbolicValue>(state.EvaluationStack);
        var callerExecutingHash = RuntimeLoadScriptCallerHash(state);
        var nestedExecutingHash = SymbolicValue.Bytes(ComputeScriptHash(scriptBytes));
        int callerSteps = state.Steps;
        PrepareRuntimeLoadScriptEntry(
            nestedInitial,
            argumentValues,
            effectiveCallFlags,
            depth + 1,
            callerExecutingHash,
            nestedExecutingHash);

        var nestedOptions = _options with
        {
            InitialCallFlags = effectiveCallFlags,
            MaxSteps = System.Math.Max(1, _options.MaxSteps - callerSteps),
        };
        var nestedResult = new SymbolicEngine(nestedProgram, nestedOptions).Run(nestedInitial);
        var continuations = new List<ExecutionState>(nestedResult.FinalStates.Length);
        foreach (var nestedFinal in nestedResult.FinalStates)
        {
            nestedFinal.Steps += callerSteps;
            if (nestedFinal.Status == TerminalStatus.Halted)
            {
                var returnStack = new List<SymbolicValue>(nestedFinal.EvaluationStack);
                nestedFinal.Status = TerminalStatus.Running;
                nestedFinal.TerminationReason = null;
                nestedFinal.Pc = inst.EndOffset;
                nestedFinal.EvaluationStack.Clear();
                nestedFinal.EvaluationStack.AddRange(callerStack);
                nestedFinal.EvaluationStack.AddRange(returnStack);
                RestoreRuntimeLoadScriptDepth(nestedFinal, depth);
            }
            continuations.Add(nestedFinal);
        }

        modeled = continuations;
        return true;
    }

    private static IEnumerable<ExecutionState> ModelRuntimeLoadScriptAsExternal(
        ExecutionState state,
        Instruction inst,
        SymbolicValue script,
        SymbolicValue callFlags,
        SymbolicValue args)
    {
        var ext = new ExternalCall
        {
            Offset = inst.Offset,
            Method = "Runtime.LoadScript",
            MethodArg = script,
            TargetHashDynamic = true,
            MethodDynamic = true,
            CallFlags = callFlags.AsConcreteInt() is { } cf
                ? (int)cf & state.CurrentCallFlags & NeoCallFlags.ReadOnly
                : 0,
            CallFlagsDynamic = !callFlags.IsConcrete,
            HasReturnValue = true,
        };
        AddRuntimeLoadScriptArguments(state, args, ext.Args);
        state.Telemetry.ExternalCalls.Add(ext);
        state.Push(SymbolicValue.Symbol(Sort.Unknown, $"ext_ret_{inst.Offset}"));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static void PrepareRuntimeLoadScriptEntry(
        ExecutionState nestedState,
        IReadOnlyList<SymbolicValue> args,
        int effectiveCallFlags,
        int depth,
        SymbolicValue callerExecutingHash,
        SymbolicValue nestedExecutingHash)
    {
        nestedState.Pc = 0;
        nestedState.Steps = 0;
        nestedState.VisitCounts.Clear();
        nestedState.EvaluationStack.Clear();
        nestedState.CallStack.Clear();
        nestedState.CallStack.Add(new CallFrame(returnPc: -1));
        nestedState.StaticFields.Clear();
        nestedState.CurrentCallFlags = effectiveCallFlags;
        nestedState.InteropContext[RuntimeCallingScriptHashKey] = callerExecutingHash;
        nestedState.InteropContext[RuntimeExecutingScriptHashKey] = nestedExecutingHash;
        nestedState.InteropContext[RuntimeLoadScriptDepthKey] = SymbolicValue.Int(depth);
        for (int i = args.Count - 1; i >= 0; i--)
            nestedState.Push(args[i]);
    }

    private SymbolicValue RuntimeLoadScriptCallerHash(ExecutionState state)
    {
        if (state.InteropContext.TryGetValue(RuntimeExecutingScriptHashKey, out var existing))
            return existing;

        if (TryGetConfiguredCurrentScriptHash(out var configured))
        {
            var value = SymbolicValue.Bytes(configured);
            state.InteropContext[RuntimeExecutingScriptHashKey] = value;
            return value;
        }

        return SymbolicValue.Bytes(ComputeScriptHash(_program.Bytes.ToArray()));
    }

    private static byte[] ComputeScriptHash(byte[] script)
    {
        byte[] sha256 = System.Security.Cryptography.SHA256.HashData(script);
        return ComputeDigest(new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest(), sha256);
    }

    private static bool TryGetRuntimeLoadScriptArguments(
        ExecutionState state,
        SymbolicValue args,
        out IReadOnlyList<SymbolicValue> argumentValues)
    {
        if (args.Expression is HeapRef href && state.Heap.Get(href.ObjectId) is ArrayObject arr)
        {
            if (arr.IsSymbolicOpen)
            {
                argumentValues = System.Array.Empty<SymbolicValue>();
                return false;
            }

            argumentValues = arr.Items;
            return true;
        }

        argumentValues = System.Array.Empty<SymbolicValue>();
        return false;
    }

    private static void AddRuntimeLoadScriptArguments(
        ExecutionState state,
        SymbolicValue args,
        List<SymbolicValue> target)
    {
        if (TryGetRuntimeLoadScriptArguments(state, args, out var argumentValues))
        {
            foreach (var arg in argumentValues)
                target.Add(arg);
        }
        else
        {
            target.Add(args);
        }
    }

    private static int GetRuntimeLoadScriptDepth(ExecutionState state)
    {
        if (state.InteropContext.TryGetValue(RuntimeLoadScriptDepthKey, out var value)
            && value.AsConcreteInt() is { } depth
            && depth >= 0
            && depth <= int.MaxValue)
        {
            return (int)depth;
        }

        return 0;
    }

    private static void RestoreRuntimeLoadScriptDepth(ExecutionState state, int depth)
    {
        if (depth <= 0)
            state.InteropContext.Remove(RuntimeLoadScriptDepthKey);
        else
            state.InteropContext[RuntimeLoadScriptDepthKey] = SymbolicValue.Int(depth);
    }

    private static void ValidateCurrentCallFlags(ExecutionState state, SyscallDescriptor descriptor)
    {
        ValidateCurrentCallFlags(state, descriptor.Name, descriptor.RequiredCallFlags);
    }

    private static void ValidateCurrentCallFlags(ExecutionState state, string operation, int requiredCallFlags)
    {
        if (requiredCallFlags == NeoCallFlags.None)
            return;

        if ((state.CurrentCallFlags & requiredCallFlags) == requiredCallFlags)
            return;

        int missing = requiredCallFlags & ~state.CurrentCallFlags;
        throw new VmFaultException(
            $"{operation} requires current call flags {FormatCallFlags(requiredCallFlags)}; current flags {FormatCallFlags(state.CurrentCallFlags)} missing {FormatCallFlags(missing)}");
    }

    private static void ValidateStorageContext(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue context,
        out bool readOnly,
        out bool dynamic)
    {
        readOnly = false;
        dynamic = false;

        if (context.IsConcreteNull)
            throw new VmFaultException($"{operation} requires a StorageContext interop object, got null");

        if (context.Expression is Symbol symbol)
        {
            if (TryClassifyStorageContextSymbol(symbol.Name, out readOnly))
                return;

            if (context.Sort is Sort.InteropInterface or Sort.Unknown)
            {
                dynamic = true;
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return;
            }
        }

        if (context.Expression is HeapRef { RefSort: Sort.InteropInterface } href
            && state.Heap.Get(href.ObjectId) is InteropObject interop)
        {
            throw new VmFaultException(
                $"{operation} requires a StorageContext interop object, got {interop.Kind} InteropInterface");
        }

        throw new VmFaultException($"{operation} requires a StorageContext interop object");
    }

    private static bool TryClassifyStorageContextSymbol(string name, out bool readOnly)
    {
        if (name.StartsWith("storage_ctx_ro_", System.StringComparison.Ordinal))
        {
            readOnly = true;
            return true;
        }

        if (name.StartsWith("storage_ctx_", System.StringComparison.Ordinal))
        {
            readOnly = false;
            return true;
        }

        readOnly = false;
        return false;
    }

    private static string FormatCallFlags(int flags)
    {
        if (flags == NeoCallFlags.None)
            return "None";

        var names = new List<string>();
        if ((flags & NeoCallFlags.ReadStates) != 0) names.Add("ReadStates");
        if ((flags & NeoCallFlags.WriteStates) != 0) names.Add("WriteStates");
        if ((flags & NeoCallFlags.AllowCall) != 0) names.Add("AllowCall");
        if ((flags & NeoCallFlags.AllowNotify) != 0) names.Add("AllowNotify");
        int unknown = flags & ~NeoCallFlags.All;
        if (unknown != 0) names.Add($"0x{unknown:X}");
        return string.Join("|", names);
    }

    private static SymbolicValue RuntimeInt(
        ExecutionState state,
        string name,
        int offset,
        long? min = null,
        long? max = null)
    {
        var value = SymbolicValue.Symbol(Sort.Int, $"{name}_{offset}");
        if (min is { } lower)
            state.PathConditions = state.PathConditions.Add(Expr.Ge(value.Expression, Expr.Int(lower)));
        if (max is { } upper)
            state.PathConditions = state.PathConditions.Add(Expr.Le(value.Expression, Expr.Int(upper)));
        return value;
    }

    private static SymbolicValue FreshRuntimeInt(
        ExecutionState state,
        string name,
        int offset,
        long? min = null,
        long? max = null)
    {
        var value = SymbolicValue.Symbol(Sort.Int, state.NextFreshSymbolName($"{name}_{offset}"));
        if (min is { } lower)
            state.PathConditions = state.PathConditions.Add(Expr.Ge(value.Expression, Expr.Int(lower)));
        if (max is { } upper)
            state.PathConditions = state.PathConditions.Add(Expr.Le(value.Expression, Expr.Int(upper)));
        return value;
    }

    private static SymbolicValue StableRuntimeInt(
        ExecutionState state,
        string name,
        long? min = null,
        long? max = null)
    {
        var value = StableRuntimeValue(
            state,
            $"runtime:{name}",
            () => SymbolicValue.Symbol(Sort.Int, name));
        if (min is { } lower)
            state.PathConditions = state.PathConditions.Add(Expr.Ge(value.Expression, Expr.Int(lower)));
        if (max is { } upper)
            state.PathConditions = state.PathConditions.Add(Expr.Le(value.Expression, Expr.Int(upper)));
        return value;
    }

    private static SymbolicValue StableLedgerCurrentIndex(ExecutionState state) =>
        StableRuntimeInt(state, "ledger_current_index", min: 0, max: UInt32MaxValue);

    private static SymbolicValue StableRuntimeBytes(
        ExecutionState state,
        string name,
        int? exactLength = null,
        int? minLength = null,
        int? maxLength = null)
    {
        var value = StableRuntimeValue(
            state,
            $"runtime:{name}",
            () => SymbolicValue.Symbol(Sort.Bytes, name));
        var size = new UnaryExpr(Sort.Int, "size", value.Expression);
        if (exactLength is { } exact)
        {
            state.PathConditions = state.PathConditions.Add(Expr.Eq(size, Expr.Int(exact)));
            return value;
        }

        if (minLength is { } lower)
            state.PathConditions = state.PathConditions.Add(Expr.Ge(size, Expr.Int(lower)));
        if (maxLength is { } upper)
            state.PathConditions = state.PathConditions.Add(Expr.Le(size, Expr.Int(upper)));
        return value;
    }

    private static SymbolicValue StableRuntimeEcPoint(ExecutionState state, string name)
    {
        var value = StableRuntimeBytes(state, name, exactLength: CompressedPublicKeyLength);
        state.PathConditions = state.PathConditions.Add(Expr.IsValidEcPoint(value.Expression));
        return value;
    }

    private static IEnumerable<ExecutionState> PushStableNullableCallingScriptHash(
        ExecutionState state,
        Instruction inst)
    {
        if (state.InteropContext.TryGetValue(RuntimeCallingScriptHashKey, out var existing))
        {
            state.Push(existing);
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        var callerValue = SymbolicValue.Symbol(Sort.Bytes, "calling_script_hash");
        var callerState = state.Clone();
        callerState.InteropContext[RuntimeCallingScriptHashKey] = callerValue;
        callerState.PathConditions = callerState.PathConditions.Add(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", callerValue.Expression),
            Expr.Int(Hash160Length)));
        callerState.Push(callerValue);
        callerState.Pc = inst.EndOffset;

        state.InteropContext[RuntimeCallingScriptHashKey] = SymbolicValue.Null();
        state.Push(SymbolicValue.Null());
        state.Pc = inst.EndOffset;
        return new[] { callerState, state };
    }

    private static SymbolicValue StableRuntimeValue(
        ExecutionState state,
        string key,
        System.Func<SymbolicValue> create)
    {
        if (!state.InteropContext.TryGetValue(key, out var value))
        {
            value = create();
            state.InteropContext[key] = value;
        }

        return value;
    }

    private SymbolicValue ExecutingScriptHash(ExecutionState state)
    {
        if (state.InteropContext.TryGetValue(RuntimeExecutingScriptHashKey, out var existing))
            return existing;

        if (TryGetConfiguredCurrentScriptHash(out var configured))
        {
            var value = SymbolicValue.Bytes(configured);
            state.InteropContext[RuntimeExecutingScriptHashKey] = value;
            return value;
        }

        return StableRuntimeBytes(state, "executing_script_hash", exactLength: Hash160Length);
    }

    private bool TryGetConfiguredCurrentScriptHash(out byte[] scriptHash)
    {
        if (!_options.CurrentScriptHash.IsDefaultOrEmpty
            && _options.CurrentScriptHash.Length == Hash160Length)
        {
            scriptHash = _options.CurrentScriptHash.ToArray();
            return true;
        }

        scriptHash = System.Array.Empty<byte>();
        return false;
    }

    private static SymbolicValue BuildSignerArray(
        ExecutionState state,
        string signerPrefix,
        int minCount)
    {
        var allowedContracts = state.Heap.NewArray(isSymbolicOpen: true, minCount: 0);
        var allowedGroups = state.Heap.NewArray(isSymbolicOpen: true, minCount: 0);
        var rules = state.Heap.NewArray(isSymbolicOpen: true, minCount: 0);
        var signer = state.Heap.NewStruct(new[]
        {
            StableRuntimeBytes(state, $"{signerPrefix}_0_account", exactLength: Hash160Length),
            StableRuntimeInt(state, $"{signerPrefix}_0_scopes", min: 0, max: 0xF1),
            SymbolicValue.HeapRef(Sort.Array, allowedContracts.Id),
            SymbolicValue.HeapRef(Sort.Array, allowedGroups.Id),
            SymbolicValue.HeapRef(Sort.Array, rules.Id),
        });
        var signers = state.Heap.NewArray(
            new[] { SymbolicValue.HeapRef(Sort.Struct, signer.Id) },
            isSymbolicOpen: true,
            minCount: minCount);
        return SymbolicValue.HeapRef(Sort.Array, signers.Id);
    }

    private static SymbolicValue BuildScriptContainerTransaction(ExecutionState state)
    {
        return BuildTransactionStruct(
            state,
            StableRuntimeBytes(state, "transaction_hash", exactLength: Hash256Length),
            "transaction");
    }

    private static SymbolicValue BuildTransactionStruct(
        ExecutionState state,
        SymbolicValue transactionHash,
        string fieldPrefix)
    {
        var tx = state.Heap.NewStruct(new[]
        {
            transactionHash,
            SymbolicValue.Int(0),
            StableRuntimeInt(state, $"{fieldPrefix}_nonce", min: 0),
            StableRuntimeBytes(state, $"{fieldPrefix}_sender", exactLength: Hash160Length),
            StableRuntimeInt(state, $"{fieldPrefix}_system_fee", min: 0),
            StableRuntimeInt(state, $"{fieldPrefix}_network_fee", min: 0),
            StableRuntimeInt(state, $"{fieldPrefix}_valid_until_block", min: 0, max: UInt32MaxValue),
            StableRuntimeBytes(state, $"{fieldPrefix}_script", minLength: 0, maxLength: state.Heap.MaxItemSize),
        });
        return SymbolicValue.HeapRef(Sort.Struct, tx.Id);
    }

    private static SymbolicValue BuildBlockStruct(
        ExecutionState state,
        SymbolicValue blockHash,
        SymbolicValue blockIndex,
        string fieldPrefix)
    {
        var block = state.Heap.NewStruct(new[]
        {
            blockHash,
            StableRuntimeInt(state, $"{fieldPrefix}_version", min: 0),
            StableRuntimeBytes(state, $"{fieldPrefix}_prev_hash", exactLength: Hash256Length),
            StableRuntimeBytes(state, $"{fieldPrefix}_merkle_root", exactLength: Hash256Length),
            StableRuntimeInt(state, $"{fieldPrefix}_timestamp", min: 0),
            StableRuntimeInt(state, $"{fieldPrefix}_nonce", min: 0),
            blockIndex,
            StableRuntimeInt(state, $"{fieldPrefix}_primary_index", min: 0, max: 255),
            StableRuntimeBytes(state, $"{fieldPrefix}_next_consensus", exactLength: Hash160Length),
            StableRuntimeInt(state, $"{fieldPrefix}_transactions_count", min: 0, max: Int32MaxValue),
        });
        return SymbolicValue.HeapRef(Sort.Struct, block.Id);
    }

    private static bool TryFilterRuntimeNotifications(
        ExecutionState state,
        SymbolicValue filter,
        out List<RuntimeNotification> notifications)
    {
        notifications = new List<RuntimeNotification>();
        if (IsWildcardNotificationFilter(filter))
        {
            notifications.AddRange(state.Telemetry.Notifications);
            return true;
        }

        foreach (var notification in state.Telemetry.Notifications)
        {
            if (!TryNotificationMatchesFilter(notification.ScriptHash, filter, out bool matches))
            {
                notifications.Clear();
                return false;
            }

            if (matches)
                notifications.Add(notification);
        }

        return true;
    }

    private static bool TryNotificationMatchesFilter(
        SymbolicValue scriptHash,
        SymbolicValue filter,
        out bool matches)
    {
        if (scriptHash.Expression.Equals(filter.Expression))
        {
            matches = true;
            return true;
        }

        if (scriptHash.AsConcreteBytes() is { Length: Hash160Length } left
            && filter.AsConcreteBytes() is { Length: Hash160Length } right)
        {
            matches = BytesEqual(left, right);
            return true;
        }

        matches = false;
        return false;
    }

    private static bool IsWildcardNotificationFilter(SymbolicValue filter)
    {
        if (filter.IsConcreteNull)
            return true;
        var bytes = filter.AsConcreteBytes();
        if (bytes is null || bytes.Length != 20)
            return false;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != 0)
                return false;
        }
        return true;
    }

    private static string? TryGetConcreteUtf8(SymbolicValue value)
    {
        var bytes = value.AsConcreteBytes();
        if (bytes is null)
            return null;

        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException)
        {
            return null;
        }
    }

    private static SymbolicValue NormalizeStorageKey(ExecutionState state, SymbolicValue key) =>
        ResolveSpliceSourceBytes(state, key) is { } bytes
            ? SymbolicValue.Of(Expr.Bytes(bytes), key.Taints)
            : key;

    private static bool TryGetPathLocalStorageValue(
        ExecutionState state,
        Expression key,
        out SymbolicValue value)
    {
        if (state.StorageValues.TryGetValue(key, out value!))
            return true;

        foreach (var (storedKey, storedValue) in state.StorageValues)
        {
            if (PathConditionsProveStorageKeysEqual(state.PathConditions, key, storedKey))
            {
                value = storedValue;
                return true;
            }
        }

        value = default!;
        return false;
    }

    private static bool PathConditionsProveStorageKeysEqual(
        IEnumerable<Expression> pathConditions,
        Expression left,
        Expression right) =>
        pathConditions.Any(condition => ContainsStorageKeyEquality(condition, left, right));

    private static bool ContainsStorageKeyEquality(Expression condition, Expression left, Expression right) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ContainsStorageKeyEquality(binary.Left, left, right)
                || ContainsStorageKeyEquality(binary.Right, left, right),
            BinaryExpr { Op: "==" } equality =>
                ExpressionsMatch(equality.Left, left, equality.Right, right)
                || ExpressionsMatch(equality.Left, right, equality.Right, left),
            _ => false,
        };

    private static bool ExpressionsMatch(
        Expression actualLeft,
        Expression expectedLeft,
        Expression actualRight,
        Expression expectedRight) =>
        actualLeft.Equals(expectedLeft) && actualRight.Equals(expectedRight);

    private static IEnumerable<ExecutionState> ForkUnknownStorageGet(
        ExecutionState state,
        Instruction inst,
        Expression? pathLocalKey)
    {
        int occurrence = state.UnknownStorageReadCounts.TryGetValue(inst.Offset, out int count)
            ? count
            : 0;
        state.UnknownStorageReadCounts[inst.Offset] = occurrence + 1;
        string occurrenceSuffix = occurrence == 0
            ? ""
            : "_" + occurrence.ToString(System.Globalization.CultureInfo.InvariantCulture);

        var exists = SymbolicValue.Symbol(Sort.Bool, $"storage_exists_{inst.Offset}{occurrenceSuffix}");

        var present = state.Clone();
        present.PathConditions = present.PathConditions.Add(exists.Expression);
        var presentValue = SymbolicValue.Symbol(Sort.Bytes, $"storage_value_{inst.Offset}{occurrenceSuffix}");
        var presentValueSize = StorageByteLengthExpression(presentValue.Expression);
        present.PathConditions = present.PathConditions
            .Add(Expr.Ge(presentValueSize, Expr.Int(0)))
            .Add(Expr.Le(presentValueSize, Expr.Int(MaxStorageValueLength)));
        if (pathLocalKey is not null)
            present.StorageValues[pathLocalKey] = presentValue;
        present.Push(presentValue);

        state.PathConditions = state.PathConditions.Add(Expr.Not(exists.Expression));
        var missingValue = SymbolicValue.Null();
        if (pathLocalKey is not null)
            state.StorageValues[pathLocalKey] = missingValue;
        state.Push(missingValue);

        return new[] { present, state };
    }

    private static void EnforceStorageByteLikeOperand(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue value,
        string operandName)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {operandName}");

        if (value.Sort is Sort.Bytes or Sort.Int or Sort.Bool or Sort.Buffer)
            return;

        if (value.Sort == Sort.Unknown)
        {
            var invalidType = Expr.Sym(
                Sort.Bool,
                state.NextFreshSymbolName($"invalid_storage_{operandName}_type_{inst.Offset}"));
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                operation,
                invalidType,
                $"{operandName} may be a non-byte-like StackItem before Neo storage byte conversion",
                "VM syscall precondition holds under requires"));
            return;
        }

        throw new VmFaultException($"{operation} {operandName} must be byte-like, got {value.Sort}");
    }

    private static void EnforceStorageKeyLength(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue key)
    {
        if (key.IsConcreteNull)
            throw new VmFaultException($"{operation} with null key");

        EnforceStorageByteLikeOperand(state, inst, operation, key, "key");

        if (Expr.CanonicalBytes(key.Expression) is { } bytes)
        {
            if (bytes.Length > MaxStorageKeyLength)
                throw new VmFaultException(
                    $"{operation} key length {bytes.Length} exceeds {MaxStorageKeyLength} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(StorageByteLengthExpression(key.Expression), Expr.Int(MaxStorageKeyLength)),
            $"key length may exceed {MaxStorageKeyLength} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceStorageValueLength(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue value)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null value");

        EnforceStorageByteLikeOperand(state, inst, operation, value, "value");

        var normalizedValue = NormalizeStorageBytes(state, value);
        if (Expr.CanonicalBytes(normalizedValue.Expression) is { } bytes)
        {
            if (bytes.Length > MaxStorageValueLength)
                throw new VmFaultException(
                    $"{operation} value length {bytes.Length} exceeds {MaxStorageValueLength} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(StorageByteLengthExpression(normalizedValue.Expression), Expr.Int(MaxStorageValueLength)),
            $"value length may exceed {MaxStorageValueLength} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static Expression StorageByteLengthExpression(Expression value) =>
        value is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary
            ? Expr.Add(StorageByteLengthExpression(binary.Left), StorageByteLengthExpression(binary.Right))
            : value is UnaryExpr { Sort: Sort.Bytes, Op: "i2b" }
                ? Expr.Int(MaxNeoVmIntegerBytes)
            : value is TernaryExpr { Sort: Sort.Bytes, Op: "ite" } ternary
                ? Expr.Max(StorageByteLengthExpression(ternary.B), StorageByteLengthExpression(ternary.C))
            : value is UnaryExpr { Sort: Sort.Bytes, Op: "standard_account" }
                ? Expr.Int(Hash160Length)
            : value is BinaryExpr { Sort: Sort.Bytes, Op: "multisig_account" }
                ? Expr.Int(Hash160Length)
            : value.Sort == Sort.Int
                ? Expr.Int(MaxNeoVmIntegerBytes)
            : value.Sort == Sort.Bool
                ? Expr.Int(1)
            : new UnaryExpr(Sort.Int, "size", value);

    private static SymbolicValue NormalizeStorageBytes(ExecutionState state, SymbolicValue value)
    {
        if (ResolveSpliceSourceBytes(state, value) is { } bytes)
            return SymbolicValue.Of(Expr.Bytes(bytes), value.Taints);
        return value.Sort switch
        {
            Sort.Int => SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "i2b", value.Expression), value.Taints),
            Sort.Bool => SymbolicValue.Of(
                Expr.Ite(value.Expression, Expr.Bytes(new byte[] { 1 }), Expr.Bytes(System.Array.Empty<byte>())),
                value.Taints),
            _ => value,
        };
    }

    private static void EnforceCheckWitnessTarget(
        ExecutionState state,
        Instruction inst,
        SymbolicValue target)
    {
        if (target.IsConcreteNull)
            throw new VmFaultException("CheckWitness with null hash or public key");

        var normalizedTarget = NormalizeStorageBytes(state, target);
        if (Expr.CanonicalBytes(normalizedTarget.Expression) is { } bytes)
        {
            if (bytes.Length is not (Hash160Length or CompressedPublicKeyLength))
            {
                throw new VmFaultException(
                    $"CheckWitness hash or public key length {bytes.Length} is not 20 or 33 bytes");
            }

            if (bytes.Length == CompressedPublicKeyLength && !NeoEcPoint.IsValidEncoding(bytes))
                throw new VmFaultException("CheckWitness with invalid public key encoding");

            return;
        }

        var size = StorageByteLengthExpression(normalizedTarget.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "CheckWitness",
            Expr.BoolAnd(
                Expr.Not(Expr.Eq(size, Expr.Int(Hash160Length))),
                Expr.BoolOr(
                    Expr.Not(Expr.Eq(size, Expr.Int(CompressedPublicKeyLength))),
                    Expr.Not(Expr.IsValidEcPoint(normalizedTarget.Expression)))),
            "hash or public key length must be 20 or 33 bytes, and 33-byte public keys must be valid ECPoint encodings",
            "hash is 20 bytes or public key is a valid ECPoint"));
    }

    private static void EnforceRuntimeLogMessage(
        ExecutionState state,
        Instruction inst,
        SymbolicValue message)
    {
        if (message.IsConcreteNull)
            throw new VmFaultException("Runtime.Log with null message");

        var normalizedMessage = NormalizeStorageBytes(state, message);
        if (Expr.CanonicalBytes(normalizedMessage.Expression) is { } bytes)
        {
            if (bytes.Length > MaxRuntimeNotificationSize)
                throw new VmFaultException(
                    $"Runtime.Log message length {bytes.Length} exceeds {MaxRuntimeNotificationSize} bytes");
            DecodeStrictUtf8OrThrow(bytes, "Runtime.Log", "message");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Runtime.Log",
            Expr.Gt(StorageByteLengthExpression(normalizedMessage.Expression), Expr.Int(MaxRuntimeNotificationSize)),
            $"message size may exceed {MaxRuntimeNotificationSize} bytes",
            "VM syscall precondition holds under requires"));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Runtime.Log",
            Expr.Not(Expr.IsStrictUtf8(normalizedMessage.Expression)),
            "message may be invalid strict UTF-8",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceRuntimeNotifyEventName(
        ExecutionState state,
        Instruction inst,
        SymbolicValue name)
    {
        if (name.IsConcreteNull)
            throw new VmFaultException("Runtime.Notify with null event name");

        var normalizedName = NormalizeStorageBytes(state, name);
        if (Expr.CanonicalBytes(normalizedName.Expression) is { } bytes)
        {
            if (bytes.Length > MaxRuntimeEventNameLength)
                throw new VmFaultException(
                    $"Runtime.Notify event name length {bytes.Length} exceeds {MaxRuntimeEventNameLength} bytes");
            DecodeStrictUtf8OrThrow(bytes, "Runtime.Notify", "event name");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Runtime.Notify",
            Expr.Gt(StorageByteLengthExpression(normalizedName.Expression), Expr.Int(MaxRuntimeEventNameLength)),
            $"event name size may exceed {MaxRuntimeEventNameLength} bytes",
            "VM syscall precondition holds under requires"));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Runtime.Notify",
            Expr.Not(Expr.IsStrictUtf8(normalizedName.Expression)),
            "event name may be invalid strict UTF-8",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceRuntimeNotifyPayloadSize(
        ExecutionState state,
        Instruction inst,
        SymbolicValue payload)
    {
        if (!TrySerializedStackItemSizeExpression(
            state,
            payload,
            new HashSet<int>(),
            "Runtime.Notify",
            "payload",
            out var serializedSize))
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return;
        }

        if (serializedSize is IntConst concrete)
        {
            if (concrete.Value > MaxRuntimeNotificationSize)
            {
                throw new VmFaultException(
                    $"Runtime.Notify payload serialized size {concrete.Value} exceeds {MaxRuntimeNotificationSize} bytes");
            }

            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Runtime.Notify",
            Expr.Gt(serializedSize, Expr.Int(MaxRuntimeNotificationSize)),
            $"payload serialized size may exceed {MaxRuntimeNotificationSize} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static bool TrySerializedStackItemSizeExpression(
        ExecutionState state,
        SymbolicValue value,
        HashSet<int> serializedCompounds,
        string operation,
        string valueName,
        out Expression size)
    {
        switch (value.Expression)
        {
            case NullConst:
                size = Expr.Int(1);
                return true;

            case BoolConst:
                size = Expr.Int(2);
                return true;

            case IntConst integer:
                {
                    int bytes = Expr.IntegerToBytes(integer.Value).Length;
                    size = Expr.Int(1 + VarSizeLength(bytes) + bytes);
                    return true;
                }

            case BytesConst bytes:
                size = SerializedVarBytesSize(bytes.Value.Length);
                return true;

            case Symbol { Sort: Sort.Int }:
                size = Expr.Int(1 + VarSizeLength(MaxNeoVmIntegerBytes) + MaxNeoVmIntegerBytes);
                return true;

            case Symbol { Sort: Sort.Bool }:
                size = Expr.Int(2);
                return true;

            case Symbol { Sort: Sort.Bytes }:
                size = SerializedSymbolicVarBytesSize(value.Expression);
                return true;

            case HeapRef { RefSort: Sort.Buffer } href:
                {
                    // Round-2 fix: an OPEN (symbolic-length) buffer has no concrete serialized length —
                    // using buffer.Length (the seeded prefix) under-approximates the serialized size.
                    // Route to the fail-closed UnknownSyscall path (return false), matching the
                    // open-Array/Map guards below.
                    if (state.Heap.Get(href.ObjectId) is not BufferObject { IsSymbolicOpen: false } buffer)
                    {
                        size = Expr.Int(0);
                        return false;
                    }

                    size = SerializedVarBytesSize(buffer.Length);
                    return true;
                }

            case HeapRef { RefSort: Sort.Array or Sort.Struct } href:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        throw new VmFaultException($"{operation} {valueName} contains repeated compound reference");

                    var heapObject = state.Heap.Get(href.ObjectId);
                    if (heapObject is ArrayObject { IsSymbolicOpen: false } array)
                        return TrySerializedSequenceSizeExpression(state, array.Items, serializedCompounds, operation, valueName, out size);
                    // Round-2 fix: guard open Structs too (was unguarded, asymmetric with the open-Array
                    // branch above) so an open Struct routes to the fail-closed UnknownSyscall path.
                    if (heapObject is StructObject { IsSymbolicOpen: false } structure)
                        return TrySerializedSequenceSizeExpression(state, structure.Fields, serializedCompounds, operation, valueName, out size);

                    size = Expr.Int(0);
                    return false;
                }

            case HeapRef { RefSort: Sort.Map } href:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        throw new VmFaultException($"{operation} {valueName} contains repeated compound reference");

                    if (state.Heap.Get(href.ObjectId) is not MapObject { IsSymbolicOpen: false } map)
                    {
                        size = Expr.Int(0);
                        return false;
                    }

                    Expression total = Expr.Int(1 + VarSizeLength(map.Entries.Count));
                    foreach (var (key, mapValue) in map.Entries)
                    {
                        if (!TrySerializedStackItemSizeExpression(state, key, serializedCompounds, operation, valueName, out var keySize)
                            || !TrySerializedStackItemSizeExpression(state, mapValue, serializedCompounds, operation, valueName, out var valueSize))
                        {
                            size = Expr.Int(0);
                            return false;
                        }

                        total = Expr.Add(Expr.Add(total, keySize), valueSize);
                    }

                    size = total;
                    return true;
                }
        }

        if (value.Sort is Sort.Pointer or Sort.InteropInterface)
            throw new VmFaultException($"{operation} {valueName} contains unserializable {value.Sort} stack item");

        size = Expr.Int(0);
        return false;
    }

    private static bool TrySerializedSequenceSizeExpression(
        ExecutionState state,
        IReadOnlyList<SymbolicValue> items,
        HashSet<int> serializedCompounds,
        string operation,
        string valueName,
        out Expression size)
    {
        Expression total = Expr.Int(1 + VarSizeLength(items.Count));
        foreach (var item in items)
        {
            if (!TrySerializedStackItemSizeExpression(state, item, serializedCompounds, operation, valueName, out var itemSize))
            {
                size = Expr.Int(0);
                return false;
            }

            total = Expr.Add(total, itemSize);
        }

        size = total;
        return true;
    }

    private static Expression SerializedVarBytesSize(int length) =>
        Expr.Int(1 + VarSizeLength(length) + length);

    private static Expression SerializedSymbolicVarBytesSize(Expression bytes) =>
        Expr.Add(Expr.Int(1 + MaxVarIntBytes), StorageByteLengthExpression(bytes));

    private static int VarSizeLength(int value)
    {
        if (value < 0xFD) return 1;
        if (value <= 0xFFFF) return 3;
        return 5;
    }

    private static string DecodeStrictUtf8OrThrow(byte[] bytes, string operation, string valueName)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException ex)
        {
            throw new VmFaultException($"{operation} {valueName} is not valid strict UTF-8", ex);
        }
    }

    private static void EnforcePublicKeyEncoding(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue publicKey)
    {
        if (publicKey.IsConcreteNull)
            throw new VmFaultException($"{operation} with null public key");

        if (Expr.CanonicalBytes(publicKey.Expression) is { } bytes)
        {
            if (!NeoEcPoint.IsValidEncoding(bytes))
                throw new VmFaultException(
                    $"{operation} with invalid public key encoding");
            return;
        }

        var size = new UnaryExpr(Sort.Int, "size", publicKey.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.BoolOr(
                Expr.BoolAnd(
                    Expr.Not(Expr.Eq(size, Expr.Int(CompressedPublicKeyLength))),
                    Expr.Not(Expr.Eq(size, Expr.Int(UncompressedPublicKeyLength)))),
                Expr.Not(Expr.IsValidEcPoint(publicKey.Expression))),
            $"public key length must be {CompressedPublicKeyLength} or {UncompressedPublicKeyLength} bytes and value must be a valid ECPoint encoding",
            "public key length is valid and value is a valid ECPoint"));
    }

    private static void EnforceSignatureLength(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue signature)
    {
        if (signature.IsConcreteNull)
            throw new VmFaultException($"{operation} with null signature");

        var normalizedSignature = NormalizeStorageBytes(state, signature);
        if (Expr.CanonicalBytes(normalizedSignature.Expression) is { } bytes)
        {
            if (bytes.Length != SignatureLength)
                throw new VmFaultException($"{operation} signature length {bytes.Length} is not {SignatureLength} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(Expr.Eq(StorageByteLengthExpression(normalizedSignature.Expression), Expr.Int(SignatureLength))),
            $"signature length must be {SignatureLength} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static IEnumerable<(SymbolicValue Key, SymbolicValue Value)> FindPathLocalStorageEntries(
        ExecutionState state,
        SymbolicValue prefix)
    {
        if (Expr.CanonicalBytes(prefix.Expression) is not { } prefixBytes)
            yield break;

        foreach (var (storedKey, storedValue) in state.StorageValues)
        {
            if (storedValue.IsConcreteNull)
                continue;
            if (Expr.CanonicalBytes(storedKey) is not { } keyBytes)
                continue;
            if (!StartsWith(keyBytes, prefixBytes))
                continue;

            yield return (SymbolicValue.Of(Expr.Bytes(keyBytes)), storedValue);
        }
    }

    private static bool StartsWith(byte[] value, byte[] prefix)
    {
        if (prefix.Length > value.Length)
            return false;
        for (int i = 0; i < prefix.Length; i++)
        {
            if (value[i] != prefix[i])
                return false;
        }
        return true;
    }

    private static void RememberIteratorFind(
        ExecutionState state,
        SymbolicValue iterator,
        SymbolicValue prefix,
        SymbolicValue options,
        IEnumerable<(SymbolicValue Key, SymbolicValue Value)> knownEntries)
    {
        if (iterator.Expression is not Symbol { Name: var name })
            return;

        state.InteropContext[$"iterator_prefix:{name}"] = prefix;
        state.InteropContext[$"iterator_options:{name}"] = options;

        var entryRefs = new List<SymbolicValue>();
        foreach (var (key, value) in knownEntries)
        {
            var entry = state.Heap.NewStruct(new[] { key, value });
            entryRefs.Add(SymbolicValue.HeapRef(Sort.Struct, entry.Id));
        }

        if (entryRefs.Count > 0)
        {
            var entries = state.Heap.NewArray(entryRefs);
            state.InteropContext[$"iterator_known_entries:{name}"] = SymbolicValue.HeapRef(Sort.Array, entries.Id);
        }
    }

    private static IEnumerable<ExecutionState> ForkIteratorNext(
        ExecutionState state,
        Instruction inst,
        SymbolicValue iterator)
    {
        var forked = new List<ExecutionState>();
        if (TryGetIteratorKnownEntryRefs(state, iterator, out var entries))
        {
            foreach (var entry in entries)
            {
                var known = state.Clone();
                SetCurrentIteratorEntry(known, iterator, entry);
                known.Push(SymbolicValue.Bool(true));
                known.Pc = inst.EndOffset;
                forked.Add(known);
            }
        }

        var unknownCurrent = state.Clone();
        SetUnknownCurrentIteratorEntry(unknownCurrent, iterator, inst);
        unknownCurrent.Push(SymbolicValue.Bool(true));
        unknownCurrent.Pc = inst.EndOffset;
        forked.Add(unknownCurrent);

        ClearCurrentIteratorEntry(state, iterator);
        state.Push(SymbolicValue.Bool(false));
        state.Pc = inst.EndOffset;
        forked.Add(state);
        return forked;
    }

    private static void SetCurrentIteratorEntry(
        ExecutionState state,
        SymbolicValue iterator,
        SymbolicValue entry)
    {
        if (iterator.Expression is Symbol { Name: var name })
            state.InteropContext[$"iterator_current_entry:{name}"] = entry;
    }

    private static void SetUnknownCurrentIteratorEntry(
        ExecutionState state,
        SymbolicValue iterator,
        Instruction inst)
    {
        if (iterator.Expression is Symbol { Name: var name })
            state.InteropContext[$"iterator_current_entry:{name}"] =
                SymbolicValue.Symbol(Sort.Unknown, $"iterator_current_unknown_{inst.Offset}");
    }

    private static void ClearCurrentIteratorEntry(ExecutionState state, SymbolicValue iterator)
    {
        if (iterator.Expression is Symbol { Name: var name })
            state.InteropContext.Remove($"iterator_current_entry:{name}");
    }

    private static SymbolicValue BuildIteratorValue(
        ExecutionState state,
        Instruction inst,
        SymbolicValue iterator)
    {
        if (!HasCurrentIteratorEntry(state, iterator))
            throw new VmFaultException("Iterator.Value without successful Iterator.Next");

        if (!TryGetIteratorFindOptions(state, iterator, out var options)
            || Expr.ConcreteInt(options.Expression) is not { } concreteOptions)
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return SymbolicValue.Symbol(Sort.Unknown, $"iterator_value_{inst.Offset}");
        }

        if (TryGetCurrentIteratorEntry(state, iterator, out var knownKey, out var knownValue))
            return BuildKnownIteratorValue(state, inst, concreteOptions, knownKey, knownValue, iterator);

        if (HasFindOption(concreteOptions, FindOptionsKeysOnly))
            return SymbolicValue.Symbol(Sort.Bytes, $"iterator_key_{inst.Offset}");

        bool valuesOnly = HasFindOption(concreteOptions, FindOptionsValuesOnly);
        bool deserializeValues = HasFindOption(concreteOptions, FindOptionsDeserializeValues);
        bool pickField = HasFindOption(concreteOptions, FindOptionsPickField0)
            || HasFindOption(concreteOptions, FindOptionsPickField1);
        if (deserializeValues || pickField)
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return SymbolicValue.Symbol(Sort.Unknown, $"iterator_value_{inst.Offset}");
        }

        if (valuesOnly)
            return SymbolicValue.Symbol(Sort.Bytes, $"iterator_value_{inst.Offset}");

        var pair = state.Heap.NewStruct(new[]
        {
            SymbolicValue.Symbol(Sort.Bytes, $"iterator_key_{inst.Offset}"),
            SymbolicValue.Symbol(Sort.Bytes, $"iterator_value_{inst.Offset}"),
        });
        return SymbolicValue.HeapRef(Sort.Struct, pair.Id);
    }

    private static SymbolicValue BuildKnownIteratorValue(
        ExecutionState state,
        Instruction inst,
        BigInteger options,
        SymbolicValue key,
        SymbolicValue value,
        SymbolicValue iterator)
    {
        bool valuesOnly = HasFindOption(options, FindOptionsValuesOnly);
        bool deserializeValues = HasFindOption(options, FindOptionsDeserializeValues);
        bool pickField = HasFindOption(options, FindOptionsPickField0)
            || HasFindOption(options, FindOptionsPickField1);
        if (deserializeValues)
        {
            var serializedValue = value;
            if (!TryDeserializeConcreteStackItem(state, serializedValue, out var deserializedValue)
                && !TryDeserializeSymbolicStackItemSummary(state, serializedValue, out deserializedValue))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return SymbolicValue.Symbol(Sort.Unknown, $"iterator_value_{inst.Offset}");
            }

            value = deserializedValue;
            if (TryGetPickFieldIndex(options, out int fieldIndex)
                && !TryPickDeserializedField(state, value, fieldIndex, out value))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return SymbolicValue.Symbol(Sort.Unknown, $"iterator_value_{inst.Offset}");
            }
        }
        else if (pickField)
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return SymbolicValue.Symbol(Sort.Unknown, $"iterator_value_{inst.Offset}");
        }

        if (valuesOnly)
            return value;

        var visibleKey = HasFindOption(options, FindOptionsRemovePrefix)
            ? RemoveIteratorPrefix(state, key, iterator)
            : key;

        if (HasFindOption(options, FindOptionsKeysOnly))
            return visibleKey;

        var pair = state.Heap.NewStruct(new[] { visibleKey, value });
        return SymbolicValue.HeapRef(Sort.Struct, pair.Id);
    }

    private static SymbolicValue RemoveIteratorPrefix(
        ExecutionState state,
        SymbolicValue key,
        SymbolicValue iterator)
    {
        if (TryGetIteratorFindPrefix(state, iterator, out var prefix)
            && Expr.CanonicalBytes(key.Expression) is { } keyBytes
            && Expr.CanonicalBytes(prefix.Expression) is { } prefixBytes
            && StartsWith(keyBytes, prefixBytes))
        {
            var suffix = new byte[keyBytes.Length - prefixBytes.Length];
            System.Array.Copy(keyBytes, prefixBytes.Length, suffix, 0, suffix.Length);
            return SymbolicValue.Of(Expr.Bytes(suffix), key.Taints);
        }

        return key;
    }

    private static bool TryGetPickFieldIndex(BigInteger options, out int fieldIndex)
    {
        if (HasFindOption(options, FindOptionsPickField0))
        {
            fieldIndex = 0;
            return true;
        }
        if (HasFindOption(options, FindOptionsPickField1))
        {
            fieldIndex = 1;
            return true;
        }

        fieldIndex = -1;
        return false;
    }

    private static bool TryPickDeserializedField(
        ExecutionState state,
        SymbolicValue value,
        int fieldIndex,
        out SymbolicValue field)
    {
        field = SymbolicValue.Null();
        if (fieldIndex < 0)
            return false;

        if (value.Expression is not HeapRef href)
            return false;

        IReadOnlyList<SymbolicValue> fields = href.RefSort switch
        {
            Sort.Array => state.Heap.Get<ArrayObject>(href.ObjectId).Items,
            Sort.Struct => state.Heap.Get<StructObject>(href.ObjectId).Fields,
            _ => System.Array.Empty<SymbolicValue>(),
        };
        if (fieldIndex >= fields.Count)
            return false;

        field = fields[fieldIndex];
        return true;
    }

    private static bool TryDeserializeConcreteStackItem(
        ExecutionState state,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        var bytes = value.AsConcreteBytes();
        if (bytes is null)
            return false;

        int offset = 0;
        if (!TryReadSerializedStackItem(state, bytes, ref offset, depth: 0, out result))
            return false;

        return offset == bytes.Length;
    }

    private static bool TrySerializeConcreteStackItem(
        ExecutionState state,
        SymbolicValue value,
        out byte[] bytes)
    {
        var output = new List<byte>();
        if (!TryWriteSerializedStackItem(state, output, value, depth: 0))
        {
            bytes = System.Array.Empty<byte>();
            return false;
        }

        bytes = output.ToArray();
        return true;
    }

    private static bool TrySerializeSymbolicStackItemSummary(
        ExecutionState state,
        Instruction inst,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!TryBuildSerializedStackItemSummary(
                state,
                value,
                new HashSet<int>(),
                depth: 0,
                out var summary))
        {
            return false;
        }

        if (!TrySerializedStackItemSizeExpression(
                state,
                value,
                new HashSet<int>(),
                "StdLib.serialize",
                "value",
                out var serializedSize))
        {
            return false;
        }

        if (serializedSize is IntConst concrete)
        {
            if (concrete.Value > state.Heap.MaxItemSize)
                return false;
        }
        else
        {
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "StdLib.serialize",
                Expr.Gt(serializedSize, Expr.Int(state.Heap.MaxItemSize)),
                $"serialized size may exceed {state.Heap.MaxItemSize} bytes",
                "serialized size is within NeoVM item limit"));
        }

        var taints = new HashSet<string>();
        CollectStackItemTaints(state, value, new HashSet<int>(), taints);
        result = SymbolicValue.Of(
            new UnaryExpr(Sort.Bytes, SerializedStackItemSummaryOp, summary),
            taints);
        return true;
    }

    private static bool TryBuildSerializedStackItemSummary(
        ExecutionState state,
        SymbolicValue value,
        HashSet<int> serializedCompounds,
        int depth,
        out Expression summary)
    {
        const int MaxSerializeDepth = 64;

        summary = Expr.Null();
        if (depth > MaxSerializeDepth)
            return false;

        if (value.Expression is NullConst)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryNullOp, Expr.Null());
            return true;
        }

        if (value.Sort == Sort.Bool)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryBoolOp, value.Expression);
            return true;
        }

        if (value.Sort == Sort.Int)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryIntOp, value.Expression);
            return true;
        }

        if (value.Sort == Sort.Bytes)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryBytesOp, value.Expression);
            return true;
        }

        if (value.Expression is not HeapRef href)
            return false;

        switch (href.RefSort)
        {
            case Sort.Buffer:
                {
                    var buffer = state.Heap.Get<BufferObject>(href.ObjectId);
                    if (buffer.Length > state.Heap.MaxItemSize)
                        return false;

                    var cells = new List<Expression>(buffer.Cells.Count);
                    foreach (var cell in buffer.Cells)
                    {
                        if (cell.Sort != Sort.Int)
                            return false;
                        if (Expr.ConcreteInt(cell) is { } concreteCell
                            && (concreteCell < BigInteger.Zero || concreteCell > new BigInteger(byte.MaxValue)))
                        {
                            return false;
                        }

                        cells.Add(cell);
                    }

                    summary = new UnaryExpr(
                        Sort.Bytes,
                        SerializedSummaryBufferOp,
                        BuildSerializedSummaryList(cells));
                    return true;
                }

            case Sort.Array:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not ArrayObject { IsSymbolicOpen: false } array)
                        return false;

                    return TryBuildSerializedSequenceSummary(
                        state,
                        array.Items,
                        serializedCompounds,
                        depth,
                        SerializedSummaryArrayOp,
                        out summary);
                }

            case Sort.Struct:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not StructObject { IsSymbolicOpen: false } structure)
                        return false;

                    return TryBuildSerializedSequenceSummary(
                        state,
                        structure.Fields,
                        serializedCompounds,
                        depth,
                        SerializedSummaryStructOp,
                        out summary);
                }

            case Sort.Map:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not MapObject { IsSymbolicOpen: false } map)
                        return false;

                    var pairs = new List<Expression>(map.Entries.Count);
                    foreach (var (key, mapValue) in map.Entries)
                    {
                        if (key.Sort is not (Sort.Bool or Sort.Int or Sort.Bytes))
                            return false;
                        if (!TryBuildSerializedStackItemSummary(
                                state,
                                key,
                                serializedCompounds,
                                depth + 1,
                                out var keySummary)
                            || !TryBuildSerializedStackItemSummary(
                                state,
                                mapValue,
                                serializedCompounds,
                                depth + 1,
                                out var valueSummary))
                        {
                            return false;
                        }

                        pairs.Add(new BinaryExpr(
                            Sort.Bytes,
                            SerializedSummaryPairOp,
                            keySummary,
                            valueSummary));
                    }

                    summary = new UnaryExpr(
                        Sort.Bytes,
                        SerializedSummaryMapOp,
                        BuildSerializedSummaryList(pairs));
                    return true;
                }

            default:
                return false;
        }
    }

    private static bool TryBuildSerializedSequenceSummary(
        ExecutionState state,
        IReadOnlyList<SymbolicValue> items,
        HashSet<int> serializedCompounds,
        int depth,
        string summaryOp,
        out Expression summary)
    {
        var itemSummaries = new List<Expression>(items.Count);
        foreach (var item in items)
        {
            if (!TryBuildSerializedStackItemSummary(
                    state,
                    item,
                    serializedCompounds,
                    depth + 1,
                    out var itemSummary))
            {
                summary = Expr.Null();
                return false;
            }

            itemSummaries.Add(itemSummary);
        }

        summary = new UnaryExpr(Sort.Bytes, summaryOp, BuildSerializedSummaryList(itemSummaries));
        return true;
    }

    private static Expression BuildSerializedSummaryList(IReadOnlyList<Expression> items)
    {
        Expression list = new UnaryExpr(Sort.Bytes, SerializedSummaryNilOp, Expr.Null());
        for (int i = items.Count - 1; i >= 0; i--)
            list = new BinaryExpr(Sort.Bytes, SerializedSummaryConsOp, items[i], list);
        return list;
    }

    private static bool TryDeserializeSymbolicStackItemSummary(
        ExecutionState state,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (value.Expression is not UnaryExpr
            {
                Sort: Sort.Bytes,
                Op: SerializedStackItemSummaryOp,
            } serialized)
        {
            return false;
        }

        return TryReadSerializedStackItemSummary(
            state,
            serialized.Operand,
            value.Taints,
            depth: 0,
            out result);
    }

    private static bool TryReadSerializedStackItemSummary(
        ExecutionState state,
        Expression summary,
        IEnumerable<string> taints,
        int depth,
        out SymbolicValue value)
    {
        const int MaxDeserializeDepth = 64;

        value = SymbolicValue.Null();
        if (depth > MaxDeserializeDepth)
            return false;

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryNullOp } nullSummary
            && nullSummary.Operand is NullConst)
        {
            value = SymbolicValue.Of(Expr.Null(), taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryBoolOp } boolSummary
            && boolSummary.Operand.Sort == Sort.Bool)
        {
            value = SymbolicValue.Of(boolSummary.Operand, taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryIntOp } intSummary
            && intSummary.Operand.Sort == Sort.Int)
        {
            value = SymbolicValue.Of(intSummary.Operand, taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryBytesOp } bytesSummary
            && bytesSummary.Operand.Sort == Sort.Bytes)
        {
            value = SymbolicValue.Of(bytesSummary.Operand, taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryBufferOp } bufferSummary)
        {
            if (!TryReadSerializedSummaryList(
                    bufferSummary.Operand,
                    state.Heap.MaxItemSize,
                    out var cellSummaries))
            {
                return false;
            }

            var cells = new List<Expression>(cellSummaries.Count);
            foreach (var cell in cellSummaries)
            {
                if (cell.Sort != Sort.Int)
                    return false;
                if (Expr.ConcreteInt(cell) is { } concreteCell
                    && (concreteCell < BigInteger.Zero || concreteCell > new BigInteger(byte.MaxValue)))
                {
                    return false;
                }

                cells.Add(cell);
            }

            var buffer = state.Heap.Allocate(id => new BufferObject(id, cells));
            value = SymbolicValue.Of(Expr.Ref(Sort.Buffer, buffer.Id), taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryArrayOp } arraySummary)
        {
            if (!TryReadSerializedSummaryList(
                    arraySummary.Operand,
                    state.Heap.MaxCollectionSize,
                    out var itemSummaries))
            {
                return false;
            }

            var items = new List<SymbolicValue>(itemSummaries.Count);
            foreach (var itemSummary in itemSummaries)
            {
                if (!TryReadSerializedStackItemSummary(
                        state,
                        itemSummary,
                        taints,
                        depth + 1,
                        out var item))
                {
                    return false;
                }

                items.Add(item);
            }

            state.Heap.EnforceCollectionGrowth(items.Count);
            var array = state.Heap.NewArray(items);
            value = SymbolicValue.Of(Expr.Ref(Sort.Array, array.Id), taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryStructOp } structSummary)
        {
            if (!TryReadSerializedSummaryList(
                    structSummary.Operand,
                    state.Heap.MaxCollectionSize,
                    out var fieldSummaries))
            {
                return false;
            }

            var fields = new List<SymbolicValue>(fieldSummaries.Count);
            foreach (var fieldSummary in fieldSummaries)
            {
                if (!TryReadSerializedStackItemSummary(
                        state,
                        fieldSummary,
                        taints,
                        depth + 1,
                        out var field))
                {
                    return false;
                }

                fields.Add(field);
            }

            state.Heap.EnforceCollectionGrowth(fields.Count);
            var structure = state.Heap.NewStruct(fields);
            value = SymbolicValue.Of(Expr.Ref(Sort.Struct, structure.Id), taints);
            return true;
        }

        if (summary is UnaryExpr { Sort: Sort.Bytes, Op: SerializedSummaryMapOp } mapSummary)
        {
            if (!TryReadSerializedSummaryList(
                    mapSummary.Operand,
                    state.Heap.MaxCollectionSize,
                    out var pairSummaries))
            {
                return false;
            }

            var entries = new List<(SymbolicValue Key, SymbolicValue Value)>(pairSummaries.Count);
            foreach (var pairSummary in pairSummaries)
            {
                if (pairSummary is not BinaryExpr
                    {
                        Sort: Sort.Bytes,
                        Op: SerializedSummaryPairOp,
                    } pair)
                {
                    return false;
                }

                if (!TryReadSerializedStackItemSummary(
                        state,
                        pair.Left,
                        taints,
                        depth + 1,
                        out var key)
                    || !TryReadSerializedStackItemSummary(
                        state,
                        pair.Right,
                        taints,
                        depth + 1,
                        out var mapValue))
                {
                    return false;
                }

                if (key.Sort is not (Sort.Bool or Sort.Int or Sort.Bytes))
                    return false;

                entries.Add((key, mapValue));
            }

            state.Heap.EnforceCollectionGrowth(entries.Count);
            var map = state.Heap.NewMap(entries);
            value = SymbolicValue.Of(Expr.Ref(Sort.Map, map.Id), taints);
            return true;
        }

        return false;
    }

    private static bool TryReadSerializedSummaryList(
        Expression list,
        int maxCount,
        out List<Expression> items)
    {
        items = new List<Expression>();
        Expression cursor = list;
        while (cursor is BinaryExpr
            {
                Sort: Sort.Bytes,
                Op: SerializedSummaryConsOp,
            } cons)
        {
            if (items.Count >= maxCount)
                return false;

            items.Add(cons.Left);
            cursor = cons.Right;
        }

        return cursor is UnaryExpr
        {
            Sort: Sort.Bytes,
            Op: SerializedSummaryNilOp,
            Operand: NullConst,
        };
    }

    private static void CollectStackItemTaints(
        ExecutionState state,
        SymbolicValue value,
        HashSet<int> visitedCompounds,
        HashSet<string> taints)
    {
        foreach (var taint in value.Taints)
            taints.Add(taint);

        if (value.Expression is not HeapRef href)
            return;

        switch (href.RefSort)
        {
            case Sort.Array:
                if (!visitedCompounds.Add(href.ObjectId))
                    return;
                foreach (var item in state.Heap.Get<ArrayObject>(href.ObjectId).Items)
                    CollectStackItemTaints(state, item, visitedCompounds, taints);
                break;

            case Sort.Struct:
                if (!visitedCompounds.Add(href.ObjectId))
                    return;
                foreach (var field in state.Heap.Get<StructObject>(href.ObjectId).Fields)
                    CollectStackItemTaints(state, field, visitedCompounds, taints);
                break;

            case Sort.Map:
                if (!visitedCompounds.Add(href.ObjectId))
                    return;
                foreach (var (key, mapValue) in state.Heap.Get<MapObject>(href.ObjectId).Entries)
                {
                    CollectStackItemTaints(state, key, visitedCompounds, taints);
                    CollectStackItemTaints(state, mapValue, visitedCompounds, taints);
                }
                break;
        }
    }

    private static bool TryJsonSerializeConcreteStackItem(
        ExecutionState state,
        SymbolicValue value,
        out byte[] bytes)
    {
        using var stream = new System.IO.MemoryStream();
        using (var writer = new System.Text.Json.Utf8JsonWriter(
                   stream,
                   new System.Text.Json.JsonWriterOptions
                   {
                       Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                   }))
        {
            if (!TryWriteJsonStackItem(state, writer, value, depth: 0))
            {
                bytes = System.Array.Empty<byte>();
                return false;
            }
        }

        bytes = stream.ToArray();
        return bytes.Length <= state.Heap.MaxItemSize;
    }

    private static bool TryJsonDeserializeConcreteStackItem(
        ExecutionState state,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        var bytes = value.AsConcreteBytes();
        if (bytes is null || bytes.Length > state.Heap.MaxItemSize)
            return false;

        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(
                bytes,
                new System.Text.Json.JsonDocumentOptions
                {
                    // Round-2 fix: Neo's StdLib.jsonDeserialize uses max_nest = 10; a deeper input
                    // faults on-chain. Parse with MaxDepth=10 so over-nested JSON is rejected (the
                    // exception is caught below and returns false → UnknownSyscall/fault) rather than
                    // accepted up to depth 64.
                    MaxDepth = 10,
                    AllowTrailingCommas = false,
                    CommentHandling = System.Text.Json.JsonCommentHandling.Disallow,
                });
            return TryReadJsonStackItem(state, document.RootElement, depth: 0, out result);
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    private static bool TryJsonSerializeSymbolicStackItemSummary(
        ExecutionState state,
        Instruction inst,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!TryBuildJsonStackItemSummary(
                state,
                inst,
                value,
                new HashSet<int>(),
                depth: 0,
                out var summary,
                out var maxJsonSize))
        {
            return false;
        }

        if (maxJsonSize is IntConst concrete)
        {
            if (concrete.Value > state.Heap.MaxItemSize)
                return false;
        }
        else
        {
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "StdLib.jsonSerialize",
                Expr.Gt(maxJsonSize, Expr.Int(state.Heap.MaxItemSize)),
                $"JSON output size may exceed {state.Heap.MaxItemSize} bytes",
                "JSON output size is within NeoVM item limit"));
        }

        var taints = new HashSet<string>();
        CollectStackItemTaints(state, value, new HashSet<int>(), taints);
        result = SymbolicValue.Of(
            new UnaryExpr(Sort.Bytes, JsonStackItemSummaryOp, summary),
            taints);
        return true;
    }

    private static bool TryBuildJsonStackItemSummary(
        ExecutionState state,
        Instruction inst,
        SymbolicValue value,
        HashSet<int> serializedCompounds,
        int depth,
        out Expression summary,
        out Expression maxJsonSize)
    {
        const int MaxJsonDepth = 64;

        summary = Expr.Null();
        maxJsonSize = Expr.Int(0);
        if (depth > MaxJsonDepth)
            return false;

        if (value.Expression is NullConst)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryNullOp, Expr.Null());
            maxJsonSize = Expr.Int(4);
            return true;
        }

        if (value.Sort == Sort.Bool)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryBoolOp, value.Expression);
            maxJsonSize = value.Expression is BoolConst boolean
                ? Expr.Int(boolean.Value ? 4 : 5)
                : Expr.Int(5);
            return true;
        }

        if (value.Sort == Sort.Int)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryIntOp, value.Expression);
            maxJsonSize = value.Expression is IntConst integer
                ? Expr.Int(integer.Value.ToString(System.Globalization.CultureInfo.InvariantCulture).Length)
                : Expr.Int(80);
            return true;
        }

        if (value.Sort == Sort.Bytes)
        {
            summary = new UnaryExpr(Sort.Bytes, SerializedSummaryBytesOp, value.Expression);
            maxJsonSize = MaxJsonStringSizeExpression(value.Expression);
            if (Expr.IsStrictUtf8(value.Expression) is not BoolConst { Value: true })
            {
                state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                    inst.Offset,
                    "StdLib.jsonSerialize",
                    Expr.Not(Expr.IsStrictUtf8(value.Expression)),
                    "string value may be invalid strict UTF-8",
                    "JSON string is valid strict UTF-8"));
            }

            return true;
        }

        if (value.Expression is not HeapRef href)
            return false;

        switch (href.RefSort)
        {
            case Sort.Array:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not ArrayObject { IsSymbolicOpen: false } array)
                        return false;

                    return TryBuildJsonSequenceSummary(
                        state,
                        inst,
                        array.Items,
                        serializedCompounds,
                        depth,
                        out summary,
                        out maxJsonSize);
                }

            case Sort.Struct:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not StructObject { IsSymbolicOpen: false } structure)
                        return false;

                    return TryBuildJsonSequenceSummary(
                        state,
                        inst,
                        structure.Fields,
                        serializedCompounds,
                        depth,
                        out summary,
                        out maxJsonSize);
                }

            case Sort.Map:
                {
                    if (!serializedCompounds.Add(href.ObjectId))
                        return false;
                    if (state.Heap.Get(href.ObjectId) is not MapObject { IsSymbolicOpen: false } map)
                        return false;

                    var pairs = new List<Expression>(map.Entries.Count);
                    Expression total = Expr.Int(2 + Math.Max(0, map.Entries.Count - 1));
                    foreach (var (key, mapValue) in map.Entries)
                    {
                        if (!TryGetJsonPropertyNameBytes(state, key, out var keyBytes)
                            || !TryBuildJsonStackItemSummary(
                                state,
                                inst,
                                mapValue,
                                serializedCompounds,
                                depth + 1,
                                out var valueSummary,
                                out var valueSize))
                        {
                            return false;
                        }

                        pairs.Add(new BinaryExpr(
                            Sort.Bytes,
                            SerializedSummaryPairOp,
                            new UnaryExpr(Sort.Bytes, SerializedSummaryBytesOp, Expr.Bytes(keyBytes)),
                            valueSummary));
                        total = Expr.Add(total, Expr.Add(Expr.Int(1 + MaxJsonConcreteStringSize(keyBytes)), valueSize));
                    }

                    summary = new UnaryExpr(
                        Sort.Bytes,
                        SerializedSummaryMapOp,
                        BuildSerializedSummaryList(pairs));
                    maxJsonSize = total;
                    return true;
                }

            default:
                return false;
        }
    }

    private static bool TryBuildJsonSequenceSummary(
        ExecutionState state,
        Instruction inst,
        IReadOnlyList<SymbolicValue> items,
        HashSet<int> serializedCompounds,
        int depth,
        out Expression summary,
        out Expression maxJsonSize)
    {
        var itemSummaries = new List<Expression>(items.Count);
        Expression total = Expr.Int(2 + Math.Max(0, items.Count - 1));
        foreach (var item in items)
        {
            if (!TryBuildJsonStackItemSummary(
                    state,
                    inst,
                    item,
                    serializedCompounds,
                    depth + 1,
                    out var itemSummary,
                    out var itemSize))
            {
                summary = Expr.Null();
                maxJsonSize = Expr.Int(0);
                return false;
            }

            itemSummaries.Add(itemSummary);
            total = Expr.Add(total, itemSize);
        }

        summary = new UnaryExpr(Sort.Bytes, SerializedSummaryArrayOp, BuildSerializedSummaryList(itemSummaries));
        maxJsonSize = total;
        return true;
    }

    private static bool TryJsonDeserializeSymbolicStackItemSummary(
        ExecutionState state,
        SymbolicValue value,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (value.Expression is not UnaryExpr
            {
                Sort: Sort.Bytes,
                Op: JsonStackItemSummaryOp,
            } json)
        {
            return false;
        }

        return TryReadSerializedStackItemSummary(
            state,
            json.Operand,
            value.Taints,
            depth: 0,
            out result);
    }

    private static Expression MaxJsonStringSizeExpression(Expression bytes) =>
        Expr.Add(Expr.Int(2), Expr.Mul(StorageByteLengthExpression(bytes), Expr.Int(6)));

    private static int MaxJsonConcreteStringSize(byte[] bytes) => 2 + bytes.Length * 6;

    private static bool TryWriteJsonStackItem(
        ExecutionState state,
        System.Text.Json.Utf8JsonWriter writer,
        SymbolicValue value,
        int depth)
    {
        const int MaxJsonDepth = 64;
        if (depth > MaxJsonDepth)
            return false;

        switch (value.Expression)
        {
            case NullConst:
                writer.WriteNullValue();
                return true;

            case BoolConst boolean:
                writer.WriteBooleanValue(boolean.Value);
                return true;

            case IntConst integer:
                // Round-2 fix: Neo's StdLib.jsonSerialize faults (InvalidOperationException) on an
                // integer outside JavaScript's safe range [-(2^53-1), 2^53-1] (MAX_SAFE_INTEGER), so
                // the serialized JSON round-trips losslessly. Mirror that fault rather than emitting an
                // out-of-range number a real node would reject.
                if (integer.Value > JsonMaxSafeInteger || integer.Value < -JsonMaxSafeInteger)
                    throw new VmFaultException("StdLib.jsonSerialize integer exceeds the JSON safe-integer range");
                writer.WriteRawValue(
                    integer.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    skipInputValidation: true);
                return true;

            case BytesConst bytes:
                return TryWriteJsonString(writer, bytes.Value);

            case HeapRef { RefSort: Sort.Buffer } href:
                {
                    if (!TryReadConcreteBufferBytes(state, href.ObjectId, out var bufferBytes))
                        return false;
                    return TryWriteJsonString(writer, bufferBytes);
                }

            case HeapRef { RefSort: Sort.Array } href:
                {
                    var array = state.Heap.Get<ArrayObject>(href.ObjectId);
                    if (array.IsSymbolicOpen)
                        return false;
                    return TryWriteJsonSequence(state, writer, array.Items, depth);
                }

            case HeapRef { RefSort: Sort.Struct } href:
                {
                    var structure = state.Heap.Get<StructObject>(href.ObjectId);
                    return TryWriteJsonSequence(state, writer, structure.Fields, depth);
                }

            case HeapRef { RefSort: Sort.Map } href:
                {
                    var map = state.Heap.Get<MapObject>(href.ObjectId);
                    if (map.IsSymbolicOpen)
                        return false;

                    writer.WriteStartObject();
                    foreach (var (key, mapValue) in map.Entries)
                    {
                        if (!TryGetJsonPropertyName(state, key, out string? name))
                            return false;
                        writer.WritePropertyName(name);
                        if (!TryWriteJsonStackItem(state, writer, mapValue, depth + 1))
                            return false;
                    }
                    writer.WriteEndObject();
                    return true;
                }

            default:
                return false;
        }
    }

    private static bool TryWriteJsonSequence(
        ExecutionState state,
        System.Text.Json.Utf8JsonWriter writer,
        IReadOnlyList<SymbolicValue> items,
        int depth)
    {
        writer.WriteStartArray();
        foreach (var item in items)
        {
            if (!TryWriteJsonStackItem(state, writer, item, depth + 1))
                return false;
        }
        writer.WriteEndArray();
        return true;
    }

    private static bool TryWriteJsonString(System.Text.Json.Utf8JsonWriter writer, byte[] bytes)
    {
        try
        {
            writer.WriteStringValue(StrictUtf8.GetString(bytes));
            return true;
        }
        catch (System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryGetJsonPropertyName(
        ExecutionState state,
        SymbolicValue key,
        out string name)
    {
        name = string.Empty;
        byte[]? bytes = key.AsConcreteBytes();
        if (bytes is null && key.Expression is HeapRef { RefSort: Sort.Buffer } bufferRef)
        {
            if (!TryReadConcreteBufferBytes(state, bufferRef.ObjectId, out bytes))
                return false;
        }
        if (bytes is null)
            return false;

        try
        {
            name = StrictUtf8.GetString(bytes);
            return true;
        }
        catch (System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryGetJsonPropertyNameBytes(
        ExecutionState state,
        SymbolicValue key,
        out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        if (!TryGetJsonPropertyName(state, key, out var name))
            return false;

        bytes = StrictUtf8.GetBytes(name);
        return bytes.Length <= state.Heap.MaxItemSize;
    }

    private static bool TryReadConcreteBufferBytes(
        ExecutionState state,
        int objectId,
        out byte[] bytes)
    {
        var buffer = state.Heap.Get<BufferObject>(objectId);
        bytes = new byte[buffer.Cells.Count];
        for (int i = 0; i < buffer.Cells.Count; i++)
        {
            if (Expr.ConcreteInt(buffer.Cells[i]) is not { } cell || cell < 0 || cell > 255)
            {
                bytes = System.Array.Empty<byte>();
                return false;
            }

            bytes[i] = (byte)cell;
        }

        return true;
    }

    private static bool TryReadJsonStackItem(
        ExecutionState state,
        System.Text.Json.JsonElement element,
        int depth,
        out SymbolicValue value)
    {
        const int MaxJsonDepth = 64;

        value = SymbolicValue.Null();
        if (depth > MaxJsonDepth)
            return false;

        switch (element.ValueKind)
        {
            case System.Text.Json.JsonValueKind.Null:
                value = SymbolicValue.Null();
                return true;

            case System.Text.Json.JsonValueKind.True:
                value = SymbolicValue.Bool(true);
                return true;

            case System.Text.Json.JsonValueKind.False:
                value = SymbolicValue.Bool(false);
                return true;

            case System.Text.Json.JsonValueKind.Number:
                {
                    string raw = element.GetRawText();
                    if (!IsJsonIntegerLiteral(raw)
                        || !BigInteger.TryParse(
                            raw,
                            System.Globalization.NumberStyles.AllowLeadingSign,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var integer)
                        || !Expr.IsWithinNeoVmIntegerRange(integer))
                    {
                        return false;
                    }

                    value = SymbolicValue.Int(integer);
                    return true;
                }

            case System.Text.Json.JsonValueKind.String:
                {
                    string? text = element.GetString();
                    if (text is null)
                        return false;
                    byte[] bytes = StrictUtf8.GetBytes(text);
                    if (bytes.Length > state.Heap.MaxItemSize)
                        return false;
                    value = SymbolicValue.Bytes(bytes);
                    return true;
                }

            case System.Text.Json.JsonValueKind.Array:
                {
                    var items = new List<SymbolicValue>();
                    foreach (var child in element.EnumerateArray())
                    {
                        if (items.Count >= state.Heap.MaxCollectionSize)
                            return false;
                        if (!TryReadJsonStackItem(state, child, depth + 1, out var item))
                            return false;
                        items.Add(item);
                    }

                    state.Heap.EnforceCollectionGrowth(items.Count);
                    value = SymbolicValue.HeapRef(Sort.Array, state.Heap.NewArray(items).Id);
                    return true;
                }

            case System.Text.Json.JsonValueKind.Object:
                {
                    var entries = new List<(SymbolicValue Key, SymbolicValue Value)>();
                    foreach (var property in element.EnumerateObject())
                    {
                        if (entries.Count >= state.Heap.MaxCollectionSize)
                            return false;
                        byte[] keyBytes = StrictUtf8.GetBytes(property.Name);
                        if (keyBytes.Length > state.Heap.MaxItemSize
                            || !TryReadJsonStackItem(state, property.Value, depth + 1, out var mapValue))
                        {
                            return false;
                        }
                        entries.Add((SymbolicValue.Bytes(keyBytes), mapValue));
                    }

                    state.Heap.EnforceCollectionGrowth(entries.Count);
                    value = SymbolicValue.HeapRef(Sort.Map, state.Heap.NewMap(entries).Id);
                    return true;
                }

            default:
                return false;
        }
    }

    private static bool IsJsonIntegerLiteral(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return false;

        int start = raw[0] == '-' ? 1 : 0;
        if (start == raw.Length)
            return false;

        for (int i = start; i < raw.Length; i++)
        {
            if (raw[i] < '0' || raw[i] > '9')
                return false;
        }

        return true;
    }

    private static bool TryWriteSerializedStackItem(
        ExecutionState state,
        List<byte> output,
        SymbolicValue value,
        int depth)
    {
        const int MaxSerializeDepth = 64;
        if (depth > MaxSerializeDepth)
            return false;

        switch (value.Expression)
        {
            case NullConst:
                output.Add(StackItemTypeCodes.Any);
                return true;

            case BoolConst boolean:
                output.Add(StackItemTypeCodes.Boolean);
                output.Add(boolean.Value ? (byte)1 : (byte)0);
                return true;

            case IntConst integer:
                output.Add(StackItemTypeCodes.Integer);
                WriteVarBytes(output, Expr.IntegerToBytes(integer.Value));
                return true;

            case BytesConst bytes:
                output.Add(StackItemTypeCodes.ByteString);
                WriteVarBytes(output, bytes.Value);
                return true;

            case HeapRef { RefSort: Sort.Buffer } href:
                {
                    var buffer = state.Heap.Get<BufferObject>(href.ObjectId);
                    // Round-2 fix: an OPEN buffer's true length is unknown; serializing only the seeded
                    // prefix cells (which can be empty) emits a wrong-length serialization. Fail closed
                    // (UnknownSyscall) for open buffers.
                    if (buffer.IsSymbolicOpen)
                        return false;
                    var bufferBytes = new byte[buffer.Cells.Count];
                    for (int i = 0; i < buffer.Cells.Count; i++)
                    {
                        if (Expr.ConcreteInt(buffer.Cells[i]) is not { } cell || cell < 0 || cell > 255)
                            return false;
                        bufferBytes[i] = (byte)cell;
                    }

                    output.Add(StackItemTypeCodes.Buffer);
                    WriteVarBytes(output, bufferBytes);
                    return true;
                }

            case HeapRef { RefSort: Sort.Array } href:
                {
                    var array = state.Heap.Get<ArrayObject>(href.ObjectId);
                    if (array.IsSymbolicOpen)
                        return false;
                    output.Add(StackItemTypeCodes.Array);
                    return TryWriteSerializedSequence(state, output, array.Items, depth);
                }

            case HeapRef { RefSort: Sort.Struct } href:
                {
                    var structure = state.Heap.Get<StructObject>(href.ObjectId);
                    output.Add(StackItemTypeCodes.Struct);
                    return TryWriteSerializedSequence(state, output, structure.Fields, depth);
                }

            case HeapRef { RefSort: Sort.Map } href:
                {
                    var map = state.Heap.Get<MapObject>(href.ObjectId);
                    if (map.IsSymbolicOpen)
                        return false;
                    output.Add(StackItemTypeCodes.Map);
                    WriteVarInt(output, map.Entries.Count);
                    foreach (var (key, mapValue) in map.Entries)
                    {
                        if (key.Sort is not (Sort.Bool or Sort.Int or Sort.Bytes))
                            return false;
                        if (!TryWriteSerializedStackItem(state, output, key, depth + 1)
                            || !TryWriteSerializedStackItem(state, output, mapValue, depth + 1))
                        {
                            return false;
                        }
                    }

                    return true;
                }

            default:
                return false;
        }
    }

    private static bool TryWriteSerializedSequence(
        ExecutionState state,
        List<byte> output,
        IReadOnlyList<SymbolicValue> items,
        int depth)
    {
        WriteVarInt(output, items.Count);
        foreach (var item in items)
        {
            if (!TryWriteSerializedStackItem(state, output, item, depth + 1))
                return false;
        }

        return true;
    }

    private static void WriteVarBytes(List<byte> output, byte[] bytes)
    {
        WriteVarInt(output, bytes.Length);
        output.AddRange(bytes);
    }

    private static void WriteVarInt(List<byte> output, int value)
    {
        if (value < 0)
            throw new VmFaultException($"negative VarInt length {value}");

        if (value < 0xFD)
        {
            output.Add((byte)value);
            return;
        }
        if (value <= 0xFFFF)
        {
            output.Add(0xFD);
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)value);
            output.AddRange(buffer.ToArray());
            return;
        }

        output.Add(0xFE);
        Span<byte> wide = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(wide, (uint)value);
        output.AddRange(wide.ToArray());
    }

    private static bool TryReadSerializedStackItem(
        ExecutionState state,
        byte[] bytes,
        ref int offset,
        int depth,
        out SymbolicValue value)
    {
        const int MaxDeserializeDepth = 64;

        value = SymbolicValue.Null();
        if (depth > MaxDeserializeDepth || offset >= bytes.Length)
            return false;

        byte type = bytes[offset++];
        switch (type)
        {
            case StackItemTypeCodes.Any:
                value = SymbolicValue.Null();
                return true;

            case StackItemTypeCodes.Boolean:
                if (!TryReadByte(bytes, ref offset, out byte boolean))
                    return false;
                value = SymbolicValue.Bool(boolean != 0);
                return true;

            case StackItemTypeCodes.Integer:
                if (!TryReadVarBytes(bytes, ref offset, MaxNeoVmIntegerBytes, out var integerBytes))
                    return false;
                value = SymbolicValue.Int(Expr.BytesToInteger(integerBytes));
                return true;

            case StackItemTypeCodes.ByteString:
                if (!TryReadVarBytes(bytes, ref offset, state.Heap.MaxItemSize, out var byteString))
                    return false;
                value = SymbolicValue.Bytes(byteString);
                return true;

            case StackItemTypeCodes.Buffer:
                if (!TryReadVarBytes(bytes, ref offset, state.Heap.MaxItemSize, out var bufferBytes))
                    return false;
                value = SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(bufferBytes).Id);
                return true;

            case StackItemTypeCodes.Array:
                if (!TryReadSerializedSequence(state, bytes, ref offset, depth, out var arrayItems))
                    return false;
                value = SymbolicValue.HeapRef(Sort.Array, state.Heap.NewArray(arrayItems).Id);
                return true;

            case StackItemTypeCodes.Struct:
                if (!TryReadSerializedSequence(state, bytes, ref offset, depth, out var structFields))
                    return false;
                value = SymbolicValue.HeapRef(Sort.Struct, state.Heap.NewStruct(structFields).Id);
                return true;

            case StackItemTypeCodes.Map:
                if (!TryReadSerializedMap(state, bytes, ref offset, depth, out var entries))
                    return false;
                value = SymbolicValue.HeapRef(Sort.Map, state.Heap.NewMap(entries).Id);
                return true;

            default:
                return false;
        }
    }

    private static bool TryReadSerializedSequence(
        ExecutionState state,
        byte[] bytes,
        ref int offset,
        int depth,
        out List<SymbolicValue> items)
    {
        items = new List<SymbolicValue>();
        if (!TryReadVarInt(bytes, ref offset, out int count) || count > state.Heap.MaxCollectionSize)
            return false;

        state.Heap.EnforceCollectionGrowth(count);
        for (int i = 0; i < count; i++)
        {
            if (!TryReadSerializedStackItem(state, bytes, ref offset, depth + 1, out var item))
                return false;
            items.Add(item);
        }

        return true;
    }

    private static bool TryReadSerializedMap(
        ExecutionState state,
        byte[] bytes,
        ref int offset,
        int depth,
        out List<(SymbolicValue Key, SymbolicValue Value)> entries)
    {
        entries = new List<(SymbolicValue Key, SymbolicValue Value)>();
        if (!TryReadVarInt(bytes, ref offset, out int count) || count > state.Heap.MaxCollectionSize)
            return false;

        state.Heap.EnforceCollectionGrowth(count);
        for (int i = 0; i < count; i++)
        {
            if (!TryReadSerializedStackItem(state, bytes, ref offset, depth + 1, out var key)
                || !TryReadSerializedStackItem(state, bytes, ref offset, depth + 1, out var mapValue))
            {
                return false;
            }
            if (key.Sort is Sort.Array or Sort.Struct or Sort.Map or Sort.Pointer or Sort.InteropInterface or Sort.Unknown)
                return false;

            entries.Add((key, mapValue));
        }

        return true;
    }

    private static bool TryReadByte(byte[] bytes, ref int offset, out byte value)
    {
        value = 0;
        if (offset >= bytes.Length)
            return false;

        value = bytes[offset++];
        return true;
    }

    private static bool TryReadVarBytes(
        byte[] bytes,
        ref int offset,
        int maxLength,
        out byte[] value)
    {
        value = System.Array.Empty<byte>();
        if (!TryReadVarInt(bytes, ref offset, out int length) || length > maxLength)
            return false;
        if (length > bytes.Length - offset)
            return false;

        value = new byte[length];
        System.Array.Copy(bytes, offset, value, 0, length);
        offset += length;
        return true;
    }

    private static bool TryReadVarInt(byte[] bytes, ref int offset, out int value)
    {
        value = 0;
        if (!TryReadByte(bytes, ref offset, out byte first))
            return false;

        ulong result;
        if (first < 0xFD)
        {
            result = first;
        }
        else if (first == 0xFD)
        {
            if (bytes.Length - offset < 2)
                return false;
            result = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
            offset += 2;
            if (result < 0xFD)
                return false;
        }
        else if (first == 0xFE)
        {
            if (bytes.Length - offset < 4)
                return false;
            result = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;
            if (result <= 0xFFFF)
                return false;
        }
        else
        {
            if (bytes.Length - offset < 8)
                return false;
            result = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));
            offset += 8;
            if (result <= 0xFFFFFFFF)
                return false;
        }

        if (result > int.MaxValue)
            return false;

        value = (int)result;
        return true;
    }

    private static bool TryGetIteratorKnownEntryRefs(
        ExecutionState state,
        SymbolicValue iterator,
        out List<SymbolicValue> entries)
    {
        entries = new List<SymbolicValue>();
        if (iterator.Expression is not Symbol { Name: var name }
            || !state.InteropContext.TryGetValue($"iterator_known_entries:{name}", out var value)
            || value.Expression is not HeapRef { RefSort: Sort.Array } entriesRef)
            return false;

        var array = state.Heap.Get<ArrayObject>(entriesRef.ObjectId);
        entries.AddRange(array.Items);
        return entries.Count > 0;
    }

    private static bool HasCurrentIteratorEntry(ExecutionState state, SymbolicValue iterator) =>
        iterator.Expression is Symbol { Name: var name }
        && state.InteropContext.ContainsKey($"iterator_current_entry:{name}");

    private static bool TryGetCurrentIteratorEntry(
        ExecutionState state,
        SymbolicValue iterator,
        out SymbolicValue key,
        out SymbolicValue value)
    {
        key = SymbolicValue.Null();
        value = SymbolicValue.Null();
        if (iterator.Expression is not Symbol { Name: var name }
            || !state.InteropContext.TryGetValue($"iterator_current_entry:{name}", out var entry)
            || entry.Expression is not HeapRef { RefSort: Sort.Struct } entryRef)
            return false;

        var fields = state.Heap.Get<StructObject>(entryRef.ObjectId).Fields;
        if (fields.Count != 2)
            return false;

        key = fields[0];
        value = fields[1];
        return true;
    }

    private static bool TryGetIteratorFindPrefix(
        ExecutionState state,
        SymbolicValue iterator,
        out SymbolicValue prefix)
    {
        if (iterator.Expression is Symbol { Name: var name }
            && state.InteropContext.TryGetValue($"iterator_prefix:{name}", out var found))
        {
            prefix = found;
            return true;
        }

        prefix = SymbolicValue.Null();
        return false;
    }

    private static bool TryGetIteratorFindOptions(
        ExecutionState state,
        SymbolicValue iterator,
        out SymbolicValue options)
    {
        if (iterator.Expression is Symbol { Name: var name }
            && state.InteropContext.TryGetValue($"iterator_options:{name}", out var found))
        {
            options = found;
            return true;
        }

        options = SymbolicValue.Null();
        return false;
    }

    private static void EnforceFindOptions(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue options)
    {
        if (options.IsConcreteNull)
            throw new VmFaultException($"{operation} with null FindOptions");

        if (Expr.ConcreteInt(options.Expression) is { } concreteOptions)
        {
            if (!IsValidFindOptions(concreteOptions))
                throw new VmFaultException($"{operation} with invalid FindOptions {concreteOptions}");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            InvalidFindOptionsCondition(options.Expression),
            "FindOptions must use only Neo-supported flags and combinations",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceCheckMultisigArguments(
        ExecutionState state,
        Instruction inst,
        SymbolicValue pubKeys,
        SymbolicValue signatures)
    {
        if (pubKeys.IsConcreteNull)
            throw new VmFaultException("CheckMultisig with null public keys");
        if (signatures.IsConcreteNull)
            throw new VmFaultException("CheckMultisig with null signatures");
        if (pubKeys.Expression is not HeapRef pubKeysRef
            || state.Heap.Get(pubKeysRef.ObjectId) is not ArrayObject pubKeysArray
            || signatures.Expression is not HeapRef signaturesRef
            || state.Heap.Get(signaturesRef.ObjectId) is not ArrayObject signaturesArray)
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return;
        }

        int publicKeyCount = pubKeysArray.Items.Count;
        int signatureCount = signaturesArray.Items.Count;
        if (publicKeyCount == 0)
            throw new VmFaultException("CheckMultisig public keys array cannot be empty");
        if (signatureCount == 0)
            throw new VmFaultException("CheckMultisig signatures array cannot be empty");
        if (signatureCount > publicKeyCount)
        {
            throw new VmFaultException(
                $"CheckMultisig signatures count {signatureCount} exceeds public keys count {publicKeyCount}");
        }

        foreach (var publicKey in pubKeysArray.Items)
            EnforcePublicKeyEncoding(state, inst, "CheckMultisig", publicKey);
        foreach (var signature in signaturesArray.Items)
            EnforceSignatureLength(state, inst, "CheckMultisig", signature);
    }

    private static bool IsValidFindOptions(BigInteger options)
    {
        if ((options & ~FindOptionsAll) != 0)
            return false;

        bool keysOnly = HasFindOption(options, FindOptionsKeysOnly);
        bool removePrefix = HasFindOption(options, FindOptionsRemovePrefix);
        bool valuesOnly = HasFindOption(options, FindOptionsValuesOnly);
        bool deserializeValues = HasFindOption(options, FindOptionsDeserializeValues);
        bool pickField0 = HasFindOption(options, FindOptionsPickField0);
        bool pickField1 = HasFindOption(options, FindOptionsPickField1);

        if (keysOnly && (valuesOnly || deserializeValues || pickField0 || pickField1))
            return false;
        if (valuesOnly && removePrefix)
            return false;
        if (pickField0 && pickField1)
            return false;
        if ((pickField0 || pickField1) && !deserializeValues)
            return false;
        return true;
    }

    private static bool HasFindOption(BigInteger options, int flag) =>
        (options & flag) != 0;

    private static Expression InvalidFindOptionsCondition(Expression options)
    {
        Expression invalid = BoolConst.True;
        foreach (int valid in ValidFindOptionsValues)
            invalid = Expr.BoolAnd(invalid, Expr.Ne(options, Expr.Int(valid)));
        return invalid;
    }

    private static int[] BuildValidFindOptionsValues()
    {
        var values = new List<int>();
        for (int value = 0; value <= FindOptionsAll; value++)
        {
            if (IsValidFindOptions(value))
                values.Add(value);
        }
        return values.ToArray();
    }

    private IEnumerable<ExecutionState> HandleContractCall(ExecutionState state, Instruction inst)
    {
        // Stack (top-down): args[], callFlags, method, hash.
        var args = state.Pop();
        var callFlags = state.Pop();
        var method = state.Pop();
        var hash = state.Pop();

        EnforceContractCallTargetHash(state, inst, hash);
        EnforceCallFlagsRange(state, inst, "Contract.Call", callFlags);
        EnforceContractCallMethodName(state, inst, method);
        EnforceContractCallArgsArray(state, inst, args);

        int? concreteCallFlags = callFlags.AsConcreteInt() is { } cf ? (int)cf : null;
        var ext = new ExternalCall
        {
            Offset = inst.Offset,
            TargetHash = hash,
            MethodArg = method,
            Method = method.AsConcreteBytes() is byte[] mb
                ? System.Text.Encoding.UTF8.GetString(mb)
                : "<dynamic>",
            TargetHashDynamic = !hash.IsConcrete,
            MethodDynamic = !method.IsConcrete,
            CallFlags = concreteCallFlags is { } flags ? flags & state.CurrentCallFlags : 0,
            CallFlagsDynamic = !callFlags.IsConcrete,
            HasReturnValue = true,
        };
        bool hasClosedArgumentArray = TryGetClosedContractCallArguments(state, args, out var closedArgs);
        ext.ArgumentsDynamic = !hasClosedArgumentArray;
        if (hasClosedArgumentArray)
        {
            foreach (var a in closedArgs) ext.Args.Add(a);
        }

        if (hasClosedArgumentArray
            && TryExecuteContractSelfCall(
                state,
                inst,
                ext,
                closedArgs,
                ContractSelfCallResultMode.ContractCall,
                out var selfCallStates))
        {
            return selfCallStates;
        }

        state.Telemetry.ExternalCalls.Add(ext);
        if (TryHandleContractManagementGetContractNativeCall(state, inst, ext, out var getContractStates))
            return getContractStates;
        if (TryHandleContractManagementGetContractByIdNativeCall(state, inst, ext, out var getContractByIdStates))
            return getContractByIdStates;
        if (TryHandleContractManagementGetContractHashesNativeCall(state, inst, ext, out var getContractHashesStates))
            return getContractHashesStates;
        if (TryHandleContractManagementHasMethodNativeCall(state, inst, ext, out var hasMethodStates))
            return hasMethodStates;
        if (TryHandleContractManagementIsContractNativeCall(state, inst, ext, out var isContractStates))
            return isContractStates;
        if (TryHandleContractManagementLifecycleNativeCall(state, inst, ext, out var lifecycleStates))
            return lifecycleStates;
        if (TryHandleOracleRequestNativeCall(state, inst, ext, out var oracleRequestStates))
            return oracleRequestStates;
        if (TryHandleNativeTokenTransferNativeCall(state, inst, ext, out var nativeTokenTransferStates))
            return nativeTokenTransferStates;
        if (TryHandleLedgerGetBlockNativeCall(state, inst, ext, out var blockStates))
            return blockStates;
        if (TryHandleLedgerGetTransactionFromBlockNativeCall(state, inst, ext, out var transactionFromBlockStates))
            return transactionFromBlockStates;
        if (TryHandleLedgerGetTransactionNativeCall(state, inst, ext, out var transactionStates))
            return transactionStates;
        if (TryHandleLedgerGetTransactionSignersNativeCall(state, inst, ext, out var transactionSignersStates))
            return transactionSignersStates;
        if (TryHandleNativeTokenGetAccountStateNativeCall(state, inst, ext, out var accountStateStates))
            return accountStateStates;
        if (TryHandleCryptoLibRecoverSecp256K1NativeCall(state, inst, ext, out var recoverSecp256K1States))
            return recoverSecp256K1States;

        if (TryHandlePureNativeCall(state, inst, ext, out var nativeReturn))
        {
            ext.ReturnModeledNative = true;
            state.Push(WithExternalReturnProvenance(nativeReturn, inst.Offset));
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        // Push a tagged return symbol so consumers can flag return-checks via expression flow.
        state.Push(SymbolicValue.Symbol(Sort.Unknown, $"ext_ret_{inst.Offset}"));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static void EnforceContractCallArgsArray(
        ExecutionState state,
        Instruction inst,
        SymbolicValue args)
    {
        if (args.Expression is HeapRef href && state.Heap.Get(href.ObjectId) is ArrayObject)
            return;

        if (args.Sort == Sort.Unknown)
        {
            var invalidType = Expr.Sym(
                Sort.Bool,
                state.NextFreshSymbolName($"invalid_contract_call_args_type_{inst.Offset}"));
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "Contract.Call",
                invalidType,
                "args may be a non-Array StackItem before Contract.Call argument conversion",
                "VM syscall precondition holds under requires"));
            return;
        }

        throw new VmFaultException($"Contract.Call args must be Array, got {args.Sort}");
    }

    private static bool TryHandleContractManagementGetContractNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!IsContractManagementCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getContract", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureReturningNativeMethodTokenShape(call, "ContractManagement.getContract", "Contract");
        EnsureExternalCallFlags(call, "ContractManagement.getContract", NeoCallFlags.ReadStates);
        EnforceUInt160Argument(state, inst, "ContractManagement.getContract", call.Args[0]);

        call.ReturnModeledNative = true;
        var target = call.Args[0];
        string cacheKey = ContractManagementIsContractCacheKey(target);
        if (state.InteropContext.TryGetValue(cacheKey, out var cachedExists)
            && cachedExists.AsConcreteBool() is { } exists)
        {
            state.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: exists));
            if (exists)
            {
                byte[] cachedPayload = target.AsConcreteBytes() ?? Array.Empty<byte>();
                var cachedContract = SymbolicValue.HeapRef(
                    Sort.InteropInterface,
                    state.Heap.NewInterop("contract", cachedPayload).Id);
                state.Push(WithExternalReturnProvenance(cachedContract, inst.Offset));
            }
            else
            {
                state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
            }

            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        present.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: true));
        present.InteropContext[cacheKey] = SymbolicValue.Bool(true);
        byte[] payload = target.AsConcreteBytes() ?? Array.Empty<byte>();
        var contract = SymbolicValue.HeapRef(
            Sort.InteropInterface,
            present.Heap.NewInterop("contract", payload).Id);
        present.Push(WithExternalReturnProvenance(contract, inst.Offset));
        present.Pc = inst.EndOffset;

        state.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: false));
        state.InteropContext[cacheKey] = SymbolicValue.Bool(false);
        state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleContractManagementGetContractByIdNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!IsContractManagementCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getContractById", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "ContractManagement.getContractById", NeoCallFlags.ReadStates);
        EnsureReturningNativeMethodTokenShape(call, "ContractManagement.getContractById", "Contract");
        EnforceInt32Argument(state, inst, "ContractManagement.getContractById", "contract id", call.Args[0]);
        call.ReturnModeledNative = true;

        var present = state.Clone();
        var contract = SymbolicValue.HeapRef(
            Sort.InteropInterface,
            present.Heap.NewInterop("contract", ContractIdInteropPayload(call.Args[0])).Id);
        present.Push(WithExternalReturnProvenance(contract, inst.Offset));
        present.Pc = inst.EndOffset;

        state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleContractManagementGetContractHashesNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsContractManagementCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getContractHashes", StringComparison.Ordinal)
            || call.Args.Count != 0)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "ContractManagement.getContractHashes", NeoCallFlags.ReadStates);
        call.ReturnModeledNative = true;

        var iterator = SymbolicValue.Symbol(Sort.InteropInterface, $"iterator_contract_hashes_{inst.Offset}");
        RememberIteratorFind(
            state,
            iterator,
            SymbolicValue.Bytes(new[] { ContractManagementContractHashPrefix }),
            SymbolicValue.Int(FindOptionsRemovePrefix),
            Array.Empty<(SymbolicValue Key, SymbolicValue Value)>());
        state.Push(WithExternalReturnProvenance(iterator, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { state };
        return true;
    }

    private static bool TryHandleContractManagementIsContractNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsContractManagementCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "isContract", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "ContractManagement.isContract", NeoCallFlags.ReadStates);
        EnforceUInt160Argument(state, inst, "ContractManagement.isContract", call.Args[0]);
        call.ReturnModeledNative = true;

        var target = call.Args[0];
        string cacheKey = ContractManagementIsContractCacheKey(target);
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        present.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: true));
        var exists = SymbolicValue.Bool(true);
        present.InteropContext[cacheKey] = exists;
        present.Push(WithExternalReturnProvenance(exists, inst.Offset));
        present.Pc = inst.EndOffset;

        state.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: false));
        var missing = SymbolicValue.Bool(false);
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleContractManagementHasMethodNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsContractManagementCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "hasMethod", StringComparison.Ordinal)
            || call.Args.Count != 3)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "ContractManagement.hasMethod", NeoCallFlags.ReadStates);
        EnforceUInt160Argument(state, inst, "ContractManagement.hasMethod", call.Args[0]);
        EnforceStrictUtf8Argument(state, inst, "ContractManagement.hasMethod", "method name", call.Args[1]);
        EnforceNonNegativeInt32Argument(state, inst, "ContractManagement.hasMethod", "parameter count", call.Args[2]);
        call.ReturnModeledNative = true;

        var target = call.Args[0];
        string existenceCacheKey = ContractManagementIsContractCacheKey(target);
        string hasMethodCacheKey = ContractManagementHasMethodCacheKey(call);

        if (state.InteropContext.TryGetValue(hasMethodCacheKey, out var cached))
        {
            if (cached.AsConcreteBool() == true)
                state.InteropContext[existenceCacheKey] = SymbolicValue.Bool(true);
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        if (state.InteropContext.TryGetValue(existenceCacheKey, out var cachedExists)
            && cachedExists.AsConcreteBool() == false)
        {
            var missing = SymbolicValue.Bool(false);
            state.InteropContext[hasMethodCacheKey] = missing;
            state.Push(WithExternalReturnProvenance(missing, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var presentWithMethod = state.Clone();
        presentWithMethod.Telemetry.ContractExistenceQueries.Add(new ContractExistenceQuery(inst.Offset, target, Exists: true));
        var hasMethod = SymbolicValue.Bool(true);
        presentWithMethod.InteropContext[existenceCacheKey] = SymbolicValue.Bool(true);
        presentWithMethod.InteropContext[hasMethodCacheKey] = hasMethod;
        presentWithMethod.Push(WithExternalReturnProvenance(hasMethod, inst.Offset));
        presentWithMethod.Pc = inst.EndOffset;

        var noMethod = SymbolicValue.Bool(false);
        state.InteropContext[hasMethodCacheKey] = noMethod;
        state.Push(WithExternalReturnProvenance(noMethod, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { presentWithMethod, state };
        return true;
    }

    private static string ContractManagementIsContractCacheKey(SymbolicValue target)
    {
        string targetSuffix = NativeBalanceAccountSuffix(target);
        return $"contract-management:isContract:{targetSuffix}";
    }

    private static string ContractManagementHasMethodCacheKey(ExternalCall call)
    {
        string targetSuffix = NativeBalanceAccountSuffix(call.Args[0]);
        string methodSuffix = NativeStringArgumentSuffix(call.Args[1], "dynamic_method");
        string parameterCountSuffix = NativeIntegerArgumentSuffix(call.Args[2], "dynamic_params");
        return $"native-contract-management:hasMethod:{targetSuffix}:{methodSuffix}:{parameterCountSuffix}";
    }

    private static bool TryHandleContractManagementLifecycleNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!IsContractManagementCall(call)
            || call.CallFlagsDynamic)
        {
            return false;
        }

        switch (call.Method)
        {
            case "deploy":
                if (call.Args.Count is not (2 or 3))
                    return false;
                EnsureReturningNativeMethodTokenShape(call, "ContractManagement.deploy", "Contract");
                EnsureExternalCallFlags(call, "ContractManagement.deploy", NeoCallFlags.All);
                EnforceContractManagementDeployArgument(
                    state,
                    inst,
                    "ContractManagement.deploy",
                    "NEF file",
                    call.Args[0]);
                EnforceContractManagementDeployArgument(
                    state,
                    inst,
                    "ContractManagement.deploy",
                    "manifest",
                    call.Args[1],
                    strictUtf8: true);

                var contract = SymbolicValue.HeapRef(
                    Sort.InteropInterface,
                    state.Heap.NewInterop("contract", Array.Empty<byte>()).Id);
                state.Push(WithExternalReturnProvenance(contract, inst.Offset));
                state.Pc = inst.EndOffset;
                states = new[] { state };
                return true;
            case "update":
                if (call.Args.Count is not (2 or 3))
                    return false;
                EnsureVoidNativeMethodTokenShape(call, "ContractManagement.update");
                EnsureExternalCallFlags(call, "ContractManagement.update", NeoCallFlags.All);
                EnforceContractManagementUpdateArgument(
                    state,
                    inst,
                    "ContractManagement.update",
                    "NEF file",
                    call.Args[0]);
                EnforceContractManagementUpdateArgument(
                    state,
                    inst,
                    "ContractManagement.update",
                    "manifest",
                    call.Args[1],
                    strictUtf8: true);
                EnforceContractManagementUpdateHasPayload(state, inst, call.Args[0], call.Args[1]);
                break;
            case "destroy":
                if (call.Args.Count != 0)
                    return false;
                EnsureVoidNativeMethodTokenShape(call, "ContractManagement.destroy");
                EnsureExternalCallFlags(call, "ContractManagement.destroy", NeoCallFlags.States | NeoCallFlags.AllowNotify);
                break;
            default:
                return false;
        }

        call.HasReturnValue = false;
        state.Pc = inst.EndOffset;
        if (!call.ReturnValueDeclaredByMethodToken)
            state.Push(SymbolicValue.Null());

        states = new[] { state };
        return true;
    }

    private static bool TryHandleOracleRequestNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!IsOracleCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "request", StringComparison.Ordinal)
            || call.Args.Count != 5)
        {
            return false;
        }

        EnsureVoidNativeMethodTokenShape(call, "Oracle.request");
        EnsureExternalCallFlags(call, "Oracle.request", NeoCallFlags.States | NeoCallFlags.AllowNotify);
        EnforceOracleRequestStringArgument(state, inst, "url", call.Args[0], MaxOracleUrlLength, allowNull: false);
        EnforceOracleRequestStringArgument(state, inst, "filter", call.Args[1], MaxOracleFilterLength, allowNull: true);
        EnforceOracleRequestStringArgument(
            state,
            inst,
            "callback",
            call.Args[2],
            MaxOracleCallbackLength,
            allowNull: false,
            rejectLeadingUnderscore: true);
        EnforceOracleRequestUserDataSize(state, inst, call.Args[3]);
        EnforceInt64AtLeastArgument(
            state,
            inst,
            "Oracle.request",
            "gasForResponse",
            call.Args[4],
            MinOracleGasForResponse);

        call.HasReturnValue = false;
        state.Pc = inst.EndOffset;
        if (!call.ReturnValueDeclaredByMethodToken)
            state.Push(SymbolicValue.Null());

        states = new[] { state };
        return true;
    }

    private static bool TryHandleNativeTokenTransferNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = System.Array.Empty<ExecutionState>();
        if (!TryGetNativeToken(call, out var token)
            || !string.Equals(call.Method, "transfer", StringComparison.Ordinal))
        {
            return false;
        }

        if (call.CallFlagsDynamic)
            return false;
        if (call.Args.Count != 4)
            return false;

        string operation = $"{token.Symbol}.transfer";
        EnsureExternalCallFlags(call, operation, NeoCallFlags.All);
        EnsureReturningNativeMethodTokenShape(call, operation, "Boolean");
        EnforceUInt160Argument(state, inst, operation, call.Args[0]);
        EnforceUInt160Argument(state, inst, operation, call.Args[1]);
        EnforceNonNegativeIntegerArgument(state, inst, operation, "amount", call.Args[2]);

        call.ReturnModeledNative = true;
        var returnValue = WithExternalReturnProvenance(
            SymbolicValue.Symbol(Sort.Bool, $"ext_ret_{inst.Offset}"),
            inst.Offset);

        var success = state.Clone();
        RecordNativeTokenTransferNotification(success, inst, call);
        success.PathConditions = success.PathConditions.Add(Expr.ToBool(returnValue.Expression));
        success.Push(returnValue);
        success.Pc = inst.EndOffset;

        state.PathConditions = state.PathConditions.Add(Expr.Not(Expr.ToBool(returnValue.Expression)));
        state.Push(returnValue);
        state.Pc = inst.EndOffset;
        states = new[] { success, state };
        return true;
    }

    private static void RecordNativeTokenTransferNotification(
        ExecutionState state,
        Instruction inst,
        ExternalCall call)
    {
        var payload = state.Heap.NewArray(new[]
        {
            call.Args[0],
            call.Args[1],
            call.Args[2],
        });
        state.Telemetry.Notifications.Add(new RuntimeNotification(
            inst.Offset,
            call.TargetHash!,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("Transfer")),
            SymbolicValue.HeapRef(Sort.Array, payload.Id),
            "Transfer"));
    }

    private static void EnsureVoidNativeMethodTokenShape(ExternalCall call, string operation)
    {
        if (call.ReturnValueDeclaredByMethodToken && call.HasReturnValue)
            throw new VmFaultException($"CALLT MethodToken for {operation} declares a return value, but the native method is Void");
    }

    private static void EnsureReturningNativeMethodTokenShape(ExternalCall call, string operation, string returnType)
    {
        if (call.ReturnValueDeclaredByMethodToken && !call.HasReturnValue)
            throw new VmFaultException($"CALLT MethodToken for {operation} declares no return value, but the native method returns {returnType}");
    }

    private static void EnsureModeledNativeMethodTokenReturnShape(ExternalCall call)
    {
        if (!call.ReturnValueDeclaredByMethodToken || call.HasReturnValue)
            return;
        if (TryGetModeledNativeReturnShape(call, out var operation, out var returnType))
            EnsureReturningNativeMethodTokenShape(call, operation, returnType);
    }

    private static bool TryGetModeledNativeReturnShape(
        ExternalCall call,
        out string operation,
        out string returnType)
    {
        operation = "";
        returnType = "";

        if (IsContractManagementCall(call))
        {
            operation = $"ContractManagement.{call.Method}";
            returnType = call.Method switch
            {
                "getContract" or "getContractById" or "deploy" => "Contract",
                "getContractHashes" => "StorageIterator",
                "isContract" or "hasMethod" => "Boolean",
                "getMinimumDeploymentFee" => "Integer",
                _ => "",
            };
            return returnType.Length > 0;
        }

        if (IsLedgerCall(call))
        {
            operation = $"Ledger.{call.Method}";
            returnType = call.Method switch
            {
                "currentIndex" => "UInt32",
                "currentHash" or "getBlockHash" => "UInt256",
                "getBlock" => "Block",
                "getTransaction" or "getTransactionFromBlock" => "Transaction",
                "getTransactionHeight" => "Integer",
                "getTransactionSigners" => "Signer[]",
                "getTransactionVMState" => "VMState",
                _ => "",
            };
            return returnType.Length > 0;
        }

        if (TryGetNativeToken(call, out var token))
        {
            operation = $"{token.Symbol}.{call.Method}";
            if (string.Equals(call.Method, "transfer", StringComparison.Ordinal))
            {
                returnType = "Boolean";
                return true;
            }

            if (!IsModeledNativeTokenReadOnlyMethod(call.Method))
                return false;

            returnType = call.Method switch
            {
                "symbol" => "String",
                "decimals" or "totalSupply" or "balanceOf" or "getRegisterPrice"
                    or "getGasPerBlock" or "unclaimedGas" or "getCandidateVote" => "Integer",
                "getCommitteeAddress" => "UInt160",
                "getAccountState" => "NeoAccountState",
                "getCandidates" or "getCommittee" or "getNextBlockValidators" => "Array",
                _ => "value",
            };
            return true;
        }

        if (IsPolicyCall(call))
        {
            operation = $"Policy.{call.Method}";
            returnType = call.Method switch
            {
                "isBlocked" => "Boolean",
                "getFeePerByte" or "getExecFeeFactor" or "getStoragePrice" or "getAttributeFee" => "Integer",
                _ => "",
            };
            return returnType.Length > 0;
        }

        if (IsRoleManagementCall(call))
        {
            operation = $"RoleManagement.{call.Method}";
            returnType = call.Method == "getDesignatedByRole" ? "Array" : "";
            return returnType.Length > 0;
        }

        if (IsOracleCall(call))
        {
            operation = $"Oracle.{call.Method}";
            returnType = call.Method == "getPrice" ? "Integer" : "";
            return returnType.Length > 0;
        }

        if (IsStdLibCall(call))
        {
            operation = $"StdLib.{call.Method}";
            returnType = call.Method switch
            {
                "memoryCompare" or "memorySearch" or "strLen" or "atoi" => "Integer",
                "stringSplit" => "Array",
                "deserialize" or "jsonDeserialize" => "StackItem",
                _ when call.Method is "serialize" or "jsonSerialize" || IsStdLibScalarMethod(call.Method) => "ByteString",
                _ => "",
            };
            return returnType.Length > 0;
        }

        if (IsCryptoLibCall(call))
        {
            operation = $"CryptoLib.{call.Method}";
            returnType = call.Method switch
            {
                "verifyWithEd25519" or "verifyWithECDsa" or "bls12381Equal" => "Boolean",
                "recoverSecp256K1" => "PublicKey",
                "bls12381Deserialize" or "bls12381Add" or "bls12381Mul" or "bls12381Pairing" => "InteropInterface",
                _ when IsCryptoLibSingleBytesHashMethod(call.Method)
                    || call.Method == "murmur32"
                    || call.Method == "bls12381Serialize" => "ByteString",
                _ => "",
            };
            return returnType.Length > 0;
        }

        return false;
    }

    private static bool TryHandleLedgerGetTransactionSignersNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsLedgerCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getTransactionSigners", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "Ledger.getTransactionSigners", NeoCallFlags.ReadStates);
        EnforceUInt256Argument(state, inst, "Ledger.getTransactionSigners", call.Args[0]);
        call.ReturnModeledNative = true;

        string transactionHashSuffix = NativeBytesArgumentSuffix(call.Args[0], "dynamic_transaction_hash");
        string cacheKey = $"ledger:getTransactionSigners:{transactionHashSuffix}";
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        var signers = BuildSignerArray(
            present,
            $"ledger_transaction_signer_{transactionHashSuffix}",
            minCount: 1);
        present.InteropContext[cacheKey] = signers;
        present.Push(WithExternalReturnProvenance(signers, inst.Offset));
        present.Pc = inst.EndOffset;

        var missing = SymbolicValue.Null();
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleLedgerGetBlockNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsLedgerCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getBlock", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "Ledger.getBlock", NeoCallFlags.ReadStates);
        call.ReturnModeledNative = true;

        var query = call.Args[0];
        string querySuffix;
        string queryKind;
        SymbolicValue blockHash;
        SymbolicValue blockIndex;

        if (query.Sort == Sort.Int)
        {
            EnforceUInt32Argument(state, inst, "Ledger.getBlock", "block index", query);
            querySuffix = NativeIntegerArgumentSuffix(query, "dynamic_block_index");
            queryKind = "index";
            blockIndex = query;
            blockHash = StableRuntimeBytes(state, $"ledger_block_{queryKind}_{querySuffix}_hash", exactLength: Hash256Length);
        }
        else
        {
            EnforceUInt256Argument(state, inst, "Ledger.getBlock", query);
            querySuffix = NativeBytesArgumentSuffix(query, "dynamic_block_hash");
            queryKind = "hash";
            blockHash = query;
            blockIndex = StableRuntimeInt(state, $"ledger_block_{queryKind}_{querySuffix}_index", min: 0, max: UInt32MaxValue);
        }

        string cacheKey = $"ledger:getBlock:{queryKind}:{querySuffix}";
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        var currentIndex = StableLedgerCurrentIndex(present);
        present.PathConditions = present.PathConditions
            .Add(Expr.Ge(blockIndex.Expression, Expr.Int(0)))
            .Add(Expr.Le(blockIndex.Expression, currentIndex.Expression));
        var block = BuildBlockStruct(
            present,
            blockHash,
            blockIndex,
            $"ledger_block_{querySuffix}");
        present.InteropContext[cacheKey] = block;
        present.Push(WithExternalReturnProvenance(block, inst.Offset));
        present.Pc = inst.EndOffset;

        var missing = SymbolicValue.Null();
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleLedgerGetTransactionFromBlockNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsLedgerCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getTransactionFromBlock", StringComparison.Ordinal)
            || call.Args.Count != 2)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "Ledger.getTransactionFromBlock", NeoCallFlags.ReadStates);
        EnforceNonNegativeInt32Argument(state, inst, "Ledger.getTransactionFromBlock", "transaction index", call.Args[1]);
        call.ReturnModeledNative = true;

        var blockReference = call.Args[0];
        var transactionIndex = call.Args[1];
        string blockReferenceKind;
        string blockReferenceSuffix;

        if (blockReference.Sort == Sort.Int)
        {
            EnforceUInt32Argument(
                state,
                inst,
                "Ledger.getTransactionFromBlock",
                "block height",
                blockReference);
            blockReferenceKind = "height";
            blockReferenceSuffix = NativeIntegerArgumentSuffix(blockReference, "dynamic_block_height");
        }
        else
        {
            EnforceUInt256Argument(state, inst, "Ledger.getTransactionFromBlock", blockReference);
            blockReferenceKind = "hash";
            blockReferenceSuffix = NativeBytesArgumentSuffix(blockReference, "dynamic_block_hash");
        }

        var transactionCount = StableRuntimeInt(
            state,
            $"ledger_block_{blockReferenceKind}_{blockReferenceSuffix}_transactions_count",
            min: 0,
            max: Int32MaxValue);
        EnforceIntegerLessThanExpressionArgument(
            state,
            inst,
            "Ledger.getTransactionFromBlock",
            "transaction index",
            transactionIndex,
            transactionCount.Expression,
            "number of transactions in the block");

        string transactionIndexSuffix = NativeIntegerArgumentSuffix(transactionIndex, "dynamic_transaction_index");
        string cacheKey =
            $"ledger:getTransactionFromBlock:{blockReferenceKind}:{blockReferenceSuffix}:{transactionIndexSuffix}";
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        string transactionPrefix = $"ledger_transaction_from_block_{blockReferenceSuffix}_{transactionIndexSuffix}";
        var transactionHash = StableRuntimeBytes(present, $"{transactionPrefix}_hash", exactLength: Hash256Length);
        var transaction = BuildTransactionStruct(present, transactionHash, transactionPrefix);
        present.PathConditions = present.PathConditions
            .Add(Expr.Ge(transactionIndex.Expression, Expr.Int(0)))
            .Add(Expr.Lt(transactionIndex.Expression, transactionCount.Expression));
        if (blockReference.Sort == Sort.Int)
        {
            var currentIndex = StableLedgerCurrentIndex(present);
            present.PathConditions = present.PathConditions.Add(Expr.Le(blockReference.Expression, currentIndex.Expression));
        }

        present.InteropContext[cacheKey] = transaction;
        present.Push(WithExternalReturnProvenance(transaction, inst.Offset));
        present.Pc = inst.EndOffset;

        var missing = SymbolicValue.Null();
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleLedgerGetTransactionNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !IsLedgerCall(call)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getTransaction", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "Ledger.getTransaction", NeoCallFlags.ReadStates);
        EnforceUInt256Argument(state, inst, "Ledger.getTransaction", call.Args[0]);
        call.ReturnModeledNative = true;

        var transactionHash = call.Args[0];
        string transactionHashSuffix = NativeBytesArgumentSuffix(transactionHash, "dynamic_transaction_hash");
        string cacheKey = $"ledger:getTransaction:{transactionHashSuffix}";
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var present = state.Clone();
        var transaction = BuildTransactionStruct(
            present,
            transactionHash,
            $"ledger_transaction_{transactionHashSuffix}");
        present.InteropContext[cacheKey] = transaction;
        present.Push(WithExternalReturnProvenance(transaction, inst.Offset));
        present.Pc = inst.EndOffset;

        var missing = SymbolicValue.Null();
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { present, state };
        return true;
    }

    private static bool TryHandleNativeTokenGetAccountStateNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!call.HasReturnValue
            || !TryGetNativeToken(call, out var token)
            || !string.Equals(token.Symbol, "NEO", StringComparison.Ordinal)
            || call.CallFlagsDynamic
            || !string.Equals(call.Method, "getAccountState", StringComparison.Ordinal)
            || call.Args.Count != 1)
        {
            return false;
        }

        EnsureExternalCallFlags(call, "NEO.getAccountState", NeoCallFlags.ReadStates);
        EnforceUInt160Argument(state, inst, "NEO.getAccountState", call.Args[0]);
        call.ReturnModeledNative = true;

        string accountSuffix = NativeBalanceAccountSuffix(call.Args[0]);
        string cacheKey = $"native-neo:getAccountState:{accountSuffix}";
        if (state.InteropContext.TryGetValue(cacheKey, out var cached))
        {
            state.Push(WithExternalReturnProvenance(cached, inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        var noVote = state.Clone();
        var voted = state.Clone();

        var noVoteAccountState = BuildNeoAccountStateValue(noVote, accountSuffix, token.FixedTotalSupply, SymbolicValue.Null());
        noVote.InteropContext[cacheKey] = noVoteAccountState;
        noVote.Push(WithExternalReturnProvenance(noVoteAccountState, inst.Offset));
        noVote.Pc = inst.EndOffset;

        var votedAccountState = BuildNeoAccountStateValue(
            voted,
            accountSuffix,
            token.FixedTotalSupply,
            StableRuntimeEcPoint(voted, $"neo_account_state_voteTo_{accountSuffix}"));
        voted.InteropContext[cacheKey] = votedAccountState;
        voted.Push(WithExternalReturnProvenance(votedAccountState, inst.Offset));
        voted.Pc = inst.EndOffset;

        var missing = SymbolicValue.Null();
        state.InteropContext[cacheKey] = missing;
        state.Push(WithExternalReturnProvenance(missing, inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { noVote, voted, state };
        return true;
    }

    private static SymbolicValue BuildNeoAccountStateValue(
        ExecutionState state,
        string accountSuffix,
        long? balanceMax,
        SymbolicValue voteTo)
    {
        var accountState = state.Heap.NewStruct(new[]
        {
            StableNativeTokenInt(
                state,
                $"neo:getAccountState:balance:{accountSuffix}",
                $"native_neo_getAccountState_balance_{accountSuffix}",
                min: 0,
                max: balanceMax),
            StableNativeTokenInt(
                state,
                $"neo:getAccountState:height:{accountSuffix}",
                $"native_neo_getAccountState_height_{accountSuffix}",
                min: 0),
            voteTo,
            StableNativeTokenInt(
                state,
                $"neo:getAccountState:lastGasPerVote:{accountSuffix}",
                $"native_neo_getAccountState_lastGasPerVote_{accountSuffix}",
                min: 0),
        });
        return SymbolicValue.HeapRef(Sort.Struct, accountState.Id);
    }

    private bool TryExecuteContractSelfCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        IReadOnlyList<SymbolicValue> args,
        ContractSelfCallResultMode resultMode,
        out IEnumerable<ExecutionState> modeled)
    {
        modeled = System.Array.Empty<ExecutionState>();
        if (_options.SelfCallResolver is null
            || call.CallFlagsDynamic
            || call.MethodDynamic
            || string.IsNullOrWhiteSpace(call.Method)
            || call.Method == "<dynamic>"
            || call.TargetHash is null
            || !IsCurrentExecutingScriptHashValue(state, call.TargetHash))
        {
            return false;
        }

        var target = _options.SelfCallResolver(call.Method, args.Count);
        if (target is null)
            return false;
        if (resultMode == ContractSelfCallResultMode.MethodToken
            && call.HasReturnValue != target.HasReturnValue)
        {
            string tokenShape = call.HasReturnValue ? "return value" : "no return value";
            string abiShape = target.HasReturnValue ? "return value" : "no return value";
            throw new VmFaultException(
                $"CALLT MethodToken for {call.Method} declares {tokenShape}, but manifest ABI target declares {abiShape}");
        }

        int depth = GetContractSelfCallDepth(state);
        if (depth >= MaxContractSelfCallDepth)
            return false;

        int effectiveCallFlags = EffectiveSelfCallFlags(call.CallFlags, target);
        call.CallFlags = effectiveCallFlags;
        call.ModeledSelfCall = true;
        state.Telemetry.ExternalCalls.Add(call);
        var currentExecutingHash = CurrentExecutingScriptHashValue(state);
        var nestedInitial = state.Clone();
        var callerStack = new List<SymbolicValue>(state.EvaluationStack);
        int callerSteps = state.Steps;
        PrepareContractSelfCallEntry(
            nestedInitial,
            target,
            args,
            effectiveCallFlags,
            depth + 1,
            currentExecutingHash);

        var nestedOptions = _options with
        {
            InitialCallFlags = effectiveCallFlags,
            MaxSteps = System.Math.Max(1, _options.MaxSteps - callerSteps),
        };
        var nestedResult = new SymbolicEngine(_program, nestedOptions).Run(nestedInitial);
        var continuations = new List<ExecutionState>(nestedResult.FinalStates.Length);
        foreach (var nestedFinal in nestedResult.FinalStates)
        {
            nestedFinal.Steps += callerSteps;
            if (nestedFinal.Status == TerminalStatus.Halted)
            {
                var returnStack = new List<SymbolicValue>(nestedFinal.EvaluationStack);
                nestedFinal.Status = TerminalStatus.Running;
                nestedFinal.TerminationReason = null;
                nestedFinal.Pc = inst.EndOffset;
                nestedFinal.EvaluationStack.Clear();
                nestedFinal.EvaluationStack.AddRange(callerStack);
                PushSelfCallReturnValue(nestedFinal, target, returnStack, call, resultMode);
                RestoreContractSelfCallDepth(nestedFinal, depth);
            }

            continuations.Add(nestedFinal);
        }

        modeled = continuations;
        return true;
    }

    private static int EffectiveSelfCallFlags(int requestedFlags, ContractSelfCallTarget target) =>
        target.Safe
            ? requestedFlags & ~(NeoCallFlags.WriteStates | NeoCallFlags.AllowNotify)
            : requestedFlags;

    private enum ContractSelfCallResultMode
    {
        ContractCall,
        MethodToken,
    }

    private static void PrepareContractSelfCallEntry(
        ExecutionState nestedState,
        ContractSelfCallTarget target,
        IReadOnlyList<SymbolicValue> args,
        int effectiveCallFlags,
        int depth,
        SymbolicValue currentExecutingHash)
    {
        nestedState.Pc = target.Offset;
        nestedState.Steps = 0;
        nestedState.VisitCounts.Clear();
        nestedState.EvaluationStack.Clear();
        nestedState.CallStack.Clear();
        nestedState.CallStack.Add(new CallFrame(returnPc: -1));
        nestedState.StaticFields.Clear();
        nestedState.CurrentCallFlags = effectiveCallFlags;
        nestedState.InteropContext[RuntimeCallingScriptHashKey] = currentExecutingHash;
        nestedState.InteropContext[RuntimeExecutingScriptHashKey] = currentExecutingHash;
        nestedState.InteropContext[RuntimeContractSelfCallDepthKey] = SymbolicValue.Int(depth);
        for (int i = args.Count - 1; i >= 0; i--)
            nestedState.Push(args[i]);
    }

    private static void PushSelfCallReturnValue(
        ExecutionState state,
        ContractSelfCallTarget target,
        IReadOnlyList<SymbolicValue> returnStack,
        ExternalCall call,
        ContractSelfCallResultMode resultMode)
    {
        switch (resultMode)
        {
            case ContractSelfCallResultMode.ContractCall:
                state.Push(target.HasReturnValue
                    ? SelfCallReturnedStackItem(returnStack)
                    : SymbolicValue.Null());
                break;
            case ContractSelfCallResultMode.MethodToken:
                if (call.HasReturnValue)
                    state.Push(SelfCallReturnedStackItem(returnStack));
                break;
        }
    }

    private static SymbolicValue SelfCallReturnedStackItem(IReadOnlyList<SymbolicValue> returnStack) =>
        returnStack.Count == 0 ? SymbolicValue.Null() : returnStack[^1];

    private static bool TryGetClosedContractCallArguments(
        ExecutionState state,
        SymbolicValue args,
        out IReadOnlyList<SymbolicValue> argumentValues)
    {
        if (args.Expression is HeapRef href
            && state.Heap.Get(href.ObjectId) is ArrayObject { IsSymbolicOpen: false } arr)
        {
            argumentValues = arr.Items;
            return true;
        }

        argumentValues = System.Array.Empty<SymbolicValue>();
        return false;
    }

    private bool IsCurrentExecutingScriptHashValue(ExecutionState state, SymbolicValue value)
    {
        if (!state.InteropContext.TryGetValue(RuntimeExecutingScriptHashKey, out var current))
        {
            if (TryGetConfiguredCurrentScriptHash(out var configured)
                && value.AsConcreteBytes() is { Length: Hash160Length } concrete
                && BytesEqual(concrete, configured))
            {
                return true;
            }

            return IsCanonicalExecutingScriptHashSymbol(value)
                || IsCurrentProgramScriptHashValue(value);
        }

        if (value.Expression == current.Expression)
            return true;
        if (value.AsConcreteBytes() is { } left
            && current.AsConcreteBytes() is { } right
            && BytesEqual(left, right))
        {
            return true;
        }

        return IsCanonicalExecutingScriptHashSymbol(current)
            && IsCurrentProgramScriptHashValue(value);
    }

    private bool IsCurrentProgramScriptHashValue(SymbolicValue value) =>
        value.AsConcreteBytes() is { Length: Hash160Length } bytes
        && BytesEqual(bytes, ComputeScriptHash(_program.Bytes.ToArray()));

    private static bool IsCanonicalExecutingScriptHashSymbol(SymbolicValue value) =>
        value.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" };

    private SymbolicValue CurrentExecutingScriptHashValue(ExecutionState state) =>
        state.InteropContext.TryGetValue(RuntimeExecutingScriptHashKey, out var current)
            ? current
            : ExecutingScriptHash(state);

    private static int GetContractSelfCallDepth(ExecutionState state)
    {
        if (state.InteropContext.TryGetValue(RuntimeContractSelfCallDepthKey, out var value)
            && value.AsConcreteInt() is { } depth
            && depth >= 0
            && depth <= int.MaxValue)
        {
            return (int)depth;
        }

        return 0;
    }

    private static void RestoreContractSelfCallDepth(ExecutionState state, int depth)
    {
        if (depth <= 0)
            state.InteropContext.Remove(RuntimeContractSelfCallDepthKey);
        else
            state.InteropContext[RuntimeContractSelfCallDepthKey] = SymbolicValue.Int(depth);
    }

    private static SymbolicValue WithExternalReturnProvenance(SymbolicValue value, int offset) =>
        value.WithTaint($"ext_ret_{offset}");

    private static bool TryHandlePureNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        if (TryHandleStdLibNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleCryptoLibNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleLedgerNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleContractManagementNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleRoleManagementNativeCall(state, inst, call, out result))
            return true;
        if (TryHandlePolicyNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleOracleNativeCall(state, inst, call, out result))
            return true;
        if (TryHandleNativeTokenReadOnlyCall(state, inst, call, out result))
            return true;

        if (IsKnownNativeContractCall(call))
            AddUnknownSyscall(state, inst.Offset);

        result = SymbolicValue.Null();
        return false;
    }

    private static bool TryHandleLedgerNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsLedgerCall(call))
            return false;
        if (call.CallFlagsDynamic)
            return false;

        EnsureExternalCallFlags(call, $"Ledger.{call.Method}", NeoCallFlags.ReadStates);
        switch (call.Method)
        {
            case "currentIndex":
                if (call.Args.Count != 0)
                    return false;
                result = StableLedgerCurrentIndex(state);
                return true;
            case "currentHash":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeBytes(state, "ledger_current_hash", exactLength: Hash256Length);
                return true;
            case "getTransactionHeight":
                if (call.Args.Count != 1)
                    return false;

                EnforceUInt256Argument(state, inst, "Ledger.getTransactionHeight", call.Args[0]);
                string transactionHashSuffix = NativeBytesArgumentSuffix(call.Args[0], "dynamic_transaction_hash");
                result = StableRuntimeInt(
                    state,
                    $"ledger_transaction_height_{transactionHashSuffix}",
                    min: -1);
                var currentIndex = StableLedgerCurrentIndex(state);
                state.PathConditions = state.PathConditions.Add(Expr.Le(result.Expression, currentIndex.Expression));
                return true;
            case "getBlockHash":
                if (call.Args.Count != 1)
                    return false;

                EnforceUInt32Argument(state, inst, "Ledger.getBlockHash", "block index", call.Args[0]);
                string blockHashIndexSuffix = NativeIntegerArgumentSuffix(call.Args[0], "dynamic_block_index");
                result = StableRuntimeBytes(
                    state,
                    $"ledger_block_hash_{blockHashIndexSuffix}",
                    exactLength: Hash256Length);
                return true;
            case "getTransactionVMState":
                if (call.Args.Count != 1)
                    return false;

                EnforceUInt256Argument(state, inst, "Ledger.getTransactionVMState", call.Args[0]);
                string vmStateTransactionHashSuffix = NativeBytesArgumentSuffix(call.Args[0], "dynamic_transaction_hash");
                result = StableRuntimeInt(state, $"ledger_transaction_vmstate_{vmStateTransactionHashSuffix}");
                ConstrainIntegerOneOf(state, result.Expression, ValidLedgerTransactionVmStates);
                return true;
            default:
                return false;
        }
    }

    private static bool TryHandleContractManagementNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsContractManagementCall(call))
            return false;
        if (call.CallFlagsDynamic)
            return false;

        EnsureExternalCallFlags(call, $"ContractManagement.{call.Method}", NeoCallFlags.ReadStates);
        switch (call.Method)
        {
            case "getMinimumDeploymentFee":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeInt(state, "contract_management_minimum_deployment_fee", min: 0);
                return true;
            case "hasMethod":
                if (call.Args.Count != 3)
                    return false;

                EnforceUInt160Argument(state, inst, "ContractManagement.hasMethod", call.Args[0]);
                EnforceStrictUtf8Argument(state, inst, "ContractManagement.hasMethod", "method name", call.Args[1]);
                EnforceNonNegativeInt32Argument(state, inst, "ContractManagement.hasMethod", "parameter count", call.Args[2]);

                if (state.InteropContext.TryGetValue(ContractManagementIsContractCacheKey(call.Args[0]), out var contractExists)
                    && contractExists.AsConcreteBool() == false)
                {
                    result = SymbolicValue.Bool(false);
                    return true;
                }

                result = StableRuntimeValue(
                    state,
                    ContractManagementHasMethodCacheKey(call),
                    () => SymbolicValue.Symbol(
                        Sort.Bool,
                        $"native_contract_hasMethod_{NativeBalanceAccountSuffix(call.Args[0])}_{NativeStringArgumentSuffix(call.Args[1], "dynamic_method")}_{NativeIntegerArgumentSuffix(call.Args[2], "dynamic_params")}"));
                return true;
            default:
                return false;
        }
    }

    private static bool TryHandlePolicyNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsPolicyCall(call))
            return false;
        if (call.CallFlagsDynamic)
            return false;

        EnsureExternalCallFlags(call, $"Policy.{call.Method}", NeoCallFlags.ReadStates);
        switch (call.Method)
        {
            case "getFeePerByte":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeInt(state, "policy_fee_per_byte", min: 0);
                return true;
            case "getExecFeeFactor":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeInt(state, "policy_exec_fee_factor", min: 0);
                return true;
            case "getStoragePrice":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeInt(state, "policy_storage_price", min: 0);
                return true;
            case "getAttributeFee":
                if (call.Args.Count != 1)
                    return false;

                EnforceIntegerOneOfArgument(
                    state,
                    inst,
                    "Policy.getAttributeFee",
                    "TransactionAttributeType",
                    call.Args[0],
                    ValidPolicyAttributeTypes);
                string attributeSuffix = NativeIntegerArgumentSuffix(call.Args[0], "dynamic_attribute_type");
                result = StableRuntimeInt(state, $"policy_attribute_fee_{attributeSuffix}", min: 0);
                return true;
            case "isBlocked":
                if (call.Args.Count != 1)
                    return false;

                EnforceUInt160Argument(state, inst, "Policy.isBlocked", call.Args[0]);
                string accountSuffix = NativeBalanceAccountSuffix(call.Args[0]);
                result = StableRuntimeValue(
                    state,
                    $"native-policy:isBlocked:{accountSuffix}",
                    () => SymbolicValue.Symbol(Sort.Bool, $"policy_isBlocked_{accountSuffix}"));
                return true;
            default:
                return false;
        }
    }

    private static bool TryHandleRoleManagementNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsRoleManagementCall(call))
            return false;
        if (call.CallFlagsDynamic)
            return false;

        EnsureExternalCallFlags(call, $"RoleManagement.{call.Method}", NeoCallFlags.ReadStates);
        switch (call.Method)
        {
            case "getDesignatedByRole":
                if (call.Args.Count != 2)
                    return false;

                EnforceIntegerOneOfArgument(
                    state,
                    inst,
                    "RoleManagement.getDesignatedByRole",
                    "role",
                    call.Args[0],
                    ValidRoleManagementRoles);
                EnforceUInt32Argument(state, inst, "RoleManagement.getDesignatedByRole", "index", call.Args[1]);
                var currentIndex = StableLedgerCurrentIndex(state);
                EnforceIntegerAtMostExpressionArgument(
                    state,
                    inst,
                    "RoleManagement.getDesignatedByRole",
                    "index",
                    call.Args[1],
                    Expr.Add(currentIndex.Expression, Expr.Int(1)),
                    "Ledger.currentIndex + 1");

                string roleSuffix = NativeIntegerArgumentSuffix(call.Args[0], "dynamic_role");
                string indexSuffix = NativeIntegerArgumentSuffix(call.Args[1], "dynamic_index");
                var designatedKey = StableRuntimeEcPoint(
                    state,
                    $"role_management_designated_key_{roleSuffix}_{indexSuffix}_0");
                var designated = state.Heap.NewArray(
                    new[] { designatedKey },
                    isSymbolicOpen: true,
                    minCount: 0);
                result = SymbolicValue.HeapRef(Sort.Array, designated.Id);
                return true;
            default:
                return false;
        }
    }

    private static bool TryHandleOracleNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsOracleCall(call))
            return false;
        if (call.CallFlagsDynamic)
            return false;

        EnsureExternalCallFlags(call, $"Oracle.{call.Method}", NeoCallFlags.ReadStates);
        switch (call.Method)
        {
            case "getPrice":
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeInt(state, "oracle_price", min: 0);
                return true;
            default:
                return false;
        }
    }

    private static bool TryHandleStdLibNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsStdLibCall(call))
            return false;

        if (call.Args.Count == 1 && string.Equals(call.Method, "serialize", System.StringComparison.Ordinal))
        {
            if (TrySerializeConcreteStackItem(state, call.Args[0], out var bytes)
                && bytes.Length <= state.Heap.MaxItemSize)
            {
                result = SymbolicValue.Bytes(bytes);
                return true;
            }

            if (!TrySerializeSymbolicStackItemSummary(state, inst, call.Args[0], out result))
            {
                AddUnknownSyscall(state, inst.Offset);
                return false;
            }

            return true;
        }

        if (call.Args.Count == 1 && string.Equals(call.Method, "deserialize", System.StringComparison.Ordinal))
        {
            if (TryDeserializeConcreteStackItem(state, call.Args[0], out result))
                return true;

            if (!TryDeserializeSymbolicStackItemSummary(state, call.Args[0], out result))
            {
                AddUnknownSyscall(state, inst.Offset);
                return false;
            }

            return true;
        }

        if (call.Args.Count == 1 && string.Equals(call.Method, "jsonSerialize", System.StringComparison.Ordinal))
        {
            if (TryJsonSerializeConcreteStackItem(state, call.Args[0], out var bytes))
            {
                result = SymbolicValue.Bytes(bytes);
                return true;
            }

            if (!TryJsonSerializeSymbolicStackItemSummary(state, inst, call.Args[0], out result))
            {
                AddUnknownSyscall(state, inst.Offset);
                return false;
            }

            return true;
        }

        if (call.Args.Count == 1 && string.Equals(call.Method, "jsonDeserialize", System.StringComparison.Ordinal))
        {
            if (TryJsonDeserializeConcreteStackItem(state, call.Args[0], out result))
                return true;

            if (!TryJsonDeserializeSymbolicStackItemSummary(state, call.Args[0], out result))
            {
                AddUnknownSyscall(state, inst.Offset);
                return false;
            }

            return true;
        }

        if (IsStdLibScalarMethod(call.Method))
        {
            if (!TryHandleStdLibScalarCall(state, call, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        return false;
    }

    private static bool TryHandleCryptoLibNativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsCryptoLibCall(call))
            return false;

        if (IsCryptoLibSingleBytesHashMethod(call.Method))
        {
            if (call.Args.Count != 1
                || !TryHandleCryptoLibSingleBytesHash(call.Method, call.Args[0], state, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        if (string.Equals(call.Method, "murmur32", System.StringComparison.Ordinal))
        {
            if (call.Args.Count != 2
                || call.Args[1].AsConcreteInt() is not { } seedValue)
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            if (seedValue.Sign < 0 || seedValue > uint.MaxValue)
                throw new VmFaultException("CryptoLib.murmur32 seed must be a uint32 value");

            if (!TryHandleCryptoLibMurmur32(call.Args[0], (uint)seedValue, state, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        if (string.Equals(call.Method, "verifyWithEd25519", System.StringComparison.Ordinal))
        {
            if (!TryHandleCryptoLibVerifyWithEd25519(call.Args, state, inst, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        if (string.Equals(call.Method, "verifyWithECDsa", System.StringComparison.Ordinal))
        {
            if (!TryHandleCryptoLibVerifyWithECDsa(call.Args, state, inst, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        if (string.Equals(call.Method, "recoverSecp256K1", System.StringComparison.Ordinal))
        {
            if (!TryHandleCryptoLibRecoverSecp256K1(call.Args, state, out result))
            {
                state.Telemetry.UnknownSyscalls.Add(inst.Offset);
                return false;
            }

            return true;
        }

        if (TryHandleCryptoLibBlsCall(call.Method, call.Args, state, inst, out result))
            return true;

        if (IsCryptoLibBlsMethod(call.Method))
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return false;
        }

        return false;
    }

    private static bool TryHandleNativeTokenReadOnlyCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!TryGetNativeToken(call, out var token))
            return false;

        if (!IsModeledNativeTokenReadOnlyMethod(call.Method))
            return false;
        if (call.CallFlagsDynamic)
            return false;
        EnsureExternalCallFlags(call, $"{token.Symbol}.{call.Method}", NeoCallFlags.ReadStates);

        switch (call.Method)
        {
            case "symbol":
                if (call.Args.Count != 0)
                    return false;
                result = SymbolicValue.Bytes(System.Text.Encoding.ASCII.GetBytes(token.Symbol));
                return true;
            case "decimals":
                if (call.Args.Count != 0)
                    return false;
                result = SymbolicValue.Int(token.Decimals);
                return true;
            case "totalSupply":
                if (call.Args.Count != 0)
                    return false;
                result = token.FixedTotalSupply is { } totalSupply
                    ? SymbolicValue.Int(totalSupply)
                    : StableNativeTokenInt(state, $"{token.Name}:totalSupply", $"native_{token.SymbolLower}_totalSupply", min: 0);
                return true;
            case "balanceOf":
                if (call.Args.Count != 1)
                    return false;
                EnforceUInt160Argument(state, inst, $"{token.Symbol}.balanceOf", call.Args[0]);
                string accountSuffix = NativeBalanceAccountSuffix(call.Args[0]);
                result = StableNativeTokenInt(
                    state,
                    $"{token.Name}:balanceOf:{accountSuffix}",
                    $"native_{token.SymbolLower}_balanceOf_{accountSuffix}",
                    min: 0,
                    max: token.FixedTotalSupply);
                return true;
            case "getRegisterPrice":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                result = StableNativeTokenInt(
                    state,
                    "neo:getRegisterPrice",
                    "native_neo_getRegisterPrice",
                    min: 0);
                return true;
            case "getGasPerBlock":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                result = StableNativeTokenInt(
                    state,
                    "neo:getGasPerBlock",
                    "native_neo_getGasPerBlock",
                    min: 0);
                return true;
            case "unclaimedGas":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 2)
                    return false;
                EnforceUInt160Argument(state, inst, "NEO.unclaimedGas", call.Args[0]);
                EnforceNeoUnclaimedGasEnd(state, inst, call.Args[1]);
                string unclaimedAccountSuffix = NativeBalanceAccountSuffix(call.Args[0]);
                result = StableNativeTokenInt(
                    state,
                    $"neo:unclaimedGas:{unclaimedAccountSuffix}",
                    $"native_neo_unclaimedGas_{unclaimedAccountSuffix}",
                    min: 0);
                return true;
            case "getCandidateVote":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 1)
                    return false;
                EnforcePublicKeyEncoding(state, inst, "NEO.getCandidateVote", call.Args[0]);
                string candidatePublicKeySuffix = NativeBytesArgumentSuffix(call.Args[0], "dynamic_candidate_public_key");
                result = StableNativeTokenInt(
                    state,
                    $"neo:getCandidateVote:{candidatePublicKeySuffix}",
                    $"native_neo_getCandidateVote_{candidatePublicKeySuffix}",
                    min: -1);
                return true;
            case "getCandidates":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                var candidate = state.Heap.NewStruct(new[]
                {
                    StableRuntimeEcPoint(state, "neo_candidate_key_0"),
                    StableNativeTokenInt(
                        state,
                        "neo:getCandidates:votes:0",
                        "native_neo_getCandidates_votes_0",
                        min: 0),
                });
                var candidates = state.Heap.NewArray(
                    new[] { SymbolicValue.HeapRef(Sort.Struct, candidate.Id) },
                    isSymbolicOpen: true,
                    minCount: 0);
                result = SymbolicValue.HeapRef(Sort.Array, candidates.Id);
                return true;
            case "getCommitteeAddress":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                result = StableRuntimeBytes(state, "neo_committee_address", exactLength: Hash160Length);
                return true;
            case "getCommittee":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                var committeeKey = StableRuntimeEcPoint(state, "neo_committee_key_0");
                var committee = state.Heap.NewArray(
                    new[] { committeeKey },
                    isSymbolicOpen: true,
                    minCount: 0);
                result = SymbolicValue.HeapRef(Sort.Array, committee.Id);
                return true;
            case "getNextBlockValidators":
                if (!string.Equals(token.Symbol, "NEO", System.StringComparison.Ordinal))
                    return false;
                if (call.Args.Count != 0)
                    return false;
                var validatorKey = StableRuntimeEcPoint(state, "neo_next_block_validator_key_0");
                var validators = state.Heap.NewArray(
                    new[] { validatorKey },
                    isSymbolicOpen: true,
                    minCount: 0);
                result = SymbolicValue.HeapRef(Sort.Array, validators.Id);
                return true;
            default:
                return false;
        }
    }

    private static bool IsModeledNativeTokenReadOnlyMethod(string method) =>
        string.Equals(method, "symbol", System.StringComparison.Ordinal)
        || string.Equals(method, "decimals", System.StringComparison.Ordinal)
        || string.Equals(method, "totalSupply", System.StringComparison.Ordinal)
        || string.Equals(method, "balanceOf", System.StringComparison.Ordinal)
        || string.Equals(method, "getRegisterPrice", System.StringComparison.Ordinal)
        || string.Equals(method, "getGasPerBlock", System.StringComparison.Ordinal)
        || string.Equals(method, "unclaimedGas", System.StringComparison.Ordinal)
        || string.Equals(method, "getCandidateVote", System.StringComparison.Ordinal)
        || string.Equals(method, "getCandidates", System.StringComparison.Ordinal)
        || string.Equals(method, "getCommitteeAddress", System.StringComparison.Ordinal)
        || string.Equals(method, "getCommittee", System.StringComparison.Ordinal)
        || string.Equals(method, "getNextBlockValidators", System.StringComparison.Ordinal);

    private static void EnsureExternalCallFlags(ExternalCall call, string operation, int requiredCallFlags)
    {
        int missing = requiredCallFlags & ~call.CallFlags;
        if (missing == 0)
            return;

        throw new VmFaultException(
            $"{operation} requires call flags {FormatCallFlags(requiredCallFlags)}; effective flags {FormatCallFlags(call.CallFlags)} missing {FormatCallFlags(missing)}");
    }

    private static SymbolicValue StableNativeTokenInt(
        ExecutionState state,
        string key,
        string symbolName,
        long? min = null,
        long? max = null)
    {
        var value = StableRuntimeValue(
            state,
            $"native-token:{key}",
            () => SymbolicValue.Symbol(Sort.Int, symbolName));
        if (min is { } lower)
            state.PathConditions = state.PathConditions.Add(Expr.Ge(value.Expression, Expr.Int(lower)));
        if (max is { } upper)
            state.PathConditions = state.PathConditions.Add(Expr.Le(value.Expression, Expr.Int(upper)));
        return value;
    }

    private static void EnforceUInt160Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue value)
    {
        EnforceFixedLengthBytesArgument(state, inst, operation, "UInt160", value, Hash160Length);
    }

    private static void EnforceNeoUnclaimedGasEnd(
        ExecutionState state,
        Instruction inst,
        SymbolicValue end)
    {
        if (end.IsConcreteNull)
            throw new VmFaultException("NEO.unclaimedGas with null end");

        var currentIndex = StableLedgerCurrentIndex(state);
        var expectedEnd = Expr.Add(currentIndex.Expression, Expr.Int(1));
        if (end.Expression.Equals(expectedEnd))
            return;

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "NEO.unclaimedGas",
            Expr.NumNe(end.Expression, expectedEnd),
            "end must equal Ledger.currentIndex + 1",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceUInt256Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue value)
    {
        EnforceFixedLengthBytesArgument(state, inst, operation, "UInt256", value, Hash256Length);
    }

    private static void EnforceFixedLengthBytesArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string typeName,
        SymbolicValue value,
        int exactLength)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {typeName} argument");

        if (Expr.CanonicalBytes(value.Expression) is { } bytes)
        {
            if (bytes.Length != exactLength)
                throw new VmFaultException(
                    $"{operation} {typeName} argument length {bytes.Length} is not {exactLength} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(Expr.Eq(new UnaryExpr(Sort.Int, "size", value.Expression), Expr.Int(exactLength))),
            $"{typeName} argument length must be exactly {exactLength} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceStrictUtf8Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        var normalized = NormalizeStorageBytes(state, value);
        if (Expr.CanonicalBytes(normalized.Expression) is { } bytes)
        {
            DecodeStrictUtf8OrThrow(bytes, operation, argumentName);
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(Expr.IsStrictUtf8(normalized.Expression)),
            $"{argumentName} may be invalid strict UTF-8",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceOracleRequestStringArgument(
        ExecutionState state,
        Instruction inst,
        string argumentName,
        SymbolicValue value,
        int maxByteLength,
        bool allowNull,
        bool rejectLeadingUnderscore = false)
    {
        const string operation = "Oracle.request";
        if (value.IsConcreteNull)
        {
            if (allowNull)
                return;
            throw new VmFaultException($"{operation} with null {argumentName}");
        }

        var normalized = NormalizeStorageBytes(state, value);
        if (Expr.CanonicalBytes(normalized.Expression) is { } bytes)
        {
            string text = DecodeStrictUtf8OrThrow(bytes, operation, argumentName);
            if (bytes.Length > maxByteLength)
                throw new VmFaultException(
                    $"{operation} {argumentName} size {bytes.Length} bytes exceeds maximum allowed size of {maxByteLength} bytes");
            if (rejectLeadingUnderscore && text.StartsWith("_", StringComparison.Ordinal))
                throw new VmFaultException($"{operation} {argumentName} cannot start with '_'");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(Expr.IsStrictUtf8(normalized.Expression)),
            $"{argumentName} may be invalid strict UTF-8",
            "VM syscall precondition holds under requires"));

        var size = StorageByteLengthExpression(normalized.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(size, Expr.Int(maxByteLength)),
            $"{argumentName} size may exceed maximum allowed size of {maxByteLength} bytes",
            "VM syscall precondition holds under requires"));

        if (rejectLeadingUnderscore)
        {
            var firstByte = new BinaryExpr(Sort.Int, "pick", normalized.Expression, Expr.Int(0));
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                operation,
                Expr.BoolAnd(
                    Expr.Gt(size, Expr.Int(0)),
                    Expr.Eq(firstByte, Expr.Int((byte)'_'))),
                $"{argumentName} may start with '_' and target a private method",
                "VM syscall precondition holds under requires"));
        }
    }

    private static void EnforceOracleRequestUserDataSize(
        ExecutionState state,
        Instruction inst,
        SymbolicValue value)
    {
        const string operation = "Oracle.request";
        const string argumentName = "userData";
        if (!TrySerializedStackItemSizeExpression(
            state,
            value,
            new HashSet<int>(),
            operation,
            argumentName,
            out var serializedSize))
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            return;
        }

        if (serializedSize is IntConst concrete)
        {
            if (concrete.Value > MaxOracleUserDataLength)
            {
                throw new VmFaultException(
                    $"{operation} {argumentName} serialized size {concrete.Value} exceeds {MaxOracleUserDataLength} bytes");
            }

            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(serializedSize, Expr.Int(MaxOracleUserDataLength)),
            $"{argumentName} serialized size may exceed {MaxOracleUserDataLength} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceContractManagementUpdateArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        bool strictUtf8 = false)
    {
        if (value.IsConcreteNull)
            return;

        var normalized = NormalizeStorageBytes(state, value);
        if (Expr.CanonicalBytes(normalized.Expression) is { } bytes)
        {
            if (bytes.Length == 0)
                throw new VmFaultException($"{operation} {argumentName} cannot be empty when provided");
            if (bytes.Length > state.Heap.MaxItemSize)
                throw new VmFaultException(
                    $"{operation} {argumentName} length {bytes.Length} exceeds {state.Heap.MaxItemSize} bytes");
            if (strictUtf8)
                DecodeStrictUtf8OrThrow(bytes, operation, argumentName);
            return;
        }

        var size = new UnaryExpr(Sort.Int, "size", normalized.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.BoolOr(
                Expr.Eq(size, Expr.Int(0)),
                Expr.Gt(size, Expr.Int(state.Heap.MaxItemSize))),
            $"{argumentName} may be empty or exceed {state.Heap.MaxItemSize} bytes",
            "VM syscall precondition holds under requires"));

        if (strictUtf8)
        {
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                operation,
                Expr.Not(Expr.IsStrictUtf8(normalized.Expression)),
                $"{argumentName} may be invalid strict UTF-8",
                "VM syscall precondition holds under requires"));
        }
    }

    private static void EnforceContractManagementDeployArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        bool strictUtf8 = false)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName} argument");

        EnforceContractManagementUpdateArgument(state, inst, operation, argumentName, value, strictUtf8);
    }

    private static void EnforceContractManagementUpdateHasPayload(
        ExecutionState state,
        Instruction inst,
        SymbolicValue nefFile,
        SymbolicValue manifest)
    {
        if (nefFile.IsConcreteNull && manifest.IsConcreteNull)
            throw new VmFaultException("ContractManagement.update requires a NEF file or manifest payload");

        if (nefFile.IsConcreteNull || manifest.IsConcreteNull)
            return;

        if (nefFile.Sort == Sort.Null && manifest.Sort == Sort.Null)
        {
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "ContractManagement.update",
                Expr.Bool(true),
                "NEF file and manifest cannot both be null",
                "VM syscall precondition holds under requires"));
        }
    }

    private static void EnforceNonNegativeIntegerArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        EnforceNeoVmIntegerInput(state, inst, operation, value, argumentName);

        if (Expr.ConcreteInt(value.Expression) is { } concrete)
        {
            if (concrete.Sign < 0)
                throw new VmFaultException($"{operation} {argumentName} {concrete} is negative");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Lt(value.Expression, Expr.Int(0)),
            $"{argumentName} may be negative",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceIntegerAtLeastArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        long minimum)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        EnforceNeoVmIntegerInput(state, inst, operation, value, argumentName);

        if (Expr.ConcreteInt(value.Expression) is { } concrete)
        {
            if (concrete < minimum)
                throw new VmFaultException($"{operation} {argumentName} {concrete} is below minimum {minimum}");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Lt(value.Expression, Expr.Int(minimum)),
            $"{argumentName} may be below minimum {minimum}",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceInt32Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        EnforceIntegerAtLeastArgument(state, inst, operation, argumentName, value, int.MinValue);
        EnforceIntegerAtMostExpressionArgument(
            state,
            inst,
            operation,
            argumentName,
            value,
            Expr.Int(int.MaxValue),
            "Int32.MaxValue");
    }

    private static void EnforceNonNegativeInt32Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        EnforceNonNegativeIntegerArgument(state, inst, operation, argumentName, value);
        EnforceIntegerAtMostExpressionArgument(
            state,
            inst,
            operation,
            argumentName,
            value,
            Expr.Int(int.MaxValue),
            "Int32.MaxValue");
    }

    private static void EnforceUInt32Argument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        EnforceNonNegativeIntegerArgument(state, inst, operation, argumentName, value);
        EnforceIntegerAtMostExpressionArgument(
            state,
            inst,
            operation,
            argumentName,
            value,
            Expr.Int((long)uint.MaxValue),
            "UInt32.MaxValue");
    }

    private static void EnforceInt64AtLeastArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        long minimum)
    {
        EnforceIntegerAtLeastArgument(state, inst, operation, argumentName, value, minimum);
        EnforceIntegerAtMostExpressionArgument(
            state,
            inst,
            operation,
            argumentName,
            value,
            Expr.Int(long.MaxValue),
            "Int64.MaxValue");
    }

    private static void EnforceIntegerAtMostExpressionArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        Expression maximum,
        string maximumDescription)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        EnforceNeoVmIntegerInput(state, inst, operation, value, argumentName);

        if (Expr.ConcreteInt(value.Expression) is { } concrete
            && Expr.ConcreteInt(maximum) is { } concreteMaximum)
        {
            if (concrete > concreteMaximum)
                throw new VmFaultException(
                    $"{operation} {argumentName} {concrete} is greater than {maximumDescription}");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(value.Expression, maximum),
            $"{argumentName} may be greater than {maximumDescription}",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceIntegerLessThanExpressionArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        Expression exclusiveMaximum,
        string maximumDescription)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        EnforceNeoVmIntegerInput(state, inst, operation, value, argumentName);

        if (Expr.ConcreteInt(value.Expression) is { } concrete
            && Expr.ConcreteInt(exclusiveMaximum) is { } concreteMaximum)
        {
            if (concrete >= concreteMaximum)
                throw new VmFaultException(
                    $"{operation} {argumentName} {concrete} is not less than {maximumDescription}");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Ge(value.Expression, exclusiveMaximum),
            $"{argumentName} may be greater than or equal to {maximumDescription}",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceIntegerOneOfArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        IReadOnlyList<int> allowedValues)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        EnforceNeoVmIntegerInput(state, inst, operation, value, argumentName);

        if (Expr.ConcreteInt(value.Expression) is { } concrete)
        {
            foreach (int allowed in allowedValues)
            {
                if (concrete == allowed)
                    return;
            }

            throw new VmFaultException($"{operation} {argumentName} {concrete} is not a valid {argumentName}");
        }

        Expression invalid = Expr.Bool(true);
        foreach (int allowed in allowedValues)
        {
            invalid = Expr.BoolAnd(invalid, Expr.NumNe(value.Expression, Expr.Int(allowed)));
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            invalid,
            $"{argumentName} may be invalid",
            "VM syscall precondition holds under requires"));
    }

    private static void ConstrainIntegerOneOf(
        ExecutionState state,
        Expression value,
        IReadOnlyList<int> allowedValues)
    {
        Expression allowed = Expr.Bool(false);
        foreach (int allowedValue in allowedValues)
        {
            allowed = Expr.BoolOr(allowed, Expr.NumEq(value, Expr.Int(allowedValue)));
        }

        state.PathConditions = state.PathConditions.Add(allowed);
    }

    private static string NativeBalanceAccountSuffix(SymbolicValue account)
    {
        if (Expr.CanonicalBytes(account.Expression) is { } bytes)
        {
            if (bytes.Length == Hash160Length && bytes.All(static b => b == 0))
                return "0";
            return System.Convert.ToHexString(bytes).ToLowerInvariant();
        }

        return NativeSymbolicArgumentSuffix(account.Expression, "symbolic_account");
    }

    private static string NativeStringArgumentSuffix(SymbolicValue value, string fallback)
    {
        if (Expr.CanonicalBytes(value.Expression) is { } bytes)
        {
            try
            {
                return SanitizeSymbolSuffix(StrictUtf8.GetString(bytes));
            }
            catch (System.Text.DecoderFallbackException)
            {
                return fallback;
            }
        }

        return NativeSymbolicArgumentSuffix(value.Expression, fallback);
    }

    private static string NativeIntegerArgumentSuffix(SymbolicValue value, string fallback) =>
        Expr.ConcreteInt(value.Expression) is { } concrete
            ? concrete.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : NativeSymbolicArgumentSuffix(value.Expression, fallback);

    private static byte[] ContractIdInteropPayload(SymbolicValue id) =>
        Expr.ConcreteInt(id.Expression) is { } concrete
            ? concrete.ToByteArray()
            : Array.Empty<byte>();

    private static string NativeBytesArgumentSuffix(SymbolicValue value, string fallback) =>
        Expr.CanonicalBytes(value.Expression) is { } bytes
            ? System.Convert.ToHexString(bytes).ToLowerInvariant()
            : NativeSymbolicArgumentSuffix(value.Expression, fallback);

    private static string NativeSymbolicArgumentSuffix(Expression expression, string fallback)
    {
        if (expression is Symbol symbol)
            return SanitizeSymbolSuffix(symbol.Name);

        string symbolPrefix = SanitizeSymbolSuffix(
            string.Join("_", expression.FreeSymbols().DefaultIfEmpty(fallback)));
        var builder = new System.Text.StringBuilder();
        AppendExpressionFingerprint(builder, expression);
        byte[] digest = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(builder.ToString()));
        string hash = System.Convert.ToHexString(digest).Substring(0, 16).ToLowerInvariant();
        return $"{symbolPrefix}_{hash}";
    }

    private static void AppendExpressionFingerprint(System.Text.StringBuilder builder, Expression expression)
    {
        switch (expression)
        {
            case IntConst value:
                builder.Append("int:")
                    .Append(value.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case BoolConst value:
                builder.Append("bool:")
                    .Append(value.Value ? "true" : "false");
                break;
            case BytesConst value:
                builder.Append("bytes:")
                    .Append(System.Convert.ToHexString(value.Value));
                break;
            case NullConst:
                builder.Append("null");
                break;
            case PointerConst value:
                builder.Append("ptr:")
                    .Append(value.TargetOffset.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case HeapRef value:
                builder.Append("heap:")
                    .Append(value.RefSort)
                    .Append(':')
                    .Append(value.ObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture));
                break;
            case Symbol value:
                AppendFingerprintAtom(builder, "sym", value.Sort.ToString(), value.Name);
                break;
            case UnaryExpr value:
                AppendFingerprintAtom(builder, "unary", value.Sort.ToString(), value.Op);
                builder.Append('(');
                AppendExpressionFingerprint(builder, value.Operand);
                builder.Append(')');
                break;
            case BinaryExpr value:
                AppendFingerprintAtom(builder, "binary", value.Sort.ToString(), value.Op);
                builder.Append('(');
                AppendExpressionFingerprint(builder, value.Left);
                builder.Append(',');
                AppendExpressionFingerprint(builder, value.Right);
                builder.Append(')');
                break;
            case TernaryExpr value:
                AppendFingerprintAtom(builder, "ternary", value.Sort.ToString(), value.Op);
                builder.Append('(');
                AppendExpressionFingerprint(builder, value.A);
                builder.Append(',');
                AppendExpressionFingerprint(builder, value.B);
                builder.Append(',');
                AppendExpressionFingerprint(builder, value.C);
                builder.Append(')');
                break;
        }
    }

    private static void AppendFingerprintAtom(
        System.Text.StringBuilder builder,
        string kind,
        string sort,
        string value)
    {
        builder.Append(kind)
            .Append(':')
            .Append(sort.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .Append(':')
            .Append(sort)
            .Append(':')
            .Append(value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value);
    }

    private static string SanitizeSymbolSuffix(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "empty";

        var chars = new char[value.Length];
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            chars[i] = char.IsAsciiLetterOrDigit(c) ? c : '_';
        }
        return new string(chars).Trim('_') is { Length: > 0 } sanitized
            ? sanitized
            : "empty";
    }

    private static bool TryGetNativeToken(ExternalCall call, out NativeTokenInfo token)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        if (bytes is { Length: 20 })
        {
            if (BytesEqual(bytes, NeoTokenContractHash))
            {
                token = NativeTokenInfo.Neo;
                return true;
            }

            if (BytesEqual(bytes, GasTokenContractHash))
            {
                token = NativeTokenInfo.Gas;
                return true;
            }
        }

        token = default;
        return false;
    }

    private static bool IsCryptoLibSingleBytesHashMethod(string method) =>
        method is "sha256" or "ripemd160" or "keccak256";

    private static bool TryHandleCryptoLibSingleBytesHash(
        string method,
        SymbolicValue input,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (input.AsConcreteBytes() is { } concrete)
        {
            if (concrete.Length > state.Heap.MaxItemSize)
                return false;

            result = SymbolicValue.Bytes(ComputeCryptoLibSingleBytesHash(method, concrete));
            return true;
        }

        if (input.Sort != Sort.Bytes)
            return false;

        result = SymbolicValue.Of(
            new UnaryExpr(Sort.Bytes, CryptoLibSingleBytesHashOp(method), input.Expression),
            input.Taints);
        return true;
    }

    private static string CryptoLibSingleBytesHashOp(string method) =>
        method switch
        {
            "sha256" => Expr.CryptoSha256Op,
            "ripemd160" => Expr.CryptoRipemd160Op,
            "keccak256" => Expr.CryptoKeccak256Op,
            _ => throw new System.ArgumentOutOfRangeException(nameof(method), method, "Unsupported CryptoLib hash method"),
        };

    private static bool TryHandleCryptoLibMurmur32(
        SymbolicValue input,
        uint seed,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (input.AsConcreteBytes() is { } concrete)
        {
            if (concrete.Length > state.Heap.MaxItemSize)
                return false;

            uint hash = Murmur32(concrete, seed);
            var hashBytes = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(hashBytes, hash);
            result = SymbolicValue.Bytes(hashBytes);
            return true;
        }

        if (input.Sort != Sort.Bytes)
            return false;

        result = SymbolicValue.Of(
            new BinaryExpr(Sort.Bytes, Expr.CryptoMurmur32Op, input.Expression, Expr.Int(seed)),
            input.Taints);
        return true;
    }

    private static bool TryGetConcreteCryptoLibBytes(
        SymbolicValue value,
        ExecutionState state,
        out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        if (value.AsConcreteBytes() is not { } concrete || concrete.Length > state.Heap.MaxItemSize)
            return false;

        bytes = concrete;
        return true;
    }

    private static byte[] ComputeCryptoLibSingleBytesHash(string method, byte[] bytes) =>
        method switch
        {
            "sha256" => System.Security.Cryptography.SHA256.HashData(bytes),
            "ripemd160" => ComputeDigest(new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest(), bytes),
            "keccak256" => ComputeDigest(new Org.BouncyCastle.Crypto.Digests.KeccakDigest(256), bytes),
            _ => throw new System.ArgumentOutOfRangeException(nameof(method), method, "Unsupported CryptoLib hash method"),
        };

    private static byte[] ComputeDigest(Org.BouncyCastle.Crypto.IDigest digest, byte[] bytes)
    {
        digest.BlockUpdate(bytes, 0, bytes.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    private static bool TryHandleCryptoLibVerifyWithEd25519(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 3)
            return false;

        if (!TryGetConcreteCryptoLibBytes(args[0], state, out var message)
            || !TryGetConcreteCryptoLibBytes(args[1], state, out var publicKey)
            || !TryGetConcreteCryptoLibBytes(args[2], state, out var signature))
        {
            return TryHandleSymbolicCryptoLibVerifyWithEd25519(args, state, inst, out result);
        }

        if (publicKey.Length != Ed25519PublicKeyLength || signature.Length != SignatureLength)
            return false;

        var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        verifier.Init(false, new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(message, 0, message.Length);
        result = SymbolicValue.Bool(verifier.VerifySignature(signature));
        return true;
    }

    private static bool TryHandleSymbolicCryptoLibVerifyWithEd25519(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsSymbolicCryptoLibBytesArgument(args[0])
            || !IsSymbolicCryptoLibBytesArgument(args[1])
            || !IsSymbolicCryptoLibBytesArgument(args[2]))
        {
            return false;
        }

        const string operation = "CryptoLib.verifyWithEd25519";
        EnforceCryptoLibByteStringArgument(state, inst, operation, "message", args[0]);
        if (!TryEnforceCryptoLibFixedByteStringArgument(
                state,
                inst,
                operation,
                "public key",
                args[1],
                Ed25519PublicKeyLength)
            || !TryEnforceCryptoLibFixedByteStringArgument(
                state,
                inst,
                operation,
                "signature",
                args[2],
                SignatureLength))
        {
            return false;
        }

        string resultSymbol = NextAuthResultSymbol(
            state,
            "sig_ok",
            inst.Offset,
            s => s.Telemetry.SignatureCheckOps.Count(op => op.Offset == inst.Offset));
        state.Telemetry.SignatureChecks.Add(inst.Offset);
        state.Telemetry.SignatureCheckOps.Add(new SignatureCheckOp(
            inst.Offset,
            args[1],
            args[2],
            resultSymbol,
            IsMultisig: false,
            Message: args[0]));
        result = SymbolicValue.Symbol(Sort.Bool, resultSymbol);
        return true;
    }

    private static bool TryHandleCryptoLibVerifyWithECDsa(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 4
            || args[3].AsConcreteInt() is not { } curveHash)
        {
            return false;
        }

        if (!TryGetNeoEcdsaCurve(curveHash, out var curveName, out var useKeccak))
            throw new VmFaultException("CryptoLib.verifyWithECDsa curve must be one of Neo's supported NamedCurveHash values");

        if (!TryGetConcreteCryptoLibBytes(args[0], state, out var message)
            || !TryGetConcreteCryptoLibBytes(args[1], state, out var publicKey)
            || !TryGetConcreteCryptoLibBytes(args[2], state, out var signature))
        {
            return TryHandleSymbolicCryptoLibVerifyWithECDsa(args, state, inst, out result);
        }

        if (signature.Length != SignatureLength)
            return false;

        byte[] digest = useKeccak
            ? ComputeDigest(new Org.BouncyCastle.Crypto.Digests.KeccakDigest(256), message)
            : System.Security.Cryptography.SHA256.HashData(message);

        try
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName(curveName);
            if (curve is null)
                return false;

            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());
            var point = curve.Curve.DecodePoint(publicKey);
            if (point.IsInfinity)
                return false;

            var publicKeyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(point, domain);
            var verifier = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            verifier.Init(false, publicKeyParameters);
            var r = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(0, 32).ToArray());
            var s = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(32, 32).ToArray());
            result = SymbolicValue.Bool(verifier.VerifySignature(digest, r, s));
            return true;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryHandleSymbolicCryptoLibVerifyWithECDsa(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsSymbolicCryptoLibBytesArgument(args[0])
            || !IsSymbolicCryptoLibBytesArgument(args[1])
            || !IsSymbolicCryptoLibBytesArgument(args[2]))
        {
            return false;
        }

        const string operation = "CryptoLib.verifyWithECDsa";
        EnforceCryptoLibByteStringArgument(state, inst, operation, "message", args[0]);
        EnforcePublicKeyEncoding(state, inst, operation, args[1]);
        EnforceSignatureLength(state, inst, operation, args[2]);

        string resultSymbol = NextAuthResultSymbol(
            state,
            "sig_ok",
            inst.Offset,
            s => s.Telemetry.SignatureCheckOps.Count(op => op.Offset == inst.Offset));
        state.Telemetry.SignatureChecks.Add(inst.Offset);
        state.Telemetry.SignatureCheckOps.Add(new SignatureCheckOp(
            inst.Offset,
            args[1],
            args[2],
            resultSymbol,
            IsMultisig: false,
            Message: args[0]));
        result = SymbolicValue.Symbol(Sort.Bool, resultSymbol);
        return true;
    }

    private static bool IsSymbolicCryptoLibBytesArgument(SymbolicValue value) =>
        !value.IsConcreteNull && value.Sort == Sort.Bytes;

    private static void EnforceCryptoLibByteStringArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");

        if (value.AsConcreteBytes() is { } bytes)
        {
            if (bytes.Length > state.Heap.MaxItemSize)
                throw new VmFaultException(
                    $"{operation} {argumentName} length {bytes.Length} exceeds {state.Heap.MaxItemSize} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Gt(StorageByteLengthExpression(value.Expression), Expr.Int(state.Heap.MaxItemSize)),
            $"{argumentName} may exceed {state.Heap.MaxItemSize} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static bool TryEnforceCryptoLibFixedByteStringArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        string argumentName,
        SymbolicValue value,
        int exactLength)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null {argumentName}");
        if (value.Sort != Sort.Bytes)
            return false;

        if (value.AsConcreteBytes() is { } bytes)
            return bytes.Length == exactLength;

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(Expr.Eq(StorageByteLengthExpression(value.Expression), Expr.Int(exactLength))),
            $"{argumentName} length must be exactly {exactLength} bytes",
            "VM syscall precondition holds under requires"));
        return true;
    }

    private static bool TryGetNeoEcdsaCurve(
        BigInteger curveHash,
        out string curveName,
        out bool useKeccak)
    {
        if (curveHash < int.MinValue || curveHash > int.MaxValue)
        {
            curveName = "";
            useKeccak = false;
            return false;
        }

        switch ((int)curveHash)
        {
            case 22:
                curveName = "secp256k1";
                useKeccak = false;
                return true;
            case 23:
                curveName = "secp256r1";
                useKeccak = false;
                return true;
            case 122:
                curveName = "secp256k1";
                useKeccak = true;
                return true;
            case 123:
                curveName = "secp256r1";
                useKeccak = true;
                return true;
            default:
                curveName = "";
                useKeccak = false;
                return false;
        }
    }

    private static bool TryHandleCryptoLibRecoverSecp256K1NativeCall(
        ExecutionState state,
        Instruction inst,
        ExternalCall call,
        out IEnumerable<ExecutionState> states)
    {
        states = Array.Empty<ExecutionState>();
        if (!IsCryptoLibCall(call)
            || !string.Equals(call.Method, "recoverSecp256K1", StringComparison.Ordinal)
            || call.Args.Count != 2)
        {
            return false;
        }

        if (TryGetConcreteCryptoLibBytes(call.Args[0], state, out _)
            && TryGetConcreteCryptoLibBytes(call.Args[1], state, out _))
        {
            return false;
        }

        if (!IsSymbolicCryptoLibBytesArgument(call.Args[0])
            || !IsSymbolicCryptoLibBytesArgument(call.Args[1]))
        {
            return false;
        }

        const string operation = "CryptoLib.recoverSecp256K1";
        if (call.Args[0].AsConcreteBytes() is { } concreteMessageHash
            && concreteMessageHash.Length <= state.Heap.MaxItemSize
            && concreteMessageHash.Length != Hash256Length)
        {
            call.ReturnModeledNative = true;
            state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        if (call.Args[1].AsConcreteBytes() is { } concreteSignature
            && concreteSignature.Length <= state.Heap.MaxItemSize
            && !TryParseSecp256K1RecoverSignature(concreteSignature, out _, out _, out _))
        {
            call.ReturnModeledNative = true;
            state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
            state.Pc = inst.EndOffset;
            states = new[] { state };
            return true;
        }

        if (!TryEnforceCryptoLibFixedByteStringArgument(
                state,
                inst,
                operation,
                "message hash",
                call.Args[0],
                Hash256Length)
            || !TryEnforceCryptoLibRecoverSignatureArgument(
                state,
                inst,
                operation,
                call.Args[1]))
        {
            return false;
        }

        call.ReturnModeledNative = true;
        var recoveredKey = SymbolicValue.Of(
            new BinaryExpr(
                Sort.Bytes,
                Expr.CryptoRecoverSecp256K1Op,
                call.Args[0].Expression,
                call.Args[1].Expression),
            call.Args[0].Taints.Union(call.Args[1].Taints));

        var recovered = state.Clone();
        recovered.Push(WithExternalReturnProvenance(recoveredKey, inst.Offset));
        recovered.Pc = inst.EndOffset;

        state.Push(WithExternalReturnProvenance(SymbolicValue.Null(), inst.Offset));
        state.Pc = inst.EndOffset;

        states = new[] { recovered, state };
        return true;
    }

    private static bool TryEnforceCryptoLibRecoverSignatureArgument(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue value)
    {
        if (value.IsConcreteNull)
            throw new VmFaultException($"{operation} with null signature");
        if (value.Sort != Sort.Bytes)
            return false;

        if (value.AsConcreteBytes() is { } bytes)
            return bytes.Length is SignatureLength or RecoverSecp256K1SignatureLength;

        var size = StorageByteLengthExpression(value.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.BoolAnd(
                Expr.Not(Expr.Eq(size, Expr.Int(SignatureLength))),
                Expr.Not(Expr.Eq(size, Expr.Int(RecoverSecp256K1SignatureLength)))),
            $"signature length must be {SignatureLength} or {RecoverSecp256K1SignatureLength} bytes",
            "VM syscall precondition holds under requires"));
        return true;
    }

    private static bool TryHandleCryptoLibRecoverSecp256K1(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 2
            || !TryGetConcreteCryptoLibBytes(args[0], state, out var messageHash)
            || !TryGetConcreteCryptoLibBytes(args[1], state, out var signature))
        {
            return false;
        }

        if (messageHash.Length != Hash256Length)
            return true;

        if (TryRecoverSecp256K1PublicKey(messageHash, signature, out var publicKey))
            result = SymbolicValue.Bytes(publicKey);

        return true;
    }

    private static bool TryRecoverSecp256K1PublicKey(
        byte[] messageHash,
        byte[] signature,
        out byte[] publicKey)
    {
        publicKey = System.Array.Empty<byte>();
        if (!TryParseSecp256K1RecoverSignature(signature, out int recoveryId, out var r, out var s))
            return false;

        try
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            if (curve is null)
                return false;

            var recovered = RecoverSecp256K1Point(curve, recoveryId, r, s, messageHash);
            if (recovered is null || recovered.IsInfinity)
                return false;

            publicKey = recovered.GetEncoded(compressed: true);
            return true;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            return false;
        }
    }

    private static bool TryParseSecp256K1RecoverSignature(
        byte[] signature,
        out int recoveryId,
        out Org.BouncyCastle.Math.BigInteger r,
        out Org.BouncyCastle.Math.BigInteger s)
    {
        recoveryId = 0;
        r = Org.BouncyCastle.Math.BigInteger.Zero;
        s = Org.BouncyCastle.Math.BigInteger.Zero;
        if (signature.Length == 65)
        {
            byte v = signature[64];
            if (v <= 3)
            {
                recoveryId = v;
            }
            else if (v is >= 27 and <= 30)
            {
                recoveryId = v - 27;
            }
            else
            {
                return false;
            }

            r = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(0, 32).ToArray());
            s = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(32, 32).ToArray());
        }
        else if (signature.Length == 64)
        {
            var sBytes = signature.AsSpan(32, 32).ToArray();
            recoveryId = (sBytes[0] & 0x80) == 0 ? 0 : 1;
            sBytes[0] &= 0x7F;
            r = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(0, 32).ToArray());
            s = new Org.BouncyCastle.Math.BigInteger(1, sBytes);
        }
        else
        {
            return false;
        }

        var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
        return curve is not null
            && r.SignValue > 0
            && s.SignValue > 0
            && r.CompareTo(curve.N) < 0
            && s.CompareTo(curve.N) < 0;
    }

    private static Org.BouncyCastle.Math.EC.ECPoint? RecoverSecp256K1Point(
        Org.BouncyCastle.Asn1.X9.X9ECParameters curve,
        int recoveryId,
        Org.BouncyCastle.Math.BigInteger r,
        Org.BouncyCastle.Math.BigInteger s,
        byte[] messageHash)
    {
        var n = curve.N;
        var x = r.Add(Org.BouncyCastle.Math.BigInteger.ValueOf(recoveryId / 2L).Multiply(n));
        var prime = curve.Curve.Field.Characteristic;
        if (x.CompareTo(prime) >= 0)
            return null;

        var compressed = new byte[CompressedPublicKeyLength];
        compressed[0] = (byte)((recoveryId & 1) == 1 ? 0x03 : 0x02);
        if (!TryCopyFixedWidthUnsigned(x, compressed.AsSpan(1)))
            return null;

        var rPoint = curve.Curve.DecodePoint(compressed);
        if (!rPoint.Multiply(n).IsInfinity)
            return null;

        var e = new Org.BouncyCastle.Math.BigInteger(1, messageHash);
        var rInv = r.ModInverse(n);
        var eInv = Org.BouncyCastle.Math.BigInteger.Zero.Subtract(e).Mod(n);
        return Org.BouncyCastle.Math.EC.ECAlgorithms.SumOfTwoMultiplies(
            curve.G,
            eInv.Multiply(rInv).Mod(n),
            rPoint,
            s.Multiply(rInv).Mod(n)).Normalize();
    }

    private static bool TryCopyFixedWidthUnsigned(
        Org.BouncyCastle.Math.BigInteger value,
        System.Span<byte> destination)
    {
        byte[] bytes = value.ToByteArrayUnsigned();
        if (bytes.Length > destination.Length)
            return false;

        destination.Clear();
        bytes.CopyTo(destination[^bytes.Length..]);
        return true;
    }

    private const string BlsG1Kind = "bls12381:g1";
    private const string BlsG2Kind = "bls12381:g2";
    private const string BlsGtKind = "bls12381:gt";
    private const string BlsAnyKind = "bls12381:any";

    private static bool IsCryptoLibBlsMethod(string method) =>
        method is "bls12381Deserialize"
            or "bls12381Serialize"
            or "bls12381Equal"
            or "bls12381Add"
            or "bls12381Mul"
            or "bls12381Pairing";

    private static bool TryHandleCryptoLibBlsCall(
        string method,
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        return method switch
        {
            "bls12381Deserialize" => TryHandleBlsDeserialize(args, state, inst, out result),
            "bls12381Serialize" => TryHandleBlsSerialize(args, state, out result),
            "bls12381Equal" => TryHandleBlsEqual(args, state, out result),
            "bls12381Add" => TryHandleBlsAdd(args, state, out result),
            "bls12381Mul" => TryHandleBlsMul(args, state, inst, out result),
            "bls12381Pairing" => TryHandleBlsPairing(args, state, out result),
            _ => false,
        };
    }

    private static bool TryHandleBlsDeserialize(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 1)
            return false;

        if (!TryGetConcreteCryptoLibBytes(args[0], state, out var bytes))
            return TryHandleSymbolicBlsDeserialize(args[0], state, inst, out result);

        if (bytes.Length is not (48 or 96 or 576))
        {
            throw new VmFaultException(
                "CryptoLib.bls12381Deserialize input length must be 48, 96, or 576 bytes");
        }

        string encodingKind = bytes.Length switch
        {
            48 => "compressed G1",
            96 => "compressed G2",
            _ => "GT",
        };

        try
        {
            InteropObject obj = bytes.Length switch
            {
                48 => state.Heap.NewInterop(
                    BlsG1Kind,
                    Neo.Cryptography.BLS12_381.G1Affine.FromCompressed(bytes).ToCompressed()),
                96 => state.Heap.NewInterop(
                    BlsG2Kind,
                    Neo.Cryptography.BLS12_381.G2Affine.FromCompressed(bytes).ToCompressed()),
                576 => state.Heap.NewInterop(
                    BlsGtKind,
                    Neo.Cryptography.BLS12_381.Gt.FromBytes(bytes).ToArray()),
                _ => throw new System.InvalidOperationException("unreachable BLS12-381 point length"),
            };
            result = SymbolicValue.HeapRef(Sort.InteropInterface, obj.Id);
            return true;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            throw new VmFaultException(
                $"CryptoLib.bls12381Deserialize input must be a valid BLS12-381 {encodingKind} encoding",
                ex);
        }
    }

    private static bool TryHandleSymbolicBlsDeserialize(
        SymbolicValue value,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsSymbolicCryptoLibBytesArgument(value))
            return false;

        const string operation = "CryptoLib.bls12381Deserialize";
        EnforceCryptoLibByteStringArgument(state, inst, operation, "data", value);
        string kind = BlsKindForSerializedValue(state, value);

        var size = StorageByteLengthExpression(value.Expression);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.BoolAnd(
                Expr.Not(Expr.Eq(size, Expr.Int(48))),
                Expr.BoolAnd(
                    Expr.Not(Expr.Eq(size, Expr.Int(96))),
                    Expr.Not(Expr.Eq(size, Expr.Int(576))))),
            "BLS12-381 serialized input length must be 48, 96, or 576 bytes",
            "VM syscall precondition holds under requires"));
        AddBlsValidityFaultCondition(state, inst, operation, kind, value.Expression, size);

        result = NewBlsInterop(state, kind, Array.Empty<byte>(), value);
        return true;
    }

    private static void AddBlsValidityFaultCondition(
        ExecutionState state,
        Instruction inst,
        string operation,
        string kind,
        Expression value,
        Expression size)
    {
        (Expression FaultCondition, string Reason) validity = kind switch
        {
            BlsG1Kind => (
                Expr.Not(new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidG1Op, value)),
                "BLS12-381 serialized input must be a valid compressed G1 encoding"),
            BlsG2Kind => (
                Expr.Not(new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidG2Op, value)),
                "BLS12-381 serialized input must be a valid compressed G2 encoding"),
            BlsGtKind => (
                Expr.Not(new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidGtOp, value)),
                "BLS12-381 serialized input must be a valid Gt encoding"),
            _ => (
                Expr.Not(Expr.BoolOr(
                    Expr.BoolAnd(
                        Expr.Eq(size, Expr.Int(48)),
                        new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidG1Op, value)),
                    Expr.BoolOr(
                        Expr.BoolAnd(
                            Expr.Eq(size, Expr.Int(96)),
                            new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidG2Op, value)),
                        Expr.BoolAnd(
                            Expr.Eq(size, Expr.Int(576)),
                            new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidGtOp, value))))),
                "BLS12-381 serialized input must be a valid compressed G1, compressed G2, or Gt encoding"),
        };

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            validity.FaultCondition,
            validity.Reason,
            "VM syscall precondition holds under requires"));
    }

    private static string? BlsKindForSerializedLength(int length) =>
        length switch
        {
            48 => BlsG1Kind,
            96 => BlsG2Kind,
            576 => BlsGtKind,
            _ => null,
        };

    private static string BlsKindForSerializedValue(ExecutionState state, SymbolicValue value)
    {
        if (Expr.FixedByteSize(value.Expression) is { } fixedSize
            && BlsKindForSerializedLength(fixedSize) is { } fixedKind)
        {
            return fixedKind;
        }

        foreach (int length in new[] { 48, 96, 576 })
        {
            if (PathConditionsProveByteLength(state, value.Expression, length)
                && BlsKindForSerializedLength(length) is { } pathKind)
            {
                return pathKind;
            }
        }

        return BlsAnyKind;
    }

    private static bool PathConditionsProveByteLength(
        ExecutionState state,
        Expression value,
        int expectedLength)
    {
        var size = StorageByteLengthExpression(value);
        var expected = Expr.Int(expectedLength);
        return state.PathConditions.Any(condition => IsEqualityCondition(condition, size, expected));
    }

    private static bool IsEqualityCondition(Expression expression, Expression left, Expression right) =>
        expression is BinaryExpr { Op: "==" or "num==", Left: var actualLeft, Right: var actualRight }
        && ((actualLeft.Equals(left) && actualRight.Equals(right))
            || (actualLeft.Equals(right) && actualRight.Equals(left)));

    private static bool HasProvedByteLength(ExecutionState state, SymbolicValue value, int expectedLength) =>
        value.AsConcreteBytes() is { } concrete
            ? concrete.Length == expectedLength
            : Expr.FixedByteSize(value.Expression) == expectedLength
                || PathConditionsProveByteLength(state, value.Expression, expectedLength);

    private static bool TryHandleBlsSerialize(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 1 || !TryGetBlsInterop(args[0], state, out var obj, allowAnyKind: true))
            return false;

        result = obj.SymbolicPayload ?? SymbolicValue.Bytes(obj.Payload);
        return true;
    }

    private static bool TryHandleBlsEqual(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 2
            || !TryGetBlsInterop(args[0], state, out var left)
            || !TryGetBlsInterop(args[1], state, out var right)
            || !string.Equals(left.Kind, right.Kind, System.StringComparison.Ordinal))
        {
            return false;
        }

        if (left.SymbolicPayload is not null || right.SymbolicPayload is not null)
            return TryHandleSymbolicBlsEqual(left, right, out result);

        result = SymbolicValue.Bool(BytesEqual(left.Payload, right.Payload));
        return true;
    }

    private static bool TryHandleSymbolicBlsEqual(
        InteropObject left,
        InteropObject right,
        out SymbolicValue result)
    {
        var leftPayload = left.SymbolicPayload ?? SymbolicValue.Bytes(left.Payload);
        var rightPayload = right.SymbolicPayload ?? SymbolicValue.Bytes(right.Payload);
        result = SymbolicValue.Of(
            Expr.Eq(leftPayload.Expression, rightPayload.Expression),
            leftPayload.Taints.Union(rightPayload.Taints));
        return true;
    }

    private static bool TryHandleBlsAdd(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 2
            || !TryGetBlsInterop(args[0], state, out var left)
            || !TryGetBlsInterop(args[1], state, out var right)
            || !string.Equals(left.Kind, right.Kind, System.StringComparison.Ordinal))
        {
            return false;
        }

        if (left.SymbolicPayload is not null || right.SymbolicPayload is not null)
            return TryHandleSymbolicBlsAdd(left, right, state, out result);

        try
        {
            result = left.Kind switch
            {
                BlsG1Kind => NewBlsInterop(
                    state,
                    BlsG1Kind,
                    new Neo.Cryptography.BLS12_381.G1Affine(
                        Neo.Cryptography.BLS12_381.G1Affine.FromCompressed(left.Payload).ToCurve()
                        + Neo.Cryptography.BLS12_381.G1Affine.FromCompressed(right.Payload).ToCurve()).ToCompressed()),
                BlsG2Kind => NewBlsInterop(
                    state,
                    BlsG2Kind,
                    new Neo.Cryptography.BLS12_381.G2Affine(
                        Neo.Cryptography.BLS12_381.G2Affine.FromCompressed(left.Payload).ToCurve()
                        + Neo.Cryptography.BLS12_381.G2Affine.FromCompressed(right.Payload).ToCurve()).ToCompressed()),
                BlsGtKind => NewBlsInterop(
                    state,
                    BlsGtKind,
                    (Neo.Cryptography.BLS12_381.Gt.FromBytes(left.Payload)
                        + Neo.Cryptography.BLS12_381.Gt.FromBytes(right.Payload)).ToArray()),
                _ => SymbolicValue.Null(),
            };

            return !result.IsConcreteNull;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            return false;
        }
    }

    private static bool TryHandleSymbolicBlsAdd(
        InteropObject left,
        InteropObject right,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        string op = left.Kind switch
        {
            BlsG1Kind => Expr.CryptoBlsAddG1Op,
            BlsG2Kind => Expr.CryptoBlsAddG2Op,
            BlsGtKind => Expr.CryptoBlsAddGtOp,
            _ => "",
        };
        if (op.Length == 0)
            return false;

        var leftPayload = left.SymbolicPayload ?? SymbolicValue.Bytes(left.Payload);
        var rightPayload = right.SymbolicPayload ?? SymbolicValue.Bytes(right.Payload);
        var payload = SymbolicValue.Of(
            new BinaryExpr(Sort.Bytes, op, leftPayload.Expression, rightPayload.Expression),
            leftPayload.Taints.Union(rightPayload.Taints));
        result = NewBlsInterop(state, left.Kind, Array.Empty<byte>(), payload);
        return true;
    }

    private static bool TryHandleBlsMul(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 3
            || !TryGetBlsInterop(args[0], state, out var obj)
            || args[1].Sort != Sort.Bytes)
        {
            return false;
        }

        bool neg;
        if (args[2].AsConcreteBool() is { } boolValue)
            neg = boolValue;
        else if (args[2].AsConcreteInt() is { } intValue)
            neg = intValue != 0;
        else
            return false;

        if (obj.SymbolicPayload is not null || args[1].AsConcreteBytes() is null)
            return TryHandleSymbolicBlsMul(obj, args[1], neg, state, inst, out result);

        if (!TryGetConcreteCryptoLibBytes(args[1], state, out var scalarBytes))
        {
            return false;
        }

        if (scalarBytes.Length != 32)
        {
            throw new VmFaultException("CryptoLib.bls12381Mul scalar length must be exactly 32 bytes");
        }

        try
        {
            var scalar = Neo.Cryptography.BLS12_381.Scalar.FromBytes(scalarBytes);
            if (neg)
                scalar = -scalar;

            result = obj.Kind switch
            {
                BlsG1Kind => NewBlsInterop(
                    state,
                    BlsG1Kind,
                    new Neo.Cryptography.BLS12_381.G1Affine(
                        Neo.Cryptography.BLS12_381.G1Affine.FromCompressed(obj.Payload) * scalar).ToCompressed()),
                BlsG2Kind => NewBlsInterop(
                    state,
                    BlsG2Kind,
                    new Neo.Cryptography.BLS12_381.G2Affine(
                        Neo.Cryptography.BLS12_381.G2Affine.FromCompressed(obj.Payload) * scalar).ToCompressed()),
                BlsGtKind => NewBlsInterop(
                    state,
                    BlsGtKind,
                    (Neo.Cryptography.BLS12_381.Gt.FromBytes(obj.Payload) * scalar).ToArray()),
                _ => SymbolicValue.Null(),
            };

            return !result.IsConcreteNull;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            throw new VmFaultException(
                "CryptoLib.bls12381Mul scalar must be a valid BLS12-381 scalar encoding",
                ex);
        }
    }

    private static bool TryHandleSymbolicBlsMul(
        InteropObject obj,
        SymbolicValue scalar,
        bool neg,
        ExecutionState state,
        Instruction inst,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!IsSymbolicCryptoLibBytesArgument(scalar))
            return false;

        const string operation = "CryptoLib.bls12381Mul";
        EnforceCryptoLibByteStringArgument(state, inst, operation, "scalar", scalar);
        if (!HasProvedByteLength(state, scalar, 32))
        {
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                operation,
                Expr.Not(Expr.Eq(StorageByteLengthExpression(scalar.Expression), Expr.Int(32))),
                "scalar length must be exactly 32 bytes",
                "VM syscall precondition holds under requires"));
            return false;
        }
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(new UnaryExpr(Sort.Bool, Expr.CryptoBlsValidScalarOp, scalar.Expression)),
            "scalar must be a valid BLS12-381 scalar encoding",
            "VM syscall precondition holds under requires"));

        string op = obj.Kind switch
        {
            BlsG1Kind => Expr.CryptoBlsMulG1Op,
            BlsG2Kind => Expr.CryptoBlsMulG2Op,
            BlsGtKind => Expr.CryptoBlsMulGtOp,
            _ => "",
        };
        if (op.Length == 0)
            return false;

        var payload = obj.SymbolicPayload ?? SymbolicValue.Bytes(obj.Payload);
        var symbolicPayload = SymbolicValue.Of(
            new TernaryExpr(Sort.Bytes, op, payload.Expression, scalar.Expression, Expr.Bool(neg)),
            payload.Taints.Union(scalar.Taints));
        result = NewBlsInterop(state, obj.Kind, Array.Empty<byte>(), symbolicPayload);
        return true;
    }

    private static bool TryHandleBlsPairing(
        IReadOnlyList<SymbolicValue> args,
        ExecutionState state,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 2
            || !TryGetBlsInterop(args[0], state, out var g1)
            || !TryGetBlsInterop(args[1], state, out var g2)
            || !string.Equals(g1.Kind, BlsG1Kind, System.StringComparison.Ordinal)
            || !string.Equals(g2.Kind, BlsG2Kind, System.StringComparison.Ordinal))
        {
            return false;
        }

        if (g1.SymbolicPayload is not null || g2.SymbolicPayload is not null)
            return TryHandleSymbolicBlsPairing(g1, g2, state, out result);

        try
        {
            var g1Affine = Neo.Cryptography.BLS12_381.G1Affine.FromCompressed(g1.Payload);
            var g2Affine = Neo.Cryptography.BLS12_381.G2Affine.FromCompressed(g2.Payload);
            result = NewBlsInterop(
                state,
                BlsGtKind,
                Neo.Cryptography.BLS12_381.Bls12.Pairing(in g1Affine, in g2Affine).ToArray());
            return true;
        }
        catch (System.Exception ex) when (ex is System.ArgumentException
            or System.FormatException
            or System.InvalidOperationException
            or System.ArithmeticException)
        {
            return false;
        }
    }

    private static bool TryHandleSymbolicBlsPairing(
        InteropObject g1,
        InteropObject g2,
        ExecutionState state,
        out SymbolicValue result)
    {
        var g1Payload = g1.SymbolicPayload ?? SymbolicValue.Bytes(g1.Payload);
        var g2Payload = g2.SymbolicPayload ?? SymbolicValue.Bytes(g2.Payload);
        var payload = SymbolicValue.Of(
            new BinaryExpr(Sort.Bytes, Expr.CryptoBlsPairingOp, g1Payload.Expression, g2Payload.Expression),
            g1Payload.Taints.Union(g2Payload.Taints));
        result = NewBlsInterop(state, BlsGtKind, Array.Empty<byte>(), payload);
        return true;
    }

    private static bool TryGetBlsInterop(
        SymbolicValue value,
        ExecutionState state,
        out InteropObject obj,
        bool allowAnyKind = false)
    {
        obj = null!;
        if (value.Expression is not HeapRef href
            || href.Sort != Sort.InteropInterface
            || state.Heap.Get(href.ObjectId) is not InteropObject interop
            || (interop.Kind is not (BlsG1Kind or BlsG2Kind or BlsGtKind)
                && !(allowAnyKind && string.Equals(interop.Kind, BlsAnyKind, StringComparison.Ordinal))))
        {
            return false;
        }

        obj = interop;
        return true;
    }

    private static SymbolicValue NewBlsInterop(
        ExecutionState state,
        string kind,
        byte[] payload,
        SymbolicValue? symbolicPayload = null) =>
        SymbolicValue.HeapRef(Sort.InteropInterface, state.Heap.NewInterop(kind, payload, symbolicPayload).Id);

    private static uint Murmur32(byte[] data, uint seed)
    {
        const uint c1 = 0xcc9e2d51;
        const uint c2 = 0x1b873593;
        uint hash = seed;
        int roundedEnd = data.Length & ~3;

        for (int i = 0; i < roundedEnd; i += 4)
        {
            uint k = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i, 4));
            k *= c1;
            k = System.Numerics.BitOperations.RotateLeft(k, 15);
            k *= c2;

            hash ^= k;
            hash = System.Numerics.BitOperations.RotateLeft(hash, 13);
            hash = (hash * 5) + 0xe6546b64;
        }

        uint tail = 0;
        switch (data.Length & 3)
        {
            case 3:
                tail ^= (uint)data[roundedEnd + 2] << 16;
                goto case 2;
            case 2:
                tail ^= (uint)data[roundedEnd + 1] << 8;
                goto case 1;
            case 1:
                tail ^= data[roundedEnd];
                tail *= c1;
                tail = System.Numerics.BitOperations.RotateLeft(tail, 15);
                tail *= c2;
                hash ^= tail;
                break;
        }

        hash ^= (uint)data.Length;
        hash ^= hash >> 16;
        hash *= 0x85ebca6b;
        hash ^= hash >> 13;
        hash *= 0xc2b2ae35;
        hash ^= hash >> 16;
        return hash;
    }

    private static bool IsStdLibScalarMethod(string method) =>
        method is "itoa" or "atoi"
            or "base58Encode" or "base58Decode"
            or "base58CheckEncode" or "base58CheckDecode"
            or "base64Encode" or "base64Decode"
            or "base64UrlEncode" or "base64UrlDecode"
            or "hexEncode" or "hexDecode"
            or "memoryCompare" or "memorySearch"
            or "strLen" or "stringSplit";

    private static bool TryHandleStdLibScalarCall(
        ExecutionState state,
        ExternalCall call,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        return call.Method switch
        {
            "itoa" => TryHandleStdLibItoa(call.Args, out result),
            "atoi" => TryHandleStdLibAtoi(call.Args, out result),
            "base58Encode" => TryHandleStdLibBytesToUtf8(call.Args, Base58Encode, "StdLib.base58Encode", out result),
            "base58Decode" => TryHandleStdLibUtf8ToBytes(call.Args, TryDecodeBase58, "StdLib.base58Decode", "valid base58 text", out result),
            "base58CheckEncode" => TryHandleStdLibBytesToUtf8(call.Args, Base58CheckEncode, "StdLib.base58CheckEncode", out result),
            "base58CheckDecode" => TryHandleStdLibUtf8ToBytes(call.Args, TryDecodeBase58Check, "StdLib.base58CheckDecode", "valid base58check text", out result),
            "base64Encode" => TryHandleStdLibBytesToUtf8(call.Args, System.Convert.ToBase64String, "StdLib.base64Encode", out result),
            "base64Decode" => TryHandleStdLibUtf8ToBytes(call.Args, TryDecodeBase64, "StdLib.base64Decode", "valid base64 text", out result),
            "base64UrlEncode" => TryHandleStdLibBytesToUtf8(call.Args, Base64UrlEncode, "StdLib.base64UrlEncode", out result),
            "base64UrlDecode" => TryHandleStdLibUtf8ToBytes(call.Args, TryDecodeBase64Url, "StdLib.base64UrlDecode", "valid base64url text", out result),
            "hexEncode" => TryHandleStdLibBytesToUtf8(call.Args, HexEncodeLower, "StdLib.hexEncode", out result),
            "hexDecode" => TryHandleStdLibUtf8ToBytes(call.Args, TryDecodeHex, "StdLib.hexDecode", "valid hexadecimal text", out result),
            "memoryCompare" => TryHandleStdLibMemoryCompare(call.Args, out result),
            "memorySearch" => TryHandleStdLibMemorySearch(call.Args, out result),
            "strLen" => TryHandleStdLibStrLen(call.Args, out result),
            "stringSplit" => TryHandleStdLibStringSplit(state, call.Args, out result),
            _ => false,
        };
    }

    private static bool TryHandleStdLibStrLen(
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 1
            || args[0].AsConcreteBytes() is not { } bytes)
        {
            return false;
        }

        EnforceStdLibMaxLength("StdLib.strLen", "value", bytes);
        string text = DecodeStrictUtf8OrThrow(bytes, "StdLib.strLen", "value");
        // Round-2 fix: Neo's StdLib.strLen counts grapheme/text-elements (StringInfo), not Unicode
        // runes. They differ for combining marks and ZWJ emoji sequences (e.g. a base char + combining
        // mark is 2 runes but 1 text element). Mirror Neo exactly.
        result = SymbolicValue.Int(new System.Globalization.StringInfo(text).LengthInTextElements);
        return true;
    }

    private static bool TryHandleStdLibStringSplit(
        ExecutionState state,
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count is not (2 or 3)
            || args[0].AsConcreteBytes() is not { } strBytes
            || args[1].AsConcreteBytes() is not { } separatorBytes)
        {
            return false;
        }

        // Round-3 audit fix: Neo's StringSplit applies [MaxLength(1024)] only to `str`, not to
        // `separator`, so the engine must not fault on a long separator (it would prune a feasible path).
        EnforceStdLibMaxLength("StdLib.stringSplit", "value", strBytes);
        string text = DecodeStrictUtf8OrThrow(strBytes, "StdLib.stringSplit", "value");
        string separator = DecodeStrictUtf8OrThrow(separatorBytes, "StdLib.stringSplit", "separator");
        if (separator.Length == 0)
            return false;

        bool removeEmptyEntries = false;
        if (args.Count == 3)
        {
            if (args[2].AsConcreteBool() is { } boolValue)
            {
                removeEmptyEntries = boolValue;
            }
            else if (args[2].AsConcreteInt() is { } intValue)
            {
                removeEmptyEntries = intValue != 0;
            }
            else
            {
                return false;
            }
        }

        var options = removeEmptyEntries
            ? System.StringSplitOptions.RemoveEmptyEntries
            : System.StringSplitOptions.None;
        string[] parts = text.Split(new[] { separator }, options);
        var items = parts.Select(part => SymbolicValue.Bytes(StrictUtf8.GetBytes(part)));
        result = SymbolicValue.HeapRef(Sort.Array, state.Heap.NewArray(items).Id);
        return true;
    }

    private static bool TryHandleStdLibMemoryCompare(
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 2
            || !TryGetStdLibConcreteBytes(args[0], "StdLib.memoryCompare", "left", out var left)
            || !TryGetStdLibConcreteBytes(args[1], "StdLib.memoryCompare", "right", out var right))
        {
            return false;
        }

        int comparison = left.AsSpan().SequenceCompareTo(right);
        result = SymbolicValue.Int(comparison < 0 ? -1 : comparison > 0 ? 1 : 0);
        return true;
    }

    private static bool TryHandleStdLibMemorySearch(
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count is < 2 or > 4
            || !TryGetStdLibConcreteBytes(args[0], "StdLib.memorySearch", "memory", out var memory)
            || !TryGetStdLibConcreteBytes(args[1], "StdLib.memorySearch", "value", out var value, enforceMaxLength: false))
        {
            return false;
        }

        int start = 0;
        if (args.Count >= 3)
        {
            if (args[2].AsConcreteInt() is not { } startValue
                || startValue < int.MinValue
                || startValue > int.MaxValue)
            {
                if (args[2].AsConcreteInt() is { })
                    throw new VmFaultException("StdLib.memorySearch start must fit in Int32");

                return false;
            }

            start = (int)startValue;
        }

        bool backward = false;
        if (args.Count == 4)
        {
            if (args[3].AsConcreteBool() is { } boolValue)
            {
                backward = boolValue;
            }
            else if (args[3].AsConcreteInt() is { } intValue)
            {
                backward = intValue != 0;
            }
            else
            {
                return false;
            }
        }

        if (start < 0 || start > memory.Length)
            throw new VmFaultException("StdLib.memorySearch start must be within memory bounds");

        int index = backward
            ? LastIndexOf(memory, value, start)
            : IndexOf(memory, value, start);
        result = SymbolicValue.Int(index);
        return true;
    }

    private static bool TryGetStdLibConcreteBytes(
        SymbolicValue value,
        string operation,
        string argumentName,
        out byte[] bytes,
        bool enforceMaxLength = true)
    {
        bytes = System.Array.Empty<byte>();
        if (value.AsConcreteBytes() is not { } concrete)
            return false;

        // Round-3 audit fix: the StdLib [MaxLength(1024)] cap is per-parameter — e.g. memorySearch
        // limits `mem` but NOT `value`, and stringSplit limits `str` but NOT `separator`. Callers pass
        // enforceMaxLength: false for the unconstrained parameter so the engine does not fault (prune a
        // feasible path) on input lengths Neo accepts.
        if (enforceMaxLength)
            EnforceStdLibMaxLength(operation, argumentName, concrete);
        bytes = concrete;
        return true;
    }

    private static void EnforceStdLibMaxLength(string operation, string argumentName, byte[] bytes)
    {
        if (bytes.Length > StdLibMaxInputLength)
            throw new VmFaultException(
                $"{operation} {argumentName} length {bytes.Length} exceeds {StdLibMaxInputLength} bytes");
    }

    private static int IndexOf(byte[] memory, byte[] value, int start)
    {
        if (value.Length == 0)
            return start;

        int lastStart = memory.Length - value.Length;
        for (int i = start; i <= lastStart; i++)
        {
            if (memory.AsSpan(i, value.Length).SequenceEqual(value))
                return i;
        }

        return -1;
    }

    private static int LastIndexOf(byte[] memory, byte[] value, int start)
    {
        if (value.Length == 0)
            return start;

        // Round-2 fix: Neo's backward memorySearch is memory.AsSpan(0, start).LastIndexOf(value),
        // so a match must lie ENTIRELY within [0, start): i + value.Length <= start. The previous
        // Math.Min(start, memory.Length - value.Length) allowed a match to extend past the start
        // window, returning a wrong (too-large) index. When start < value.Length this yields a
        // negative bound and the loop correctly returns -1.
        int lastStart = start - value.Length;
        for (int i = lastStart; i >= 0; i--)
        {
            if (memory.AsSpan(i, value.Length).SequenceEqual(value))
                return i;
        }

        return -1;
    }

    private static bool TryHandleStdLibItoa(
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!TryGetStdLibBase(args, "StdLib.itoa", out int numberBase)
            || args[0].AsConcreteInt() is not { } value)
        {
            return false;
        }

        string text;
        if (numberBase == 10)
        {
            text = value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        else if (numberBase == 16 && value.Sign >= 0)
        {
            text = value.ToString("x", System.Globalization.CultureInfo.InvariantCulture);
        }
        else
        {
            return false;
        }

        result = SymbolicValue.Bytes(StrictUtf8.GetBytes(text));
        return true;
    }

    private static bool TryHandleStdLibAtoi(
        IReadOnlyList<SymbolicValue> args,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (!TryGetStdLibBase(args, "StdLib.atoi", out int numberBase)
            || args[0].AsConcreteBytes() is not { } textBytes)
        {
            return false;
        }

        EnforceStdLibMaxLength("StdLib.atoi", "value", textBytes);
        string text = DecodeStrictUtf8OrThrow(textBytes, "StdLib.atoi", "value");
        BigInteger value;
        if (numberBase == 10)
        {
            if (!BigInteger.TryParse(
                    text,
                    System.Globalization.NumberStyles.AllowLeadingSign,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out value))
            {
                throw new VmFaultException("StdLib.atoi input must be a valid base-10 integer");
            }
        }
        else if (numberBase == 16)
        {
            // Review fix (#3): Neo's StdLib.Atoi(value, 16) is
            // BigInteger.Parse(text, NumberStyles.AllowHexSpecifier, InvariantCulture), which is
            // TWO'S-COMPLEMENT: the high bit of the leading hex nibble is the sign bit
            // (atoi("ff",16) == -1, atoi("80",16) == -128, atoi("0ff",16) == 255). The previous
            // unsigned accumulation returned +255/+128, feeding a wrong concrete value into proofs
            // and spuriously faulting in-range negatives (all-F strings). Mirror Neo exactly.
            if (!BigInteger.TryParse(
                    text,
                    System.Globalization.NumberStyles.AllowHexSpecifier,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out value))
            {
                throw new VmFaultException("StdLib.atoi input must be a valid base-16 integer");
            }
        }
        else
        {
            return false;
        }

        if (!Expr.IsWithinNeoVmIntegerRange(value))
            throw new VmFaultException("StdLib.atoi result exceeds NeoVM integer range");

        result = SymbolicValue.Int(value);
        return true;
    }

    private static bool TryGetStdLibBase(
        IReadOnlyList<SymbolicValue> args,
        string operation,
        out int numberBase)
    {
        numberBase = 10;
        if (args.Count is not (1 or 2))
            return false;
        if (args.Count == 2)
        {
            if (args[1].AsConcreteInt() is not { } baseValue)
                return false;

            if (baseValue != 10 && baseValue != 16)
                throw new VmFaultException($"{operation} base must be 10 or 16");

            numberBase = (int)baseValue;
        }

        return true;
    }

    private static bool TryHandleStdLibBytesToUtf8(
        IReadOnlyList<SymbolicValue> args,
        System.Func<byte[], string> encode,
        string operation,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 1 || args[0].AsConcreteBytes() is not { } bytes)
            return false;

        EnforceStdLibMaxLength(operation, "value", bytes);
        result = SymbolicValue.Bytes(StrictUtf8.GetBytes(encode(bytes)));
        return true;
    }

    private static bool TryHandleStdLibUtf8ToBytes(
        IReadOnlyList<SymbolicValue> args,
        TryDecodeText decode,
        string operation,
        string expectedDescription,
        out SymbolicValue result)
    {
        result = SymbolicValue.Null();
        if (args.Count != 1 || args[0].AsConcreteBytes() is not { } textBytes)
            return false;

        EnforceStdLibMaxLength(operation, "value", textBytes);
        string text = DecodeStrictUtf8OrThrow(textBytes, operation, "value");
        if (!decode(text, out var bytes))
            throw new VmFaultException($"{operation} input must be {expectedDescription}");

        if (bytes.Length > StdLibMaxInputLength)
            return false;

        result = SymbolicValue.Bytes(bytes);
        return true;
    }

    private delegate bool TryDecodeText(string text, out byte[] bytes);

    private static string HexEncodeLower(byte[] bytes) =>
        System.Convert.ToHexString(bytes).ToLowerInvariant();

    private static bool TryDecodeHex(string text, out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        if ((text.Length & 1) != 0)
            return false;

        try
        {
            bytes = System.Convert.FromHexString(text);
            return true;
        }
        catch (System.FormatException)
        {
            return false;
        }
    }

    private static bool TryDecodeBase64(string text, out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        try
        {
            bytes = System.Convert.FromBase64String(text);
            return true;
        }
        catch (System.FormatException)
        {
            return false;
        }
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        System.Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryDecodeBase64Url(string text, out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        string normalized = text.Replace('-', '+').Replace('_', '/');
        int padding = normalized.Length % 4;
        if (padding == 1)
            return false;
        if (padding > 0)
            normalized = normalized.PadRight(normalized.Length + 4 - padding, '=');
        return TryDecodeBase64(normalized, out bytes);
    }

    private static string Base58Encode(byte[] bytes)
    {
        if (bytes.Length == 0)
            return string.Empty;

        int leadingZeroCount = 0;
        while (leadingZeroCount < bytes.Length && bytes[leadingZeroCount] == 0)
            leadingZeroCount++;

        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        var chars = new List<char>();
        while (value > BigInteger.Zero)
        {
            value = BigInteger.DivRem(value, 58, out var remainder);
            chars.Add(Base58Alphabet[(int)remainder]);
        }

        for (int i = 0; i < leadingZeroCount; i++)
            chars.Add(Base58Alphabet[0]);

        chars.Reverse();
        return new string(chars.ToArray());
    }

    private static bool TryDecodeBase58(string text, out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();

        var value = BigInteger.Zero;
        foreach (char ch in text)
        {
            int digit = Base58Alphabet.IndexOf(ch, System.StringComparison.Ordinal);
            if (digit < 0)
                return false;
            value = (value * 58) + digit;
        }

        int leadingZeroCount = 0;
        while (leadingZeroCount < text.Length && text[leadingZeroCount] == Base58Alphabet[0])
            leadingZeroCount++;

        byte[] payload = value.IsZero
            ? System.Array.Empty<byte>()
            : value.ToByteArray(isUnsigned: true, isBigEndian: true);
        bytes = new byte[leadingZeroCount + payload.Length];
        System.Array.Copy(payload, 0, bytes, leadingZeroCount, payload.Length);
        return true;
    }

    private static string Base58CheckEncode(byte[] bytes)
    {
        byte[] payload = new byte[bytes.Length + 4];
        System.Array.Copy(bytes, payload, bytes.Length);
        System.Array.Copy(Hash256(bytes), 0, payload, bytes.Length, 4);
        return Base58Encode(payload);
    }

    private static bool TryDecodeBase58Check(string text, out byte[] bytes)
    {
        bytes = System.Array.Empty<byte>();
        if (!TryDecodeBase58(text, out var payload) || payload.Length < 4)
            return false;

        int dataLength = payload.Length - 4;
        var data = new byte[dataLength];
        System.Array.Copy(payload, data, dataLength);
        byte[] checksum = Hash256(data);
        for (int i = 0; i < 4; i++)
        {
            if (payload[dataLength + i] != checksum[i])
                return false;
        }

        bytes = data;
        return true;
    }

    private static byte[] Hash256(byte[] bytes)
    {
        byte[] first = System.Security.Cryptography.SHA256.HashData(bytes);
        return System.Security.Cryptography.SHA256.HashData(first);
    }

    private static bool IsStdLibCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, StdLibContractHash);
    }

    private static bool IsCryptoLibCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, CryptoLibContractHash);
    }

    private static bool IsContractManagementCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, ContractManagementHash);
    }

    private static bool IsLedgerCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, LedgerContractHash);
    }

    private static bool IsPolicyCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, PolicyContractHash);
    }

    private static bool IsRoleManagementCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, RoleManagementHash);
    }

    private static bool IsOracleCall(ExternalCall call)
    {
        var bytes = call.TargetHash?.AsConcreteBytes();
        return bytes is { Length: 20 } && BytesEqual(bytes, OracleContractHash);
    }

    private static bool IsKnownNativeContractCall(ExternalCall call) =>
        NeoNativeContractHashes.IsKnownNativeContractHash(call.TargetHash?.AsConcreteBytes());

    private static void AddUnknownSyscall(ExecutionState state, int offset)
    {
        if (!state.Telemetry.UnknownSyscalls.Contains(offset))
            state.Telemetry.UnknownSyscalls.Add(offset);
    }

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

    private static void EnforceContractCallTargetHash(
        ExecutionState state,
        Instruction inst,
        SymbolicValue hash)
    {
        if (hash.IsConcreteNull)
            throw new VmFaultException("Contract.Call with null target hash");

        if (Expr.CanonicalBytes(hash.Expression) is { } bytes)
        {
            if (bytes.Length != Hash160Length)
                throw new VmFaultException(
                    $"Contract.Call target hash length {bytes.Length} is not {Hash160Length} bytes");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Contract.Call",
            Expr.Not(Expr.Eq(new UnaryExpr(Sort.Int, "size", hash.Expression), Expr.Int(Hash160Length))),
            $"target hash length must be exactly {Hash160Length} bytes",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceContractCallMethodName(
        ExecutionState state,
        Instruction inst,
        SymbolicValue method)
    {
        if (method.IsConcreteNull)
            throw new VmFaultException("Contract.Call with null method name");

        var normalizedMethod = NormalizeStorageBytes(state, method);
        if (Expr.CanonicalBytes(normalizedMethod.Expression) is { } bytes)
        {
            string name = DecodeStrictUtf8OrThrow(bytes, "Contract.Call", "method name");
            if (name.StartsWith("_", System.StringComparison.Ordinal))
                throw new VmFaultException($"Contract.Call to private method '{name}'");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Contract.Call",
            Expr.Not(Expr.IsStrictUtf8(normalizedMethod.Expression)),
            "method name may be invalid strict UTF-8",
            "VM syscall precondition holds under requires"));

        var size = StorageByteLengthExpression(normalizedMethod.Expression);
        var firstByte = new BinaryExpr(Sort.Int, "pick", normalizedMethod.Expression, Expr.Int(0));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "Contract.Call",
            Expr.BoolAnd(
                Expr.Gt(size, Expr.Int(0)),
                Expr.Eq(firstByte, Expr.Int((byte)'_'))),
            "method name may start with '_' and target a private method",
            "VM syscall precondition holds under requires"));
    }

    private static void EnforceCallFlagsRange(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue callFlags)
    {
        if (Expr.ConcreteInt(callFlags.Expression) is { } flags)
        {
            if (flags < 0 || flags > MaxContractCallFlags)
                throw new VmFaultException($"{operation} with invalid call flags {flags}");
            return;
        }

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.BoolOr(
                Expr.Lt(callFlags.Expression, Expr.Int(0)),
                Expr.Gt(callFlags.Expression, Expr.Int(MaxContractCallFlags))),
            $"call flags must be between 0 and {MaxContractCallFlags}",
            "VM syscall precondition holds under requires"));
    }

    private IEnumerable<ExecutionState> HandleContractCallNative(ExecutionState state, Instruction inst)
    {
        state.Pop(); // version
        throw new VmFaultException("System.Contract.CallNative is not allowed to be used directly by user contracts");
    }

    private IEnumerable<ExecutionState> HandleCallToken(ExecutionState state, Instruction inst)
    {
        ValidateCurrentCallFlags(state, "CALLT", NeoCallFlags.ReadStates | NeoCallFlags.AllowCall);

        // CALLT operand: 2-byte token index into the NEF's MethodToken[]. Audit M1 fix:
        // when the program carries token metadata, pop the declared parameter count and only
        // push a return value if the token has one. Without metadata the stack effect is unknown,
        // so continuing would under-approximate the call and corrupt later stack semantics.
        ushort idx = inst.Operand.Length >= 2
            ? System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(inst.Operand.Span)
            : (ushort)0;

        Nef.MethodToken? token = null;
        if (idx < _program.Tokens.Length) token = _program.Tokens[idx];
        if (token is null)
        {
            state.Terminate(
                TerminalStatus.Stopped,
                $"CALLT token #{idx} requires NEF MethodToken metadata; verify the .nef instead of raw script bytes");
            return Single(state);
        }
        if (token.CallFlags < 0 || token.CallFlags > MaxContractCallFlags)
            throw new VmFaultException($"CALLT token #{idx} has invalid call flags {token.CallFlags}");
        if (token.Method.StartsWith("_", System.StringComparison.Ordinal))
            throw new VmFaultException($"CALLT token #{idx} targets private method '{token.Method}'");

        var ext = new ExternalCall
        {
            Offset = inst.Offset,
            Method = token.Method,
            TargetHash = SymbolicValue.Bytes(token.Hash),
            TargetHashDynamic = false,
            MethodDynamic = false,
            CallFlags = token.CallFlags & state.CurrentCallFlags,
            CallFlagsDynamic = false,
            HasReturnValue = token.HasReturnValue,
            ReturnValueDeclaredByMethodToken = true,
        };

        // Pop the declared parameter count; record them on the call for taint analysis.
        for (int i = 0; i < token.ParametersCount; i++)
        {
            if (state.EvaluationStack.Count == 0)
                throw new VmFaultException($"CALLT to {token.Method}: stack underflow on parameter {i}");
            ext.Args.Insert(0, state.Pop());
        }

        if (TryExecuteContractSelfCall(
                state,
                inst,
                ext,
                ext.Args,
                ContractSelfCallResultMode.MethodToken,
                out var selfCallStates))
        {
            return selfCallStates;
        }

        state.Telemetry.ExternalCalls.Add(ext);
        EnsureModeledNativeMethodTokenReturnShape(ext);
        if (TryHandleContractManagementGetContractNativeCall(state, inst, ext, out var getContractStates))
            return getContractStates;
        if (TryHandleContractManagementIsContractNativeCall(state, inst, ext, out var isContractStates))
            return isContractStates;
        if (TryHandleContractManagementHasMethodNativeCall(state, inst, ext, out var hasMethodStates))
            return hasMethodStates;
        if (TryHandleContractManagementGetContractHashesNativeCall(state, inst, ext, out var getContractHashesStates))
            return getContractHashesStates;
        if (TryHandleContractManagementGetContractByIdNativeCall(state, inst, ext, out var getContractByIdStates))
            return getContractByIdStates;
        if (TryHandleContractManagementLifecycleNativeCall(state, inst, ext, out var lifecycleStates))
            return lifecycleStates;
        if (TryHandleOracleRequestNativeCall(state, inst, ext, out var oracleRequestStates))
            return oracleRequestStates;
        if (TryHandleNativeTokenTransferNativeCall(state, inst, ext, out var nativeTokenTransferStates))
            return nativeTokenTransferStates;
        if (TryHandleLedgerGetBlockNativeCall(state, inst, ext, out var blockStates))
            return blockStates;
        if (TryHandleLedgerGetTransactionFromBlockNativeCall(state, inst, ext, out var transactionFromBlockStates))
            return transactionFromBlockStates;
        if (TryHandleLedgerGetTransactionNativeCall(state, inst, ext, out var transactionStates))
            return transactionStates;
        if (TryHandleLedgerGetTransactionSignersNativeCall(state, inst, ext, out var transactionSignersStates))
            return transactionSignersStates;
        if (TryHandleNativeTokenGetAccountStateNativeCall(state, inst, ext, out var accountStateStates))
            return accountStateStates;
        if (ext.HasReturnValue
            && TryHandleCryptoLibRecoverSecp256K1NativeCall(state, inst, ext, out var recoverSecp256K1States))
        {
            return recoverSecp256K1States;
        }
        if (ext.HasReturnValue && TryHandlePureNativeCall(state, inst, ext, out var nativeReturn))
        {
            ext.ReturnModeledNative = true;
            state.Push(WithExternalReturnProvenance(nativeReturn, inst.Offset));
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        if (ext.HasReturnValue)
            state.Push(SymbolicValue.Symbol(Sort.Unknown, $"ext_ret_{inst.Offset}"));
        else if (IsKnownNativeContractCall(ext))
            AddUnknownSyscall(state, inst.Offset);
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
