using System.Buffers.Binary;
using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> HandleSyscall(ExecutionState state, Instruction inst)
    {
        // Operand is a 4-byte little-endian syscall hash (per Neo N3).
        if (inst.Operand.Length != 4)
            throw new VmFaultException("SYSCALL requires 4-byte operand");
        uint hash = BinaryPrimitives.ReadUInt32LittleEndian(inst.Operand.Span);
        var syscall = SyscallRegistry.Lookup(hash);

        if (syscall is null)
        {
            state.Telemetry.UnknownSyscalls.Add(inst.Offset);
            state.Push(SymbolicValue.Symbol(Sort.Unknown, $"unknown_syscall_{inst.Offset}"));
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        // Audit C# #6 fix: accumulate per-syscall gas so GasExhaustionDetector has data to act on.
        state.Telemetry.GasCost += syscall.Price;
        return DispatchSyscall(state, inst, syscall);
    }

    private IEnumerable<ExecutionState> DispatchSyscall(ExecutionState state, Instruction inst, SyscallDescriptor descriptor)
    {
        switch (descriptor.Name)
        {
            case "System.Runtime.CheckWitness":
                {
                    state.Pop();
                    state.Telemetry.WitnessChecks.Add(inst.Offset);
                    state.Push(SymbolicValue.Symbol(Sort.Bool, $"witness_ok_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetCallingScriptHash":
                {
                    state.Push(SymbolicValue.Symbol(Sort.Bytes, $"caller_hash_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetExecutingScriptHash":
            case "System.Runtime.GetEntryScriptHash":
                {
                    state.Push(SymbolicValue.Symbol(Sort.Bytes, $"{descriptor.Name}_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetTime":
                {
                    state.Telemetry.TimeAccesses.Add(inst.Offset);
                    state.Push(SymbolicValue.Symbol(Sort.Int, "timestamp"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.GetRandom":
                {
                    state.Telemetry.RandomnessAccesses.Add(inst.Offset);
                    state.Push(SymbolicValue.Symbol(Sort.Int, $"random_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.Notify":
                {
                    state.Pop(); // state args
                    state.Pop(); // event name
                    state.Telemetry.EventsEmitted.Add(inst.Offset);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Runtime.Log":
                {
                    state.Pop();
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
                    state.Pop();
                    state.Push(SymbolicValue.Symbol(Sort.InteropInterface, $"storage_ctx_ro_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Get":
                {
                    var key = state.Pop();
                    var ctx = state.Pop();
                    bool ro = ctx.Expression is Symbol s && s.Name.StartsWith("storage_ctx_ro_", System.StringComparison.Ordinal);
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Get, key, null,
                        ContextDynamic: ctx.Expression is not Symbol, ContextReadOnly: ro));
                    state.Push(SymbolicValue.Symbol(Sort.Bytes, $"storage_value_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Put":
                {
                    var value = state.Pop();
                    var key = state.Pop();
                    var ctx = state.Pop();
                    bool ro = ctx.Expression is Symbol s && s.Name.StartsWith("storage_ctx_ro_", System.StringComparison.Ordinal);
                    if (ro) throw new VmFaultException("Storage.Put on read-only context");
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Put, key, value,
                        ContextDynamic: ctx.Expression is not Symbol, ContextReadOnly: false));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Delete":
                {
                    var key = state.Pop();
                    var ctx = state.Pop();
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Delete, key, null,
                        ContextDynamic: ctx.Expression is not Symbol, ContextReadOnly: false));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Storage.Find":
                {
                    state.Pop(); // options
                    var prefix = state.Pop();
                    var ctx = state.Pop();
                    state.Telemetry.StorageOps.Add(new StorageOp(inst.Offset, StorageOpKind.Find, prefix, null,
                        ContextDynamic: ctx.Expression is not Symbol, ContextReadOnly: false));
                    state.Push(SymbolicValue.Symbol(Sort.InteropInterface, $"iterator_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Iterator.Next":
                {
                    state.Pop();
                    state.Push(SymbolicValue.Symbol(Sort.Bool, $"iterator_has_next_{inst.Offset}"));
                    state.Telemetry.IteratorLoops.Add(inst.Offset);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Iterator.Value":
                {
                    state.Pop();
                    state.Push(SymbolicValue.Symbol(Sort.Bytes, $"iterator_value_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Crypto.CheckSig":
                {
                    state.Pop(); // signature
                    state.Pop(); // pubkey
                    state.Telemetry.SignatureChecks.Add(inst.Offset);
                    state.Push(SymbolicValue.Symbol(Sort.Bool, $"sig_ok_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Crypto.CheckMultisig":
                {
                    state.Pop(); // signatures
                    state.Pop(); // pubkeys
                    state.Telemetry.SignatureChecks.Add(inst.Offset);
                    state.Push(SymbolicValue.Symbol(Sort.Bool, $"multisig_ok_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case "System.Contract.Call":
                return HandleContractCall(state, inst);
            case "System.Contract.CallNative":
                return HandleContractCallNative(state, inst);
            case "System.Contract.GetCallFlags":
                {
                    state.Push(SymbolicValue.Symbol(Sort.Int, $"call_flags_{inst.Offset}"));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }

            default:
                // Modeled descriptor with no specific handler — push a sort-typed symbol if the
                // descriptor declares a return value, otherwise nothing.
                for (int i = 0; i < descriptor.PopArgs; i++)
                    state.Pop();
                if (descriptor.HasReturnValue)
                    state.Push(SymbolicValue.Symbol(Sort.Unknown, $"{descriptor.Name}_ret_{inst.Offset}"));
                state.Pc = inst.EndOffset;
                return Single(state);
        }
    }

    private IEnumerable<ExecutionState> HandleContractCall(ExecutionState state, Instruction inst)
    {
        // Stack (top-down): args[], callFlags, method, hash.
        var args = state.Pop();
        var callFlags = state.Pop();
        var method = state.Pop();
        var hash = state.Pop();

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
            CallFlags = callFlags.AsConcreteInt() is { } cf ? (int)cf : 0,
            CallFlagsDynamic = !callFlags.IsConcrete,
            HasReturnValue = true,
        };
        if (args.Expression is HeapRef href && state.Heap.Get(href.ObjectId) is ArrayObject arr)
        {
            foreach (var a in arr.Items) ext.Args.Add(a);
        }
        else
        {
            ext.Args.Add(args);
        }
        state.Telemetry.ExternalCalls.Add(ext);

        // Push a tagged return symbol so consumers can flag return-checks via expression flow.
        state.Push(SymbolicValue.Symbol(Sort.Unknown, $"ext_ret_{inst.Offset}"));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleContractCallNative(ExecutionState state, Instruction inst)
    {
        // Audit C5: native calls must be recorded as ExternalCall so detectors see Update/Destroy.
        state.Pop(); // version
        var ext = new ExternalCall
        {
            Offset = inst.Offset,
            Method = "<native>",
            HasReturnValue = true,
        };
        state.Telemetry.ExternalCalls.Add(ext);
        state.Push(SymbolicValue.Symbol(Sort.Unknown, $"native_ret_{inst.Offset}"));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleCallToken(ExecutionState state, Instruction inst)
    {
        // CALLT operand: 2-byte token index into the NEF's MethodToken[]. Audit M1 fix:
        // when the program carries token metadata, pop the declared parameter count and only
        // push a return value if the token has one. Without metadata we fall back to dynamic
        // and pop nothing (engine continues; the unchecked-return / dynamic-call detectors
        // surface the limitation).
        ushort idx = inst.Operand.Length >= 2
            ? System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(inst.Operand.Span)
            : (ushort)0;

        Nef.MethodToken? token = null;
        if (idx < _program.Tokens.Length) token = _program.Tokens[idx];

        var ext = new ExternalCall
        {
            Offset = inst.Offset,
            Method = token?.Method ?? $"<callt#{idx}>",
            TargetHash = token is not null
                ? SymbolicValue.Bytes(token.Hash)
                : null,
            TargetHashDynamic = token is null,
            MethodDynamic = token is null,
            CallFlags = token?.CallFlags ?? 0,
            CallFlagsDynamic = token is null,
            HasReturnValue = token?.HasReturnValue ?? true,
        };

        // Pop the declared parameter count; record them on the call for taint analysis.
        if (token is not null)
        {
            for (int i = 0; i < token.ParametersCount; i++)
            {
                if (state.EvaluationStack.Count == 0)
                    throw new VmFaultException($"CALLT to {token.Method}: stack underflow on parameter {i}");
                ext.Args.Add(state.Pop());
            }
        }

        state.Telemetry.ExternalCalls.Add(ext);
        if (ext.HasReturnValue)
            state.Push(SymbolicValue.Symbol(Sort.Unknown, $"ext_ret_{inst.Offset}"));
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
