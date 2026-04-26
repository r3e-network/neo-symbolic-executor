using System;
using System.Collections.Generic;
using System.Numerics;

namespace Neo.SymbolicExecutor.Fuzzer.Generators;

/// <summary>
/// Generator for synthetic <see cref="ExecutionState"/> instances with random telemetry.
/// Used to stress detector logic without depending on the engine.
/// </summary>
public static class StateGen
{
    public static ExecutionState RandomState(Random rng)
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        s.Pc = rng.Next(0, 4096);
        s.Status = (rng.Next(4)) switch
        {
            0 => TerminalStatus.Halted,
            1 => TerminalStatus.Faulted,
            2 => TerminalStatus.Stopped,
            _ => TerminalStatus.Halted,
        };

        int sw = rng.Next(0, 8);
        for (int i = 0; i < sw; i++)
        {
            var key = rng.Next(2) == 0
                ? SymbolicValue.Bytes(RandomKeyBytes(rng))
                : SymbolicValue.Symbol(Sort.Bytes, $"key_{rng.Next()}");
            var op = (StorageOpKind)(rng.Next(4));
            s.Telemetry.StorageOps.Add(new StorageOp(rng.Next(0, 4096), op, key,
                op == StorageOpKind.Put ? SymbolicValue.Int(rng.Next()) : null,
                ContextDynamic: rng.Next(2) == 0,
                ContextReadOnly: rng.Next(4) == 0));
        }

        int ec = rng.Next(0, 6);
        for (int i = 0; i < ec; i++)
        {
            string method = rng.Next(5) switch
            {
                0 => "transfer", 1 => "balanceOf", 2 => "update", 3 => "destroy", _ => "doStuff",
            };
            s.Telemetry.ExternalCalls.Add(new ExternalCall
            {
                Offset = rng.Next(0, 4096),
                Method = method,
                TargetHash = rng.Next(2) == 0 ? SymbolicValue.Bytes(RandomHash(rng)) : SymbolicValue.Symbol(Sort.Bytes, "target"),
                TargetHashDynamic = rng.Next(2) == 0,
                MethodDynamic = rng.Next(3) == 0,
                CallFlags = rng.Next(0, 16),
                CallFlagsDynamic = rng.Next(4) == 0,
                HasReturnValue = rng.Next(2) == 0,
                ReturnChecked = rng.Next(2) == 0,
            });
        }

        int wc = rng.Next(0, 4);
        for (int i = 0; i < wc; i++)
        {
            int off = rng.Next(0, 4096);
            s.Telemetry.WitnessChecks.Add(off);
            if (rng.Next(2) == 0) s.Telemetry.WitnessChecksEnforced.Add(off);
        }

        int ao = rng.Next(0, 6);
        for (int i = 0; i < ao; i++)
        {
            string op = rng.Next(5) switch
            { 0 => "ADD", 1 => "SUB", 2 => "MUL", 3 => "DIV", _ => "MOD" };
            s.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
                rng.Next(0, 4096), op,
                SymbolicValue.Int(rng.Next()), SymbolicValue.Int(rng.Next()),
                OverflowPossible: rng.Next(2) == 0,
                DivisorMaybeZero: rng.Next(4) == 0,
                Checked: rng.Next(3) == 0));
        }

        if (rng.Next(8) == 0) s.Telemetry.ReentrancyGuard = true;
        if (rng.Next(16) == 0) s.Telemetry.Truncated = true;
        s.Telemetry.MaxCallStackDepth = rng.Next(0, 32);
        s.Telemetry.GasCost = rng.Next(0, 10_000_000);

        return s;
    }

    private static byte[] RandomKeyBytes(Random rng)
    {
        int len = rng.Next(1, 32);
        byte[] b = new byte[len];
        rng.NextBytes(b);
        return b;
    }

    private static byte[] RandomHash(Random rng)
    {
        byte[] b = new byte[20];
        rng.NextBytes(b);
        return b;
    }
}
