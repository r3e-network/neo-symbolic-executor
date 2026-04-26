using System;
using System.Collections.Generic;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Oracle: every heap reference reachable from an <see cref="ExecutionState"/> after
/// <see cref="SymbolicEngine.Run"/> resolves to a live entry in that state's heap. A dangling
/// reference would make a Get(id) call throw <see cref="VmFaultException"/> downstream — a
/// classic source of crashes that survive the engine outer try/catch only as an opaque fault.
///
/// Walks all roots: EvaluationStack, StaticFields, all CallFrames' Locals + Args, and
/// transitively into containers (ArrayObject.Items, StructObject.Fields, MapObject.Entries).
/// BufferObject cells are Expressions, not SymbolicValues, so they cannot themselves hold
/// heap refs and are skipped.
/// </summary>
public sealed class HeapInvariantTarget : IFuzzTarget
{
    public string Name => "heap-invariants";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 6, 80);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000, MaxPaths = 16, MaxStackSize = 64,
            MaxItemSize = 16 * 1024, MaxCollectionSize = 128,
        }).Run();

        foreach (var s in result.FinalStates)
        {
            if (!CheckState(s, out var why))
            {
                reason = why;
                return false;
            }
        }
        return true;
    }

    private static bool CheckState(ExecutionState s, out string reason)
    {
        var visited = new HashSet<int>();
        var queue = new Queue<SymbolicValue>();
        foreach (var v in s.EvaluationStack) queue.Enqueue(v);
        foreach (var v in s.StaticFields) if (v is not null) queue.Enqueue(v);
        foreach (var f in s.CallStack)
        {
            foreach (var v in f.Locals) if (v is not null) queue.Enqueue(v);
            foreach (var v in f.Args) if (v is not null) queue.Enqueue(v);
        }

        while (queue.TryDequeue(out var v))
        {
            if (v.Expression is not HeapRef href) continue;
            int hid = href.ObjectId;
            if (!visited.Add(hid)) continue;

            if (!s.Heap.Objects.TryGetValue(hid, out var obj))
            {
                reason = $"dangling heap ref {hid} (state pc=0x{s.Pc:X4})";
                return false;
            }

            switch (obj)
            {
                case ArrayObject ao:
                    foreach (var item in ao.Items) queue.Enqueue(item);
                    break;
                case StructObject so:
                    foreach (var item in so.Fields) queue.Enqueue(item);
                    break;
                case MapObject mo:
                    foreach (var (k, val) in mo.Entries) { queue.Enqueue(k); queue.Enqueue(val); }
                    break;
                // BufferObject cells are bare Expressions (bytes), not SymbolicValues, and cannot
                // themselves carry heap refs. Skipping.
            }
        }
        reason = string.Empty;
        return true;
    }
}
