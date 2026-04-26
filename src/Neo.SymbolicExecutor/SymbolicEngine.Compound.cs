using System.Collections.Generic;
using System.Linq;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> DispatchExtended(ExecutionState state, Instruction inst)
    {
        switch (inst.OpCode)
        {
            // ---- Compound: array, struct, map
            case NeoVm.OpCode.NEWARRAY0:
                {
                    var arr = state.Heap.NewArray();
                    state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.NEWSTRUCT0:
                {
                    var s = state.Heap.NewStruct();
                    state.Push(SymbolicValue.HeapRef(Sort.Struct, s.Id));
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.NEWMAP:
                {
                    var m = state.Heap.NewMap();
                    state.Push(SymbolicValue.HeapRef(Sort.Map, m.Id));
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.NEWARRAY:
                return NewSized(state, inst, kind: "array");
            case NeoVm.OpCode.NEWSTRUCT:
                return NewSized(state, inst, kind: "struct");
            case NeoVm.OpCode.NEWARRAY_T:
                {
                    int typeByte = inst.Operand.Span[0]; // currently we ignore the per-cell type
                    _ = typeByte;
                    return NewSized(state, inst, kind: "array");
                }

            case NeoVm.OpCode.PACK:    return PackArrayOrStructOrMap(state, inst, mode: PackMode.Array);
            case NeoVm.OpCode.PACKSTRUCT: return PackArrayOrStructOrMap(state, inst, mode: PackMode.Struct);
            case NeoVm.OpCode.PACKMAP:    return PackArrayOrStructOrMap(state, inst, mode: PackMode.Map);

            case NeoVm.OpCode.UNPACK:
                return Unpack(state, inst);

            case NeoVm.OpCode.SIZE:
                {
                    var v = state.Pop();
                    int? size = ConcreteSize(state, v);
                    if (size is null)
                    {
                        state.Push(SymbolicValue.Of(new UnaryExpr(Sort.Int, "size", v.Expression), v.Taints));
                    }
                    else
                    {
                        state.Push(SymbolicValue.Int(size.Value));
                    }
                    state.Pc = inst.EndOffset; return Single(state);
                }

            case NeoVm.OpCode.HASKEY: return CollectionLookup(state, inst, mode: LookupMode.HasKey);
            case NeoVm.OpCode.PICKITEM: return CollectionLookup(state, inst, mode: LookupMode.Get);
            case NeoVm.OpCode.SETITEM: return CollectionWrite(state, inst, mode: WriteMode.Set);
            case NeoVm.OpCode.APPEND: return CollectionWrite(state, inst, mode: WriteMode.Append);
            case NeoVm.OpCode.REVERSEITEMS: return CollectionMutate(state, inst, ReverseInPlace);
            case NeoVm.OpCode.CLEARITEMS: return CollectionMutate(state, inst, ClearInPlace);
            case NeoVm.OpCode.POPITEM: return PopItem(state, inst);
            case NeoVm.OpCode.REMOVE: return CollectionWrite(state, inst, mode: WriteMode.Remove);
            case NeoVm.OpCode.KEYS: return MapKeys(state, inst);
            case NeoVm.OpCode.VALUES: return MapValues(state, inst);

            // ---- Splice (covered in SymbolicEngine.Splice.cs partial)
            case NeoVm.OpCode.NEWBUFFER: return HandleNewBuffer(state, inst);
            case NeoVm.OpCode.MEMCPY: return HandleMemCpy(state, inst);
            case NeoVm.OpCode.CAT: return HandleCat(state, inst);
            case NeoVm.OpCode.SUBSTR: return HandleSubstr(state, inst);
            case NeoVm.OpCode.LEFT: return HandleLeft(state, inst);
            case NeoVm.OpCode.RIGHT: return HandleRight(state, inst);

            case NeoVm.OpCode.CALLT:
                return HandleCallToken(state, inst);

            default:
                state.Telemetry.UnknownOpcodes.Add(inst.Offset);
                state.Terminate(TerminalStatus.Stopped, $"unsupported opcode {inst.OpCode} (0x{(byte)inst.OpCode:X2}) at 0x{inst.Offset:X4}");
                return Single(state);
        }
    }

    private IEnumerable<ExecutionState> NewSized(ExecutionState state, Instruction inst, string kind)
    {
        var n = state.Pop();
        var sz = n.AsConcreteInt();
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, $"NEW{kind.ToUpper()} requires concrete size"); return Single(state); }
        if (sz.Value < 0 || sz.Value > _options.MaxCollectionSize)
            throw new VmFaultException($"NEW{kind.ToUpper()} size {sz} out of range");
        var fill = Enumerable.Repeat(SymbolicValue.Null(), (int)sz.Value);
        if (kind == "array")
        {
            var a = state.Heap.NewArray(fill);
            state.Push(SymbolicValue.HeapRef(Sort.Array, a.Id));
        }
        else
        {
            var s = state.Heap.NewStruct(fill);
            state.Push(SymbolicValue.HeapRef(Sort.Struct, s.Id));
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private enum PackMode { Array, Struct, Map }

    private IEnumerable<ExecutionState> PackArrayOrStructOrMap(ExecutionState state, Instruction inst, PackMode mode)
    {
        var n = state.Pop();
        var sz = n.AsConcreteInt();
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, "PACK requires concrete size"); return Single(state); }
        int count = (int)sz.Value;
        if (count < 0) throw new VmFaultException("PACK negative size");
        state.Heap.EnforceCollectionGrowth(count);
        switch (mode)
        {
            case PackMode.Array:
                {
                    var items = new List<SymbolicValue>(count);
                    for (int i = 0; i < count; i++) items.Add(state.Pop());
                    var a = state.Heap.NewArray(items);
                    state.Push(SymbolicValue.HeapRef(Sort.Array, a.Id));
                    break;
                }
            case PackMode.Struct:
                {
                    var items = new List<SymbolicValue>(count);
                    for (int i = 0; i < count; i++) items.Add(state.Pop());
                    var s = state.Heap.NewStruct(items);
                    state.Push(SymbolicValue.HeapRef(Sort.Struct, s.Id));
                    break;
                }
            case PackMode.Map:
                {
                    var entries = new List<(SymbolicValue, SymbolicValue)>(count);
                    for (int i = 0; i < count; i++)
                    {
                        var key = state.Pop();
                        var value = state.Pop();
                        entries.Add((key, value));
                    }
                    var m = state.Heap.NewMap(entries);
                    state.Push(SymbolicValue.HeapRef(Sort.Map, m.Id));
                    break;
                }
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> Unpack(ExecutionState state, Instruction inst)
    {
        var v = state.Pop();
        if (v.Expression is not HeapRef href)
            throw new VmFaultException("UNPACK on non-collection");
        var obj = state.Heap.Get(href.ObjectId);
        switch (obj)
        {
            case ArrayObject a:
                for (int i = a.Items.Count - 1; i >= 0; i--) state.Push(a.Items[i]);
                state.Push(SymbolicValue.Int(a.Items.Count));
                break;
            case StructObject s:
                for (int i = s.Fields.Count - 1; i >= 0; i--) state.Push(s.Fields[i]);
                state.Push(SymbolicValue.Int(s.Fields.Count));
                break;
            case MapObject m:
                for (int i = m.Entries.Count - 1; i >= 0; i--)
                {
                    state.Push(m.Entries[i].Value);
                    state.Push(m.Entries[i].Key);
                }
                state.Push(SymbolicValue.Int(m.Entries.Count));
                break;
            default:
                throw new VmFaultException($"UNPACK on {obj.Sort}");
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static int? ConcreteSize(ExecutionState state, SymbolicValue v) => v.Expression switch
    {
        BytesConst by => by.Value.Length,
        HeapRef href => state.Heap.Get(href.ObjectId) switch
        {
            ArrayObject a => a.Items.Count,
            StructObject s => s.Fields.Count,
            MapObject m => m.Entries.Count,
            BufferObject b => b.Length,
            _ => null,
        },
        IntConst i => Expr.IntegerToBytes(i.Value).Length,
        BoolConst => 1,
        NullConst => 0,
        _ => null,
    };

    private enum LookupMode { Get, HasKey }
    private enum WriteMode { Set, Append, Remove }

    private IEnumerable<ExecutionState> CollectionLookup(ExecutionState state, Instruction inst, LookupMode mode)
    {
        var key = state.Pop();
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href)
        {
            // Primitive type: PICKITEM by index over Bytes
            return PrimitivePickItem(state, inst, coll, key, mode);
        }
        var obj = state.Heap.Get(href.ObjectId);
        switch (obj)
        {
            case ArrayObject a:
                return ArrayLookup(state, inst, a, key, mode);
            case StructObject s:
                return ArrayLookup(state, inst, new ArrayWrapper(s.Fields), key, mode);
            case MapObject m:
                return MapLookup(state, inst, m, key, mode);
            case BufferObject b:
                return BufferLookup(state, inst, b, key, mode);
            default:
                throw new VmFaultException($"PICKITEM/HASKEY on {obj.Sort}");
        }
    }

    private IEnumerable<ExecutionState> PrimitivePickItem(ExecutionState state, Instruction inst, SymbolicValue coll, SymbolicValue key, LookupMode mode)
    {
        var bytes = Expr.CanonicalBytes(coll.Expression);
        var idx = key.AsConcreteInt();
        if (bytes is null || idx is null)
        {
            state.Push(SymbolicValue.Of(new BinaryExpr(Sort.Int, mode == LookupMode.Get ? "pick" : "haskey", coll.Expression, key.Expression)));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        int i = (int)idx.Value;
        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Bool(i >= 0 && i < bytes.Length));
        }
        else
        {
            // Audit MED-2: out-of-range PICKITEM on PrimitiveType is a CatchableException — but for now
            // we surface as a fault and let TRY/CATCH propagation handle it (since we throw the fault path).
            if (i < 0 || i >= bytes.Length)
                throw new CatchableVmException($"PICKITEM index {i} out of range (size {bytes.Length})");
            state.Push(SymbolicValue.Int(bytes[i]));
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static IEnumerable<ExecutionState> ArrayLookup(ExecutionState state, Instruction inst, ArrayObject a, SymbolicValue key, LookupMode mode)
    {
        var idx = key.AsConcreteInt();
        if (idx is null)
        {
            // Symbolic index over array — concretization deferred.
            state.Terminate(TerminalStatus.Stopped, "Array PICKITEM/HASKEY with symbolic index not yet supported");
            return Single(state);
        }
        int i = (int)idx.Value;
        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Bool(i >= 0 && i < a.Items.Count));
        }
        else
        {
            if (i < 0 || i >= a.Items.Count)
                throw new CatchableVmException($"PICKITEM index {i} out of array range (size {a.Items.Count})");
            state.Push(a.Items[i]);
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    /// <summary>Wrapper to share array-style indexing logic between Array and Struct.</summary>
    private sealed class ArrayWrapper
    {
        private readonly List<SymbolicValue> _items;
        public ArrayWrapper(List<SymbolicValue> items) { _items = items; }
        public List<SymbolicValue> Items => _items;
    }

    private static IEnumerable<ExecutionState> ArrayLookup(ExecutionState state, Instruction inst, ArrayWrapper a, SymbolicValue key, LookupMode mode)
    {
        var idx = key.AsConcreteInt();
        if (idx is null)
        {
            state.Terminate(TerminalStatus.Stopped, "Struct PICKITEM/HASKEY with symbolic index not yet supported");
            return new[] { state };
        }
        int i = (int)idx.Value;
        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Bool(i >= 0 && i < a.Items.Count));
        }
        else
        {
            if (i < 0 || i >= a.Items.Count)
                throw new CatchableVmException($"PICKITEM index {i} out of struct range (size {a.Items.Count})");
            state.Push(a.Items[i]);
        }
        state.Pc = inst.EndOffset;
        return new[] { state };
    }

    private static IEnumerable<ExecutionState> BufferLookup(ExecutionState state, Instruction inst, BufferObject b, SymbolicValue key, LookupMode mode)
    {
        var idx = key.AsConcreteInt();
        if (idx is null)
        {
            state.Terminate(TerminalStatus.Stopped, "Buffer PICKITEM with symbolic index not yet supported");
            return new[] { state };
        }
        int i = (int)idx.Value;
        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Bool(i >= 0 && i < b.Length));
        }
        else
        {
            if (i < 0 || i >= b.Length)
                throw new CatchableVmException($"PICKITEM index {i} out of buffer range (size {b.Length})");
            state.Push(SymbolicValue.Of(b.Cells[i]));
        }
        state.Pc = inst.EndOffset;
        return new[] { state };
    }

    private static IEnumerable<ExecutionState> MapLookup(ExecutionState state, Instruction inst, MapObject m, SymbolicValue key, LookupMode mode)
    {
        // Concrete-key path: search using NeoVM cross-type equality.
        if (key.IsConcrete)
        {
            int idx = FindMapEntry(m, key);
            if (mode == LookupMode.HasKey)
            {
                state.Push(SymbolicValue.Bool(idx >= 0));
            }
            else
            {
                if (idx < 0)
                    throw new CatchableVmException("PICKITEM map key not found");
                state.Push(m.Entries[idx].Value);
            }
            state.Pc = inst.EndOffset;
            return new[] { state };
        }
        // Symbolic key — defer (full path explosion would otherwise occur). SMT layer pulls weight here.
        state.Terminate(TerminalStatus.Stopped, "Map PICKITEM/HASKEY with symbolic key not yet supported");
        return new[] { state };
    }

    private static int FindMapEntry(MapObject m, SymbolicValue key)
    {
        for (int i = 0; i < m.Entries.Count; i++)
        {
            if (m.Entries[i].Key.IsConcrete && Expr.PrimitiveEqualsConcrete(m.Entries[i].Key.Expression, key.Expression))
                return i;
        }
        return -1;
    }

    private IEnumerable<ExecutionState> CollectionWrite(ExecutionState state, Instruction inst, WriteMode mode)
    {
        switch (mode)
        {
            case WriteMode.Set:
                {
                    var value = state.Pop();
                    var key = state.Pop();
                    var coll = state.Pop();
                    if (coll.Expression is not HeapRef href) throw new VmFaultException("SETITEM on non-collection");
                    var obj = state.Heap.Get(href.ObjectId);
                    SetItem(state, obj, key, value);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case WriteMode.Append:
                {
                    var value = state.Pop();
                    var coll = state.Pop();
                    if (coll.Expression is not HeapRef href) throw new VmFaultException("APPEND on non-collection");
                    var obj = state.Heap.Get(href.ObjectId);
                    if (obj is ArrayObject a)
                    {
                        state.Heap.EnforceCollectionGrowth(a.Items.Count + 1);
                        a.Items.Add(value);
                    }
                    else if (obj is StructObject s)
                    {
                        state.Heap.EnforceCollectionGrowth(s.Fields.Count + 1);
                        s.Fields.Add(value);
                    }
                    else throw new VmFaultException("APPEND only valid on Array/Struct");
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case WriteMode.Remove:
                {
                    var key = state.Pop();
                    var coll = state.Pop();
                    if (coll.Expression is not HeapRef href) throw new VmFaultException("REMOVE on non-collection");
                    var obj = state.Heap.Get(href.ObjectId);
                    RemoveItem(obj, key);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
        }
        return Single(state);
    }

    private static void SetItem(ExecutionState state, HeapObject obj, SymbolicValue key, SymbolicValue value)
    {
        switch (obj)
        {
            case ArrayObject a:
                {
                    var idx = key.AsConcreteInt() ?? throw new VmFaultException("SETITEM array requires concrete index");
                    int i = (int)idx;
                    if (i < 0 || i >= a.Items.Count)
                        throw new CatchableVmException($"SETITEM index {i} out of array range");
                    a.Items[i] = value;
                    break;
                }
            case StructObject s:
                {
                    var idx = key.AsConcreteInt() ?? throw new VmFaultException("SETITEM struct requires concrete index");
                    int i = (int)idx;
                    if (i < 0 || i >= s.Fields.Count)
                        throw new CatchableVmException($"SETITEM index {i} out of struct range");
                    s.Fields[i] = value;
                    break;
                }
            case MapObject m:
                {
                    if (!key.IsConcrete) throw new VmFaultException("SETITEM map with symbolic key not yet supported");
                    int idx = FindMapEntry(m, key);
                    if (idx >= 0)
                    {
                        // Audit LOW-4: keep the original key on overwrite (NeoVM semantics).
                        m.Entries[idx] = (m.Entries[idx].Key, value);
                    }
                    else
                    {
                        state.Heap.EnforceCollectionGrowth(m.Entries.Count + 1);
                        m.Entries.Add((key, value));
                    }
                    break;
                }
            case BufferObject b:
                {
                    var idx = key.AsConcreteInt() ?? throw new VmFaultException("SETITEM buffer requires concrete index");
                    int i = (int)idx;
                    if (i < 0 || i >= b.Length)
                        throw new CatchableVmException($"SETITEM index {i} out of buffer range");
                    b.Cells[i] = value.Expression;
                    break;
                }
            default:
                throw new VmFaultException($"SETITEM on {obj.Sort}");
        }
    }

    private static void RemoveItem(HeapObject obj, SymbolicValue key)
    {
        switch (obj)
        {
            case ArrayObject a:
                {
                    var idx = key.AsConcreteInt() ?? throw new VmFaultException("REMOVE requires concrete index");
                    int i = (int)idx;
                    if (i < 0 || i >= a.Items.Count) throw new CatchableVmException("REMOVE out of range");
                    a.Items.RemoveAt(i);
                    break;
                }
            case StructObject s:
                {
                    var idx = key.AsConcreteInt() ?? throw new VmFaultException("REMOVE requires concrete index");
                    int i = (int)idx;
                    if (i < 0 || i >= s.Fields.Count) throw new CatchableVmException("REMOVE out of range");
                    s.Fields.RemoveAt(i);
                    break;
                }
            case MapObject m:
                {
                    if (!key.IsConcrete) throw new VmFaultException("REMOVE map with symbolic key not yet supported");
                    int idx = FindMapEntry(m, key);
                    if (idx >= 0) m.Entries.RemoveAt(idx);
                    break;
                }
            default:
                throw new VmFaultException($"REMOVE on {obj.Sort}");
        }
    }

    private IEnumerable<ExecutionState> CollectionMutate(ExecutionState state, Instruction inst, System.Action<HeapObject> mutator)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("collection op on non-collection");
        mutator(state.Heap.Get(href.ObjectId));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static void ReverseInPlace(HeapObject obj)
    {
        switch (obj)
        {
            case ArrayObject a: a.Items.Reverse(); break;
            case StructObject s: s.Fields.Reverse(); break;
            case BufferObject b: b.Cells.Reverse(); break;
            default: throw new VmFaultException("REVERSEITEMS on non-list collection");
        }
    }

    private static void ClearInPlace(HeapObject obj)
    {
        switch (obj)
        {
            case ArrayObject a: a.Items.Clear(); break;
            case StructObject s: s.Fields.Clear(); break;
            case MapObject m: m.Entries.Clear(); break;
            case BufferObject b:
                for (int i = 0; i < b.Length; i++) b.Cells[i] = Expr.Int(0);
                break;
        }
    }

    private IEnumerable<ExecutionState> PopItem(ExecutionState state, Instruction inst)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("POPITEM on non-array");
        var obj = state.Heap.Get(href.ObjectId);
        if (obj is ArrayObject a)
        {
            if (a.Items.Count == 0) throw new CatchableVmException("POPITEM on empty array");
            var v = a.Items[^1];
            a.Items.RemoveAt(a.Items.Count - 1);
            state.Push(v);
        }
        else
        {
            throw new VmFaultException($"POPITEM on {obj.Sort}");
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> MapKeys(ExecutionState state, Instruction inst)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("KEYS on non-map");
        if (state.Heap.Get(href.ObjectId) is not MapObject m)
            throw new VmFaultException("KEYS on non-map");
        var arr = state.Heap.NewArray(m.Entries.Select(e => e.Key));
        state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> MapValues(ExecutionState state, Instruction inst)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("VALUES on non-map");
        if (state.Heap.Get(href.ObjectId) is not MapObject m)
            throw new VmFaultException("VALUES on non-map");
        var arr = state.Heap.NewArray(m.Entries.Select(e => e.Value));
        state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
