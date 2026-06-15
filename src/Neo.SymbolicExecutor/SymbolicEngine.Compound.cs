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
                return NewSized(state, inst, CompoundKind.Array);
            case NeoVm.OpCode.NEWSTRUCT:
                return NewSized(state, inst, CompoundKind.Struct);
            case NeoVm.OpCode.NEWARRAY_T:
                {
                    // Audit fix (engine H5): NeoVM prefills cells with the type's default
                    // (Boolean.False / Integer.Zero / ByteString.Empty / Null for everything
                    // else). The prior `_ = typeByte` discarded the operand entirely, leaving
                    // every cell as Null and breaking downstream ISTYPE/CONVERT branches.
                    return NewSizedTyped(state, inst, (byte)inst.Operand.Span[0]);
                }

            case NeoVm.OpCode.PACK: return PackArrayOrStructOrMap(state, inst, mode: PackMode.Array);
            case NeoVm.OpCode.PACKSTRUCT: return PackArrayOrStructOrMap(state, inst, mode: PackMode.Struct);
            case NeoVm.OpCode.PACKMAP: return PackArrayOrStructOrMap(state, inst, mode: PackMode.Map);

            case NeoVm.OpCode.UNPACK:
                return Unpack(state, inst);

            case NeoVm.OpCode.SIZE:
                {
                    var v = state.Pop();
                    // Round-3 audit fix: NeoVM's SIZE faults (uncatchable, verified on the real VM) on
                    // Null — only primitives (Size = GetSpan().Length) and compounds (Count) are valid.
                    // The prior ConcreteSize mapping of Null to 0 silently hid that fault.
                    if (v.IsConcreteNull)
                        throw new VmFaultException("SIZE of Null");
                    if (TryOpenSequenceSize(state, v) is { } openSize)
                    {
                        state.Push(openSize);
                    }
                    else if (ConcreteSize(state, v) is { } size)
                    {
                        state.Push(SymbolicValue.Int(size));
                    }
                    else
                    {
                        state.Push(SymbolicValue.Of(new UnaryExpr(Sort.Int, "size", v.Expression), v.Taints));
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

    private IEnumerable<ExecutionState> NewSizedTyped(ExecutionState state, Instruction inst, byte typeByte)
    {
        // Validate the operand byte. NeoVM rejects undefined types with InvalidOperationException.
        if (!IsValidArrayCellType(typeByte))
            throw new VmFaultException($"NEWARRAY_T with invalid cell type 0x{typeByte:X2}");
        var n = state.Pop();
        var sz = TryConcretizeIndex(state, n, lo: 0, hi: _options.MaxCollectionSize);
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, "NEWARRAY_T requires concrete size (no SMT model)"); return Single(state); }
        if (sz < 0 || sz > _options.MaxCollectionSize)
            throw new VmFaultException($"NEWARRAY_T size {sz} out of range");
        var fill = new List<SymbolicValue>((int)sz.Value);
        var defaultValue = DefaultForType(typeByte);
        for (int i = 0; i < sz.Value; i++) fill.Add(defaultValue);
        var arr = state.Heap.NewArray(fill);
        state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static bool IsValidArrayCellType(byte b) => b is
        StackItemTypeCodes.Any or
        StackItemTypeCodes.Boolean or
        StackItemTypeCodes.Integer or
        StackItemTypeCodes.ByteString or
        StackItemTypeCodes.Buffer or
        StackItemTypeCodes.Array or
        StackItemTypeCodes.Struct or
        StackItemTypeCodes.Map or
        StackItemTypeCodes.Pointer or
        StackItemTypeCodes.InteropInterface;

    private static SymbolicValue DefaultForType(byte typeByte) => typeByte switch
    {
        StackItemTypeCodes.Boolean => SymbolicValue.Bool(false),
        StackItemTypeCodes.Integer => SymbolicValue.Int(0),
        StackItemTypeCodes.ByteString => SymbolicValue.Bytes(System.Array.Empty<byte>()),
        // Reference types (Buffer/Array/Struct/Map/Pointer/InteropInterface) and Any: Null is the
        // NeoVM default for "no concrete object yet".
        _ => SymbolicValue.Null(),
    };

    private enum CompoundKind { Array, Struct }

    private IEnumerable<ExecutionState> NewSized(ExecutionState state, Instruction inst, CompoundKind kind)
    {
        var n = state.Pop();
        var sz = TryConcretizeIndex(state, n, lo: 0, hi: _options.MaxCollectionSize);
        string opName = inst.OpCode.ToString();
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, $"{opName} requires concrete size (no SMT model)"); return Single(state); }
        if (sz < 0 || sz > _options.MaxCollectionSize)
            throw new VmFaultException($"{opName} size {sz} out of range");
        var fill = Enumerable.Repeat(SymbolicValue.Null(), (int)sz.Value);
        switch (kind)
        {
            case CompoundKind.Array:
                var a = state.Heap.NewArray(fill);
                state.Push(SymbolicValue.HeapRef(Sort.Array, a.Id));
                break;
            case CompoundKind.Struct:
                var s = state.Heap.NewStruct(fill);
                state.Push(SymbolicValue.HeapRef(Sort.Struct, s.Id));
                break;
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private enum PackMode { Array, Struct, Map }

    private IEnumerable<ExecutionState> PackArrayOrStructOrMap(ExecutionState state, Instruction inst, PackMode mode)
    {
        var n = state.Pop();
        var sz = TryConcretizeIndex(state, n, lo: 0, hi: _options.MaxCollectionSize);
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, "PACK requires concrete size (no SMT model)"); return Single(state); }
        if (sz < 0 || sz > _options.MaxCollectionSize)
            throw new VmFaultException($"PACK size {sz} out of range");
        int count = (int)sz.Value;
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
                        EnsureMapKeyPrimitive(state, inst, "PACKMAP", key);
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
        // Review fix (open-collection soundness): UNPACK pushes one element per slot plus the
        // collection length. For an open (symbolic-length) collection the true count is unknown,
        // so materializing only the seeded prefix and pushing its concrete count silently
        // under-approximates the runtime length. Terminate as a modeling limit so the verifier
        // downgrades to Incomplete (and analyze marks coverage incomplete) instead of proving over
        // a single seeded length. SIZE/PICKITEM/SETITEM/REMOVE already model open length precisely;
        // UNPACK cannot because its result shape depends on the unknown count.
        if (obj is ArrayObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("UNPACK over open symbolic Array of unknown length not modeled");
        if (obj is StructObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("UNPACK over open symbolic Struct of unknown length not modeled");
        if (obj is MapObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("UNPACK over open symbolic Map of unknown size not modeled");
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

    private static int? ConcreteSize(ExecutionState state, SymbolicValue v)
    {
        if (Expr.FixedByteSize(v.Expression) is { } fixedByteSize)
            return fixedByteSize;

        return v.Expression switch
        {
            BytesConst by => by.Value.Length,
            HeapRef href => state.Heap.Get(href.ObjectId) switch
            {
                // Round-2 fix: an open (symbolic-length) collection has no concrete size — returning
                // the seeded materialized count would let `coll.Count == N` fold to a concrete value
                // and prune feasible paths (false negative). SIZE of an open Array/Struct/Buffer is
                // already intercepted by TryOpenSequenceSize before this method; open Maps were NOT
                // (TryOpenSequenceSize has no Map case), so an open Map's SIZE reached here and
                // returned the seeded Entries.Count. Return null for every open kind so SIZE falls
                // through to a symbolic size node (Buffer already did this).
                ArrayObject { IsSymbolicOpen: true } => null,
                StructObject { IsSymbolicOpen: true } => null,
                MapObject { IsSymbolicOpen: true } => null,
                ArrayObject a => a.Items.Count,
                StructObject s => s.Fields.Count,
                MapObject m => m.Entries.Count,
                BufferObject { IsSymbolicOpen: true } => null,
                BufferObject b => b.Length,
                _ => null,
            },
            IntConst i => Expr.IntegerToBytes(i.Value).Length,
            // Round-3 audit fix: a Boolean's GetSpan() is a single byte ([0x00]/[0x01]), so SIZE is
            // always 1 (the prior `false => 0` was wrong). Null is handled (faulted) by the SIZE
            // handler before reaching here.
            BoolConst => 1,
            _ => null,
        };
    }

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
        return obj switch
        {
            ArrayObject a => ArrayLookup(state, inst, a, key, mode),
            StructObject s => StructLookup(state, inst, s, key, mode),
            MapObject m => MapLookup(state, inst, m, key, mode),
            BufferObject b => BufferLookup(state, inst, b, key, mode),
            _ => throw new VmFaultException($"PICKITEM/HASKEY on {obj.Sort}"),
        };
    }

    private IEnumerable<ExecutionState> PrimitivePickItem(ExecutionState state, Instruction inst, SymbolicValue coll, SymbolicValue key, LookupMode mode)
    {
        key = NormalizeCollectionIndex(state, inst, mode == LookupMode.HasKey ? "HASKEY" : "PICKITEM", key);
        var bytes = Expr.CanonicalBytes(coll.Expression);
        var idx = key.AsConcreteInt();
        if (bytes is null || idx is null)
        {
            Expression size = bytes is null
                ? new UnaryExpr(Sort.Int, "size", coll.Expression)
                : Expr.Int(bytes.Length);
            var inRange = Expr.BoolAnd(
                Expr.Ge(key.Expression, Expr.Int(0)),
                Expr.Lt(key.Expression, size));
            if (mode == LookupMode.HasKey)
            {
                state.Push(SymbolicValue.Of(inRange, coll.Taints.Union(key.Taints)));
            }
            else
            {
                state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                    inst.Offset,
                    "PICKITEM",
                    Expr.Not(inRange),
                    "primitive ByteString index may be negative or outside the byte length",
                    "primitive ByteString PICKITEM index is within range"));
                state.Push(SymbolicValue.Of(
                    new BinaryExpr(Sort.Int, "pick", coll.Expression, key.Expression),
                    coll.Taints.Union(key.Taints)));
            }
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var index = idx.Value;
        if (mode == LookupMode.HasKey)
        {
            // Round-3 audit fix: NeoVM's HASKEY on a ByteString/Buffer/Array faults (uncatchable
            // InvalidOperationException, verified on the real VM) for a negative index — it does not
            // push false. Only a non-negative index pushes the in-bounds boolean.
            if (index < 0)
                throw new VmFaultException($"HASKEY negative index {index}");
            state.Push(SymbolicValue.Bool(index < bytes.Length));
        }
        else
        {
            // Audit MED-2: out-of-range PICKITEM on PrimitiveType is a CatchableException — but for now
            // we surface as a fault and let TRY/CATCH propagation handle it (since we throw the fault path).
            if (index < 0 || index >= bytes.Length)
                throw new CatchableVmException($"PICKITEM index {index} out of range (size {bytes.Length})");
            int i = (int)index;
            state.Push(SymbolicValue.Int(bytes[i]));
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static SymbolicValue NormalizeCollectionIndex(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue key)
    {
        Expression expression = key.Sort switch
        {
            Sort.Int => key.Expression,
            Sort.Bool => key.Expression is BoolConst or IntConst or BytesConst
                ? Expr.Int(Expr.ConcreteInt(key.Expression)!.Value)
                : Expr.Ite(key.Expression, Expr.Int(1), Expr.Int(0)),
            Sort.Bytes => CollectionByteStringIndexExpression(state, inst, operation, key),
            Sort.Unknown => UnknownCollectionIndexExpression(state, inst, operation),
            _ => throw new VmFaultException($"{operation}: index {key.Sort} is not a primitive key"),
        };

        return SymbolicValue.Of(expression, key.Taints);
    }

    private static Expression CollectionByteStringIndexExpression(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue key)
    {
        if (key.AsConcreteBytes() is { } bytes)
        {
            if (bytes.Length > MaxNeoVmIntegerBytes)
                throw new VmFaultException(
                    $"{operation}: index ByteString length {bytes.Length} exceeds NeoVM's {MaxNeoVmIntegerBytes}-byte integer input limit");

            return Expr.Int(Expr.BytesToInteger(bytes));
        }

        AddNeoVmIntegerInputFaultCondition(state, inst, operation, key.Expression, "ByteString index operand");
        return new UnaryExpr(Sort.Int, "b2i", key.Expression);
    }

    private static Expression UnknownCollectionIndexExpression(
        ExecutionState state,
        Instruction inst,
        string operation)
    {
        AddUnknownNeoVmIntegerInputFaultCondition(state, inst, operation, "index operand");
        return Expr.Sym(Sort.Int, state.NextFreshSymbolName($"collection_index_{inst.Offset}"));
    }

    private static IEnumerable<ExecutionState> ArrayLookup(
        ExecutionState state,
        Instruction inst,
        ArrayObject array,
        SymbolicValue key,
        LookupMode mode)
    {
        if (!array.IsSymbolicOpen)
            return IndexedLookup(state, inst, array.Items, "array", key, mode);

        return OpenSequenceLookup(state, inst, array.Items, array.OpenWrites, "array", array.Id, array.MinCount, array.OpenSizeOffset, key, mode);
    }

    private static IEnumerable<ExecutionState> StructLookup(
        ExecutionState state,
        Instruction inst,
        StructObject structure,
        SymbolicValue key,
        LookupMode mode)
    {
        if (!structure.IsSymbolicOpen)
            return IndexedLookup(state, inst, structure.Fields, "struct", key, mode);

        return OpenSequenceLookup(state, inst, structure.Fields, structure.OpenWrites, "struct", structure.Id, structure.MinCount, structure.OpenSizeOffset, key, mode);
    }

    private static IEnumerable<ExecutionState> OpenSequenceLookup(
        ExecutionState state,
        Instruction inst,
        IList<SymbolicValue> items,
        IReadOnlyList<(SymbolicValue Key, SymbolicValue Value)> openWrites,
        string kindLabel,
        int objectId,
        int minCount,
        int sizeOffset,
        SymbolicValue key,
        LookupMode mode)
    {
        key = NormalizeCollectionIndex(state, inst, mode == LookupMode.HasKey ? "HASKEY" : "PICKITEM", key);
        var idx = key.AsConcreteInt();
        var size = OpenSequenceSize(state, kindLabel, objectId, minCount, sizeOffset);
        Expression inRange;
        SymbolicValue value;
        if (idx is null)
        {
            inRange = Expr.BoolAnd(
                Expr.Ge(key.Expression, Expr.Int(0)),
                Expr.Lt(key.Expression, size.Expression));
            value = OpenSequenceItemSymbol(kindLabel, objectId, key);
        }
        else
        {
            var i = idx.Value;
            if (i < 0)
            {
                // Round-3 audit fix: NeoVM's HASKEY faults (uncatchable) on a negative index rather
                // than pushing false. PICKITEM's out-of-range fault is catchable (both verified on the
                // real VM), so the two diverge in fault kind.
                if (mode == LookupMode.HasKey)
                    throw new VmFaultException($"HASKEY negative index {i} on {kindLabel}");

                throw new CatchableVmException($"PICKITEM index {i} out of {kindLabel} range");
            }

            inRange = Expr.Lt(Expr.Int(i), size.Expression);
            value = i >= 0 && i < items.Count
                ? items[(int)i]
                : OpenSequenceItemSymbol(kindLabel, objectId, key);
        }

        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Of(inRange, key.Taints));
        }
        else
        {
            AddOpenSequencePickItemFaultCondition(state, inst, kindLabel, inRange);
            state.Push(ApplyOpenSequenceWrites(openWrites, key, value));
        }

        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static SymbolicValue ApplyOpenSequenceWrites(
        IReadOnlyList<(SymbolicValue Key, SymbolicValue Value)> openWrites,
        SymbolicValue key,
        SymbolicValue baseValue)
    {
        var value = baseValue;
        for (int i = openWrites.Count - 1; i >= 0; i--)
        {
            var write = openWrites[i];
            if (write.Value.Sort != value.Sort)
                throw new ModelingLimitException("open sequence read after heterogeneous SETITEM writes not yet supported");

            var readFromWrite = Expr.Eq(key.Expression, write.Key.Expression);
            value = SymbolicValue.Of(
                Expr.Ite(readFromWrite, write.Value.Expression, value.Expression),
                value.Taints.Union(write.Key.Taints).Union(write.Value.Taints).Union(key.Taints));
        }

        return value;
    }

    private static SymbolicValue OpenSequenceSize(
        ExecutionState state,
        string kindLabel,
        int objectId,
        int minCount,
        int sizeOffset = 0)
    {
        var baseSize = SymbolicValue.Symbol(Sort.Int, $"{kindLabel}_size_{objectId}");
        state.PathConditions = state.PathConditions.Add(Expr.Ge(baseSize.Expression, Expr.Int(minCount)));
        if (sizeOffset == 0)
            return baseSize;

        return SymbolicValue.Of(
            Expr.Add(baseSize.Expression, Expr.Int(sizeOffset)),
            baseSize.Taints);
    }

    private static SymbolicValue OpenSequenceItemSymbol(string kindLabel, int objectId, SymbolicValue key) =>
        SymbolicValue.Symbol(Sort.Bytes, $"{kindLabel}_{objectId}_item_{MapKeyLabel(key.Expression)}");

    private static void AddOpenSequencePickItemFaultCondition(
        ExecutionState state,
        Instruction inst,
        string kindLabel,
        Expression inRange)
    {
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "PICKITEM",
            Expr.Not(inRange),
            $"open {kindLabel} index may be outside the runtime length",
            $"{kindLabel} PICKITEM index is within runtime length"));
    }

    /// <summary>
    /// Shared concrete-index lookup over a closed list-backed compound.
    /// HASKEY pushes Bool(idx in range); PICKITEM pushes the element or throws a Catchable for
    /// out-of-range — the exception will be routed through the active TRY frame, matching NeoVM.
    /// Symbolic indices over same-sort lists produce a finite ITE value plus a fault condition;
    /// heterogeneous symbolic selection remains incomplete because NeoVM StackItems are union-typed.
    /// </summary>
    private static IEnumerable<ExecutionState> IndexedLookup(
        ExecutionState state, Instruction inst,
        IList<SymbolicValue> items, string kindLabel,
        SymbolicValue key, LookupMode mode)
    {
        key = NormalizeCollectionIndex(state, inst, mode == LookupMode.HasKey ? "HASKEY" : "PICKITEM", key);
        var idx = key.AsConcreteInt();
        if (idx is null)
        {
            var inRange = Expr.BoolAnd(
                Expr.Ge(key.Expression, Expr.Int(0)),
                Expr.Lt(key.Expression, Expr.Int(items.Count)));
            if (mode == LookupMode.HasKey)
            {
                state.Push(SymbolicValue.Of(inRange, key.Taints));
            }
            else
            {
                if (!TryBuildClosedIndexedValue(items, key, out var value))
                {
                    state.Terminate(TerminalStatus.Stopped, $"{kindLabel} PICKITEM with symbolic index over heterogeneous values not yet supported");
                    return Single(state);
                }

                state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                    inst.Offset,
                    "PICKITEM",
                    Expr.Not(inRange),
                    $"closed {kindLabel} index may be negative or outside the runtime length",
                    $"{kindLabel} PICKITEM index is within range"));
                state.Push(value);
            }
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var index = idx.Value;
        if (mode == LookupMode.HasKey)
        {
            // Round-3 audit fix: NeoVM's HASKEY faults (uncatchable) on a negative index rather than
            // pushing false (verified on the real VM); only a non-negative index pushes the bound check.
            if (index < 0)
                throw new VmFaultException($"HASKEY negative index {index} on {kindLabel}");
            state.Push(SymbolicValue.Bool(index < items.Count));
        }
        else
        {
            if (index < 0 || index >= items.Count)
            {
                throw new CatchableVmException($"PICKITEM index {index} out of {kindLabel} range (size {items.Count})");
            }
            int i = (int)index;
            state.Push(items[i]);
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static bool TryBuildClosedIndexedValue(
        IList<SymbolicValue> items,
        SymbolicValue key,
        out SymbolicValue value)
    {
        value = default!;
        if (items.Count == 0)
            return false;

        var sort = items[0].Sort;
        if (items.Any(item => item.Sort != sort))
            return false;

        var expr = items[0].Expression;
        for (int i = items.Count - 1; i >= 0; i--)
            expr = Expr.Ite(Expr.Eq(key.Expression, Expr.Int(i)), items[i].Expression, expr);

        value = SymbolicValue.Of(
            expr,
            items.SelectMany(item => item.Taints).Concat(key.Taints));
        return true;
    }

    private static SymbolicValue? TryOpenSequenceSize(ExecutionState state, SymbolicValue v)
    {
        if (v.Expression is not HeapRef href)
            return null;

        return state.Heap.Get(href.ObjectId) switch
        {
            ArrayObject { IsSymbolicOpen: true } array =>
                OpenSequenceSize(state, "array", array.Id, array.MinCount, array.OpenSizeOffset).WithTaints(v.Taints),
            StructObject { IsSymbolicOpen: true } structure =>
                OpenSequenceSize(state, "struct", structure.Id, structure.MinCount, structure.OpenSizeOffset).WithTaints(v.Taints),
            BufferObject { IsSymbolicOpen: true } buffer =>
                OpenBufferSize(state, buffer).WithTaints(v.Taints),
            _ => null,
        };
    }

    private static IEnumerable<ExecutionState> BufferLookup(ExecutionState state, Instruction inst, BufferObject b, SymbolicValue key, LookupMode mode)
    {
        key = NormalizeCollectionIndex(state, inst, mode == LookupMode.HasKey ? "HASKEY" : "PICKITEM", key);
        if (b.IsSymbolicOpen)
            return OpenBufferLookup(state, inst, b, key, mode);

        var idx = key.AsConcreteInt();
        if (idx is null)
        {
            var inRange = Expr.BoolAnd(
                Expr.Ge(key.Expression, Expr.Int(0)),
                Expr.Lt(key.Expression, Expr.Int(b.Length)));
            if (mode == LookupMode.HasKey)
            {
                state.Push(SymbolicValue.Of(inRange, key.Taints));
            }
            else
            {
                state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                    inst.Offset,
                    "PICKITEM",
                    Expr.Not(inRange),
                    "buffer index may be negative or outside the runtime length",
                    "buffer PICKITEM index is within range"));
                state.Push(SymbolicValue.Of(
                    new BinaryExpr(Sort.Int, "buffer_pick", Expr.Ref(Sort.Buffer, b.Id), key.Expression),
                    key.Taints));
            }
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var index = idx.Value;
        if (mode == LookupMode.HasKey)
        {
            // Round-3 audit fix: NeoVM's HASKEY faults (uncatchable) on a negative buffer index rather
            // than pushing false (verified on the real VM).
            if (index < 0)
                throw new VmFaultException($"HASKEY negative index {index} on buffer");
            state.Push(SymbolicValue.Bool(index < b.Length));
        }
        else
        {
            if (index < 0 || index >= b.Length)
                throw new CatchableVmException($"PICKITEM index {index} out of buffer range (size {b.Length})");
            int i = (int)index;
            state.Push(SymbolicValue.Of(b.Cells[i]));
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static SymbolicValue OpenBufferSize(ExecutionState state, BufferObject buffer)
    {
        var runtimeLength = buffer.SymbolicLength ?? Expr.Sym(Sort.Int, $"buffer_size_{buffer.Id}");
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(runtimeLength, Expr.Int(buffer.MinLength)))
            .Add(Expr.Le(runtimeLength, Expr.Int(state.Heap.MaxItemSize)));
        return SymbolicValue.Of(runtimeLength);
    }

    private static IEnumerable<ExecutionState> OpenBufferLookup(
        ExecutionState state,
        Instruction inst,
        BufferObject buffer,
        SymbolicValue key,
        LookupMode mode)
    {
        var idx = key.AsConcreteInt();
        var size = OpenBufferSize(state, buffer);
        Expression inRange;
        SymbolicValue value;

        if (idx is null)
        {
            inRange = Expr.BoolAnd(
                Expr.Ge(key.Expression, Expr.Int(0)),
                Expr.Lt(key.Expression, size.Expression));
            value = OpenBufferCell(state, buffer, key);
        }
        else
        {
            int i = (int)idx.Value;
            if (i < 0)
            {
                if (mode == LookupMode.HasKey)
                {
                    state.Push(SymbolicValue.Bool(false));
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }

                throw new CatchableVmException($"PICKITEM index {i} out of buffer range");
            }

            inRange = Expr.Lt(Expr.Int(i), size.Expression);
            value = i < buffer.Cells.Count
                ? SymbolicValue.Of(buffer.Cells[i])
                : OpenBufferCell(state, buffer, key);
        }

        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Of(inRange, key.Taints));
        }
        else
        {
            AddOpenBufferPickItemFaultCondition(state, inst, inRange);
            state.Push(ApplyOpenBufferWrites(buffer.OpenWrites, key, value));
        }

        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static SymbolicValue OpenBufferCell(ExecutionState state, BufferObject buffer, SymbolicValue key)
    {
        Expression cell = buffer.SourceBytes is { } sourceBytes
            ? new BinaryExpr(Sort.Int, "pick", sourceBytes, key.Expression)
            : Expr.Sym(Sort.Int, $"buffer_{buffer.Id}_item_{MapKeyLabel(key.Expression)}");
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(cell, Expr.Int(byte.MinValue)))
            .Add(Expr.Le(cell, Expr.Int(byte.MaxValue)));
        return SymbolicValue.Of(cell, key.Taints);
    }

    private static SymbolicValue ApplyOpenBufferWrites(
        IReadOnlyList<(SymbolicValue Key, SymbolicValue Value)> openWrites,
        SymbolicValue key,
        SymbolicValue baseValue)
    {
        var value = baseValue;
        for (int i = openWrites.Count - 1; i >= 0; i--)
        {
            var write = openWrites[i];
            if (write.Value.Sort != Sort.Int)
                throw new ModelingLimitException("open Buffer read after non-Integer SETITEM writes not yet supported");

            var readFromWrite = Expr.Eq(key.Expression, write.Key.Expression);
            value = SymbolicValue.Of(
                Expr.Ite(readFromWrite, write.Value.Expression, value.Expression),
                value.Taints.Union(write.Key.Taints).Union(write.Value.Taints).Union(key.Taints));
        }

        return value;
    }

    private static void AddOpenBufferPickItemFaultCondition(
        ExecutionState state,
        Instruction inst,
        Expression inRange)
    {
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "PICKITEM",
            Expr.Not(inRange),
            "open buffer index may be outside the runtime length",
            "buffer PICKITEM index is within runtime length"));
    }

    private static IEnumerable<ExecutionState> MapLookup(ExecutionState state, Instruction inst, MapObject m, SymbolicValue key, LookupMode mode)
    {
        EnsureMapKeyPrimitive(state, inst, mode == LookupMode.HasKey ? "HASKEY" : "PICKITEM", key);
        // Concrete-key path: search using NeoVM StackItem equality.
        if (key.IsConcrete)
        {
            int idx = FindMapEntry(m, key);
            if (mode == LookupMode.HasKey)
            {
                var baseHasKey = idx >= 0 || !m.IsSymbolicOpen
                    ? Expr.Bool(idx >= 0)
                    : OpenMapHasKeySymbol(m, key).Expression;
                state.Push(SymbolicValue.Of(
                    ApplyOpenMapWritesToHasKey(m, key, baseHasKey),
                    key.Taints.Concat(m.OpenUpdates.SelectMany(update => update.Key.Taints))));
            }
            else
            {
                SymbolicValue value;
                Expression hasKey;
                if (idx < 0)
                {
                    if (!m.IsSymbolicOpen)
                        throw new CatchableVmException("PICKITEM map key not found");
                    hasKey = OpenMapHasKeySymbol(m, key).Expression;
                    value = OpenMapValueSymbol(m, key);
                }
                else
                {
                    hasKey = Expr.Bool(true);
                    value = m.Entries[idx].Value;
                }

                hasKey = ApplyOpenMapWritesToHasKey(m, key, hasKey);
                AddOpenMapPickItemFaultCondition(state, inst, hasKey);
                state.Push(ApplyOpenMapWritesToValue(m, key, value));
            }
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (m.IsSymbolicOpen)
        {
            var hasKey = ApplyOpenMapWritesToHasKey(m, key, OpenMapHasKeySymbol(m, key).Expression);
            if (mode == LookupMode.HasKey)
            {
                state.Push(SymbolicValue.Of(
                    hasKey,
                    key.Taints.Concat(m.OpenUpdates.SelectMany(update => update.Key.Taints))));
            }
            else
            {
                AddOpenMapPickItemFaultCondition(state, inst, hasKey);
                state.Push(ApplyOpenMapWritesToValue(m, key, OpenMapValueSymbol(m, key)));
            }
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var hasKnownKey = ClosedMapHasKeyPredicate(m, key);
        if (mode == LookupMode.HasKey)
        {
            state.Push(SymbolicValue.Of(hasKnownKey, ClosedMapKeyTaints(m, key)));
        }
        else
        {
            if (!TryBuildClosedMapLookupValue(m, key, out var value))
            {
                if (m.Entries.Count == 0)
                    throw new CatchableVmException("PICKITEM map key not found");

                state.Terminate(TerminalStatus.Stopped, "Map PICKITEM with symbolic key over heterogeneous values not yet supported");
                return Single(state);
            }

            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "PICKITEM",
                Expr.Not(hasKnownKey),
                "closed Map key may be absent at runtime",
                "Map PICKITEM key exists"));
            state.Push(value);
        }
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static Expression ClosedMapHasKeyPredicate(MapObject map, SymbolicValue key)
    {
        Expression hasKnownKey = Expr.Bool(false);
        foreach (var entry in map.Entries)
            hasKnownKey = Expr.BoolOr(hasKnownKey, Expr.Eq(key.Expression, entry.Key.Expression));
        return hasKnownKey;
    }

    private static IEnumerable<string> ClosedMapKeyTaints(MapObject map, SymbolicValue key) =>
        key.Taints.Concat(map.Entries.SelectMany(entry => entry.Key.Taints));

    private static bool TryBuildClosedMapLookupValue(
        MapObject map,
        SymbolicValue key,
        out SymbolicValue value)
    {
        value = default!;
        if (map.Entries.Count == 0)
            return false;

        var sort = map.Entries[0].Value.Sort;
        if (map.Entries.Any(entry => entry.Value.Sort != sort))
            return false;

        var expr = map.Entries[0].Value.Expression;
        for (int i = map.Entries.Count - 1; i >= 0; i--)
        {
            var entry = map.Entries[i];
            expr = Expr.Ite(Expr.Eq(key.Expression, entry.Key.Expression), entry.Value.Expression, expr);
        }

        value = SymbolicValue.Of(
            expr,
            key.Taints
                .Concat(map.Entries.SelectMany(entry => entry.Key.Taints))
                .Concat(map.Entries.SelectMany(entry => entry.Value.Taints)));
        return true;
    }

    private static SymbolicValue OpenMapHasKeySymbol(MapObject map, SymbolicValue key) =>
        SymbolicValue.Symbol(Sort.Bool, OpenMapLookupName(map, key, LookupMode.HasKey));

    private static SymbolicValue OpenMapValueSymbol(MapObject map, SymbolicValue key) =>
        SymbolicValue.Symbol(Sort.Bytes, OpenMapLookupName(map, key, LookupMode.Get));

    private static void AddOpenMapPickItemFaultCondition(
        ExecutionState state,
        Instruction inst,
        Expression hasKey)
    {
        if (Expr.Truthy(hasKey) == true)
            return;

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "PICKITEM",
            Expr.Not(hasKey),
            "open Map key may be absent at runtime",
            "Map PICKITEM key exists"));
    }

    private static Expression ApplyOpenMapWritesToHasKey(
        MapObject map,
        SymbolicValue key,
        Expression baseHasKey)
    {
        var hasKey = baseHasKey;
        foreach (var update in map.OpenUpdates)
        {
            var updateMatchesKey = Expr.Eq(key.Expression, update.Key.Expression);
            hasKey = Expr.Ite(updateMatchesKey, Expr.Bool(!update.IsRemove), hasKey);
        }
        return hasKey;
    }

    private static SymbolicValue ApplyOpenMapWritesToValue(
        MapObject map,
        SymbolicValue key,
        SymbolicValue baseValue)
    {
        var value = baseValue;
        foreach (var update in map.OpenUpdates)
        {
            var readFromUpdate = Expr.Eq(key.Expression, update.Key.Expression);
            if (update.IsRemove)
            {
                value = SymbolicValue.Of(
                    Expr.Ite(readFromUpdate, baseValue.Expression, value.Expression),
                    value.Taints.Union(update.Key.Taints).Union(key.Taints));
                continue;
            }

            var write = update.Value;
            if (Expr.Truthy(readFromUpdate) == true)
            {
                value = SymbolicValue.Of(
                    write.Expression,
                    value.Taints.Union(update.Key.Taints).Union(write.Taints).Union(key.Taints));
                continue;
            }

            if (write.Sort != value.Sort)
                throw new ModelingLimitException("open Map read after heterogeneous SETITEM writes not yet supported");

            value = SymbolicValue.Of(
                Expr.Ite(readFromUpdate, write.Expression, value.Expression),
                value.Taints.Union(update.Key.Taints).Union(write.Taints).Union(key.Taints));
        }

        return value;
    }

    private static string OpenMapLookupName(MapObject map, SymbolicValue key, LookupMode mode)
    {
        string op = mode == LookupMode.Get ? "value" : "has";
        return $"open_map_{map.Id}_{op}_{MapKeyLabel(key.Expression)}";
    }

    private static string MapKeyLabel(Expression key) => key switch
    {
        IntConst i => i.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
        BoolConst b => b.Value ? "true" : "false",
        BytesConst bytes => System.Convert.ToHexString(bytes.Value),
        NullConst => "null",
        Symbol s => s.Name,
        _ => "expr_" + StableExpressionDigest(key),
    };

    private static string StableExpressionDigest(Expression expression)
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes(CanonicalExpressionLabel(expression));
        byte[] hash = System.Security.Cryptography.SHA256.HashData(data);
        return System.Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }

    private static string CanonicalExpressionLabel(Expression expression) => expression switch
    {
        IntConst i => "int:" + i.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
        BoolConst b => "bool:" + (b.Value ? "true" : "false"),
        BytesConst bytes => "bytes:" + System.Convert.ToHexString(bytes.Value),
        NullConst => "null",
        PointerConst pointer => "ptr:" + pointer.TargetOffset.ToString(System.Globalization.CultureInfo.InvariantCulture),
        HeapRef href => $"heap:{href.RefSort}:{href.ObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture)}",
        Symbol s => $"sym:{s.Sort}:{s.Name.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}:{s.Name}",
        UnaryExpr u => $"unary:{u.Sort}:{u.Op.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}:{u.Op}({CanonicalExpressionLabel(u.Operand)})",
        BinaryExpr b => $"binary:{b.Sort}:{b.Op.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}:{b.Op}({CanonicalExpressionLabel(b.Left)},{CanonicalExpressionLabel(b.Right)})",
        TernaryExpr t => $"ternary:{t.Sort}:{t.Op.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}:{t.Op}({CanonicalExpressionLabel(t.A)},{CanonicalExpressionLabel(t.B)},{CanonicalExpressionLabel(t.C)})",
        _ => expression.ToString() ?? expression.Sort.ToString(),
    };

    private static int FindMapEntry(MapObject m, SymbolicValue key)
    {
        for (int i = 0; i < m.Entries.Count; i++)
        {
            if (m.Entries[i].Key.IsConcrete
                && Expr.Eq(m.Entries[i].Key.Expression, key.Expression) is BoolConst { Value: true })
            {
                return i;
            }
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
                    var obj = state.Heap.GetForWrite(href.ObjectId);
                    SetItem(state, inst, obj, key, value);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
            case WriteMode.Append:
                {
                    var value = state.Pop();
                    var coll = state.Pop();
                    if (coll.Expression is not HeapRef href) throw new VmFaultException("APPEND on non-collection");
                    var obj = state.Heap.GetForWrite(href.ObjectId);
                    if (obj is ArrayObject a)
                    {
                        state.Heap.EnforceCollectionGrowth(a.Items.Count + 1);
                        a.Items.Add(state.Heap.CloneStructValueForCollection(value));
                        // Review fix (open-collection size desync): for an open Array the modeled
                        // length is array_size + OpenSizeOffset; APPEND must grow it by one,
                        // mirroring REMOVE's OpenSizeOffset--. Without this, SIZE returns the
                        // pre-append length, making `arr.Count == oldLen+1` lower to S==S+1 (UNSAT)
                        // and silently pruning the feasible post-append branch.
                        if (a.IsSymbolicOpen) a.OpenSizeOffset++;
                    }
                    else if (obj is StructObject s)
                    {
                        state.Heap.EnforceCollectionGrowth(s.Fields.Count + 1);
                        s.Fields.Add(state.Heap.CloneStructValueForCollection(value));
                        if (s.IsSymbolicOpen) s.OpenSizeOffset++;
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
                    var obj = state.Heap.GetForWrite(href.ObjectId);
                    RemoveItem(state, inst, obj, key);
                    state.Pc = inst.EndOffset;
                    return Single(state);
                }
        }
        return Single(state);
    }

    private static void SetItem(ExecutionState state, Instruction inst, HeapObject obj, SymbolicValue key, SymbolicValue value)
    {
        switch (obj)
        {
            case ArrayObject a:
                {
                    value = state.Heap.CloneStructValueForCollection(value);
                    key = NormalizeCollectionIndex(state, inst, "SETITEM", key);
                    var idx = key.AsConcreteInt();
                    if (a.IsSymbolicOpen)
                    {
                        ApplyOpenSequenceSetItem(state, inst, a.Items, a.OpenWrites, "array", a.Id, a.MinCount, a.OpenSizeOffset, key, value);
                        break;
                    }
                    if (idx is null)
                    {
                        ApplyClosedSequenceSetItem(state, inst, a.Items, "array", key, value);
                        break;
                    }
                    var index = idx.Value;
                    if (index < 0 || index >= a.Items.Count)
                        throw new CatchableVmException($"SETITEM index {index} out of array range");
                    int i = (int)index;
                    a.Items[i] = value;
                    break;
                }
            case StructObject s:
                {
                    value = state.Heap.CloneStructValueForCollection(value);
                    key = NormalizeCollectionIndex(state, inst, "SETITEM", key);
                    var idx = key.AsConcreteInt();
                    if (s.IsSymbolicOpen)
                    {
                        ApplyOpenSequenceSetItem(state, inst, s.Fields, s.OpenWrites, "struct", s.Id, s.MinCount, s.OpenSizeOffset, key, value);
                        break;
                    }
                    if (idx is null)
                    {
                        ApplyClosedSequenceSetItem(state, inst, s.Fields, "struct", key, value);
                        break;
                    }
                    var index = idx.Value;
                    if (index < 0 || index >= s.Fields.Count)
                        throw new CatchableVmException($"SETITEM index {index} out of struct range");
                    int i = (int)index;
                    s.Fields[i] = value;
                    break;
                }
            case MapObject m:
                {
                    value = state.Heap.CloneStructValueForCollection(value);
                    EnsureMapKeyPrimitive(state, inst, "SETITEM", key);
                    if (m.IsSymbolicOpen)
                    {
                        ApplyOpenMapSetItem(state, m, key, value);
                        break;
                    }

                    if (!key.IsConcrete)
                    {
                        var hasKnownKey = ClosedMapHasKeyPredicate(m, key);
                        if (!PathConditionIncludes(state, hasKnownKey))
                            throw new ModelingLimitException("SETITEM closed map with symbolic key that may insert a new entry not yet supported");

                        ApplyClosedMapSetItem(m, key, value);
                        break;
                    }

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
                    key = NormalizeCollectionIndex(state, inst, "SETITEM", key);
                    if (b.IsSymbolicOpen)
                    {
                        ApplyOpenBufferSetItem(state, inst, b, key, value);
                        break;
                    }

                    var idx = key.AsConcreteInt();
                    if (idx is null)
                    {
                        ApplyBufferSetItem(state, inst, b, key, value);
                        break;
                    }
                    var index = idx.Value;
                    if (index < 0 || index >= b.Length)
                        throw new CatchableVmException($"SETITEM index {index} out of buffer range");
                    int i = (int)index;
                    b.Cells[i] = NormalizeBufferSetItemValue(state, inst, value);
                    break;
                }
            default:
                throw new VmFaultException($"SETITEM on {obj.Sort}");
        }
    }

    private static bool PathConditionIncludes(ExecutionState state, Expression condition) =>
        Expr.Truthy(condition) == true || state.PathConditions.Contains(condition);

    private static void ApplyOpenMapSetItem(ExecutionState state, MapObject map, SymbolicValue key, SymbolicValue value)
    {
        if (key.IsConcrete)
        {
            int idx = FindMapEntry(map, key);
            if (idx >= 0)
            {
                map.Entries[idx] = (map.Entries[idx].Key, value);
            }
            else
            {
                state.Heap.EnforceCollectionGrowth(map.Entries.Count + 1);
                map.Entries.Add((key, value));
            }
        }

        map.OpenUpdates.Add(new MapOpenUpdate(key, value, IsRemove: false));
    }

    private static void ApplyOpenMapRemoveItem(MapObject map, SymbolicValue key)
    {
        if (key.IsConcrete)
        {
            int idx = FindMapEntry(map, key);
            if (idx >= 0)
                map.Entries.RemoveAt(idx);
        }

        map.OpenUpdates.Add(new MapOpenUpdate(key, SymbolicValue.Null(), IsRemove: true));
    }

    private static void ApplyClosedMapSetItem(MapObject map, SymbolicValue key, SymbolicValue value)
    {
        for (int i = 0; i < map.Entries.Count; i++)
        {
            var entry = map.Entries[i];
            if (entry.Value.Sort != value.Sort)
                throw new ModelingLimitException("SETITEM closed map with symbolic key over heterogeneous values not yet supported");

            var updateHere = Expr.Eq(key.Expression, entry.Key.Expression);
            map.Entries[i] = (
                entry.Key,
                SymbolicValue.Of(
                    Expr.Ite(updateHere, value.Expression, entry.Value.Expression),
                    entry.Key.Taints.Union(entry.Value.Taints).Union(key.Taints).Union(value.Taints)));
        }
    }

    private static void ApplyBufferSetItem(
        ExecutionState state,
        Instruction inst,
        BufferObject buffer,
        SymbolicValue key,
        SymbolicValue value)
    {
        var byteValue = NormalizeBufferSetItemValue(state, inst, value);
        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, Expr.Int(buffer.Length)));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "SETITEM",
            Expr.Not(inRange),
            "buffer index may be negative or outside the runtime length",
            "buffer SETITEM index is within range"));

        for (int i = 0; i < buffer.Length; i++)
        {
            var updateHere = Expr.Eq(key.Expression, Expr.Int(i));
            buffer.Cells[i] = Expr.Ite(updateHere, byteValue, buffer.Cells[i]);
        }
    }

    private static void ApplyOpenBufferSetItem(
        ExecutionState state,
        Instruction inst,
        BufferObject buffer,
        SymbolicValue key,
        SymbolicValue value)
    {
        if (key.AsConcreteInt() is { } concreteIndex && concreteIndex < 0)
            throw new CatchableVmException($"SETITEM index {concreteIndex} out of buffer range");

        var byteValue = NormalizeBufferSetItemValue(state, inst, value);
        var normalizedValue = SymbolicValue.Of(byteValue, value.Taints);
        var size = OpenBufferSize(state, buffer);
        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, size.Expression));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "SETITEM",
            Expr.Not(inRange),
            "open buffer index may be negative or outside the runtime length",
            "buffer SETITEM index is within runtime length"));

        for (int i = 0; i < buffer.Cells.Count; i++)
        {
            var updateHere = Expr.Eq(key.Expression, Expr.Int(i));
            buffer.Cells[i] = Expr.Ite(updateHere, byteValue, buffer.Cells[i]);
        }

        buffer.OpenWrites.Add((key, normalizedValue));
    }

    private static Expression NormalizeBufferSetItemValue(ExecutionState state, Instruction inst, SymbolicValue value)
    {
        var valueInt = BufferSetItemIntegerExpression(state, inst, value);
        if (Expr.ConcreteInt(valueInt) is { } concrete)
        {
            if (concrete < sbyte.MinValue || concrete > byte.MaxValue)
                throw new VmFaultException($"SETITEM buffer value {concrete} is not a byte");

            return Expr.Int(unchecked((byte)(int)concrete));
        }

        var inByteRange = Expr.BoolAnd(
            Expr.Ge(valueInt, Expr.Int(sbyte.MinValue)),
            Expr.Le(valueInt, Expr.Int(byte.MaxValue)));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "SETITEM",
            Expr.Not(inByteRange),
            "buffer SETITEM value may be outside NeoVM byte range -128..255",
            "buffer SETITEM value is within byte range"));
        return Expr.Ite(
            Expr.Lt(valueInt, Expr.Int(0)),
            Expr.Add(valueInt, Expr.Int(256)),
            valueInt);
    }

    private static Expression BufferSetItemIntegerExpression(ExecutionState state, Instruction inst, SymbolicValue value)
    {
        switch (value.Sort)
        {
            case Sort.Int:
                return value.Expression;
            case Sort.Bool:
                return value.Expression is BoolConst or IntConst or BytesConst
                    ? Expr.Int(Expr.ConcreteInt(value.Expression)!.Value)
                    : Expr.Ite(value.Expression, Expr.Int(1), Expr.Int(0));
            case Sort.Bytes:
                EnforceNeoVmIntegerInput(state, inst, "SETITEM", value, "buffer value");
                return Expr.ConcreteInt(value.Expression) is { } concrete
                    ? Expr.Int(concrete)
                    : new UnaryExpr(Sort.Int, "b2i", value.Expression);
            case Sort.Unknown:
                EnforceNeoVmIntegerInput(state, inst, "SETITEM", value, "buffer value");
                return Expr.Sym(Sort.Int, state.NextFreshSymbolName($"buffer_setitem_value_{inst.Offset}"));
            default:
                throw new VmFaultException($"SETITEM buffer value {value.Sort} is not primitive");
        }
    }

    private static void ApplyOpenSequenceSetItem(
        ExecutionState state,
        Instruction inst,
        IList<SymbolicValue> items,
        IList<(SymbolicValue Key, SymbolicValue Value)> openWrites,
        string kindLabel,
        int objectId,
        int minCount,
        int sizeOffset,
        SymbolicValue key,
        SymbolicValue value)
    {
        if (key.AsConcreteInt() is { } concreteIndex && concreteIndex < 0)
            throw new CatchableVmException($"SETITEM index {concreteIndex} out of {kindLabel} range");
        if (items.Any(item => item.Sort != value.Sort))
            throw new ModelingLimitException($"SETITEM open {kindLabel} with symbolic index over heterogeneous values not yet supported");

        var size = OpenSequenceSize(state, kindLabel, objectId, minCount, sizeOffset);
        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, size.Expression));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "SETITEM",
            Expr.Not(inRange),
            $"open {kindLabel} index may be negative or outside the runtime length",
            $"{kindLabel} SETITEM index is within runtime length"));

        for (int i = 0; i < items.Count; i++)
        {
            var updateHere = Expr.Eq(key.Expression, Expr.Int(i));
            items[i] = SymbolicValue.Of(
                Expr.Ite(updateHere, value.Expression, items[i].Expression),
                items[i].Taints.Union(value.Taints).Union(key.Taints));
        }

        openWrites.Add((key, value));
    }

    private static void ApplyClosedSequenceSetItem(
        ExecutionState state,
        Instruction inst,
        IList<SymbolicValue> items,
        string kindLabel,
        SymbolicValue key,
        SymbolicValue value)
    {
        if (items.Any(item => item.Sort != value.Sort))
            throw new ModelingLimitException($"SETITEM {kindLabel} with symbolic index over heterogeneous values not yet supported");

        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, Expr.Int(items.Count)));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "SETITEM",
            Expr.Not(inRange),
            $"closed {kindLabel} index may be negative or outside the runtime length",
            $"{kindLabel} SETITEM index is within range"));

        for (int i = 0; i < items.Count; i++)
        {
            var updateHere = Expr.Eq(key.Expression, Expr.Int(i));
            items[i] = SymbolicValue.Of(
                Expr.Ite(updateHere, value.Expression, items[i].Expression),
                items[i].Taints.Union(value.Taints).Union(key.Taints));
        }
    }

    private static void RemoveItem(ExecutionState state, Instruction inst, HeapObject obj, SymbolicValue key)
    {
        switch (obj)
        {
            case ArrayObject a:
                {
                    key = NormalizeCollectionIndex(state, inst, "REMOVE", key);
                    var idx = key.AsConcreteInt();
                    if (a.IsSymbolicOpen)
                    {
                        ApplyOpenSequenceRemoveItem(state, inst, a.Items, a.OpenWrites, "array", a.Id, a.MinCount, a.OpenSizeOffset, key);
                        a.OpenSizeOffset--;
                        break;
                    }
                    if (idx is null)
                    {
                        ApplyClosedSequenceRemoveItem(state, inst, a.Items, "array", key);
                        break;
                    }
                    var index = idx.Value;
                    if (index < 0 || index >= a.Items.Count) throw new VmFaultException("REMOVE out of range");
                    int i = (int)index;
                    a.Items.RemoveAt(i);
                    break;
                }
            case StructObject s:
                {
                    key = NormalizeCollectionIndex(state, inst, "REMOVE", key);
                    var idx = key.AsConcreteInt();
                    if (s.IsSymbolicOpen)
                    {
                        ApplyOpenSequenceRemoveItem(state, inst, s.Fields, s.OpenWrites, "struct", s.Id, s.MinCount, s.OpenSizeOffset, key);
                        s.OpenSizeOffset--;
                        break;
                    }
                    if (idx is null)
                    {
                        ApplyClosedSequenceRemoveItem(state, inst, s.Fields, "struct", key);
                        break;
                    }
                    var index = idx.Value;
                    if (index < 0 || index >= s.Fields.Count) throw new VmFaultException("REMOVE out of range");
                    int i = (int)index;
                    s.Fields.RemoveAt(i);
                    break;
                }
            case MapObject m:
                {
                    EnsureMapKeyPrimitive(state, inst, "REMOVE", key);
                    if (m.IsSymbolicOpen)
                    {
                        ApplyOpenMapRemoveItem(m, key);
                        break;
                    }

                    if (!key.IsConcrete)
                    {
                        var hasKnownKey = ClosedMapHasKeyPredicate(m, key);
                        if (!PathConditionIncludes(state, hasKnownKey))
                            throw new ModelingLimitException("REMOVE map with symbolic key that may be absent not yet supported");

                        ApplyClosedMapRemoveItem(m, key);
                        break;
                    }

                    int idx = FindMapEntry(m, key);
                    if (idx >= 0) m.Entries.RemoveAt(idx);
                    break;
                }
            default:
                throw new VmFaultException($"REMOVE on {obj.Sort}");
        }
    }

    // NeoVM faults (uncatchable) when a Map key exceeds Map.MaxKeySize — verified on the real VM
    // (a 65-byte key faults, a 64-byte key succeeds). Integer keys are <= 32 bytes and Boolean keys
    // are 1 byte, so only a ByteString key can exceed the limit.
    private const int MapMaxKeySize = 64;

    private static void EnsureMapKeyPrimitive(
        ExecutionState state,
        Instruction inst,
        string operation,
        SymbolicValue key)
    {
        if (key.Sort is Sort.Int or Sort.Bool or Sort.Bytes)
        {
            // Round-3 audit fix: enforce Map.MaxKeySize for a concrete ByteString key (an Integer key
            // is <= 32 bytes and a Boolean key is 1 byte, so only a ByteString can exceed the limit).
            // The symbolic-length case is left to the existing symbolic key machinery to avoid emitting
            // an over-conservative oversize fault on every unbounded map key.
            if (key.Sort == Sort.Bytes && key.AsConcreteBytes() is { Length: > MapMaxKeySize } keyBytes)
                throw new VmFaultException(
                    $"{operation}: Map key size {keyBytes.Length} exceeds MaxKeySize {MapMaxKeySize}");
            return;
        }

        if (key.Sort == Sort.Unknown)
        {
            var invalidType = Expr.Sym(Sort.Bool, state.NextFreshSymbolName($"invalid_map_key_type_{inst.Offset}"));
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                operation,
                invalidType,
                "Map key may be a non-primitive StackItem",
                "Map key is a primitive StackItem"));
            return;
        }

        throw new VmFaultException($"{operation}: Map key {key.Sort} is not primitive");
    }

    private static void ApplyClosedMapRemoveItem(MapObject map, SymbolicValue key)
    {
        if (map.Entries.Count == 0)
            return;

        if (map.Entries.Select(entry => entry.Key.Sort).Distinct().Count() != 1
            || map.Entries.Select(entry => entry.Value.Sort).Distinct().Count() != 1)
        {
            throw new ModelingLimitException("REMOVE closed map with symbolic key over heterogeneous keys or values not yet supported");
        }

        var oldEntries = map.Entries.ToArray();
        map.Entries.Clear();
        for (int i = 0; i < oldEntries.Length - 1; i++)
        {
            Expression shiftLeft = Expr.Bool(false);
            for (int j = 0; j <= i; j++)
                shiftLeft = Expr.BoolOr(shiftLeft, Expr.Eq(key.Expression, oldEntries[j].Key.Expression));

            map.Entries.Add((
                SymbolicValue.Of(
                    Expr.Ite(shiftLeft, oldEntries[i + 1].Key.Expression, oldEntries[i].Key.Expression),
                    oldEntries[i].Key.Taints.Union(oldEntries[i + 1].Key.Taints).Union(key.Taints)),
                SymbolicValue.Of(
                    Expr.Ite(shiftLeft, oldEntries[i + 1].Value.Expression, oldEntries[i].Value.Expression),
                    oldEntries[i].Value.Taints.Union(oldEntries[i + 1].Value.Taints).Union(key.Taints))));
        }
    }

    private static void ApplyOpenSequenceRemoveItem(
        ExecutionState state,
        Instruction inst,
        IList<SymbolicValue> items,
        IList<(SymbolicValue Key, SymbolicValue Value)> openWrites,
        string kindLabel,
        int objectId,
        int minCount,
        int sizeOffset,
        SymbolicValue key)
    {
        if (key.AsConcreteInt() is { } concreteIndex && concreteIndex < 0)
            throw new VmFaultException("REMOVE out of range");
        if (openWrites.Count > 0)
            throw new ModelingLimitException($"REMOVE open {kindLabel} after symbolic SETITEM writes not yet supported");
        if (items.Select(item => item.Sort).Distinct().Count() > 1)
            throw new ModelingLimitException($"REMOVE open {kindLabel} with symbolic index over heterogeneous values not yet supported");

        var size = OpenSequenceSize(state, kindLabel, objectId, minCount, sizeOffset);
        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, size.Expression));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "REMOVE",
            Expr.Not(inRange),
            $"open {kindLabel} index may be negative or outside the runtime length",
            $"{kindLabel} REMOVE index is within runtime length"));

        var oldItems = items.ToArray();
        items.Clear();
        for (int i = 0; i < oldItems.Length; i++)
        {
            var next = i + 1 < oldItems.Length
                ? oldItems[i + 1]
                : OpenSequenceItemSymbol(kindLabel, objectId, SymbolicValue.Int(i + 1));
            if (next.Sort != oldItems[i].Sort)
                throw new ModelingLimitException($"REMOVE open {kindLabel} symbolic tail over non-ByteString values not yet supported");

            items.Add(SymbolicValue.Of(
                Expr.Ite(Expr.Le(key.Expression, Expr.Int(i)), next.Expression, oldItems[i].Expression),
                oldItems[i].Taints.Union(next.Taints).Union(key.Taints)));
        }
    }

    private static void ApplyClosedSequenceRemoveItem(
        ExecutionState state,
        Instruction inst,
        IList<SymbolicValue> items,
        string kindLabel,
        SymbolicValue key)
    {
        if (items.Count == 0)
            throw new VmFaultException("REMOVE out of range");
        if (items.Select(item => item.Sort).Distinct().Count() != 1)
            throw new ModelingLimitException($"REMOVE {kindLabel} with symbolic index over heterogeneous values not yet supported");

        var inRange = Expr.BoolAnd(
            Expr.Ge(key.Expression, Expr.Int(0)),
            Expr.Lt(key.Expression, Expr.Int(items.Count)));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "REMOVE",
            Expr.Not(inRange),
            $"closed {kindLabel} index may be negative or outside the runtime length",
            $"{kindLabel} REMOVE index is within range"));

        var oldItems = items.ToArray();
        items.Clear();
        for (int i = 0; i < oldItems.Length - 1; i++)
        {
            items.Add(SymbolicValue.Of(
                Expr.Ite(Expr.Le(key.Expression, Expr.Int(i)), oldItems[i + 1].Expression, oldItems[i].Expression),
                oldItems[i].Taints.Union(oldItems[i + 1].Taints).Union(key.Taints)));
        }
    }

    private IEnumerable<ExecutionState> CollectionMutate(ExecutionState state, Instruction inst, System.Action<HeapObject> mutator)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("collection op on non-collection");
        mutator(state.Heap.GetForWrite(href.ObjectId));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static void ReverseInPlace(HeapObject obj)
    {
        // Review fix (open-collection soundness): reversing only the materialized prefix of an
        // open collection leaves the unknown-length symbolic tail and OpenWrites resolving against
        // their original logical indices, yielding a state consistent with neither pre- nor
        // post-reverse semantics. Terminate as a modeling limit so the verifier downgrades.
        if (obj is ArrayObject { IsSymbolicOpen: true } or StructObject { IsSymbolicOpen: true } or BufferObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("REVERSEITEMS over open symbolic collection of unknown length not modeled");
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
        // Review fix (open-collection soundness): CLEARITEMS yields a definitely-empty collection,
        // but clearing only the materialized prefix of an open collection leaves the modeled length
        // (array_size + OpenSizeOffset, MinCount lower bound, OpenWrites) non-zero with no
        // incompleteness signal. IsSymbolicOpen is immutable on the object, so the empty result
        // cannot be represented in place; terminate as a modeling limit so the verifier downgrades.
        if (obj is ArrayObject { IsSymbolicOpen: true } or StructObject { IsSymbolicOpen: true } or MapObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("CLEARITEMS over open symbolic collection of unknown length not modeled");
        switch (obj)
        {
            case ArrayObject a: a.Items.Clear(); break;
            case StructObject s: s.Fields.Clear(); break;
            case MapObject m: m.Entries.Clear(); break;
            case BufferObject: throw new VmFaultException("CLEARITEMS on Buffer");
            default: throw new VmFaultException($"CLEARITEMS on {obj.Sort}");
        }
    }

    private IEnumerable<ExecutionState> PopItem(ExecutionState state, Instruction inst)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("POPITEM on non-collection");
        var obj = state.Heap.GetForWrite(href.ObjectId);
        // Audit fix (iter-2 wakeup-4 differential): NeoVM accepts POPITEM on any CompoundType
        // (Array, Struct, Map). Our prior implementation rejected Struct; the differential
        // target found this within seconds.
        // Review fix (open-collection soundness): POPITEM on an open collection reads/removes the
        // last element and its empty-fault depends on the unknown true length. The seeded prefix
        // is not the runtime tail, and an open collection whose true length may be 0 has a feasible
        // "POPITEM on empty" catchable fault that the materialized-count check misses. Terminate as
        // a modeling limit so the verifier downgrades instead of proving over the seeded prefix.
        if (obj is ArrayObject { IsSymbolicOpen: true } or StructObject { IsSymbolicOpen: true } or MapObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("POPITEM over open symbolic collection of unknown length not modeled");
        if (obj is ArrayObject a)
        {
            if (a.Items.Count == 0) throw new VmFaultException("POPITEM on empty collection");
            var v = a.Items[^1];
            a.Items.RemoveAt(a.Items.Count - 1);
            state.Push(v);
        }
        else if (obj is StructObject st)
        {
            if (st.Fields.Count == 0) throw new VmFaultException("POPITEM on empty collection");
            var v = st.Fields[^1];
            st.Fields.RemoveAt(st.Fields.Count - 1);
            state.Push(v);
        }
        else if (obj is MapObject m)
        {
            if (m.Entries.Count == 0) throw new VmFaultException("POPITEM on empty collection");
            var (_, v) = m.Entries[^1];
            m.Entries.RemoveAt(m.Entries.Count - 1);
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
        // Review fix (open-collection soundness): an open Map has an unknown key set; emitting only
        // the seeded keys plus a single fresh symbol under-approximates the runtime key array
        // length and contents. Terminate as a modeling limit so the verifier downgrades instead of
        // proving over the seeded key set.
        if (m.IsSymbolicOpen)
            throw new ModelingLimitException("KEYS over open symbolic Map of unknown key set not modeled");
        var keys = m.Entries.Select(e => e.Key).ToList();
        var arr = state.Heap.NewArray(keys);
        state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> MapValues(ExecutionState state, Instruction inst)
    {
        var coll = state.Pop();
        if (coll.Expression is not HeapRef href) throw new VmFaultException("VALUES on non-collection");
        var obj = state.Heap.Get(href.ObjectId);
        // Audit fix (iter-2 wakeup-4 differential): NeoVM's VALUES operates on any CompoundType
        // — Array.SubItems, Struct.Fields, or Map.Entries.Values. Our prior code restricted
        // to MapObject; the differential target found a real divergence on Array/Struct.
        // Review fix (open-collection soundness): for an open collection the value set has unknown
        // length; emitting only the seeded prefix (plus, for maps, one fresh symbol)
        // under-approximates it. Terminate as a modeling limit so the verifier downgrades.
        if (obj is MapObject { IsSymbolicOpen: true } or ArrayObject { IsSymbolicOpen: true } or StructObject { IsSymbolicOpen: true })
            throw new ModelingLimitException("VALUES over open symbolic collection of unknown length not modeled");
        // Review fix (#12 struct-by-value): NeoVM's VALUES copies each compound element by value
        // (PrimitiveType/StackItem.DeepCopy on extraction). Clone Struct elements so the result
        // array does not alias the source structs, matching APPEND/SETITEM.
        var values = obj switch
        {
            MapObject m => m.Entries.Select(e => state.Heap.CloneStructValueForCollection(e.Value)),
            ArrayObject a => a.Items.Select(state.Heap.CloneStructValueForCollection),
            StructObject s => s.Fields.Select(state.Heap.CloneStructValueForCollection),
            _ => throw new VmFaultException($"VALUES on {obj.Sort}"),
        };
        var arr = state.Heap.NewArray(values);
        state.Push(SymbolicValue.HeapRef(Sort.Array, arr.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
