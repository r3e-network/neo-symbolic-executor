using System.Linq;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Heap clone-isolation regression net. Every mutation pathway on every HeapObject subtype
/// is exercised against a clone, verifying the parent heap's object is unaffected. With the
/// v0.8.0 copy-on-write Heap, callers MUST use <see cref="Heap.GetForWrite{T}"/> before
/// mutating an existing object; <see cref="Heap.Get"/> returns a possibly-shared instance and
/// is read-only. Each test exercises one mutation pathway through that contract.
///
/// The fuzzer's CloneIsolationOracleTarget covers the same invariant at scale (random
/// scripts, all telemetry fields); this file covers each Heap API call as a unit-test,
/// pinned at the assertion level, so a CoW regression on a specific mutation pathway surfaces
/// with a clear failure rather than a noisy fuzz crash.
/// </summary>
public class HeapCloneIsolationTests
{
    [Fact]
    public void ArrayItemsAdd_OnClone_DoesNotAffectParent()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2) });
        var clone = parent.Clone();

        clone.GetForWrite<ArrayObject>(arr.Id).Items.Add(SymbolicValue.Int(99));

        ((ArrayObject)parent.Get(arr.Id)).Items.Count.Should().Be(2);
        ((ArrayObject)clone.Get(arr.Id)).Items.Count.Should().Be(3);
    }

    [Fact]
    public void ArrayItemsSet_OnClone_DoesNotAffectParent()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2) });
        var clone = parent.Clone();

        clone.GetForWrite<ArrayObject>(arr.Id).Items[0] = SymbolicValue.Int(99);

        ((ArrayObject)parent.Get(arr.Id)).Items[0].AsConcreteInt().Should().Be((System.Numerics.BigInteger)1);
        ((ArrayObject)clone.Get(arr.Id)).Items[0].AsConcreteInt().Should().Be((System.Numerics.BigInteger)99);
    }

    [Fact]
    public void ArrayItemsRemoveAt_OnClone_DoesNotAffectParent()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2), SymbolicValue.Int(3) });
        var clone = parent.Clone();

        clone.GetForWrite<ArrayObject>(arr.Id).Items.RemoveAt(1);

        ((ArrayObject)parent.Get(arr.Id)).Items.Count.Should().Be(3);
        ((ArrayObject)clone.Get(arr.Id)).Items.Count.Should().Be(2);
    }

    [Fact]
    public void ArrayItemsReverse_OnClone_DoesNotAffectParent()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2), SymbolicValue.Int(3) });
        var clone = parent.Clone();

        clone.GetForWrite<ArrayObject>(arr.Id).Items.Reverse();

        ((ArrayObject)parent.Get(arr.Id)).Items[0].AsConcreteInt().Should().Be((System.Numerics.BigInteger)1);
        ((ArrayObject)clone.Get(arr.Id)).Items[0].AsConcreteInt().Should().Be((System.Numerics.BigInteger)3);
    }

    [Fact]
    public void ArrayItemsClear_OnClone_DoesNotAffectParent()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2) });
        var clone = parent.Clone();

        clone.GetForWrite<ArrayObject>(arr.Id).Items.Clear();

        ((ArrayObject)parent.Get(arr.Id)).Items.Count.Should().Be(2);
        ((ArrayObject)clone.Get(arr.Id)).Items.Count.Should().Be(0);
    }

    [Fact]
    public void StructFieldsMutations_OnClone_DoNotAffectParent()
    {
        var parent = new Heap();
        var s = parent.NewStruct(new[] { SymbolicValue.Int(1), SymbolicValue.Int(2) });
        var clone = parent.Clone();

        var cloneStruct = clone.GetForWrite<StructObject>(s.Id);
        cloneStruct.Fields[0] = SymbolicValue.Int(99);
        cloneStruct.Fields.Add(SymbolicValue.Int(3));
        cloneStruct.Fields.RemoveAt(1);

        var parentStruct = (StructObject)parent.Get(s.Id);
        parentStruct.Fields.Count.Should().Be(2);
        parentStruct.Fields[0].AsConcreteInt().Should().Be((System.Numerics.BigInteger)1);
        parentStruct.Fields[1].AsConcreteInt().Should().Be((System.Numerics.BigInteger)2);
    }

    [Fact]
    public void MapEntriesMutations_OnClone_DoNotAffectParent()
    {
        var parent = new Heap();
        var m = parent.NewMap(new[]
        {
            (SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(10)),
            (SymbolicValue.Bytes(new byte[] { 2 }), SymbolicValue.Int(20)),
        });
        var clone = parent.Clone();

        var cloneMap = clone.GetForWrite<MapObject>(m.Id);
        cloneMap.Entries.Add((SymbolicValue.Bytes(new byte[] { 3 }), SymbolicValue.Int(30)));
        cloneMap.Entries[0] = (cloneMap.Entries[0].Key, SymbolicValue.Int(999));
        cloneMap.Entries.RemoveAt(1);

        var parentMap = (MapObject)parent.Get(m.Id);
        parentMap.Entries.Count.Should().Be(2);
        parentMap.Entries[0].Value.AsConcreteInt().Should().Be((System.Numerics.BigInteger)10);
        parentMap.Entries[1].Value.AsConcreteInt().Should().Be((System.Numerics.BigInteger)20);
    }

    [Fact]
    public void BufferCellsMutations_OnClone_DoNotAffectParent()
    {
        var parent = new Heap();
        var buf = parent.NewBuffer(new byte[] { 1, 2, 3, 4 });
        var clone = parent.Clone();

        var cloneBuf = clone.GetForWrite<BufferObject>(buf.Id);
        cloneBuf.Cells[0] = Expr.Int(99);
        cloneBuf.Cells.Reverse();

        var parentBuf = (BufferObject)parent.Get(buf.Id);
        parentBuf.Cells[0].Equals(Expr.Int(1)).Should().BeTrue();
        parentBuf.Cells[3].Equals(Expr.Int(4)).Should().BeTrue();
    }

    [Fact]
    public void AllocateOnClone_DoesNotAppearInParent()
    {
        var parent = new Heap();
        var existing = parent.NewArray(new[] { SymbolicValue.Int(1) });
        var clone = parent.Clone();

        var newOnClone = clone.NewArray(new[] { SymbolicValue.Int(99) });

        parent.Objects.ContainsKey(newOnClone.Id).Should().BeFalse();
        clone.Objects.ContainsKey(newOnClone.Id).Should().BeTrue();
        // Existing object still resolvable from both heaps.
        parent.Objects.ContainsKey(existing.Id).Should().BeTrue();
        clone.Objects.ContainsKey(existing.Id).Should().BeTrue();
    }

    [Fact]
    public void NextIdAdvancesIndependentlyOnClonedHeaps()
    {
        // After clone, each heap allocates from its own _nextId. Sharing it would mean a
        // parent allocation collides with a clone allocation made before fork. The current
        // semantics (parent and clone fork at the same _nextId then advance independently)
        // is preserved by CoW.
        var parent = new Heap();
        parent.NewArray();
        var clone = parent.Clone();

        var parentNext = parent.NewArray();
        var cloneNext = clone.NewArray();

        // Both heaps assign the same id to the next allocation — they forked at the same point.
        parentNext.Id.Should().Be(cloneNext.Id);
        // But each is a distinct HeapObject instance, owned by its respective heap.
        ReferenceEquals(parentNext, cloneNext).Should().BeFalse();
    }

    [Fact]
    public void TransitiveClone_IsolatesParentAndIntermediate()
    {
        // A → Clone → B → Mutate B's array → Clone B → C → Mutate C's array
        // A and B should both be unaffected by C's mutations; A unaffected by B's.
        var a = new Heap();
        var arr = a.NewArray(new[] { SymbolicValue.Int(0) });

        var b = a.Clone();
        b.GetForWrite<ArrayObject>(arr.Id).Items.Add(SymbolicValue.Int(1));

        var c = b.Clone();
        c.GetForWrite<ArrayObject>(arr.Id).Items.Add(SymbolicValue.Int(2));

        ((ArrayObject)a.Get(arr.Id)).Items.Count.Should().Be(1);
        ((ArrayObject)b.Get(arr.Id)).Items.Count.Should().Be(2);
        ((ArrayObject)c.Get(arr.Id)).Items.Count.Should().Be(3);
    }

    [Fact]
    public void StressClone_ManyObjects_AlternatingMutationsIsolated()
    {
        var parent = new Heap();
        for (int i = 0; i < 50; i++) parent.NewArray(new[] { SymbolicValue.Int(i) });

        var clone = parent.Clone();
        // Mutate every other object on the clone.
        foreach (var id in clone.Objects.Keys.Where(k => k % 2 == 0).ToList())
            clone.GetForWrite<ArrayObject>(id).Items.Add(SymbolicValue.Int(-1));

        foreach (var (id, obj) in parent.Objects)
            ((ArrayObject)obj).Items.Count.Should().Be(1, $"parent's object {id} should be untouched");
    }

    [Fact]
    public void Clone_AfterMutation_StartsFromPostMutationState()
    {
        // Parent mutates, then clones. The clone should see the post-mutation state.
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1) });
        ((ArrayObject)parent.Get(arr.Id)).Items.Add(SymbolicValue.Int(2));

        var clone = parent.Clone();

        ((ArrayObject)clone.Get(arr.Id)).Items.Count.Should().Be(2);
        ((ArrayObject)clone.Get(arr.Id)).Items[1].AsConcreteInt().Should().Be((System.Numerics.BigInteger)2);
    }

    [Fact]
    public void GetForWrite_OnUnshared_ReturnsSameInstance()
    {
        // Before any Clone, every object is unshared. GetForWrite must be a no-op (return the
        // existing instance) — otherwise even single-heap mutation paths would pay the copy
        // cost.
        var heap = new Heap();
        var arr = heap.NewArray(new[] { SymbolicValue.Int(1) });
        ReferenceEquals(heap.GetForWrite<ArrayObject>(arr.Id), arr).Should().BeTrue();
    }

    [Fact]
    public void GetForWrite_OnShared_ReturnsDistinctInstance()
    {
        var parent = new Heap();
        var arr = parent.NewArray(new[] { SymbolicValue.Int(1) });
        var clone = parent.Clone();

        // After clone both heaps point at the same instance. GetForWrite on the clone must
        // materialize a distinct instance so subsequent mutations are isolated.
        var cloneArr = clone.GetForWrite<ArrayObject>(arr.Id);
        ReferenceEquals(cloneArr, arr).Should().BeFalse();
        // Calling GetForWrite again returns the already-materialized private copy, not a new one.
        ReferenceEquals(clone.GetForWrite<ArrayObject>(arr.Id), cloneArr).Should().BeTrue();
    }

    // ---- Telemetry copy-on-write isolation (#31). Telemetry.Clone() forks its CowList/CowSet
    // collections in O(1); the backing storage must be copied on the first write so a parent and clone
    // never observe each other's appends.

    [Fact]
    public void TelemetryCowList_AddOnClone_DoesNotAffectParent()
    {
        var parent = new Telemetry();
        parent.StorageOps.Add(new StorageOp(0, StorageOpKind.Get, SymbolicValue.Int(1), null, false, false));
        var clone = parent.Clone();

        clone.StorageOps.Add(new StorageOp(1, StorageOpKind.Put, SymbolicValue.Int(2), SymbolicValue.Int(3), false, false));

        parent.StorageOps.Count.Should().Be(1);
        clone.StorageOps.Count.Should().Be(2);
    }

    [Fact]
    public void TelemetryCowList_AddOnParentAfterClone_DoesNotAffectClone()
    {
        var parent = new Telemetry();
        var clone = parent.Clone();

        parent.UnknownSyscalls.Add(42);

        parent.UnknownSyscalls.Count.Should().Be(1);
        clone.UnknownSyscalls.Count.Should().Be(0);
    }

    [Fact]
    public void TelemetryCowSet_AddOnClone_DoesNotAffectParent()
    {
        var parent = new Telemetry();
        parent.LoopsDetected.Add(10);
        var clone = parent.Clone();

        clone.LoopsDetected.Add(20);

        parent.LoopsDetected.Count.Should().Be(1);
        parent.LoopsDetected.Contains(20).Should().BeFalse();
        clone.LoopsDetected.Count.Should().Be(2);
        clone.LoopsDetected.Contains(20).Should().BeTrue();
    }

    [Fact]
    public void TelemetryFaultConditions_AddOnClone_DoesNotAffectParent()
    {
        var parent = new Telemetry();
        parent.FaultConditions.Add(new FaultConditionOp(0, "OP", BoolConst.True, "r", "f"));
        var clone = parent.Clone();

        clone.FaultConditions.Add(new FaultConditionOp(1, "OP2", BoolConst.True, "r2", "f2"));

        parent.FaultConditions.Count.Should().Be(1);
        clone.FaultConditions.Count.Should().Be(2);
    }

    [Fact]
    public void TelemetryExternalCalls_MutateCloneElement_DoesNotAffectParent()
    {
        // ExternalCall objects are mutated in place, so the list stays eagerly deep-copied (not COW).
        var parent = new Telemetry();
        parent.ExternalCalls.Add(new ExternalCall { Offset = 0, Method = "transfer" });
        var clone = parent.Clone();

        clone.ExternalCalls[0].ReturnChecked = true;

        parent.ExternalCalls[0].ReturnChecked.Should().BeFalse();
        clone.ExternalCalls[0].ReturnChecked.Should().BeTrue();
    }
}
