using System.Collections.Generic;
using System.Linq;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> HandleNewBuffer(ExecutionState state, Instruction inst)
    {
        var n = state.Pop();
        var sz = TryConcretizeIndex(state, n, lo: 0, hi: _options.MaxItemSize);
        if (sz is null) { state.Terminate(TerminalStatus.Stopped, "NEWBUFFER requires concrete size (no SMT model)"); return Single(state); }
        // Round-3 audit fix: fault only above NeoVM's real 1 MiB item limit (also guards the int cast);
        // Heap.NewBuffer -> EnforceItemSize turns a size between the 64 KiB materialization budget and
        // 1 MiB into a modeling limit (CoverageIncomplete), not a false fault.
        if (sz < 0 || sz > Heap.NeoVmMaxItemSize)
            throw new VmFaultException($"NEWBUFFER size {sz} exceeds NeoVM MaxItemSize {Heap.NeoVmMaxItemSize}");
        var buf = state.Heap.NewBuffer((int)sz.Value);
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleMemCpy(ExecutionState state, Instruction inst)
    {
        // Stack (top-down): count, srcIndex, src, dstIndex, dst (followed by dst-buffer ref).
        var count = state.Pop();
        var srcIdx = state.Pop();
        var src = state.Pop();
        var dstIdx = state.Pop();
        var dst = state.Pop();

        if (dst.Expression is not HeapRef dstRef)
            throw new VmFaultException("MEMCPY destination is not a Buffer");
        if (state.Heap.GetForWrite(dstRef.ObjectId) is not BufferObject dstBuf)
            throw new VmFaultException("MEMCPY destination is not a Buffer");

        // Round-2 fix: MEMCPY into an OPEN (symbolic-length) destination buffer cannot be modeled —
        // the destination range checks and the per-cell writes are evaluated against the seeded
        // prefix length, so writes past the prefix are silently dropped (no OpenWrites record) and a
        // concrete over-prefix write spuriously faults. Both directions are unsound (false negative /
        // unflagged incompleteness). Terminate as a modeling limit so the verifier downgrades, as the
        // round-1 open-collection opcodes do.
        if (dstBuf.IsSymbolicOpen)
            throw new ModelingLimitException("MEMCPY into open symbolic Buffer of unknown length not modeled");

        var srcBytes = ResolveSpliceSourceBytes(state, src);
        if (srcBytes is null || count.AsConcreteInt() is not { } cn || srcIdx.AsConcreteInt() is not { } si || dstIdx.AsConcreteInt() is not { } di)
        {
            var source = ResolveSpliceSourceExpression(state, src);
            if (source is not null)
            {
                var sourceStart = SpliceIntegerExpression(srcIdx);
                var destinationStart = SpliceIntegerExpression(dstIdx);
                var copyLength = SpliceIntegerExpression(count);
                var concreteSourceStart = Expr.ConcreteInt(sourceStart);
                var concreteDestinationStart = Expr.ConcreteInt(destinationStart);
                var concreteCopyLength = Expr.ConcreteInt(copyLength);
                var concreteSourceSize = Expr.CanonicalBytes(source)?.Length;

                if (concreteSourceStart is { } sourceStartValue && sourceStartValue < 0)
                    throw new CatchableVmException("MEMCPY range out of bounds");
                if (concreteDestinationStart is { } destinationStartValue
                    && (destinationStartValue < 0 || destinationStartValue > dstBuf.Length))
                    throw new CatchableVmException("MEMCPY range out of bounds");
                if (concreteCopyLength is { } copyLengthValue
                    && (copyLengthValue < 0 || copyLengthValue > _options.MaxItemSize))
                {
                    throw new CatchableVmException("MEMCPY range out of bounds");
                }
                if (concreteDestinationStart is { } concreteDestination
                    && concreteCopyLength is { } concreteCopy
                    && concreteDestination + concreteCopy > dstBuf.Length)
                    throw new CatchableVmException("MEMCPY range out of bounds");
                if (concreteSourceSize is { } concreteSourceLength
                    && concreteSourceStart is { } sourceStartConcrete
                    && concreteCopyLength is { } copyLengthConcrete
                    && sourceStartConcrete + copyLengthConcrete > concreteSourceLength)
                    throw new CatchableVmException("MEMCPY range out of bounds");

                var sourceSize = new UnaryExpr(Sort.Int, "size", source);
                var sourceInRange = Expr.BoolAnd(
                    Expr.Ge(sourceStart, Expr.Int(0)),
                    Expr.BoolAnd(
                        Expr.Ge(copyLength, Expr.Int(0)),
                        Expr.Le(Expr.Add(sourceStart, copyLength), sourceSize)));
                var destinationInRange = Expr.BoolAnd(
                    Expr.Ge(destinationStart, Expr.Int(0)),
                    Expr.Le(Expr.Add(destinationStart, copyLength), Expr.Int(dstBuf.Length)));
                AddSpliceRangeFaultCondition(
                    state,
                    inst,
                    "MEMCPY",
                    Expr.BoolAnd(sourceInRange, destinationInRange),
                    "symbolic ByteString MEMCPY range may be outside the source or destination size",
                    "MEMCPY ranges are within source and destination sizes");

                if (concreteDestinationStart is { } concreteDestinationCellStart)
                {
                    int destinationCellStart = (int)concreteDestinationCellStart;
                    int cellsToUpdate = concreteCopyLength is { } finiteCopyLength
                        ? (int)finiteCopyLength
                        : dstBuf.Length - destinationCellStart;
                    for (int i = 0; i < cellsToUpdate; i++)
                    {
                        var sourceOffset = Expr.Add(sourceStart, Expr.Int(i));
                        var sourceByte = new BinaryExpr(Sort.Int, "pick", source, sourceOffset);
                        var copyThisCell = Expr.Gt(copyLength, Expr.Int(i));
                        dstBuf.Cells[destinationCellStart + i] =
                            Expr.Ite(copyThisCell, sourceByte, dstBuf.Cells[destinationCellStart + i]);
                    }
                }
                else if (concreteCopyLength != 0)
                {
                    for (int cell = 0; cell < dstBuf.Length; cell++)
                    {
                        var destinationCell = Expr.Int(cell);
                        var copyThisCell = Expr.Within(
                            destinationCell,
                            destinationStart,
                            Expr.Add(destinationStart, copyLength));
                        var sourceOffset = Expr.Add(sourceStart, Expr.Sub(destinationCell, destinationStart));
                        var sourceByte = new BinaryExpr(Sort.Int, "pick", source, sourceOffset);
                        dstBuf.Cells[cell] = Expr.Ite(copyThisCell, sourceByte, dstBuf.Cells[cell]);
                    }
                }

                state.Pc = inst.EndOffset;
                return Single(state);
            }

            state.Terminate(TerminalStatus.Stopped, "MEMCPY with symbolic operands not yet supported");
            return Single(state);
        }
        // Audit fix (fuzzer-found): bound the BigInteger operands BEFORE casting to int.
        // The prior `(int)cn` truncated huge values and `s + c > srcBytes.Length` overflowed
        // into negative-territory, letting an out-of-range MEMCPY slip past the check and crash
        // inside Span<T>.CopyTo with ArgumentOutOfRangeException.
        if (cn < 0 || si < 0 || di < 0
            || cn > srcBytes.Length || si > srcBytes.Length || di > dstBuf.Length
            || si + cn > srcBytes.Length || di + cn > dstBuf.Length)
            throw new CatchableVmException("MEMCPY range out of bounds");
        int c = (int)cn, s = (int)si, d = (int)di;
        for (int i = 0; i < c; i++)
            dstBuf.Cells[d + i] = Expr.Int(srcBytes[s + i]);

        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleCat(ExecutionState state, Instruction inst)
    {
        var b = state.Pop();
        var a = state.Pop();
        var ab = ResolveSpliceSourceBytes(state, a);
        var bb = ResolveSpliceSourceBytes(state, b);
        if (ab is null || bb is null)
        {
            var ae = ResolveSpliceSourceExpression(state, a);
            var be = ResolveSpliceSourceExpression(state, b);
            if (ae is null || be is null)
            {
                state.Terminate(TerminalStatus.Stopped, "CAT with unsupported byte source");
                return Single(state);
            }

            // #13/#14: NeoVM's CAT yields a mutable Buffer (the concrete arm above already does), so the
            // symbolic result must also be a Buffer — otherwise a later MEMCPY/SETITEM into it spuriously
            // faults on an immutable ByteString, and EQUAL uses content equality where NeoVM uses Buffer
            // reference identity. Model it as a symbolic Buffer whose byte-source is the `cat` expression
            // and whose length is size(a)+size(b). Carrying the structural `cat` expression (resolved back
            // by NormalizeStorageKey/Bytes -> StorageByteLengthExpression) preserves the precise key/value
            // length, avoiding the false ">64 byte" storage-key fault that reverted the earlier attempt.
            var catExpr = new BinaryExpr(Sort.Bytes, "cat", ae, be);
            var catLength = Expr.Add(
                new UnaryExpr(Sort.Int, "size", ae),
                new UnaryExpr(Sort.Int, "size", be));
            var catBuffer = state.Heap.NewSymbolicBuffer(catExpr, catLength);
            state.Push(SymbolicValue.HeapRef(Sort.Buffer, catBuffer.Id).WithTaints(a.Taints.Union(b.Taints)));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        int total = ab.Length + bb.Length;
        state.Heap.EnforceItemSize(total);
        var combined = new byte[total];
        ab.AsSpan().CopyTo(combined);
        bb.AsSpan().CopyTo(combined.AsSpan(ab.Length));
        var buf = state.Heap.NewBuffer(combined);
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleSubstr(ExecutionState state, Instruction inst)
    {
        var count = state.Pop();
        var index = state.Pop();
        var src = state.Pop();
        var bytes = ResolveSpliceSourceBytes(state, src);
        if (bytes is null || index.AsConcreteInt() is not { } i || count.AsConcreteInt() is not { } c)
        {
            var source = ResolveSpliceSourceExpression(state, src);
            if (source is not null)
            {
                if (index.AsConcreteInt() is { } concreteStart && concreteStart < 0)
                    throw new CatchableVmException("SUBSTR range out of bounds");
                if (count.AsConcreteInt() is { } concreteLength && (concreteLength < 0 || concreteLength > _options.MaxItemSize))
                    throw new CatchableVmException("SUBSTR range out of bounds");

                var start = SpliceIntegerExpression(index);
                var length = SpliceIntegerExpression(count);
                var sourceSize = new UnaryExpr(Sort.Int, "size", source);
                var inRange = Expr.BoolAnd(
                    Expr.Ge(start, Expr.Int(0)),
                    Expr.BoolAnd(
                        Expr.Ge(length, Expr.Int(0)),
                        Expr.Le(Expr.Add(start, length), sourceSize)));
                AddSpliceRangeFaultCondition(
                    state,
                    inst,
                    "SUBSTR",
                    inRange,
                    "symbolic ByteString SUBSTR range may be outside the source size",
                    "SUBSTR range is within source size");
                var sliceExpression = new TernaryExpr(Sort.Bytes, "substr", source, start, length);
                var buffer = state.Heap.NewSymbolicBuffer(sliceExpression, length);
                state.Push(SymbolicValue
                    .HeapRef(Sort.Buffer, buffer.Id)
                    .WithTaints(src.Taints.Union(index.Taints).Union(count.Taints)));
                state.Pc = inst.EndOffset;
                return Single(state);
            }

            state.Terminate(TerminalStatus.Stopped, "SUBSTR with symbolic operands not yet supported");
            return Single(state);
        }
        // Audit fix (fuzzer-found): bound BigInteger operands BEFORE casting. The prior `(int)i`
        // truncated huge values and `idx + cnt > bytes.Length` overflowed, surfacing
        // ArgumentOutOfRangeException out of Run() instead of a clean fault.
        if (i < 0 || c < 0 || i > bytes.Length || c > bytes.Length || i + c > bytes.Length)
            throw new CatchableVmException("SUBSTR range out of bounds");
        int idx = (int)i, cnt = (int)c;
        var slice = new byte[cnt];
        bytes.AsSpan(idx, cnt).CopyTo(slice);
        var buf = state.Heap.NewBuffer(slice);
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleLeft(ExecutionState state, Instruction inst)
    {
        var count = state.Pop();
        var src = state.Pop();
        var bytes = ResolveSpliceSourceBytes(state, src);
        if (bytes is null || count.AsConcreteInt() is not { } c)
        {
            var source = ResolveSpliceSourceExpression(state, src);
            if (source is not null)
            {
                if (count.AsConcreteInt() is { } concreteLength && (concreteLength < 0 || concreteLength > _options.MaxItemSize))
                    throw new CatchableVmException("LEFT count out of bounds");

                var length = SpliceIntegerExpression(count);
                var sourceSize = new UnaryExpr(Sort.Int, "size", source);
                var inRange = Expr.BoolAnd(
                    Expr.Ge(length, Expr.Int(0)),
                    Expr.Le(length, sourceSize));
                AddSpliceRangeFaultCondition(
                    state,
                    inst,
                    "LEFT",
                    inRange,
                    "symbolic ByteString LEFT count may be outside the source size",
                    "LEFT count is within source size");
                var slice = new BinaryExpr(Sort.Bytes, "left", source, length);
                var buffer = state.Heap.NewSymbolicBuffer(slice, length);
                state.Push(SymbolicValue
                    .HeapRef(Sort.Buffer, buffer.Id)
                    .WithTaints(src.Taints.Union(count.Taints)));
                state.Pc = inst.EndOffset;
                return Single(state);
            }

            state.Terminate(TerminalStatus.Stopped, "LEFT with symbolic operands not yet supported");
            return Single(state);
        }
        // Audit fix (fuzzer-found, sibling of SUBSTR): bound BigInteger before casting to int.
        if (c < 0 || c > bytes.Length)
            throw new CatchableVmException("LEFT count out of bounds");
        int cnt = (int)c;
        var buf = state.Heap.NewBuffer(bytes.AsSpan(0, cnt).ToArray());
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleRight(ExecutionState state, Instruction inst)
    {
        var count = state.Pop();
        var src = state.Pop();
        var bytes = ResolveSpliceSourceBytes(state, src);
        if (bytes is null || count.AsConcreteInt() is not { } c)
        {
            var source = ResolveSpliceSourceExpression(state, src);
            if (source is not null)
            {
                if (count.AsConcreteInt() is { } concreteLength && (concreteLength < 0 || concreteLength > _options.MaxItemSize))
                    throw new CatchableVmException("RIGHT count out of bounds");

                var length = SpliceIntegerExpression(count);
                var sourceSize = new UnaryExpr(Sort.Int, "size", source);
                var inRange = Expr.BoolAnd(
                    Expr.Ge(length, Expr.Int(0)),
                    Expr.Le(length, sourceSize));
                AddSpliceRangeFaultCondition(
                    state,
                    inst,
                    "RIGHT",
                    inRange,
                    "symbolic ByteString RIGHT count may be outside the source size",
                    "RIGHT count is within source size");
                var slice = new BinaryExpr(Sort.Bytes, "right", source, length);
                var buffer = state.Heap.NewSymbolicBuffer(slice, length);
                state.Push(SymbolicValue
                    .HeapRef(Sort.Buffer, buffer.Id)
                    .WithTaints(src.Taints.Union(count.Taints)));
                state.Pc = inst.EndOffset;
                return Single(state);
            }

            state.Terminate(TerminalStatus.Stopped, "RIGHT with symbolic operands not yet supported");
            return Single(state);
        }
        // Audit fix (fuzzer-found, sibling of SUBSTR): bound BigInteger before casting to int.
        if (c < 0 || c > bytes.Length)
            throw new CatchableVmException("RIGHT count out of bounds");
        int cnt = (int)c;
        var buf = state.Heap.NewBuffer(bytes.AsSpan(bytes.Length - cnt, cnt).ToArray());
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static void AddSpliceRangeFaultCondition(
        ExecutionState state,
        Instruction inst,
        string operation,
        Expression inRange,
        string reason,
        string failedCondition)
    {
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            operation,
            Expr.Not(inRange),
            reason,
            failedCondition));
    }

    private static Expression SpliceIntegerExpression(SymbolicValue value)
    {
        if (value.AsConcreteInt() is { } concrete)
            return Expr.Int(concrete);

        return value.Expression switch
        {
            NullConst => Expr.Int(0),
            BoolConst or IntConst or BytesConst => Expr.Int(Expr.ConcreteInt(value.Expression)!.Value),
            UnaryExpr { Sort: Sort.Int } or BinaryExpr { Sort: Sort.Int } or TernaryExpr { Sort: Sort.Int } or Symbol { Sort: Sort.Int } =>
                value.Expression,
            Symbol { Sort: Sort.Bytes } or UnaryExpr { Sort: Sort.Bytes } or BinaryExpr { Sort: Sort.Bytes } or TernaryExpr { Sort: Sort.Bytes } =>
                new UnaryExpr(Sort.Int, "b2i", value.Expression),
            Symbol { Sort: Sort.Bool } or UnaryExpr { Sort: Sort.Bool } or BinaryExpr { Sort: Sort.Bool } or TernaryExpr { Sort: Sort.Bool } =>
                Expr.Ite(value.Expression, Expr.Int(1), Expr.Int(0)),
            _ => value.Expression,
        };
    }

    private static byte[]? ResolveSpliceSourceBytes(ExecutionState state, SymbolicValue v) => v.Expression switch
    {
        BytesConst by => by.Value,
        IntConst i => Expr.IntegerToBytes(i.Value),
        BoolConst bc => bc.Value ? new byte[] { 1 } : System.Array.Empty<byte>(),
        NullConst => null,
        HeapRef href => state.Heap.Get(href.ObjectId) is BufferObject { IsSymbolicOpen: false } buf
                        && buf.Cells.All(c => c is IntConst)
            ? buf.Cells.Select(c => (byte)((IntConst)c).Value).ToArray()
            : null,
        _ => null,
    };

    private static Expression? ResolveSpliceSourceExpression(ExecutionState state, SymbolicValue v)
    {
        if (ResolveSpliceSourceBytes(state, v) is { } bytes)
            return Expr.Bytes(bytes);

        return v.Expression switch
        {
            Symbol { Sort: Sort.Bytes } => v.Expression,
            UnaryExpr { Sort: Sort.Bytes } => v.Expression,
            BinaryExpr { Sort: Sort.Bytes } => v.Expression,
            TernaryExpr { Sort: Sort.Bytes } => v.Expression,
            HeapRef href when state.Heap.Get(href.ObjectId) is BufferObject { SourceBytes: { } sourceBytes } => sourceBytes,
            _ => null,
        };
    }
}
