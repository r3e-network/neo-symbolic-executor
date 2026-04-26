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
        if (sz < 0 || sz > _options.MaxItemSize)
            throw new VmFaultException($"NEWBUFFER size {sz} out of range");
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

        if (dst.Expression is not HeapRef dstRef || state.Heap.Get(dstRef.ObjectId) is not BufferObject dstBuf)
            throw new VmFaultException("MEMCPY destination is not a Buffer");

        var srcBytes = ResolveSpliceSourceBytes(state, src);
        if (srcBytes is null || count.AsConcreteInt() is not { } cn || srcIdx.AsConcreteInt() is not { } si || dstIdx.AsConcreteInt() is not { } di)
        {
            state.Terminate(TerminalStatus.Stopped, "MEMCPY with symbolic operands not yet supported");
            return Single(state);
        }
        int c = (int)cn, s = (int)si, d = (int)di;
        if (c < 0 || s < 0 || d < 0 || s + c > srcBytes.Length || d + c > dstBuf.Length)
            throw new CatchableVmException("MEMCPY range out of bounds");
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
            state.Terminate(TerminalStatus.Stopped, "CAT with symbolic byte source not yet supported");
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
            state.Terminate(TerminalStatus.Stopped, "SUBSTR with symbolic operands not yet supported");
            return Single(state);
        }
        int idx = (int)i, cnt = (int)c;
        if (idx < 0 || cnt < 0 || idx + cnt > bytes.Length)
            throw new CatchableVmException("SUBSTR range out of bounds");
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
            state.Terminate(TerminalStatus.Stopped, "LEFT with symbolic operands not yet supported");
            return Single(state);
        }
        int cnt = (int)c;
        if (cnt < 0 || cnt > bytes.Length)
            throw new CatchableVmException("LEFT count out of bounds");
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
            state.Terminate(TerminalStatus.Stopped, "RIGHT with symbolic operands not yet supported");
            return Single(state);
        }
        int cnt = (int)c;
        if (cnt < 0 || cnt > bytes.Length)
            throw new CatchableVmException("RIGHT count out of bounds");
        var buf = state.Heap.NewBuffer(bytes.AsSpan(bytes.Length - cnt, cnt).ToArray());
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buf.Id));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static byte[]? ResolveSpliceSourceBytes(ExecutionState state, SymbolicValue v) => v.Expression switch
    {
        BytesConst by => by.Value,
        IntConst i => Expr.IntegerToBytes(i.Value),
        BoolConst bc => bc.Value ? new byte[] { 1 } : System.Array.Empty<byte>(),
        NullConst => null,
        HeapRef href => state.Heap.Get(href.ObjectId) is BufferObject buf
                        && buf.Cells.All(c => c is IntConst)
            ? buf.Cells.Select(c => (byte)((IntConst)c).Value).ToArray()
            : null,
        _ => null,
    };
}
