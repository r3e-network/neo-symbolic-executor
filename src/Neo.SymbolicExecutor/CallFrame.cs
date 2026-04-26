using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor;

/// <summary>
/// A single call frame: own slot arrays plus a pointer-back to the program counter to resume at on RET.
/// Static fields are NOT per-frame (NeoVM shares static slots across the whole execution context),
/// so they live on <see cref="ExecutionState"/> instead.
/// </summary>
public sealed class CallFrame
{
    public int ReturnPc { get; set; }
    public List<SymbolicValue?> Locals { get; }
    public List<SymbolicValue?> Args { get; }
    public List<TryFrame> TryStack { get; }

    public CallFrame(int returnPc)
    {
        ReturnPc = returnPc;
        Locals = new List<SymbolicValue?>();
        Args = new List<SymbolicValue?>();
        TryStack = new List<TryFrame>();
    }

    private CallFrame(int returnPc,
                      List<SymbolicValue?> locals,
                      List<SymbolicValue?> args,
                      List<TryFrame> tryStack)
    {
        ReturnPc = returnPc;
        Locals = locals;
        Args = args;
        TryStack = tryStack;
    }

    public CallFrame Clone() =>
        new(ReturnPc,
            new List<SymbolicValue?>(Locals),
            new List<SymbolicValue?>(Args),
            TryStack.Select(t => t.Clone()).ToList());

    public void InitSlots(int localsCount, int argsCount)
    {
        for (int i = 0; i < localsCount; i++) Locals.Add(SymbolicValue.Null());
        for (int i = 0; i < argsCount; i++) Args.Add(SymbolicValue.Null());
    }
}
