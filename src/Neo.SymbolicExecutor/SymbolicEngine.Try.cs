using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> HandleTry(ExecutionState state, Instruction inst)
    {
        var (catchOffset, finallyOffset) = ScriptDecoder.ResolveTryTargets(inst);
        // NeoVM JumpTable.ExecuteTry faults ONLY when BOTH raw operand offsets are 0 (a TRY with neither
        // a catch nor a finally handler). It does NOT validate handler target ranges at TRY time — an
        // out-of-range target only faults if a later THROW transfers control there (where both engine and
        // NeoVM fault on the bad jump). The prior `< 0` check also tripped when a non-zero offset RESOLVED
        // to a negative (out-of-script) address, faulting where NeoVM HALTs (differential fuzzer:
        // seed=1700441197). NoTryHandler is the raw-zero sentinel, distinct from such resolved negatives.
        if (catchOffset == ScriptDecoder.NoTryHandler && finallyOffset == ScriptDecoder.NoTryHandler)
            throw new VmFaultException("TRY requires catch or finally target");
        var frame = state.CurrentFrame;
        if (frame.TryStack.Count >= _options.MaxTryDepth)
            throw new VmFaultException("TRY depth exceeded");
        frame.TryStack.Add(new TryFrame
        {
            CatchOffset = catchOffset,
            FinallyOffset = finallyOffset,
            EndOffset = inst.EndOffset,
            State = TryFrameState.Try,
            InitialStackDepth = state.EvaluationStack.Count,
            InitialCallDepth = state.CallStack.Count,
        });
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleEndTry(ExecutionState state, Instruction inst)
    {
        var frame = state.CurrentFrame;
        if (frame.TryStack.Count == 0)
            throw new VmFaultException("ENDTRY with no active TRY");
        var current = frame.TryStack[^1];
        if (current.State == TryFrameState.Finally)
        {
            state.Terminate(TerminalStatus.Faulted, "ENDTRY inside FINALLY block");
            return Single(state);
        }
        int continuation = inst.Target;
        if (current.HasFinally)
        {
            // Replace top-of-tryStack with a clone in Finally state (audit: avoid in-place mutation).
            // Audit C# #1 fix: stash the post-finally continuation on the frame so ENDFINALLY
            // can resume there. Without this, ENDFINALLY would default to its own EndOffset
            // and skip any code between the finally block and the next instruction.
            var advanced = current.Clone();
            advanced.State = TryFrameState.Finally;
            advanced.PostFinallyPc = continuation;
            frame.TryStack[^1] = advanced;
            state.Pc = current.FinallyOffset;
        }
        else
        {
            frame.TryStack.RemoveAt(frame.TryStack.Count - 1);
            state.Pc = continuation;
        }
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleEndFinally(ExecutionState state, Instruction inst)
    {
        var frame = state.CurrentFrame;
        if (frame.TryStack.Count == 0)
            throw new VmFaultException("ENDFINALLY with no active TRY");
        var current = frame.TryStack[^1];
        frame.TryStack.RemoveAt(frame.TryStack.Count - 1);
        if (state.UncaughtException is not null)
        {
            // Re-raise after finally ran.
            return PropagateException(state);
        }
        // Audit C# #1 fix: resume at the continuation ENDTRY recorded on the frame, not
        // the byte after ENDFINALLY. PostFinallyPc=-1 (default) means ENDTRY didn't set it,
        // either because finally ran without a corresponding ENDTRY (unhandled-exception
        // path uses PropagateException above) or via legacy paths — fall back to EndOffset.
        state.Pc = current.PostFinallyPc >= 0 ? current.PostFinallyPc : inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleThrow(ExecutionState state, Instruction inst)
    {
        var ex = state.Pop();
        state.UncaughtException = ex;
        state.Telemetry.ExceptionsThrown.Add(inst.Offset);
        return PropagateException(state);
    }

    /// <summary>
    /// Walk the call stack looking for a catch or finally. Audit MED-6: search non-destructively,
    /// commit unwind only after a handler is found.
    /// </summary>
    private IEnumerable<ExecutionState> PropagateException(ExecutionState state)
    {
        for (int frameIdx = state.CallStack.Count - 1; frameIdx >= 0; frameIdx--)
        {
            var frame = state.CallStack[frameIdx];
            for (int tryIdx = frame.TryStack.Count - 1; tryIdx >= 0; tryIdx--)
            {
                var tryFrame = frame.TryStack[tryIdx];
                if (tryFrame.State == TryFrameState.Try && tryFrame.HasCatch)
                {
                    return UnwindTo(state, frameIdx, tryIdx, tryFrame.CatchOffset, advance: TryFrameState.Catch);
                }
                if (tryFrame.State != TryFrameState.Finally && tryFrame.HasFinally)
                {
                    return UnwindTo(state, frameIdx, tryIdx, tryFrame.FinallyOffset, advance: TryFrameState.Finally);
                }
            }
        }
        // No handler — fault.
        var msg = state.UncaughtException is null ? "uncaught throw" : "uncaught: " + DescribeMessage(state.UncaughtException);
        state.Terminate(TerminalStatus.Faulted, msg);
        return Single(state);
    }

    private static IEnumerable<ExecutionState> UnwindTo(ExecutionState state, int frameIdx, int tryIdx, int targetPc, TryFrameState advance)
    {
        // Drop frames above frameIdx.
        if (frameIdx < state.CallStack.Count - 1)
            state.CallStack.RemoveRange(frameIdx + 1, state.CallStack.Count - frameIdx - 1);
        var frame = state.CallStack[frameIdx];
        // Drop try frames above tryIdx.
        if (tryIdx < frame.TryStack.Count - 1)
            frame.TryStack.RemoveRange(tryIdx + 1, frame.TryStack.Count - tryIdx - 1);
        // Replace target try frame with a clone in the new state (no in-place mutation).
        var oldTf = frame.TryStack[tryIdx];
        var newTf = oldTf.Clone();
        newTf.State = advance;
        frame.TryStack[tryIdx] = newTf;
        if (advance == TryFrameState.Catch)
        {
            // Push the exception onto the eval stack and clear pending exception per NeoVM.
            if (state.UncaughtException is not null)
                state.Push(state.UncaughtException);
            state.UncaughtException = null;
        }
        state.Pc = targetPc;
        return new[] { state };
    }
}
