using System.Linq;
using System.Numerics;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Locked-in regressions for bugs the fuzzer surfaced. Each test covers one bug class so a
/// reintroduction of the bug fails CI immediately rather than waiting on a fuzz run.
/// </summary>
public class FuzzerRegressionTests
{
    [Fact]
    public void Engine_CatchableException_NeverLeaksOutOfRun()
    {
        // Bug: PICKITEM with an out-of-range index threw CatchableVmException up through
        // SymbolicEngine.Run() instead of being converted to a faulted terminal state.
        // Fix: outer catch in Run() routes the exception through PropagateException.
        // Repro: PUSH a single-byte ByteString, PUSH a large index, PICKITEM.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHDATA1, 0x01, 0xAA,   // bytes [0xAA]
            (byte)NeoVm.OpCode.PUSH9,                    // index 9
            (byte)NeoVm.OpCode.PICKITEM,                 // out-of-range
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
    }

    [Fact]
    public void Engine_RemoveOnArrayWithBadIndex_DoesNotCrashRun()
    {
        // Bug: REMOVE on an array with a bad concrete index threw CatchableVmException through
        // Run(). Fix: outer catch handles it.
        byte[] script =
        {
            (byte)NeoVm.OpCode.NEWARRAY0,                // empty array
            (byte)NeoVm.OpCode.PUSH3,                    // index 3
            (byte)NeoVm.OpCode.REMOVE,                   // out-of-range
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
    }

    [Fact]
    public void Engine_BigIntegerIndexCast_FaultsCleanly()
    {
        // Bug: a runtime-supplied index larger than Int32.MaxValue caused (int)bi to throw
        // System.OverflowException out of Run(). Fix: outer catch surfaces a faulted terminal.
        // Repro: push a 9-byte little-endian value > Int32.MaxValue, then NEWARRAY (which
        // casts to int internally).
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHINT64,
            0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,   // = 2^31 (just over Int32.MaxValue)
            (byte)NeoVm.OpCode.NEWARRAY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
        // Either Faulted (NEWARRAY size out of range) or Stopped is acceptable —
        // the key property is no exception leaks out.
    }

    [Fact]
    public void Engine_PickItemOnLargeIndex_FaultsCleanly()
    {
        // Companion to the BigInteger cast test: PICKITEM with a giant index should fault, not
        // throw OverflowException out of Run().
        byte[] script =
        {
            (byte)NeoVm.OpCode.NEWARRAY0,
            (byte)NeoVm.OpCode.PUSHINT64,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,   // Int64.MaxValue
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
    }

    [Fact]
    public void Engine_SubstrLargeOperands_DoNotLeakArgumentOutOfRangeException()
    {
        // Bug surfaced 2026-04-27 by engine-seeded target: SUBSTR with two large positive int
        // operands had `idx + cnt` overflow in the bounds check, letting Span<T>.AsSpan throw
        // ArgumentOutOfRangeException out of Run(). Fix: bound BigInteger before casting to int.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHDATA1, 0x02, 0xAA, 0xBB,   // src = 2 bytes
            (byte)NeoVm.OpCode.PUSHINT32, 0x00, 0x00, 0x00, 0x40,  // index = 2^30
            (byte)NeoVm.OpCode.PUSHINT32, 0x00, 0x00, 0x00, 0x40,  // count = 2^30 — sum overflows
            (byte)NeoVm.OpCode.SUBSTR,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
        result.FinalStates.All(s => s.Status == TerminalStatus.Faulted).Should().BeTrue();
    }

    [Fact]
    public void Engine_LeftLargeCount_DoesNotLeakArgumentOutOfRangeException()
    {
        // Companion to the SUBSTR bug: LEFT with count > Int32.MaxValue used to OverflowException
        // out of Run() during the (int)c cast. Now bounds-check BigInteger first.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHDATA1, 0x01, 0xAA,
            (byte)NeoVm.OpCode.PUSHINT64,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,   // Int64.MaxValue
            (byte)NeoVm.OpCode.LEFT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
    }

    [Fact]
    public void Engine_JmpToInsideOperand_DecodesJustInTime_DifferentialOracle()
    {
        // Bug surfaced 2026-04-27 by differential-neovm target: a JMP whose target lands
        // inside a previously-decoded instruction's operand bytes faulted the engine with
        // "PC at unaligned offset" while Neo.VM happily executed the new instruction.
        // Fix: NeoProgram.AtOffsetOrDecode JIT-decodes when the linear-scan index misses.
        // Repro from seed=15672414. The JMP +14 lands inside the ISTYPE operand at offset 14
        // (which is the byte 0x11 = PUSH1).
        byte[] script =
        {
            0x22, 0x0e, 0x93, 0x97, 0xd1, 0xe0, 0x1d, 0x70,
            0x09, 0x08, 0xa3, 0x4e, 0x9b, 0xd9, 0x11, 0x43,
            0x0f, 0x3b, 0x88, 0xe6, 0x09, 0xa8, 0x40,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 1_000, MaxPaths = 16, MaxStackSize = 64, PerRunDeadline = System.TimeSpan.FromSeconds(2),
        }).Run();
        // The script may halt or stop; the key assertion is that NO state faults with
        // "PC at unaligned" — that's the exact divergence we fixed.
        result.FinalStates.Should().NotBeEmpty();
        result.FinalStates.All(s =>
            s.TerminationReason is null
            || !s.TerminationReason.Contains("unaligned offset"))
            .Should().BeTrue("JIT-decode should let any byte-aligned offset execute");
    }

    [Fact]
    public void Engine_ShlShrZeroShift_DoesNotPopX_DifferentialOracle()
    {
        // Bug surfaced 2026-04-27 by differential-neovm target: NeoVM's SHL/SHR pop the
        // shift count first and ONLY pop x when shift != 0. Our engine always popped both,
        // producing a Stack-underflow fault on PUSH0 SHR with stack=[0].
        // Repro from seed=15894885. Bytes: 10 a9 40 = PUSH0 SHR RET.
        byte[] script = { 0x10, 0xA9, 0x40 };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().ContainSingle();
        var s = result.FinalStates[0];
        s.Status.Should().Be(TerminalStatus.Halted, "shift==0 should leave x on the stack and halt");
        // Stack at end: empty (no x was on the stack to begin with).
        s.EvaluationStack.Should().BeEmpty();
    }

    [Fact]
    public void Engine_WorklistCap_BoundsPathExplosion()
    {
        // Bug: deeply-forking symbolic loops filled the worklist with millions of states before
        // any of them terminated, so MaxPaths (which counts FINAL states) didn't fire until
        // very late. Fix: MaxQueuedStates caps the worklist and triggers a drain.
        // Repro from fuzz seed 575437178: a script with two backward JMPIF loops.
        byte[] script =
        {
            0x18, 0x99, 0x0F, 0x0F, 0x4B, 0xAA, 0x9B, 0x24, 0xFE, 0x0B,
            0xB6, 0x26, 0x02, 0x16, 0x0F, 0x24, 0xFA, 0xA0, 0x1D, 0x54, 0x40,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000,
            MaxPaths = 32,
            MaxQueuedStates = 256,
        });
        var result = engine.Run();
        result.StatesExplored.Should().BeLessThan(50_000,
            "the worklist cap should bound exploration well below the prior 1.3M-state blowup");
        result.FinalStates.All(s => s.Status != TerminalStatus.Running).Should().BeTrue();
        result.BudgetExceeded.Should().BeTrue();
    }
}
