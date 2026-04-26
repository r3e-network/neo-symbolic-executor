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
}
