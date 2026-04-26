using System.Collections.Immutable;
using System.Linq;
using Neo.SymbolicExecutor.Nef;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Audit M1 regression: CALLT must pop the declared parameter count from the token
/// metadata, attach the resolved hash + method name to the recorded ExternalCall, and only
/// push a return value when the token has one.
/// </summary>
public class CalltTests
{
    [Fact]
    public void Callt_WithToken_PopsParameters_PushesReturn()
    {
        // Token #0: hash 0x11.., method "foo", parametersCount=2, hasReturnValue=true.
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x11, 20).ToArray(),
            Method: "foo",
            ParametersCount: 2,
            HasReturnValue: true,
            CallFlags: 0x01));

        // Script: PUSH1 PUSH2 CALLT 0,0 RET
        // Stack before CALLT: [1, 2]; after: [<ret_symbol>] (both args popped).
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().ContainSingle();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Halted);
        state.EvaluationStack.Should().HaveCount(1);
        state.EvaluationStack.Single().Sort.Should().Be(Sort.Unknown);

        state.Telemetry.ExternalCalls.Should().ContainSingle();
        var call = state.Telemetry.ExternalCalls.Single();
        call.Method.Should().Be("foo");
        call.Args.Should().HaveCount(2);
        call.HasReturnValue.Should().BeTrue();
        call.TargetHashDynamic.Should().BeFalse();
        call.MethodDynamic.Should().BeFalse();
        call.CallFlags.Should().Be(0x01);
    }

    [Fact]
    public void Callt_WithVoidReturn_DoesNotPushReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x22, 20).ToArray(),
            Method: "doStuff",
            ParametersCount: 1,
            HasReturnValue: false,
            CallFlags: 0));

        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH7,
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Halted);
        state.EvaluationStack.Should().BeEmpty();
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.HasReturnValue.Should().BeFalse();
    }

    [Fact]
    public void Callt_NoTokens_FallsBackToDynamic()
    {
        // No tokens attached: CALLT pops nothing, pushes a return symbol, marks dynamic.
        byte[] script =
        {
            (byte)NeoVm.OpCode.CALLT, 0x05, 0x00,  // token index 5, doesn't exist
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();
        var state = result.FinalStates.Single();
        state.Telemetry.ExternalCalls.Single().TargetHashDynamic.Should().BeTrue();
        state.Telemetry.ExternalCalls.Single().MethodDynamic.Should().BeTrue();
    }

    [Fact]
    public void Callt_StackUnderflow_FaultsCleanly()
    {
        // Token wants 3 params but stack has only 1. Should fault, not crash the host.
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: new byte[20],
            Method: "needsThree",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: 0));
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);
        var result = new SymbolicEngine(program).Run();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Faulted);
    }
}
