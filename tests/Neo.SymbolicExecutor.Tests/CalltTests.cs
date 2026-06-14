using System.Collections.Immutable;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
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
        call.Args.Select(a => a.AsConcreteInt()).Should().Equal(1, 2);
        call.HasReturnValue.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
        call.TargetHashDynamic.Should().BeFalse();
        call.MethodDynamic.Should().BeFalse();
        call.CallFlags.Should().Be(0x01);
    }

    [Fact]
    public void Callt_StdLibSerialize_ModelsConcreteStackItemReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "serialize",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("alice"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal(Convert.FromHexString("2805616C696365"));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("serialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibDeserialize_ModelsConcreteStackItemReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "deserialize",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(Convert.FromHexString("2805616C696365")),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal("alice"u8.ToArray());
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("deserialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibJsonSerialize_ModelsConcreteUtf8StackItemReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "jsonSerialize",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("alice"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal("\"alice\""u8.ToArray());
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("jsonSerialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibJsonDeserialize_ModelsConcreteUtf8StackItemReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "jsonDeserialize",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("\"alice\""u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal("alice"u8.ToArray());
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("jsonDeserialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibHexEncode_ModelsConcreteBytesReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "hexEncode",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(new byte[] { 0x0A, 0xFF }),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal("0aff"u8.ToArray());
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("hexEncode");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibHexDecode_ModelsConcreteUtf8Return()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "hexDecode",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("0aff"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal(new byte[] { 0x0A, 0xFF });
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("hexDecode");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData("base58Encode", "6E656F", "65356838")]
    [InlineData("base58Decode", "65356838", "6E656F")]
    [InlineData("base58CheckEncode", "6E656F", "3542654E555565566E35")]
    [InlineData("base58CheckDecode", "3542654E555565566E35", "6E656F")]
    public void Callt_StdLibBase58_ModelsConcreteBytesReturn(
        string method,
        string inputHex,
        string expectedHex)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: method,
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(inputHex)),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal(Convert.FromHexString(expectedHex));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibMemoryCompare_ModelsConcreteBytesReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "memoryCompare",
            ParametersCount: 2,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("aa"u8.ToArray()),
            Pushdata1("ab"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteInt().Should().Be(new System.Numerics.BigInteger(-1));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("memoryCompare");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibMemorySearch_ModelsConcreteBytesReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "memorySearch",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("banana"u8.ToArray()),
            Pushdata1("ana"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)2 },
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteInt().Should().Be(new System.Numerics.BigInteger(3));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("memorySearch");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibStrLen_ModelsConcreteUtf8ScalarCountReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "strLen",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(Convert.FromHexString("41C3A3F09F9982")),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteInt().Should().Be(new System.Numerics.BigInteger(3));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("strLen");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_StdLibStringSplit_ModelsConcreteUtf8ArrayReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: StdLibHashBytes(),
            Method: "stringSplit",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("a,,b"u8.ToArray()),
            Pushdata1(","u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHT },
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var href = state.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        var array = state.Heap.Get<ArrayObject>(href.ObjectId);
        array.Items.Select(item => item.AsConcreteBytes()).Should()
            .SatisfyRespectively(
                item => item.Should().Equal("a"u8.ToArray()),
                item => item.Should().Equal("b"u8.ToArray()));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("stringSplit");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_CryptoLibSha256_ModelsConcreteBytesReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "sha256",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("neo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal(
            Convert.FromHexString("73EF176D9F12809E64363B2B5F4553ABECCA7AAE157327F190323CFA0E42C815"));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("sha256");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData("ripemd160", "098E87D8477D2279FF1CF6927A628C0F180E04EF", false)]
    [InlineData("keccak256", "D00D26E6BBB181308D622B89BEB026A4A9A5A80906AD56A318911E045FC4AFAF", false)]
    [InlineData("murmur32", "AF3A07FA", true)]
    public void Callt_CryptoLibHashMethods_ModelConcreteBytesReturn(
        string method,
        string expectedHex,
        bool hasSeed)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: method,
            ParametersCount: hasSeed ? (ushort)2 : (ushort)1,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("neo"u8.ToArray()),
            hasSeed
                ? new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)123 }
                : System.Array.Empty<byte>(),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes().Should().Equal(Convert.FromHexString(expectedHex));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_CryptoLibVerifyWithEd25519_ModelsConcreteSignatureReturn()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "verifyWithEd25519",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(System.Array.Empty<byte>()),
            Pushdata1(Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")),
            Pushdata1(Convert.FromHexString("E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B")),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBool().Should().BeTrue();
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("verifyWithEd25519");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData(22, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED8", true)]
    [InlineData(23, "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "4497D608BA54548FE46C89E4E2B8D5D5B9EE8515AE40BF902D7171E8CDCED4306CBD0782AF220FF41990D3BC271535F65B05118E02F7683BDD1FCEB459176568", true)]
    [InlineData(122, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "97A4044840CC4A1CF31771B7ADE7401466269EEC1E7778FC9DCF49F6CB1F968D7448520369F03E466D8FDDB873E9C8A44675236958853C57E7A59861D4C83250", true)]
    [InlineData(123, "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "5B872BA92E1D39ACABC5C2B414A18537C65FA441252595BB887F1F071071A68FD73D814903CA970D4A19FBA0F3FEA987B63E39FF09169B4C6B1278B44899B863", true)]
    [InlineData(22, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED9", false)]
    public void Callt_CryptoLibVerifyWithECDsa_ModelsConcreteSignatureReturn(
        int curveHash,
        string publicKeyHex,
        string signatureHex,
        bool expected)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "verifyWithECDsa",
            ParametersCount: 4,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1("neo-symbolic-executor"u8.ToArray()),
            Pushdata1(Convert.FromHexString(publicKeyHex)),
            Pushdata1(Convert.FromHexString(signatureHex)),
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)curveHash },
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBool().Should().Be(expected);
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("verifyWithECDsa");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED81B", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED800", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000B4D3BE58B0F28D1047A0FE94F14198ABC9C7918C3A170B17DD2B7A6A68CC3269", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("00", null)]
    public void Callt_CryptoLibRecoverSecp256K1_ModelsConcreteSignatureReturn(
        string signatureHex,
        string? expectedPublicKeyHex)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "recoverSecp256K1",
            ParametersCount: 2,
            HasReturnValue: true,
            CallFlags: 0x01));

        byte[] script = Concat(
            Pushdata1(Convert.FromHexString("533E60831C7DDFC12204218D58A6D785A3C32750EE4D98CAD7B954FE00A22AD1")),
            Pushdata1(Convert.FromHexString(signatureHex)),
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        if (expectedPublicKeyHex is null)
        {
            state.EvaluationStack.Single().IsConcreteNull.Should().BeTrue();
        }
        else
        {
            state.EvaluationStack.Single().AsConcreteBytes()
                .Should().Equal(Convert.FromHexString(expectedPublicKeyHex));
        }

        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("recoverSecp256K1");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Callt_CryptoLibBls12381DeserializeSerialize_RoundTripsConcreteG1()
    {
        var tokens = ImmutableArray.Create(
            CryptoLibToken("bls12381Deserialize", 1),
            CryptoLibToken("bls12381Serialize", 1));
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            Callt(0),
            Callt(1),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Single().AsConcreteBytes()
            .Should().Equal(Convert.FromHexString(BlsG1GeneratorHex));
        state.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Serialize");
    }

    [Fact]
    public void Callt_CryptoLibBls12381Equal_ReturnsConcreteTrueForSamePoint()
    {
        var tokens = ImmutableArray.Create(
            CryptoLibToken("bls12381Deserialize", 1),
            CryptoLibToken("bls12381Equal", 2));
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.DUP },
            Callt(1),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        result.Halted.Should().ContainSingle().Which
            .EvaluationStack.Single().AsConcreteBool().Should().BeTrue();
    }

    [Fact]
    public void Callt_CryptoLibBls12381PairingSerializesConcreteGeneratorPairing()
    {
        var tokens = ImmutableArray.Create(
            CryptoLibToken("bls12381Deserialize", 1),
            CryptoLibToken("bls12381Pairing", 2),
            CryptoLibToken("bls12381Serialize", 1));
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            Callt(0),
            Pushdata1(Convert.FromHexString(BlsG2GeneratorHex)),
            Callt(0),
            Callt(1),
            Callt(2),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        result.Halted.Should().ContainSingle().Which
            .EvaluationStack.Single().AsConcreteBytes()
            .Should().Equal(Convert.FromHexString(BlsGtGeneratorPairingHex));
    }

    [Fact]
    public void Callt_CryptoLibBls12381AddSerializesConcreteG1Double()
    {
        var tokens = ImmutableArray.Create(
            CryptoLibToken("bls12381Deserialize", 1),
            CryptoLibToken("bls12381Add", 2),
            CryptoLibToken("bls12381Serialize", 1));
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.DUP },
            Callt(1),
            Callt(2),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        result.Halted.Should().ContainSingle().Which
            .EvaluationStack.Single().AsConcreteBytes()
            .Should().Equal(Convert.FromHexString(BlsG1DoubleHex));
    }

    [Fact]
    public void Callt_CryptoLibBls12381MulSerializesConcreteG1TimesTwo()
    {
        var tokens = ImmutableArray.Create(
            CryptoLibToken("bls12381Deserialize", 1),
            CryptoLibToken("bls12381Mul", 3),
            CryptoLibToken("bls12381Serialize", 1));
        var scalarTwo = new byte[32];
        scalarTwo[0] = 2;
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            Callt(0),
            Pushdata1(scalarTwo),
            new[] { (byte)NeoVm.OpCode.PUSHF },
            Callt(1),
            Callt(2),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        result.Halted.Should().ContainSingle().Which
            .EvaluationStack.Single().AsConcreteBytes()
            .Should().Equal(Convert.FromHexString(BlsG1DoubleHex));
    }

    [Fact]
    public void Callt_NeoTokenReadOnlyMethodsReturnConcreteConstants()
    {
        var tokens = ImmutableArray.Create(
            NeoToken("symbol", 0),
            NeoToken("decimals", 0),
            NeoToken("totalSupply", 0));
        byte[] script = Concat(
            Callt(0),
            Callt(1),
            Callt(2),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().HaveCount(3);
        state.EvaluationStack[0].AsConcreteBytes().Should().Equal("NEO"u8.ToArray());
        state.EvaluationStack[1].AsConcreteInt().Should().Be(System.Numerics.BigInteger.Zero);
        state.EvaluationStack[2].AsConcreteInt().Should().Be(new System.Numerics.BigInteger(100_000_000));
        state.Telemetry.ExternalCalls.Should().OnlyContain(call => call.HasReturnValue && call.ReturnModeledNative);
    }

    [Fact]
    public void Callt_GasTokenBalanceOfReturnsStableNonNegativeSymbol()
    {
        var tokens = ImmutableArray.Create(GasToken("balanceOf", 1));
        byte[] script = Concat(
            Pushdata1(new byte[20]),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var balance = state.EvaluationStack.Single();
        balance.Sort.Should().Be(Sort.Int);
        balance.Expression.FreeSymbols().Should().Contain("native_gas_balanceOf_0");
        state.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains("native_gas_balanceOf_0"));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.HasReturnValue.Should().BeTrue("modeled native token calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Callt_NeoTokenCandidateVoteReturnsStableMinusOneOrNonNegativeSymbol()
    {
        var tokens = ImmutableArray.Create(NeoToken("getCandidateVote", 1));
        byte[] pubkey = Convert.FromHexString(
            "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        byte[] script = Concat(
            Pushdata1(pubkey),
            Callt(0),
            Pushdata1(pubkey),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.NUMEQUAL, (byte)NeoVm.OpCode.ASSERT },
            Pushdata1(pubkey),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        string suffix = Convert.ToHexString(pubkey).ToLowerInvariant();
        string symbol = $"native_neo_getCandidateVote_{suffix}";
        var candidateVotes = state.EvaluationStack.Single();
        candidateVotes.Sort.Should().Be(Sort.Int);
        candidateVotes.Expression.FreeSymbols().Should().Contain(symbol);
        state.PathConditions.Should().Contain(Expr.Ge(candidateVotes.Expression, Expr.Int(-1)));
        state.PathConditions.Should().NotContain(Expr.Ge(candidateVotes.Expression, Expr.Int(0)));
        state.Telemetry.ExternalCalls.Should().HaveCount(3);
        state.Telemetry.ExternalCalls.Should().OnlyContain(call =>
            call.Method == "getCandidateVote" && call.HasReturnValue && call.ReturnModeledNative);
    }

    [Fact]
    public void Callt_NeoTokenUnclaimedGasReturnsStableNonNegativeSymbolForCurrentIndexSuccessor()
    {
        var tokens = ImmutableArray.Create(
            LedgerToken("currentIndex", 0),
            NeoToken("unclaimedGas", 2));
        byte[] account = new byte[20];
        byte[] script = Concat(
            Pushdata1(account),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.ADD },
            Callt(1),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var unclaimed = state.EvaluationStack.Single();
        unclaimed.Sort.Should().Be(Sort.Int);
        unclaimed.Expression.FreeSymbols().Should().Contain("native_neo_unclaimedGas_0");
        state.PathConditions.Should().Contain(Expr.Ge(unclaimed.Expression, Expr.Int(0)));
        state.Telemetry.FaultConditions.Should().NotContain(fault => fault.Operation == "NEO.unclaimedGas");
        state.Telemetry.ExternalCalls.Should().HaveCount(2);
        state.Telemetry.ExternalCalls.Should().OnlyContain(call => call.HasReturnValue && call.ReturnModeledNative);
    }

    [Fact]
    public void Callt_GasTokenTransferReturnsModeledBooleanAndNativePreconditions()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: GasTokenHashBytes(),
            Method: "transfer",
            ParametersCount: 4,
            HasReturnValue: true,
            CallFlags: NeoCallFlags.All));
        byte[] from = Enumerable.Range(0, 20).Select(i => (byte)(0x10 + i)).ToArray();
        byte[] to = Enumerable.Range(0, 20).Select(i => (byte)(0x40 + i)).ToArray();
        byte[] script = Concat(
            Pushdata1(from),
            Pushdata1(to),
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var states = result.Halted.ToArray();
        states.Should().HaveCount(2, "native token transfer has success and false-return paths");
        states.Should().OnlyContain(state => state.EvaluationStack.Count == 1);
        states.Should().OnlyContain(state => state.Telemetry.UnknownSyscalls.Count == 0);
        states.Should().OnlyContain(state => !state.Telemetry.FaultConditions.Any(fault => fault.Operation == "GAS.transfer"));
        states.Should().OnlyContain(state => state.Telemetry.ExternalCalls.Count == 1);

        foreach (var state in states)
        {
            var transferOk = state.EvaluationStack.Single();
            transferOk.Sort.Should().Be(Sort.Bool);
            transferOk.Expression.FreeSymbols().Should().Contain(symbol => symbol.StartsWith("ext_ret_", StringComparison.Ordinal));
            var call = state.Telemetry.ExternalCalls.Single();
            call.Method.Should().Be("transfer");
            call.Args.Should().HaveCount(4);
            call.CallFlags.Should().Be(NeoCallFlags.All);
            call.HasReturnValue.Should().BeTrue();
            call.ReturnModeledNative.Should().BeTrue();
            call.ReturnChecked.Should().BeFalse();
        }

        string returnSymbol = states
            .SelectMany(state => state.EvaluationStack.Single().Expression.FreeSymbols())
            .Distinct(StringComparer.Ordinal)
            .Single(symbol => symbol.StartsWith("ext_ret_", StringComparison.Ordinal));
        states.Should().ContainSingle(state =>
            state.PathConditions.Contains(Expr.Sym(Sort.Bool, returnSymbol))
            && state.Telemetry.Notifications.Count == 1);
        states.Should().ContainSingle(state =>
            state.PathConditions.Contains(Expr.Not(Expr.Sym(Sort.Bool, returnSymbol)))
            && state.Telemetry.Notifications.Count == 0);
    }

    [Fact]
    public void Callt_NeoTokenGetCandidatesReturnsStructuredOpenArray()
    {
        var tokens = ImmutableArray.Create(NeoToken("getCandidates", 0));
        byte[] script = Concat(
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var candidatesRef = state.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        var candidates = state.Heap.Get<ArrayObject>(candidatesRef.ObjectId);
        candidates.IsSymbolicOpen.Should().BeTrue();
        candidates.MinCount.Should().Be(0);
        var candidateRef = candidates.Items.Should().ContainSingle().Subject.Expression.Should().BeOfType<HeapRef>().Subject;
        var candidate = state.Heap.Get<StructObject>(candidateRef.ObjectId);
        candidate.Fields.Should().HaveCount(2);
        candidate.Fields[0].Sort.Should().Be(Sort.Bytes);
        candidate.Fields[0].Expression.FreeSymbols().Should().Contain("neo_candidate_key_0");
        candidate.Fields[1].Sort.Should().Be(Sort.Int);
        candidate.Fields[1].Expression.FreeSymbols().Should().Contain("native_neo_getCandidates_votes_0");
        state.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains("neo_candidate_key_0"));
        state.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains("native_neo_getCandidates_votes_0"));
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Callt_NeoTokenGetAccountStateReturnsStableNullableStruct()
    {
        var tokens = ImmutableArray.Create(NeoToken("getAccountState", 1));
        byte[] script = Concat(
            Pushdata1(new byte[20]),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(3);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);

        var presentStates = halted
            .Where(state => state.EvaluationStack.Single().Expression is HeapRef)
            .ToList();
        presentStates.Should().HaveCount(2);

        foreach (var state in presentStates)
        {
            var accountStateRef = (HeapRef)state.EvaluationStack.Single().Expression;
            var accountState = state.Heap.Get<StructObject>(accountStateRef.ObjectId);
            accountState.Fields.Should().HaveCount(4);
            accountState.Fields[0].Sort.Should().Be(Sort.Int);
            accountState.Fields[0].Expression.FreeSymbols().Should().Contain("native_neo_getAccountState_balance_0");
            accountState.Fields[1].Sort.Should().Be(Sort.Int);
            accountState.Fields[1].Expression.FreeSymbols().Should().Contain("native_neo_getAccountState_height_0");
            accountState.Fields[3].Sort.Should().Be(Sort.Int);
            accountState.Fields[3].Expression.FreeSymbols().Should().Contain("native_neo_getAccountState_lastGasPerVote_0");
            state.PathConditions.Should().Contain(condition =>
                condition.FreeSymbols().Contains("native_neo_getAccountState_balance_0"));
            state.PathConditions.Should().Contain(condition =>
                condition.FreeSymbols().Contains("native_neo_getAccountState_height_0"));
            state.PathConditions.Should().Contain(condition =>
                condition.FreeSymbols().Contains("native_neo_getAccountState_lastGasPerVote_0"));
            state.Telemetry.ExternalCalls.Should().ContainSingle()
                .Which.ReturnModeledNative.Should().BeTrue();
        }

        presentStates.Any(state =>
        {
            var accountStateRef = (HeapRef)state.EvaluationStack.Single().Expression;
            return state.Heap.Get<StructObject>(accountStateRef.ObjectId).Fields[2].IsConcreteNull;
        }).Should().BeTrue();
        presentStates.Any(state =>
        {
            var accountStateRef = (HeapRef)state.EvaluationStack.Single().Expression;
            var voteTo = state.Heap.Get<StructObject>(accountStateRef.ObjectId).Fields[2];
            return voteTo.Sort == Sort.Bytes
                && voteTo.Expression.FreeSymbols().Contains("neo_account_state_voteTo_0")
                && state.PathConditions.Any(condition => condition.FreeSymbols().Contains("neo_account_state_voteTo_0"));
        }).Should().BeTrue();
    }

    [Fact]
    public void Callt_ContractManagementIsContractForksExistenceResult()
    {
        var tokens = ImmutableArray.Create(ContractManagementToken("isContract", 1));
        byte[] targetHash = Enumerable.Repeat((byte)0x42, 20).ToArray();
        byte[] script = Concat(
            Pushdata1(targetHash),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Select(state => state.EvaluationStack.Single().AsConcreteBool())
            .Should().BeEquivalentTo(new bool?[] { true, false });
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "isContract"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative);
        halted.Should().Contain(state =>
            state.Telemetry.ContractExistenceQueries.Single().Exists
            && state.Telemetry.ContractExistenceQueries.Single().Target.AsConcreteBytes()!.SequenceEqual(targetHash));
        halted.Should().Contain(state =>
            !state.Telemetry.ContractExistenceQueries.Single().Exists
            && state.Telemetry.ContractExistenceQueries.Single().Target.AsConcreteBytes()!.SequenceEqual(targetHash));
    }

    [Fact]
    public void Callt_ContractManagementGetContractByIdReturnsNullableContract()
    {
        var tokens = ImmutableArray.Create(ContractManagementToken("getContractById", 1));
        byte[] script = Concat(
            PushInt32(17),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);
        var contractState = halted.Single(state => state.EvaluationStack.Single().Expression is HeapRef);
        var href = contractState.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        contractState.Heap.Get<InteropObject>(href.ObjectId).Kind.Should().Be("contract");
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "getContractById"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative
            && state.Telemetry.UnknownSyscalls.Count == 0);
    }

    [Fact]
    public void Callt_ContractManagementGetContractHashesReturnsIteratorPairs()
    {
        var tokens = ImmutableArray.Create(ContractManagementToken("getContractHashes", 0));
        byte[] script = Concat(
            Callt(0),
            new[] { (byte)NeoVm.OpCode.DUP },
            Syscall("System.Iterator.Next"),
            new[]
            {
                (byte)NeoVm.OpCode.JMPIF,
                (byte)0x04,
                (byte)NeoVm.OpCode.DROP,
                (byte)NeoVm.OpCode.RET,
            },
            Syscall("System.Iterator.Value"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        result.Faulted.Should().BeEmpty();
        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().OnlyContain(state => state.Telemetry.UnknownSyscalls.Count == 0);
        var valueState = halted.Single(state => state.EvaluationStack.Count == 1);
        var valueRef = valueState.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        valueRef.RefSort.Should().Be(Sort.Struct);
        valueState.Heap.Get<StructObject>(valueRef.ObjectId).Fields.Should().HaveCount(2);
        var call = valueState.Telemetry.ExternalCalls.Should().ContainSingle().Subject;
        call.Method.Should().Be("getContractHashes");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Callt_ContractManagementLifecycleVoidCallsAreModeled()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: ContractManagementHashBytes(),
                Method: "update",
                ParametersCount: 3,
                HasReturnValue: false,
                CallFlags: (byte)NeoCallFlags.All),
            new MethodToken(
                Hash: ContractManagementHashBytes(),
                Method: "destroy",
                ParametersCount: 0,
                HasReturnValue: false,
                CallFlags: (byte)(NeoCallFlags.States | NeoCallFlags.AllowNotify)));
        byte[] script = Concat(
            Pushdata1(new byte[] { 0x4E, 0x45, 0x46 }),
            Pushdata1("""{"name":"Updated"}"""u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Callt(0),
            Callt(1),
            new[] { (byte)NeoVm.OpCode.PUSHT, (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().ContainSingle().Which.AsConcreteBool().Should().BeTrue();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
        state.Telemetry.ExternalCalls.Should().HaveCount(2);
        state.Telemetry.ExternalCalls.Select(call => call.Method).Should().Equal("update", "destroy");
        state.Telemetry.ExternalCalls.Should().OnlyContain(call =>
            call.TargetHash!.AsConcreteBytes()!.SequenceEqual(ContractManagementHashBytes())
            && !call.HasReturnValue
            && !call.ReturnModeledNative);
    }

    [Fact]
    public void ContractCall_ContractManagementUpdatePushesNullButRemainsSensitiveExternalCall()
    {
        byte[] script = Concat(
            Pushdata1(ContractManagementHashBytes()),
            Pushdata1("update"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH15 },
            Pushdata1(new byte[] { 0x4E, 0x45, 0x46 }),
            Pushdata1("""{"name":"Updated"}"""u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL, (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().ContainSingle().Which.IsConcreteNull.Should().BeTrue();
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("update");
        call.Args.Should().HaveCount(3);
        call.HasReturnValue.Should().BeFalse();
        call.ReturnModeledNative.Should().BeFalse();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_ContractManagementDeployReturnsContractAndRemainsSensitiveExternalCall()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: ContractManagementHashBytes(),
            Method: "deploy",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: (byte)NeoCallFlags.All));
        byte[] script = Concat(
            Pushdata1(new byte[] { 0x4E, 0x45, 0x46 }),
            Pushdata1("""{"name":"Created"}"""u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var returned = state.EvaluationStack.Should().ContainSingle().Which;
        returned.Sort.Should().Be(Sort.InteropInterface);
        var href = returned.Expression.Should().BeOfType<HeapRef>().Subject;
        state.Heap.Get<InteropObject>(href.ObjectId).Kind.Should().Be("contract");
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("deploy");
        call.Args.Should().HaveCount(3);
        call.HasReturnValue.Should().BeTrue();
        call.ReturnModeledNative.Should().BeFalse();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void ContractCall_ContractManagementDeployReturnsContractButRemainsSensitiveExternalCall()
    {
        byte[] script = Concat(
            Pushdata1(ContractManagementHashBytes()),
            Pushdata1("deploy"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH15 },
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Pushdata1("""{"name":"Created"}"""u8.ToArray()),
            Pushdata1(new byte[] { 0x4E, 0x45, 0x46 }),
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var returned = state.EvaluationStack.Should().ContainSingle().Which;
        returned.Sort.Should().Be(Sort.InteropInterface);
        var href = returned.Expression.Should().BeOfType<HeapRef>().Subject;
        state.Heap.Get<InteropObject>(href.ObjectId).Kind.Should().Be("contract");
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("deploy");
        call.Args.Should().HaveCount(3);
        call.HasReturnValue.Should().BeTrue();
        call.ReturnModeledNative.Should().BeFalse();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_OracleRequestVoidCallIsModeledAsSensitiveExternalCall()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: OracleContractHashBytes(),
            Method: "request",
            ParametersCount: 5,
            HasReturnValue: false,
            CallFlags: (byte)(NeoCallFlags.States | NeoCallFlags.AllowNotify)));
        byte[] script = Concat(
            Pushdata1("https://example.test/oracle"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Pushdata1("callback"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            PushInt32(10_000_000),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.PUSHT, (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().ContainSingle().Which.AsConcreteBool().Should().BeTrue();
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("request");
        call.Args.Should().HaveCount(5);
        call.HasReturnValue.Should().BeFalse();
        call.ReturnModeledNative.Should().BeFalse();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void ContractCall_OracleRequestPushesNullButRemainsSensitiveExternalCall()
    {
        byte[] script = Concat(
            Pushdata1(OracleContractHashBytes()),
            Pushdata1("request"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH11 },
            PushInt32(10_000_000),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Pushdata1("callback"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHNULL },
            Pushdata1("https://example.test/oracle"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH5, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().ContainSingle().Which.IsConcreteNull.Should().BeTrue();
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("request");
        call.Args.Should().HaveCount(5);
        call.HasReturnValue.Should().BeFalse();
        call.ReturnModeledNative.Should().BeFalse();
        state.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_LedgerGetTransactionSignersReturnsNullableOpenSignerArray()
    {
        var tokens = ImmutableArray.Create(LedgerToken("getTransactionSigners", 1));
        byte[] script = Concat(
            Pushdata1(new byte[32]),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);
        var present = halted.Single(state => state.EvaluationStack.Single().Expression is HeapRef);

        var signersRef = (HeapRef)present.EvaluationStack.Single().Expression;
        var signers = present.Heap.Get<ArrayObject>(signersRef.ObjectId);
        signers.IsSymbolicOpen.Should().BeTrue();
        signers.MinCount.Should().Be(1);
        var signerRef = signers.Items.Should().ContainSingle().Subject.Expression.Should().BeOfType<HeapRef>().Subject;
        var signer = present.Heap.Get<StructObject>(signerRef.ObjectId);
        signer.Fields.Should().HaveCount(5);
        signer.Fields[0].Sort.Should().Be(Sort.Bytes);
        signer.Fields[0].Expression.FreeSymbols().Should().Contain($"ledger_transaction_signer_{new string('0', 64)}_0_account");
        signer.Fields[1].Sort.Should().Be(Sort.Int);
        signer.Fields[1].Expression.FreeSymbols().Should().Contain($"ledger_transaction_signer_{new string('0', 64)}_0_scopes");
        signer.Fields[2].Expression.Should().BeOfType<HeapRef>().Which.RefSort.Should().Be(Sort.Array);
        signer.Fields[3].Expression.Should().BeOfType<HeapRef>().Which.RefSort.Should().Be(Sort.Array);
        signer.Fields[4].Expression.Should().BeOfType<HeapRef>().Which.RefSort.Should().Be(Sort.Array);
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_signer_{new string('0', 64)}_0_account"));
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_signer_{new string('0', 64)}_0_scopes"));
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "getTransactionSigners"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative);
    }

    [Fact]
    public void Callt_LedgerGetTransactionReturnsNullableTransactionStruct()
    {
        var tokens = ImmutableArray.Create(LedgerToken("getTransaction", 1));
        byte[] transactionHash = Enumerable.Repeat((byte)0x54, 32).ToArray();
        byte[] script = Concat(
            Pushdata1(transactionHash),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);
        var present = halted.Single(state => state.EvaluationStack.Single().Expression is HeapRef);

        var transactionRef = (HeapRef)present.EvaluationStack.Single().Expression;
        var transaction = present.Heap.Get<StructObject>(transactionRef.ObjectId);
        transaction.Fields.Should().HaveCount(8);
        transaction.Fields[0].AsConcreteBytes().Should().Equal(transactionHash);
        transaction.Fields[1].AsConcreteInt().Should().Be(System.Numerics.BigInteger.Zero);
        transaction.Fields[2].Sort.Should().Be(Sort.Int);
        transaction.Fields[2].Expression.FreeSymbols().Should().Contain($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_nonce");
        transaction.Fields[3].Sort.Should().Be(Sort.Bytes);
        transaction.Fields[3].Expression.FreeSymbols().Should().Contain($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_sender");
        transaction.Fields[4].Sort.Should().Be(Sort.Int);
        transaction.Fields[5].Sort.Should().Be(Sort.Int);
        transaction.Fields[6].Sort.Should().Be(Sort.Int);
        transaction.Fields[7].Sort.Should().Be(Sort.Bytes);
        transaction.Fields[7].Expression.FreeSymbols().Should().Contain($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_script");
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_sender"));
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_system_fee"));
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_{Convert.ToHexString(transactionHash).ToLowerInvariant()}_script"));
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "getTransaction"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative);
    }

    [Fact]
    public void Callt_LedgerGetTransactionFromBlockReturnsNullableTransactionStruct()
    {
        var tokens = ImmutableArray.Create(LedgerToken("getTransactionFromBlock", 2));
        byte[] blockHash = Enumerable.Repeat((byte)0x56, 32).ToArray();
        string suffix = $"{Convert.ToHexString(blockHash).ToLowerInvariant()}_0";
        byte[] script = Concat(
            Pushdata1(blockHash),
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);
        var present = halted.Single(state => state.EvaluationStack.Single().Expression is HeapRef);

        var transactionRef = (HeapRef)present.EvaluationStack.Single().Expression;
        var transaction = present.Heap.Get<StructObject>(transactionRef.ObjectId);
        transaction.Fields.Should().HaveCount(8);
        transaction.Fields[0].Sort.Should().Be(Sort.Bytes);
        transaction.Fields[0].Expression.FreeSymbols().Should().Contain($"ledger_transaction_from_block_{suffix}_hash");
        transaction.Fields[1].AsConcreteInt().Should().Be(System.Numerics.BigInteger.Zero);
        transaction.Fields[2].Expression.FreeSymbols().Should().Contain($"ledger_transaction_from_block_{suffix}_nonce");
        transaction.Fields[3].Expression.FreeSymbols().Should().Contain($"ledger_transaction_from_block_{suffix}_sender");
        transaction.Fields[4].Sort.Should().Be(Sort.Int);
        transaction.Fields[5].Sort.Should().Be(Sort.Int);
        transaction.Fields[6].Sort.Should().Be(Sort.Int);
        transaction.Fields[7].Expression.FreeSymbols().Should().Contain($"ledger_transaction_from_block_{suffix}_script");
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_from_block_{suffix}_hash"));
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_transaction_from_block_{suffix}_sender"));
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "getTransactionFromBlock"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative);
    }

    [Fact]
    public void Callt_LedgerGetBlockReturnsNullableBlockStruct()
    {
        var tokens = ImmutableArray.Create(LedgerToken("getBlock", 1));
        byte[] blockHash = Enumerable.Repeat((byte)0x55, 32).ToArray();
        string suffix = Convert.ToHexString(blockHash).ToLowerInvariant();
        byte[] script = Concat(
            Pushdata1(blockHash),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.ToList();
        halted.Should().HaveCount(2);
        halted.Should().Contain(state => state.EvaluationStack.Single().IsConcreteNull);
        var present = halted.Single(state => state.EvaluationStack.Single().Expression is HeapRef);

        var blockRef = (HeapRef)present.EvaluationStack.Single().Expression;
        var block = present.Heap.Get<StructObject>(blockRef.ObjectId);
        block.Fields.Should().HaveCount(10);
        block.Fields[0].AsConcreteBytes().Should().Equal(blockHash);
        block.Fields[1].Sort.Should().Be(Sort.Int);
        block.Fields[1].Expression.FreeSymbols().Should().Contain($"ledger_block_{suffix}_version");
        block.Fields[2].Sort.Should().Be(Sort.Bytes);
        block.Fields[2].Expression.FreeSymbols().Should().Contain($"ledger_block_{suffix}_prev_hash");
        block.Fields[3].Sort.Should().Be(Sort.Bytes);
        block.Fields[3].Expression.FreeSymbols().Should().Contain($"ledger_block_{suffix}_merkle_root");
        block.Fields[4].Sort.Should().Be(Sort.Int);
        block.Fields[5].Sort.Should().Be(Sort.Int);
        block.Fields[6].Sort.Should().Be(Sort.Int);
        block.Fields[7].Sort.Should().Be(Sort.Int);
        block.Fields[8].Sort.Should().Be(Sort.Bytes);
        block.Fields[8].Expression.FreeSymbols().Should().Contain($"ledger_block_{suffix}_next_consensus");
        block.Fields[9].Sort.Should().Be(Sort.Int);
        block.Fields[9].Expression.FreeSymbols().Should().Contain($"ledger_block_{suffix}_transactions_count");
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_block_{suffix}_next_consensus"));
        present.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains($"ledger_block_{suffix}_transactions_count"));
        halted.Should().OnlyContain(state =>
            state.Telemetry.ExternalCalls.Count == 1
            && state.Telemetry.ExternalCalls.Single().Method == "getBlock"
            && state.Telemetry.ExternalCalls.Single().ReturnModeledNative);
    }

    [Fact]
    public void ContractCall_GasTokenBalanceOfReturnsStableNonNegativeSymbol()
    {
        byte[] script = Concat(
            Pushdata1(GasTokenHashBytes()),
            Pushdata1("balanceOf"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(new byte[20]),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        var balance = state.EvaluationStack.Single();
        balance.Sort.Should().Be(Sort.Int);
        balance.Expression.FreeSymbols().Should().Contain("native_gas_balanceOf_0");
        state.PathConditions.Should().Contain(condition =>
            condition.FreeSymbols().Contains("native_gas_balanceOf_0"));
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("balanceOf");
        call.HasReturnValue.Should().BeTrue("modeled native token calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void ContractCall_RequestedCallFlagsAreMaskedByCurrentContext()
    {
        byte[] script = Concat(
            Pushdata1(Enumerable.Repeat((byte)0x55, 20).ToArray()),
            Pushdata1("foo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH15 },
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { InitialCallFlags = NeoCallFlags.ReadOnly }).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.CallFlags.Should().Be(NeoCallFlags.ReadOnly);
    }

    [Theory]
    [InlineData(NeoCallFlags.ReadStates, "AllowCall")]
    [InlineData(NeoCallFlags.AllowCall, "ReadStates")]
    public void ContractCall_MissingCurrentContextCallFlags_Faults(int currentFlags, string missingFlag)
    {
        byte[] script = Concat(
            Pushdata1(Enumerable.Repeat((byte)0x56, 20).ToArray()),
            Pushdata1("foo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { InitialCallFlags = currentFlags }).Run();

        var state = result.FinalStates.Should().ContainSingle().Which;
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("System.Contract.Call");
        state.TerminationReason.Should().Contain(missingFlag);
        state.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_GasTokenBalanceOfWithoutReadStates_Faults()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: GasTokenHashBytes(),
            Method: "balanceOf",
            ParametersCount: 1,
            HasReturnValue: true,
            CallFlags: 0x00));
        byte[] script = Concat(
            Pushdata1(new byte[20]),
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("GAS.balanceOf");
        state.TerminationReason.Should().Contain("ReadStates");
        state.Telemetry.ExternalCalls.Should().ContainSingle().Which
            .CallFlags.Should().Be(0);
    }

    [Fact]
    public void Callt_TokenCallFlagsAreMaskedByCurrentContext()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x57, 20).ToArray(),
            Method: "foo",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: NeoCallFlags.All));
        byte[] script = Concat(
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { InitialCallFlags = NeoCallFlags.ReadOnly }).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.CallFlags.Should().Be(NeoCallFlags.ReadOnly);
    }

    [Theory]
    [InlineData(NeoCallFlags.ReadStates, "AllowCall")]
    [InlineData(NeoCallFlags.AllowCall, "ReadStates")]
    public void Callt_MissingCurrentContextCallFlags_Faults(int currentFlags, string missingFlag)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x58, 20).ToArray(),
            Method: "foo",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: NeoCallFlags.ReadOnly));
        byte[] script = Concat(
            Callt(0),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { InitialCallFlags = currentFlags }).Run();

        var state = result.FinalStates.Should().ContainSingle().Which;
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("CALLT");
        state.TerminationReason.Should().Contain(missingFlag);
        state.Telemetry.ExternalCalls.Should().BeEmpty();
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
            .Which.ReturnValueDeclaredByMethodToken.Should().BeTrue();
        state.Telemetry.ExternalCalls.Single().HasReturnValue.Should().BeFalse();
    }

    [Fact]
    public void Callt_SameContractToken_ExecutesCalleeWithoutPushingVoidReturn()
    {
        byte[] caller =
        {
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        byte[] script = Concat(
            caller,
            new[] { (byte)NeoVm.OpCode.RET });
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: ScriptHash(script),
            Method: "callee",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: 0x00));
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);
        ContractSelfCallResolver resolver = (method, argumentCount) =>
            method == "callee" && argumentCount == 0
                ? new ContractSelfCallTarget("callee", caller.Length, 0, HasReturnValue: false, Safe: false)
                : null;

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { SelfCallResolver = resolver }).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        state.EvaluationStack.Should().BeEmpty();
        var call = state.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("callee");
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
        call.ModeledSelfCall.Should().BeTrue();
    }

    [Fact]
    public void Callt_SameContractToken_IncrementsRuntimeInvocationCounterInCallee()
    {
        byte[] caller =
        {
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        byte[] script = Concat(
            caller,
            Syscall("System.Runtime.GetInvocationCounter"),
            new[] { (byte)NeoVm.OpCode.RET });
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: ScriptHash(script),
            Method: "callee",
            ParametersCount: 0,
            HasReturnValue: true,
            CallFlags: 0x00));
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);
        ContractSelfCallResolver resolver = (method, argumentCount) =>
            method == "callee" && argumentCount == 0
                ? new ContractSelfCallTarget("callee", caller.Length, 0, HasReturnValue: true, Safe: false)
                : null;

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { SelfCallResolver = resolver }).Run();

        var state = result.Halted.Should().ContainSingle().Which;
        // Review fix (#13): the top-level invocation counter is nondeterministic (the contract may be
        // the outermost call or already re-entered), modeled as a stable base symbol >= 1. The CALLT
        // self-call deterministically increments it, so the callee observes base + 1 (== caller + 1)
        // rather than a hard-coded concrete 2. Both the base symbol and the +1 increment are present.
        var counter = state.EvaluationStack.Should().ContainSingle().Subject;
        counter.AsConcreteInt().Should().BeNull("the invocation counter is nondeterministic at a fresh analysis entry");
        counter.Expression.FreeSymbols().Should().Contain("invocation_counter_base");
        counter.Expression.Should().BeOfType<BinaryExpr>()
            .Which.Op.Should().Be("+");
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.ModeledSelfCall.Should().BeTrue();
    }

    [Fact]
    public void Callt_SameContractToken_PropagatesCalleeFault()
    {
        byte[] caller =
        {
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        byte[] script = Concat(
            caller,
            new[] { (byte)NeoVm.OpCode.ABORT });
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: ScriptHash(script),
            Method: "callee",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: 0x00));
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);
        ContractSelfCallResolver resolver = (method, argumentCount) =>
            method == "callee" && argumentCount == 0
                ? new ContractSelfCallTarget("callee", caller.Length, 0, HasReturnValue: false, Safe: false)
                : null;

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { SelfCallResolver = resolver }).Run();

        var state = result.FinalStates.Should().ContainSingle().Which;
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("ABORT");
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.ModeledSelfCall.Should().BeTrue();
    }

    [Fact]
    public void Callt_InvalidTokenCallFlags_Faults()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x33, 20).ToArray(),
            Method: "badFlags",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: 0x80));

        byte[] script =
        {
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("CALLT");
        state.TerminationReason.Should().Contain("call flags");
        state.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_PrivateTokenMethodName_Faults()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: Enumerable.Repeat((byte)0x44, 20).ToArray(),
            Method: "_private",
            ParametersCount: 0,
            HasReturnValue: false,
            CallFlags: 0x01));

        byte[] script =
        {
            (byte)NeoVm.OpCode.CALLT, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script).WithTokens(tokens);

        var result = new SymbolicEngine(program).Run();

        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("CALLT");
        state.TerminationReason.Should().Contain("private method");
        state.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Callt_NoTokens_StopsAsIncomplete()
    {
        // Without NEF MethodToken metadata, CALLT parameter count and return shape are unknown.
        byte[] script =
        {
            (byte)NeoVm.OpCode.CALLT, 0x05, 0x00,  // token index 5, doesn't exist
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Stopped);
        state.TerminationReason.Should().Contain("CALLT token #5 requires NEF MethodToken metadata");
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain("CALLT token #5");
        state.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void CallNative_UserContractDirectUseFaults()
    {
        uint syscall = SyscallRegistry.ComputeHash("System.Contract.CallNative");
        byte[] syscallBytes = System.BitConverter.GetBytes(syscall);
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.SYSCALL,
            syscallBytes[0],
            syscallBytes[1],
            syscallBytes[2],
            syscallBytes[3],
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Faulted);
        state.TerminationReason.Should().Contain("CallNative");
        state.Telemetry.ExternalCalls.Should().BeEmpty();
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

    private static byte[] Concat(params byte[][] parts)
    {
        int len = parts.Sum(p => p.Length);
        byte[] result = new byte[len];
        int offset = 0;
        foreach (var part in parts)
        {
            System.Array.Copy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }

    private static byte[] Pushdata1(byte[] data)
    {
        byte[] result = new byte[data.Length + 2];
        result[0] = (byte)NeoVm.OpCode.PUSHDATA1;
        result[1] = (byte)data.Length;
        System.Array.Copy(data, 0, result, 2, data.Length);
        return result;
    }

    private static byte[] PushInt32(int value) =>
        Concat(
            new[] { (byte)NeoVm.OpCode.PUSHINT32 },
            BitConverter.GetBytes(value));

    private static byte[] StdLibHashBytes() =>
        Convert.FromHexString("ACCE6FD80D44E1796AA0C2C625E9E4E0CE39EFC0");

    private static byte[] CryptoLibHashBytes() =>
        Convert.FromHexString("726CB6E0CD8628A1350A611384688911AB75F51B");

    private static byte[] NeoTokenHashBytes() =>
        Convert.FromHexString("EF4073A0F2B305A38EC4050E4D3D28BC40EA63F5");

    private static byte[] GasTokenHashBytes() =>
        Convert.FromHexString("D2A4CFF31913016155E38E474A2C06D08BE276CF");

    private static byte[] ContractManagementHashBytes() =>
        Convert.FromHexString("FFFDC93764DBADDD97C48F252A53EA4643FAA3FD");

    private static byte[] LedgerContractHashBytes() =>
        Convert.FromHexString("DA65B600F7124CE6C79950C1772A36403104F2BE");

    private static byte[] OracleContractHashBytes() =>
        Convert.FromHexString("FE924B7CFE89DDD271ABAF7210A80A7E11178758");

    private static byte[] ScriptHash(byte[] script)
    {
        byte[] sha256 = System.Security.Cryptography.SHA256.HashData(script);
        var digest = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
        digest.BlockUpdate(sha256, 0, sha256.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }

    private static MethodToken NeoToken(string method, ushort parametersCount) =>
        new(
            Hash: NeoTokenHashBytes(),
            Method: method,
            ParametersCount: parametersCount,
            HasReturnValue: true,
            CallFlags: 0x01);

    private static MethodToken ContractManagementToken(string method, ushort parametersCount) =>
        new(
            Hash: ContractManagementHashBytes(),
            Method: method,
            ParametersCount: parametersCount,
            HasReturnValue: true,
            CallFlags: 0x01);

    private static MethodToken LedgerToken(string method, ushort parametersCount) =>
        new(
            Hash: LedgerContractHashBytes(),
            Method: method,
            ParametersCount: parametersCount,
            HasReturnValue: true,
            CallFlags: 0x01);

    private static MethodToken GasToken(string method, ushort parametersCount) =>
        new(
            Hash: GasTokenHashBytes(),
            Method: method,
            ParametersCount: parametersCount,
            HasReturnValue: true,
            CallFlags: 0x01);

    private static MethodToken CryptoLibToken(string method, ushort parametersCount) =>
        new(
            Hash: CryptoLibHashBytes(),
            Method: method,
            ParametersCount: parametersCount,
            HasReturnValue: true,
            CallFlags: 0x01);

    private static byte[] Syscall(string name)
    {
        uint hash = SyscallRegistry.ComputeHash(name);
        byte[] bytes = BitConverter.GetBytes(hash);
        return new[] { (byte)NeoVm.OpCode.SYSCALL, bytes[0], bytes[1], bytes[2], bytes[3] };
    }

    private static byte[] Callt(ushort tokenIndex) =>
        new[]
        {
            (byte)NeoVm.OpCode.CALLT,
            (byte)(tokenIndex & 0xFF),
            (byte)(tokenIndex >> 8),
        };

    private const string BlsG1GeneratorHex =
        "97F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB";

    private const string BlsG2GeneratorHex =
        "93E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8";

    private const string BlsG1DoubleHex =
        "A572CBEA904D67468808C8EB50A9450C9721DB309128012543902D0AC358A62AE28F75BB8F1C7C42C39A8C5529BF0F4E";

    private const string BlsGtGeneratorPairingHex =
        "0F41E58663BF08CF068672CBD01A7EC73BACA4D72CA93544DEFF686BFD6DF543D48EAA24AFE47E1EFDE449383B67663104C581234D086A9902249B64728FFD21A189E87935A954051C7CDBA7B3872629A4FAFC05066245CB9108F0242D0FE3EF03350F55A7AEFCD3C31B4FCB6CE5771CC6A0E9786AB5973320C806AD360829107BA810C5A09FFDD9BE2291A0C25A99A211B8B424CD48BF38FCEF68083B0B0EC5C81A93B330EE1A677D0D15FF7B984E8978EF48881E32FAC91B93B47333E2BA5706FBA23EB7C5AF0D9F80940CA771B6FFD5857BAAF222EB95A7D2809D61BFE02E1BFD1B68FF02F0B8102AE1C2D5D5AB1A19F26337D205FB469CD6BD15C3D5A04DC88784FBB3D0B2DBDEA54D43B2B73F2CBB12D58386A8703E0F948226E47EE89D018107154F25A764BD3C79937A45B84546DA634B8F6BE14A8061E55CCEBA478B23F7DACAA35C8CA78BEAE9624045B4B601B2F522473D171391125BA84DC4007CFBF2F8DA752F7C74185203FCCA589AC719C34DFFBBAAD8431DAD1C1FB597AAA5193502B86EDB8857C273FA075A50512937E0794E1E65A7617C90D8BD66065B1FFFE51D7A579973B1315021EC3C19934F1368BB445C7C2D209703F239689CE34C0378A68E72A6B3B216DA0E22A5031B54DDFF57309396B38C881C4C849EC23E87089A1C5B46E5110B86750EC6A532348868A84045483C92B7AF5AF689452EAFABF1A8943E50439F1D59882A98EAA0170F1250EBD871FC0A92A7B2D83168D0D727272D441BEFA15C503DD8E90CE98DB3E7B6D194F60839C508A84305AACA1789B6";
}
