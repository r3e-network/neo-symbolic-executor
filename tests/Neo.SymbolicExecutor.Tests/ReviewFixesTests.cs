using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
using Neo.SymbolicExecutor.Smt;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Verification;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

public class ReviewFixesTests
{
    [Fact]
    public void SymbolicAssert_ConsumesExternalReturnOnBothBranches()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 16,
            Method = "transfer",
            HasReturnValue = true,
        });
        state.Push(SymbolicValue.Symbol(Sort.Bool, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.FinalStates.Should().HaveCount(2);
        result.FinalStates.SelectMany(s => s.Telemetry.ExternalCalls)
            .Should().OnlyContain(call => call.ReturnChecked);
        new UncheckedReturnDetector()
            .Analyze(new AnalysisContext { States = result.FinalStates })
            .Should().BeEmpty();
    }

    [Fact]
    public void IsNull_PreservesUnknownExternalReturnProvenance()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ISNULL,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Unknown, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().Expression.Should().Be(
            new UnaryExpr(Sort.Bool, "isnull", Expr.Sym(Sort.Unknown, "ext_ret_16")));
    }

    [Fact]
    public void IsNullAssert_ConsumesUnknownExternalReturn()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.ISNULL,
            (byte)NeoVm.OpCode.NOT,
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 16,
            Method = "transfer",
            HasReturnValue = true,
        });
        state.Push(SymbolicValue.Symbol(Sort.Unknown, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.FinalStates.SelectMany(s => s.Telemetry.ExternalCalls)
            .Should().OnlyContain(call => call.ReturnChecked);
        new UncheckedReturnDetector()
            .Analyze(new AnalysisContext { States = result.FinalStates })
            .Should().BeEmpty("ISNULL/NOT/ASSERT is a real nullable-return check");
    }

    [Fact]
    public void IsType_PreservesUnknownExternalReturnProvenance()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ISTYPE,
            SymbolicEngine.StackItemTypeCodes.ByteString,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Unknown, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().Expression.Should().Be(
            new UnaryExpr(Sort.Bool, "istype:28", Expr.Sym(Sort.Unknown, "ext_ret_16")));
    }

    [Fact]
    public void IsTypeAssert_ConsumesUnknownExternalReturn()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.ISTYPE,
            SymbolicEngine.StackItemTypeCodes.ByteString,
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 16,
            Method = "transfer",
            HasReturnValue = true,
        });
        state.Push(SymbolicValue.Symbol(Sort.Unknown, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.FinalStates.SelectMany(s => s.Telemetry.ExternalCalls)
            .Should().OnlyContain(call => call.ReturnChecked);
        new UncheckedReturnDetector()
            .Analyze(new AnalysisContext { States = result.FinalStates })
            .Should().BeEmpty("ISTYPE/ASSERT is a real external-return type check");
    }

    [Fact]
    public void IsTypeAssert_RefinesUnknownExternalReturnForIntegerConvert()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.ISTYPE,
            SymbolicEngine.StackItemTypeCodes.Integer,
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.CONVERT,
            SymbolicEngine.StackItemTypeCodes.Integer,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Unknown, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.Telemetry.FaultConditions.Should().BeEmpty();
        halted.EvaluationStack.Single().Expression.Should().Be(
            new BinaryExpr(Sort.Int, "+", Expr.Sym(Sort.Int, "ext_ret_16_as_int"), Expr.Int(1)));
        halted.PathConditions.Should().Contain(Expr.Ge(Expr.Sym(Sort.Int, "ext_ret_16_as_int"), Expr.Int(Expr.NeoVmIntegerMin)));
        halted.PathConditions.Should().Contain(Expr.Le(Expr.Sym(Sort.Int, "ext_ret_16_as_int"), Expr.Int(Expr.NeoVmIntegerMax)));
        result.Faulted.Should().ContainSingle("the failing ISTYPE assertion branch is still represented");
    }

    [Fact]
    public void Assert_PrunesUnsatisfiableFailureBranchWithSmt()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Bool, "ok"));
        var backend = new StubSmtBackend(expr => IsNotSymbol(expr, "ok") ? SmtOutcome.Unsat : SmtOutcome.Sat);

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { SmtBackend = backend }).Run(state);

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].PathConditions.Should().ContainSingle()
            .Which.Should().Be(Expr.Sym(Sort.Bool, "ok"));
    }

    [Theory]
    [InlineData("System.Runtime.CheckWitness")]
    [InlineData("System.Runtime.Notify")]
    [InlineData("System.Runtime.Log")]
    [InlineData("System.Runtime.GetNotifications")]
    [InlineData("System.Runtime.BurnGas")]
    [InlineData("System.Iterator.Next")]
    [InlineData("System.Iterator.Value")]
    [InlineData("System.Crypto.CheckSig")]
    [InlineData("System.Crypto.CheckMultisig")]
    [InlineData("System.Storage.AsReadOnly")]
    [InlineData("System.Storage.Local.Get")]
    [InlineData("System.Storage.Local.Put")]
    [InlineData("System.Storage.Local.Delete")]
    [InlineData("System.Storage.Local.Find")]
    [InlineData("System.Contract.CallNative")]
    public void ModeledSyscall_StackUnderflowFaults(string syscallName)
    {
        uint hash = SyscallRegistry.ComputeHash(syscallName);
        byte[] hashBytes = System.BitConverter.GetBytes(hash);
        byte[] script =
        {
            (byte)NeoVm.OpCode.SYSCALL,
            hashBytes[0],
            hashBytes[1],
            hashBytes[2],
            hashBytes[3],
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
        result.FinalStates[0].TerminationReason.Should().Contain("Stack underflow");
    }

    [Fact]
    public void Engine_ModelsStorageLocalPutGetAsCurrentContextStorage()
    {
        byte[] script = Concat(
            Pushdata1("owner"u8.ToArray()),
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Local.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.StorageOps.Select(op => op.Kind).Should()
            .Equal(StorageOpKind.Put, StorageOpKind.Get);
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal("alice"u8.ToArray(), "Storage.Local.Get should read path-local values written by Storage.Local.Put");
    }

    [Fact]
    public void Engine_UnknownSyscallHashStopsBeforeExecutingFollowingInstructions()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.SYSCALL,
            0xEF,
            0xBE,
            0xAD,
            0xDE,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var stopped = result.Stopped.Should().ContainSingle().Subject;
        stopped.Telemetry.UnknownSyscalls.Should().ContainSingle().Which.Should().Be(1);
        stopped.TerminationReason.Should().Contain("unknown syscall hash 0xDEADBEEF");
        stopped.EvaluationStack.Should().ContainSingle()
            .Which.AsConcreteInt().Should().Be(BigInteger.One);
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain("unknown syscall hash 0xDEADBEEF");
    }

    [Fact]
    public void Engine_NumericOpcodeFaultsOnConcreteByteStringOperandOverNeoVmIntegerLimit()
    {
        byte[] script = Concat(
            Pushdata1(Enumerable.Repeat((byte)0x01, 33).ToArray()),
            new[] { (byte)NeoVm.OpCode.SIGN, (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("SIGN");
        faulted.TerminationReason.Should().Contain("32");
    }

    [Fact]
    public void Engine_NumericOpcodeRecordsSymbolicByteStringIntegerInputFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SIGN,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Bytes, "data"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.Halted.Should().ContainSingle().Subject;
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SIGN");
        fault.FaultCondition.Should().Be(
            Expr.Gt(new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "data")), Expr.Int(32)));
        fault.Reason.Should().Contain("ByteString operand may exceed 32 bytes");
    }

    [Fact]
    public void Engine_NumericOpcodeRecordsOpenBufferIntegerInputFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SIGN,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        var runtimeLength = Expr.Sym(Sort.Int, "arg_buffer_size");
        var buffer = state.Heap.Allocate(id => new BufferObject(
            id,
            Array.Empty<Expression>(),
            isSymbolicOpen: true,
            minLength: 0,
            symbolicLength: runtimeLength));
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.Halted.Should().ContainSingle().Subject;
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SIGN");
        fault.FaultCondition.Should().Be(Expr.Gt(runtimeLength, Expr.Int(32)));
        fault.Reason.Should().Contain("Buffer operand may exceed 32 bytes");
    }

    [Theory]
    [InlineData(NeoVm.OpCode.SHL)]
    [InlineData(NeoVm.OpCode.SHR)]
    public void Engine_SymbolicZeroShiftBranchDoesNotPopMissingValue(NeoVm.OpCode opCode)
    {
        byte[] script =
        {
            (byte)opCode,
            (byte)NeoVm.OpCode.RET,
        };
        var shift = SymbolicValue.Symbol(Sort.Int, "shift");
        var state = NewState(pc: 0);
        state.Push(shift);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var zeroShift = Expr.NumEq(shift.Expression, Expr.Int(0));
        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Should().BeEmpty();
        halted.PathConditions.Should().Contain(zeroShift);

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("Stack underflow");
        faulted.PathConditions.Should().Contain(Expr.Not(zeroShift));
    }

    [Theory]
    [InlineData(NeoVm.OpCode.SHL, "<<")]
    [InlineData(NeoVm.OpCode.SHR, ">>")]
    public void Engine_SymbolicZeroShiftBranchLeavesValueOnStack(NeoVm.OpCode opCode, string expressionOp)
    {
        byte[] script =
        {
            (byte)opCode,
            (byte)NeoVm.OpCode.RET,
        };
        var value = SymbolicValue.Int(7);
        var shift = SymbolicValue.Symbol(Sort.Int, "shift");
        var state = NewState(pc: 0);
        state.Push(value);
        state.Push(shift);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var zeroShift = Expr.NumEq(shift.Expression, Expr.Int(0));
        result.Faulted.Should().BeEmpty();
        result.Halted.Should().HaveCount(2);

        var zeroState = result.Halted.Single(s => s.PathConditions.Contains(zeroShift));
        zeroState.EvaluationStack.Should().ContainSingle()
            .Which.Expression.Should().Be(value.Expression);

        var nonZeroState = result.Halted.Single(s => s.PathConditions.Contains(Expr.Not(zeroShift)));
        nonZeroState.EvaluationStack.Should().ContainSingle()
            .Which.Expression.Should().Be(new BinaryExpr(Sort.Int, expressionOp, value.Expression, shift.Expression));
    }

    [Fact]
    public void Engine_RepeatedStorageGetAtSameOffsetUsesDistinctUnknownValuesForDifferentKeys()
    {
        byte[] script = Concat(
            Pushdata1("a"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALL, (byte)0x08 },
            Pushdata1("b"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CALL, (byte)0x03 },
            new[] { (byte)NeoVm.OpCode.RET },
            Syscall("System.Storage.Local.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        program.Instructions.Single(i => i.Offset == 3).Target.Should().Be(11);
        program.Instructions.Single(i => i.Offset == 8).Target.Should().Be(11);
        var result = new SymbolicEngine(program).Run();

        var bothPresent = result.Halted.Should().Contain(s =>
            s.EvaluationStack.Count == 2
            && s.EvaluationStack.All(v => v.Sort == Sort.Bytes)).Subject;
        var names = bothPresent.EvaluationStack
            .Select(v => ((Symbol)v.Expression).Name)
            .ToArray();
        names.Should().Contain(new[] { "storage_value_11", "storage_value_11_1" });
        names.Should().OnlyHaveUniqueItems("different storage keys read at the same opcode must not alias");
        bothPresent.PathConditions.Should().Contain(Expr.Sym(Sort.Bool, "storage_exists_11"));
        bothPresent.PathConditions.Should().Contain(Expr.Sym(Sort.Bool, "storage_exists_11_1"));
    }

    [Fact]
    public void Engine_IteratorValuesOnlyCanExposePathLocalStorageLocalPut()
    {
        byte[] script = Concat(
            Pushdata1("acct:alice"u8.ToArray()),
            Pushdata1("100"u8.ToArray()),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("acct:"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH4 },
            Syscall("System.Storage.Local.Find"),
            IteratorValueAfterSuccessfulNextAndReturn());

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().HaveCount(3, "known path-local entries, unknown persisted entries, and exhausted iterators are all modeled");
        result.Faulted.Should().BeEmpty();
        var valueStates = result.Halted.Where(s => s.EvaluationStack.Count == 1).ToList();
        valueStates.Select(s => s.EvaluationStack.Single().AsConcreteBytes() is { } bytes
                ? Convert.ToHexString(bytes)
                : null)
            .Should().Contain(Convert.ToHexString("100"u8.ToArray()));
        valueStates.Should().Contain(s =>
            s.EvaluationStack.Single().Expression.FreeSymbols().Any(name =>
                name.StartsWith("iterator_value_", StringComparison.Ordinal)));
    }

    [Fact]
    public void Engine_IteratorKeysOnlyRemovePrefixCanExposePathLocalStorageKeySuffix()
    {
        byte[] script = Concat(
            Pushdata1("acct:alice"u8.ToArray()),
            Pushdata1("100"u8.ToArray()),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("acct:"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH3 },
            Syscall("System.Storage.Local.Find"),
            IteratorValueAfterSuccessfulNextAndReturn());

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().HaveCount(3);
        result.Faulted.Should().BeEmpty();
        var valueStates = result.Halted.Where(s => s.EvaluationStack.Count == 1).ToList();
        valueStates.Select(s => s.EvaluationStack.Single().AsConcreteBytes() is { } bytes
                ? Convert.ToHexString(bytes)
                : null)
            .Should().Contain(Convert.ToHexString("alice"u8.ToArray()));
        valueStates.Should().Contain(s =>
            s.EvaluationStack.Single().Expression.FreeSymbols().Any(name =>
                name.StartsWith("iterator_key_", StringComparison.Ordinal)));
    }

    [Fact]
    public void Engine_IteratorDeserializeValuesCanExposePathLocalSerializedStruct()
    {
        byte[] serializedStruct = Convert.FromHexString("41022805616C696365210164");
        byte[] script = Concat(
            Pushdata1("acct:alice"u8.ToArray()),
            Pushdata1(serializedStruct),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("acct:"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)0x0C },
            Syscall("System.Storage.Local.Find"),
            IteratorValueAfterSuccessfulNextAndReturn());

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().HaveCount(3);
        result.Faulted.Should().BeEmpty();
        var valueStates = result.Halted.Where(s => s.EvaluationStack.Count == 1).ToList();
        var known = valueStates.Single(state => state.EvaluationStack.Single().Sort == Sort.Struct);
        var structRef = known.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        var fields = known.Heap.Get<StructObject>(structRef.ObjectId).Fields;
        fields.Should().HaveCount(2);
        fields[0].AsConcreteBytes().Should().Equal("alice"u8.ToArray());
        fields[1].AsConcreteInt().Should().Be(new System.Numerics.BigInteger(100));
        valueStates.Any(state =>
            state.EvaluationStack.Single().Expression.FreeSymbols().Any(name =>
                name.StartsWith("iterator_value_", StringComparison.Ordinal))).Should().BeTrue();
    }

    [Fact]
    public void Engine_IteratorDeserializeValuesCanProjectSymbolicSerializedStackItemSummary()
    {
        byte[] callScript = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var serializeState = NewState(0);
        var structure = serializeState.Heap.NewStruct(new[]
        {
            SymbolicValue.Symbol(Sort.Bytes, "iterator_storage_value"),
            SymbolicValue.Int(42),
        });
        var serializeArgs = serializeState.Heap.NewArray(new[]
        {
            SymbolicValue.HeapRef(Sort.Struct, structure.Id),
        });
        serializeState.Push(SymbolicValue.Bytes(StdLibHashBytes()));
        serializeState.Push(SymbolicValue.Bytes("serialize"u8.ToArray()));
        serializeState.Push(SymbolicValue.Int(NeoCallFlags.ReadOnly));
        serializeState.Push(SymbolicValue.HeapRef(Sort.Array, serializeArgs.Id));

        var serializeResult = new SymbolicEngine(ScriptDecoder.Decode(callScript)).Run(serializeState);

        var serialized = serializeResult.Halted.Should().ContainSingle().Which;
        serialized.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var serializedValue = serialized.EvaluationStack.Should().ContainSingle().Which;
        serializedValue.Sort.Should().Be(Sort.Bytes);
        serializedValue.Expression.FreeSymbols().Should().Contain("iterator_storage_value");

        const int valuesOnlyDeserializeValues = (1 << 2) | (1 << 3);
        var valueScript = Concat(
            Syscall("System.Iterator.Value"),
            new[] { (byte)NeoVm.OpCode.RET });
        var iterator = SymbolicValue.Symbol(Sort.InteropInterface, "iterator_symbolic_serialized");
        ExecutionState NewIteratorState(int options)
        {
            var state = NewState(0);
            var entry = state.Heap.NewStruct(new[]
            {
                SymbolicValue.Bytes("acct:alice"u8.ToArray()),
                serializedValue,
            });
            state.InteropContext["iterator_current_entry:iterator_symbolic_serialized"] =
                SymbolicValue.HeapRef(Sort.Struct, entry.Id);
            state.InteropContext["iterator_options:iterator_symbolic_serialized"] =
                SymbolicValue.Int(options);
            state.Push(iterator);
            return state;
        }

        var valueResult = new SymbolicEngine(ScriptDecoder.Decode(valueScript)).Run(
            NewIteratorState(valuesOnlyDeserializeValues));

        var halted = valueResult.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var returnedRef = halted.EvaluationStack.Should().ContainSingle().Which.Expression
            .Should().BeOfType<HeapRef>().Which;
        returnedRef.RefSort.Should().Be(Sort.Struct);
        var fields = halted.Heap.Get<StructObject>(returnedRef.ObjectId).Fields;
        fields.Should().HaveCount(2);
        fields[0].Expression.FreeSymbols().Should().ContainSingle().Which.Should().Be("iterator_storage_value");
        fields[1].AsConcreteInt().Should().Be(new BigInteger(42));

        const int valuesOnlyDeserializeValuesPickField1 = valuesOnlyDeserializeValues | (1 << 5);
        var pickResult = new SymbolicEngine(ScriptDecoder.Decode(valueScript)).Run(
            NewIteratorState(valuesOnlyDeserializeValuesPickField1));

        var picked = pickResult.Halted.Should().ContainSingle().Which;
        picked.Telemetry.UnknownSyscalls.Should().BeEmpty();
        picked.EvaluationStack.Should().ContainSingle().Which.AsConcreteInt().Should().Be(new BigInteger(42));
    }

    [Fact]
    public void Engine_IteratorPickFieldCanExposePathLocalSerializedStructField()
    {
        byte[] serializedStruct = Convert.FromHexString("41022805616C696365210164");
        byte[] script = Concat(
            Pushdata1("acct:alice"u8.ToArray()),
            Pushdata1(serializedStruct),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("acct:"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)0x2C },
            Syscall("System.Storage.Local.Find"),
            IteratorValueAfterSuccessfulNextAndReturn());

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().HaveCount(3);
        result.Faulted.Should().BeEmpty();
        var valueStates = result.Halted.Where(s => s.EvaluationStack.Count == 1).ToList();
        valueStates.Select(state => state.EvaluationStack.Single().AsConcreteInt())
            .Should().Contain(new System.Numerics.BigInteger(100));
        valueStates.Any(state =>
            state.EvaluationStack.Single().Expression.FreeSymbols().Any(name =>
                name.StartsWith("iterator_value_", StringComparison.Ordinal))).Should().BeTrue();
    }

    [Fact]
    public void Engine_IteratorDeserializeValuesRejectsNonCanonicalSerializedVarIntAsIncomplete()
    {
        byte[] malformedStruct = Convert.FromHexString("410128FD0500616C696365");
        byte[] script = Concat(
            Pushdata1("acct:alice"u8.ToArray()),
            Pushdata1(malformedStruct),
            Syscall("System.Storage.Local.Put"),
            Pushdata1("acct:"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)0x0C },
            Syscall("System.Storage.Local.Find"),
            IteratorValueAfterSuccessfulNextAndReturn());

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().HaveCount(3);
        result.Faulted.Should().BeEmpty();
        var valueStates = result.Halted.Where(s => s.EvaluationStack.Count == 1).ToList();
        valueStates.Should().OnlyContain(state => state.EvaluationStack.Single().Sort == Sort.Unknown);
        valueStates.Should().OnlyContain(state => state.Telemetry.UnknownSyscalls.Count > 0);
    }

    [Fact]
    public void Engine_ContractCallStdLibSerializeModelsConcreteStackItem()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("serialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("alice"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal(Convert.FromHexString("2805616C696365"));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("serialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibDeserializeModelsConcreteStackItem()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("deserialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString("2805616C696365")),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("alice"u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("deserialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibSerializeDeserializeRoundTripsClosedSymbolicStruct()
    {
        byte[] callScript = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var serializeState = NewState(0);
        var structure = serializeState.Heap.NewStruct(new[]
        {
            SymbolicValue.Symbol(Sort.Bytes, "storage_value_k"),
            SymbolicValue.Int(7),
        });
        var serializeArgs = serializeState.Heap.NewArray(new[]
        {
            SymbolicValue.HeapRef(Sort.Struct, structure.Id),
        });
        serializeState.Push(SymbolicValue.Bytes(StdLibHashBytes()));
        serializeState.Push(SymbolicValue.Bytes("serialize"u8.ToArray()));
        serializeState.Push(SymbolicValue.Int(NeoCallFlags.ReadOnly));
        serializeState.Push(SymbolicValue.HeapRef(Sort.Array, serializeArgs.Id));

        var serializeResult = new SymbolicEngine(ScriptDecoder.Decode(callScript)).Run(serializeState);

        var serialized = serializeResult.Halted.Should().ContainSingle().Which;
        serialized.Telemetry.UnknownSyscalls.Should().BeEmpty();
        serialized.Telemetry.FaultConditions.Should().ContainSingle(condition =>
            condition.Operation == "StdLib.serialize"
            && condition.Reason.Contains("serialized size may exceed"));
        var serializeCall = serialized.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        serializeCall.Method.Should().Be("serialize");
        serializeCall.ReturnModeledNative.Should().BeTrue();
        var serializedValue = serialized.EvaluationStack.Should().ContainSingle().Which;
        serializedValue.Sort.Should().Be(Sort.Bytes);
        serializedValue.Expression.FreeSymbols().Should().Contain("storage_value_k");

        var deserializeState = NewState(0);
        var deserializeArgs = deserializeState.Heap.NewArray(new[] { serializedValue });
        deserializeState.Push(SymbolicValue.Bytes(StdLibHashBytes()));
        deserializeState.Push(SymbolicValue.Bytes("deserialize"u8.ToArray()));
        deserializeState.Push(SymbolicValue.Int(NeoCallFlags.ReadOnly));
        deserializeState.Push(SymbolicValue.HeapRef(Sort.Array, deserializeArgs.Id));

        var deserializeResult = new SymbolicEngine(ScriptDecoder.Decode(callScript)).Run(deserializeState);

        var deserialized = deserializeResult.Halted.Should().ContainSingle().Which;
        deserialized.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var deserializeCall = deserialized.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        deserializeCall.Method.Should().Be("deserialize");
        deserializeCall.ReturnModeledNative.Should().BeTrue();
        var returnedRef = deserialized.EvaluationStack.Should().ContainSingle().Which.Expression
            .Should().BeOfType<HeapRef>().Which;
        returnedRef.RefSort.Should().Be(Sort.Struct);
        var returnedFields = deserialized.Heap.Get<StructObject>(returnedRef.ObjectId).Fields;
        returnedFields.Should().HaveCount(2);
        returnedFields[0].Expression.FreeSymbols().Should().ContainSingle().Which.Should().Be("storage_value_k");
        returnedFields[1].AsConcreteInt().Should().Be(new System.Numerics.BigInteger(7));
    }

    [Fact]
    public void Engine_ContractCallStdLibJsonSerializeModelsConcreteUtf8StackItem()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("jsonSerialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("alice"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("\"alice\""u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("jsonSerialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibJsonDeserializeModelsConcreteUtf8StackItem()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("jsonDeserialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("\"alice\""u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("alice"u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("jsonDeserialize");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibJsonSerializeDeserializeRoundTripsClosedSymbolicArray()
    {
        byte[] callScript = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var serializeState = NewState(0);
        var array = serializeState.Heap.NewArray(new[]
        {
            SymbolicValue.Symbol(Sort.Bytes, "json_label"),
            SymbolicValue.Int(7),
        });
        var serializeArgs = serializeState.Heap.NewArray(new[]
        {
            SymbolicValue.HeapRef(Sort.Array, array.Id),
        });
        serializeState.Push(SymbolicValue.Bytes(StdLibHashBytes()));
        serializeState.Push(SymbolicValue.Bytes("jsonSerialize"u8.ToArray()));
        serializeState.Push(SymbolicValue.Int(NeoCallFlags.ReadOnly));
        serializeState.Push(SymbolicValue.HeapRef(Sort.Array, serializeArgs.Id));

        var serializeResult = new SymbolicEngine(ScriptDecoder.Decode(callScript)).Run(serializeState);

        var serialized = serializeResult.Halted.Should().ContainSingle().Which;
        serialized.Telemetry.UnknownSyscalls.Should().BeEmpty();
        serialized.Telemetry.FaultConditions.Should().Contain(condition =>
            condition.Operation == "StdLib.jsonSerialize"
            && condition.Reason.Contains("invalid strict UTF-8"));
        serialized.Telemetry.FaultConditions.Should().Contain(condition =>
            condition.Operation == "StdLib.jsonSerialize"
            && condition.Reason.Contains("JSON output size may exceed"));
        var serializeCall = serialized.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        serializeCall.Method.Should().Be("jsonSerialize");
        serializeCall.ReturnModeledNative.Should().BeTrue();
        var jsonValue = serialized.EvaluationStack.Should().ContainSingle().Which;
        jsonValue.Sort.Should().Be(Sort.Bytes);
        jsonValue.Expression.FreeSymbols().Should().Contain("json_label");

        var deserializeState = NewState(0);
        var deserializeArgs = deserializeState.Heap.NewArray(new[] { jsonValue });
        deserializeState.Push(SymbolicValue.Bytes(StdLibHashBytes()));
        deserializeState.Push(SymbolicValue.Bytes("jsonDeserialize"u8.ToArray()));
        deserializeState.Push(SymbolicValue.Int(NeoCallFlags.ReadOnly));
        deserializeState.Push(SymbolicValue.HeapRef(Sort.Array, deserializeArgs.Id));

        var deserializeResult = new SymbolicEngine(ScriptDecoder.Decode(callScript)).Run(deserializeState);

        var deserialized = deserializeResult.Halted.Should().ContainSingle().Which;
        deserialized.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var deserializeCall = deserialized.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        deserializeCall.Method.Should().Be("jsonDeserialize");
        deserializeCall.ReturnModeledNative.Should().BeTrue();
        var returnedRef = deserialized.EvaluationStack.Should().ContainSingle().Which.Expression
            .Should().BeOfType<HeapRef>().Which;
        returnedRef.RefSort.Should().Be(Sort.Array);
        var returnedItems = deserialized.Heap.Get<ArrayObject>(returnedRef.ObjectId).Items;
        returnedItems.Should().HaveCount(2);
        returnedItems[0].Expression.FreeSymbols().Should().ContainSingle().Which.Should().Be("json_label");
        returnedItems[1].AsConcreteInt().Should().Be(new System.Numerics.BigInteger(7));
    }

    [Fact]
    public void Engine_ContractCallStdLibItoaModelsConcreteBase16Integer()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("itoa"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)16 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)42 },
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("2a"u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("itoa");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibAtoiModelsConcreteBase16String()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("atoi"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)16 },
            Pushdata1("2a"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(42));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("atoi");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    // ---- Review-finding regression guards (2026-06 review fix pass) ----

    private static SymbolicValue StdLibAtoiBase16(string text)
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("atoi"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)16 },
            Pushdata1(System.Text.Encoding.UTF8.GetBytes(text)),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        return result.Halted.Should().ContainSingle().Which.EvaluationStack.Single();
    }

    [Fact]
    public void Engine_StdLibAtoiBase16UsesTwosComplement_FfIsNegativeOne()
    {
        // Review fix (#3): Neo's StdLib.Atoi(value,16) uses NumberStyles.AllowHexSpecifier
        // (two's-complement); the high bit of the leading hex nibble is a sign bit, so "ff" == -1.
        StdLibAtoiBase16("ff").AsConcreteInt().Should().Be(new BigInteger(-1));
        StdLibAtoiBase16("80").AsConcreteInt().Should().Be(new BigInteger(-128));
    }

    [Fact]
    public void Engine_StdLibAtoiBase16LeadingZeroIsPositive()
    {
        // A leading zero nibble keeps the sign bit clear: "0ff" == 255, "2a" == 42.
        StdLibAtoiBase16("0ff").AsConcreteInt().Should().Be(new BigInteger(255));
        StdLibAtoiBase16("2a").AsConcreteInt().Should().Be(new BigInteger(42));
    }

    private static ExecutionResult RunOpenCollectionOpcode(NeoVm.OpCode opcode, string abiType)
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)opcode,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("c", abiType) });
        return engine.Run(entry);
    }

    [Theory]
    [InlineData(NeoVm.OpCode.UNPACK, "Array", "UNPACK over open symbolic Array")]
    [InlineData(NeoVm.OpCode.POPITEM, "Array", "POPITEM over open symbolic collection")]
    [InlineData(NeoVm.OpCode.VALUES, "Map", "VALUES over open symbolic collection")]
    [InlineData(NeoVm.OpCode.KEYS, "Map", "KEYS over open symbolic Map")]
    [InlineData(NeoVm.OpCode.REVERSEITEMS, "Array", "REVERSEITEMS over open symbolic collection")]
    [InlineData(NeoVm.OpCode.CLEARITEMS, "Array", "CLEARITEMS over open symbolic collection")]
    public void Engine_LengthSensitiveOpcodeOverOpenCollectionMarksCoverageIncomplete(
        NeoVm.OpCode opcode, string abiType, string expectedReason)
    {
        // Review fix (#5/#6): these opcodes cannot soundly enumerate an open (unknown-length)
        // collection, so the engine terminates as a modeling limit (coverage incomplete) instead of
        // silently collapsing to the seeded prefix and (for the verifier) emitting an unsound Proved.
        var result = RunOpenCollectionOpcode(opcode, abiType);
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain(expectedReason);
        result.FinalStates.Should().OnlyContain(s => s.Status == TerminalStatus.Stopped);
    }

    [Theory]
    [InlineData(NeoVm.OpCode.LT)]
    [InlineData(NeoVm.OpCode.LE)]
    [InlineData(NeoVm.OpCode.GT)]
    [InlineData(NeoVm.OpCode.GE)]
    public void Engine_RelationalOperatorWithNullOperandPushesFalseAndDoesNotFault(NeoVm.OpCode op)
    {
        // Round-2 fix: real NeoVM HALTs and pushes False for LT/LE/GT/GE when either operand is Null
        // (verified by executing Neo.VM 3.9 `PUSHNULL PUSH1 <op>` -> HALT, result False). The engine
        // previously faulted on a Null relational operand, which unsoundly pruned the feasible
        // false-return path (a verifier proof that ignored it could be unsound).
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)op,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var result = engine.Run(engine.CreateMethodEntryState(0, parameters: null));
        result.Faulted.Should().BeEmpty("a Null relational operand pushes False in NeoVM rather than faulting");
        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBool().Should().BeFalse();
    }

    [Fact]
    public void Engine_ConvertOpenArrayToStructMarksCoverageIncomplete()
    {
        // Round-2 fix: CONVERT Array<->Struct over an open (symbolic-length) source would drop
        // IsSymbolicOpen and let a later SIZE/PICKITEM fold the seeded prefix to a concrete length
        // (false negative / unsound Proved), so the engine terminates as a modeling limit instead.
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT, SymbolicEngine.StackItemTypeCodes.Struct,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("c", "Array") });
        var result = engine.Run(entry);
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain("CONVERT over open symbolic Array of unknown length not modeled");
        result.FinalStates.Should().OnlyContain(s => s.Status == TerminalStatus.Stopped);
    }

    [Fact]
    public void Engine_CreateMultisigAccountOverOpenPublicKeyArrayMarksCoverageIncomplete()
    {
        // Round-2 fix: the seeded-prefix Items.Count of an open public-key array would drive the
        // MaxMultisigPublicKeys bound and the threshold-vs-count fault condition with a wrong length,
        // so the syscall terminates as a modeling limit when the key array is open.
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x01 },
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.LDARG0 },
            Syscall("System.Contract.CreateMultisigAccount"),
            new[] { (byte)NeoVm.OpCode.RET });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("keys", "Array") });
        var result = engine.Run(entry);
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain("CreateMultisigAccount over open symbolic public-key array");
        result.FinalStates.Should().OnlyContain(s => s.Status == TerminalStatus.Stopped);
    }

    private static ExecutionResult RunNoArgScript(params byte[] script)
    {
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        return engine.Run(engine.CreateMethodEntryState(0, parameters: null));
    }

    [Fact]
    public void Engine_EqualIntegerVsByteStringIsFalse()
    {
        // Round-3 audit fix: NeoVM's EQUAL is type-strict, so an Integer never equals a same-canonical
        // -bytes ByteString (verified on the real VM: Int(5) EQUAL Bytes([5]) -> False).
        var halted = RunNoArgScript(
            (byte)NeoVm.OpCode.PUSH5, (byte)NeoVm.OpCode.PUSHDATA1, 0x01, 0x05,
            (byte)NeoVm.OpCode.EQUAL, (byte)NeoVm.OpCode.RET).Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBool().Should().BeFalse();
    }

    [Fact]
    public void Engine_SizeOfNullFaults()
    {
        // Round-3 audit fix: NeoVM's SIZE faults (uncatchable) on Null (verified on the real VM).
        var result = RunNoArgScript((byte)NeoVm.OpCode.PUSHNULL, (byte)NeoVm.OpCode.SIZE, (byte)NeoVm.OpCode.RET);
        result.Faulted.Should().ContainSingle();
        result.Halted.Should().BeEmpty();
    }

    [Theory]
    [InlineData(NeoVm.OpCode.PUSHT)]
    [InlineData(NeoVm.OpCode.PUSHF)]
    public void Engine_SizeOfBooleanIsOne(NeoVm.OpCode push)
    {
        // Round-3 audit fix: a Boolean's primitive span is a single byte ([0x00]/[0x01]), so SIZE is 1
        // for both true and false (verified on the real VM).
        var halted = RunNoArgScript((byte)push, (byte)NeoVm.OpCode.SIZE, (byte)NeoVm.OpCode.RET)
            .Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(1));
    }

    [Fact]
    public void Engine_HasKeyNegativeIndexFaults()
    {
        // Round-3 audit fix: NeoVM's HASKEY faults (uncatchable) on a negative index (verified on the
        // real VM); it does not push false.
        var result = RunNoArgScript(
            (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.NEWARRAY, (byte)NeoVm.OpCode.PUSHM1,
            (byte)NeoVm.OpCode.HASKEY, (byte)NeoVm.OpCode.RET);
        result.Faulted.Should().ContainSingle();
    }

    [Fact]
    public void Engine_FallingOffScriptEndIsImplicitReturn()
    {
        // Round-3 audit fix: NeoVM performs an implicit RET when the program counter reaches the end of
        // the script — a clean HALT, not a fault (verified: `PUSH1` with no RET HALTs with 1).
        var halted = RunNoArgScript((byte)NeoVm.OpCode.PUSH1)
            .Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(1));
    }

    [Fact]
    public void Engine_MapByteStringKeyOver64BytesFaults()
    {
        // Round-3 audit fix: NeoVM faults on a Map key longer than 64 bytes (verified: a 65-byte key
        // faults, a 64-byte key succeeds).
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.NEWMAP, (byte)NeoVm.OpCode.DUP, (byte)NeoVm.OpCode.PUSHDATA1, (byte)65 },
            new byte[65],
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.SETITEM, (byte)NeoVm.OpCode.RET });
        RunNoArgScript(script).Faulted.Should().ContainSingle();
    }

    [Fact]
    public void Heap_StructCloneCopiesSharedSubStructIndependently()
    {
        // Round-3 audit fix: NeoVM's Struct.Clone copies each sub-struct independently (no
        // memoization), so a sub-struct shared by two fields becomes two DISTINCT copies. The prior
        // id-memoization aliased them, so a later mutation of one wrongly affected the other.
        var heap = new Heap();
        var t = heap.NewStruct(new[] { SymbolicValue.Int(42) });
        var tRef = SymbolicValue.HeapRef(Sort.Struct, t.Id);
        var s = heap.NewStruct(new[] { tRef, tRef });

        var cloneRef = heap.CloneStructValueForCollection(SymbolicValue.HeapRef(Sort.Struct, s.Id));
        var clone = heap.Get<StructObject>(cloneRef.Expression.Should().BeOfType<HeapRef>().Which.ObjectId);
        int field0Id = clone.Fields[0].Expression.Should().BeOfType<HeapRef>().Which.ObjectId;
        int field1Id = clone.Fields[1].Expression.Should().BeOfType<HeapRef>().Which.ObjectId;

        field0Id.Should().NotBe(field1Id, "NeoVM copies each shared sub-struct into a distinct object");
        heap.Get<StructObject>(field0Id).Fields[0] = SymbolicValue.Int(99);
        heap.Get<StructObject>(field1Id).Fields[0].AsConcreteInt().Should().Be(new BigInteger(42));
    }

    [Fact]
    public void Heap_StructCloneFaultsOnCircularStruct()
    {
        // Round-3 audit fix: without memoization a circular struct would loop forever; NeoVM bounds the
        // clone by MaxStackSize-1 subitems and faults ("Beyond struct subitem clone limits").
        var heap = new Heap();
        var s = heap.NewStruct();
        heap.Get<StructObject>(s.Id).Fields.Add(SymbolicValue.HeapRef(Sort.Struct, s.Id));

        var act = () => heap.CloneStructValueForCollection(SymbolicValue.HeapRef(Sort.Struct, s.Id));
        act.Should().Throw<VmFaultException>().WithMessage("*subitem clone limits*");
    }

    [Fact]
    public void Engine_NewBufferAboveBudgetBelowNeoVmLimitIsModelingLimit()
    {
        // Round-3 audit fix: a NEWBUFFER size between the 64 KiB materialization budget and NeoVM's
        // 1 MiB item limit succeeds on the real VM, so the engine flags coverage-incomplete (a modeling
        // limit), not a fault.
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.PUSHINT32 }, BitConverter.GetBytes(100_000),
            new[] { (byte)NeoVm.OpCode.NEWBUFFER, (byte)NeoVm.OpCode.RET });
        var result = RunNoArgScript(script);
        result.CoverageIncomplete.Should().BeTrue();
        result.Faulted.Should().BeEmpty();
    }

    [Fact]
    public void Engine_NewBufferAboveNeoVmItemLimitFaults()
    {
        // A size above NeoVM's real MaxItemSize (131070, verified against Neo.VM 3.10.0) faults. 200_000
        // is above 131070 but below the wrong 1 MiB the engine briefly used, so this pins the constant.
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.PUSHINT32 }, BitConverter.GetBytes(200_000),
            new[] { (byte)NeoVm.OpCode.NEWBUFFER, (byte)NeoVm.OpCode.RET });
        RunNoArgScript(script).Faulted.Should().ContainSingle();
    }

    [Fact]
    public void Engine_ShiftByOversizedCountFaultsEvenWithSymbolicValue()
    {
        // Round-3 audit fix: NeoVM validates the shift count before the value, so a concrete shift
        // greater than the 256 limit faults even when the value operand is symbolic.
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x01, (byte)NeoVm.OpCode.LDARG0 },
            new[] { (byte)NeoVm.OpCode.PUSHINT16, (byte)0x2C, (byte)0x01 }, // shift = 300
            new[] { (byte)NeoVm.OpCode.SHL, (byte)NeoVm.OpCode.RET });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("v", "Integer") });
        engine.Run(entry).Faulted.Should().ContainSingle();
    }

    [Fact]
    public void Engine_ByteStringOver32BytesAsBooleanFaults()
    {
        // Round-3 audit fix: NeoVM's ByteString.GetBoolean faults when the byte length exceeds 32, so a
        // >32-byte ByteString used in any boolean context (here NOT) faults (verified on the real VM).
        byte[] b33 = new byte[33]; b33[0] = 1;
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.PUSHDATA1, (byte)33 }, b33,
            new[] { (byte)NeoVm.OpCode.NOT, (byte)NeoVm.OpCode.RET });
        RunNoArgScript(script).Faulted.Should().ContainSingle();
    }

    [Fact]
    public void Engine_StoragePutAliasesPossiblyEqualCachedKey()
    {
        // Round-3 audit fix (#16): caching a Get of k1, then Put-ing a structurally-different but
        // possibly-runtime-equal key k2, must make a later Get(k1) conditional on k1 == k2 instead of
        // returning the stale cached value. The re-read therefore yields an ite(k1==k2, putValue, old).
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x02 },
            Syscall("System.Storage.GetContext"), new[] { (byte)NeoVm.OpCode.LDARG0 },
            Syscall("System.Storage.Get"), new[] { (byte)NeoVm.OpCode.DROP },
            Syscall("System.Storage.GetContext"),
            new[] { (byte)NeoVm.OpCode.LDARG1, (byte)NeoVm.OpCode.PUSHDATA1, (byte)0x01, (byte)0x2A },
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"), new[] { (byte)NeoVm.OpCode.LDARG0 },
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("k1", "ByteArray"),
            new ContractParameterDefinition("k2", "ByteArray"),
        });
        var result = engine.Run(entry);
        result.Halted.Should().NotBeEmpty();
        // The storage-exists state rewrites the cached k1 entry to ite(k1 == k2, putValue, oldValue);
        // the not-exists state (cached Null) takes the sound invalidation fallback. So at least one
        // halted state reflects the write conditionally instead of returning the stale cached value.
        result.Halted.Any(s => s.EvaluationStack.Single().Expression is TernaryExpr { Op: "ite" })
            .Should().BeTrue();
    }

    [Fact]
    public void Engine_ByteString32BytesAsBooleanIsOk()
    {
        // 32 bytes is within the GetBoolean limit, so no fault.
        byte[] b32 = new byte[32]; b32[0] = 1;
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.PUSHDATA1, (byte)32 }, b32,
            new[] { (byte)NeoVm.OpCode.NOT, (byte)NeoVm.OpCode.RET });
        RunNoArgScript(script).Halted.Should().ContainSingle();
    }

    [Fact]
    public void Engine_AppendOnOpenArrayGrowsModeledSize()
    {
        // Review fix (#2): APPEND on an open array increments OpenSizeOffset, so SIZE after APPEND is
        // array_size + 1 (a "+"-rooted expression), not the bare pre-append size symbol. Without the
        // fix, `arr.Count == oldLen + 1` would lower to S == S+1 (UNSAT) and prune the feasible path.
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH7,
            (byte)NeoVm.OpCode.APPEND,
            (byte)NeoVm.OpCode.SIZE,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("items", "Array") });
        var halted = engine.Run(entry).Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().Expression.Should().BeOfType<BinaryExpr>()
            .Which.Op.Should().Be("+");
    }

    [Fact]
    public void Engine_SizeOfOpenMapParameterIsSymbolicNotSeededCount()
    {
        // Round-2 fix: SIZE of an open (unknown-size) Map parameter must NOT return the seeded
        // materialized entry count (which would let `map.Count == N` fold to a concrete value and
        // prune feasible paths). TryOpenSequenceSize had no Map case, so SIZE fell through to
        // ConcreteSize and returned the seeded Entries.Count; ConcreteSize now returns null for all
        // open kinds, so SIZE yields a symbolic node instead.
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.SIZE,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[] { new ContractParameterDefinition("m", "Map") });
        var size = engine.Run(entry).Halted.Should().ContainSingle().Which.EvaluationStack.Single();
        size.AsConcreteInt().Should().BeNull("an open map has no concrete size");
        size.Expression.Should().BeOfType<UnaryExpr>().Which.Op.Should().Be("size");
    }

    [Fact]
    public void Engine_DoesNotPruneBranchWhenSmtReturnsUnknown()
    {
        // Review test-gap (#66): the over-approximation invariant requires pruning ONLY on UNSAT,
        // never on UNKNOWN. With a backend that returns Unknown for the failure branch, both the
        // passing and the ASSERT-faulting failing branches must be retained.
        byte[] script =
        {
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Bool, "ok"));
        var backend = new StubSmtBackend(_ => SmtOutcome.Unknown, _ => SmtOutcome.Unknown);

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { SmtBackend = backend }).Run(state);

        result.FinalStates.Should().HaveCount(2);
        result.FinalStates.Should().Contain(s => s.Status == TerminalStatus.Halted);
        result.FinalStates.Should().Contain(s => s.Status == TerminalStatus.Faulted);
    }

    [Fact]
    public void Engine_StepBudgetExhaustionMarksBudgetExceededAndTruncated()
    {
        // Review test-gap (#28): a run that exhausts the step budget must report BudgetExceeded and
        // mark its state Truncated, terminating Stopped (not Halted). The verifier's IncompleteReasons
        // consumes both BudgetExceeded and Telemetry.Truncated, so any proof over that method
        // downgrades to Incomplete rather than proving over a truncated exploration. (A budget stop is
        // deliberately excluded from the engine's CoverageIncomplete flag, which tracks non-budget
        // coverage gaps; BudgetExceeded is the budget signal.)
        byte[] script =
        {
            (byte)NeoVm.OpCode.JMP, 0x00, // relative +0 → unconditional self-loop
        };
        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { MaxSteps = 8 }).Run();

        result.BudgetExceeded.Should().BeTrue();
        result.FinalStates.Should().OnlyContain(s => s.Status == TerminalStatus.Stopped);
        result.FinalStates.Should().Contain(s => s.Telemetry.Truncated);
    }

    [Fact]
    public void Engine_ContractCallStdLibAtoiConcreteInvalidInputFaults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("atoi"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("not-int"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.atoi");
        faulted.TerminationReason.Should().Contain("valid base-10 integer");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallStdLibAtoiConcreteOverflowFaults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("atoi"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(System.Text.Encoding.UTF8.GetBytes(new string('9', 100))),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.atoi");
        faulted.TerminationReason.Should().Contain("NeoVM integer range");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallStdLibBase64EncodeModelsConcreteBytes()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("base64Encode"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("neo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("bmVv"u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("base64Encode");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibBase64DecodeModelsConcreteString()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("base64Decode"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("bmVv"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal("neo"u8.ToArray());
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("base64Decode");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibBase64DecodeConcreteInvalidInputFaults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("base64Decode"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("not-base64!"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.base64Decode");
        faulted.TerminationReason.Should().Contain("valid base64");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Theory]
    [InlineData("base58Encode", "6E656F", "65356838")]
    [InlineData("base58Decode", "65356838", "6E656F")]
    [InlineData("base58CheckEncode", "6E656F", "3542654E555565566E35")]
    [InlineData("base58CheckDecode", "3542654E555565566E35", "6E656F")]
    public void Engine_ContractCallStdLibBase58ModelsConcreteBytes(
        string method,
        string inputHex,
        string expectedHex)
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1(System.Text.Encoding.UTF8.GetBytes(method)),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString(inputHex)),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal(Convert.FromHexString(expectedHex));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibMemoryCompareModelsConcreteBytes()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("memoryCompare"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("aa"u8.ToArray()),
            Pushdata1("ab"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(1));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("memoryCompare");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibMemorySearchModelsConcreteBackwardBytes()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("memorySearch"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHT },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)5 },
            Pushdata1("ana"u8.ToArray()),
            Pushdata1("banana"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH4, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        // Round-2 fix: Neo's backward memorySearch is memory.AsSpan(0, start).LastIndexOf(value), so a
        // match must lie entirely within [0, start). In "banana" with start=5, "ana" fits only at
        // index 1 (1+3=4 <= 5); index 3 would extend to 6 > 5 and is excluded. Neo returns 1, not 3.
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(1));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("memorySearch");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibStrLenModelsConcreteUtf8ScalarCount()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("strLen"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString("41C3A3F09F9982")),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(3));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("strLen");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibStrLenConcreteInvalidUtf8Faults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("strLen"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString("FF")),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.strLen");
        faulted.TerminationReason.Should().Contain("strict UTF-8");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallStdLibStringSplitModelsConcreteUtf8Array()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("stringSplit"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHT },
            Pushdata1(","u8.ToArray()),
            Pushdata1("a,,b"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        var href = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        var array = halted.Heap.Get<ArrayObject>(href.ObjectId);
        array.Items.Select(item => item.AsConcreteBytes()).Should()
            .SatisfyRespectively(
                item => item.Should().Equal("a"u8.ToArray()),
                item => item.Should().Equal("b"u8.ToArray()));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("stringSplit");
        call.HasReturnValue.Should().BeTrue("modeled pure StdLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallStdLibStringSplitConcreteInvalidSeparatorUtf8Faults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("stringSplit"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHT },
            Pushdata1(Convert.FromHexString("FF")),
            Pushdata1("a,b"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.stringSplit");
        faulted.TerminationReason.Should().Contain("separator");
        faulted.TerminationReason.Should().Contain("strict UTF-8");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallStdLibMemorySearchConcreteInvalidStartFaults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("memorySearch"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHM1 },
            Pushdata1("a"u8.ToArray()),
            Pushdata1("abc"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.memorySearch");
        faulted.TerminationReason.Should().Contain("start");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallStdLibMemoryCompareConcreteOverMaxLengthFaults()
    {
        byte[] script = Concat(
            Pushdata1(StdLibHashBytes()),
            Pushdata1("memoryCompare"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Array.Empty<byte>()),
            PushData(Enumerable.Repeat((byte)0x41, 1025).ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("StdLib.memoryCompare");
        faulted.TerminationReason.Should().Contain("1024");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibSha256ModelsConcreteBytes()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("sha256"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1("neo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal(
            Convert.FromHexString("73EF176D9F12809E64363B2B5F4553ABECCA7AAE157327F190323CFA0E42C815"));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("sha256");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibMurmur32ConcreteInvalidSeedFaults()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("murmur32"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHM1 },
            Pushdata1("neo"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("CryptoLib.murmur32");
        faulted.TerminationReason.Should().Contain("uint32");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Theory]
    [InlineData("ripemd160", "098E87D8477D2279FF1CF6927A628C0F180E04EF", false)]
    [InlineData("keccak256", "D00D26E6BBB181308D622B89BEB026A4A9A5A80906AD56A318911E045FC4AFAF", false)]
    [InlineData("murmur32", "AF3A07FA", true)]
    public void Engine_ContractCallCryptoLibHashMethodsModelConcreteBytes(
        string method,
        string expectedHex,
        bool hasSeed)
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1(System.Text.Encoding.UTF8.GetBytes(method)),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            hasSeed
                ? new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)123 }
                : System.Array.Empty<byte>(),
            Pushdata1("neo"u8.ToArray()),
            hasSeed
                ? new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK }
                : new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBytes().Should().Equal(Convert.FromHexString(expectedHex));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Theory]
    [InlineData("sha256", 32, false)]
    [InlineData("ripemd160", 20, false)]
    [InlineData("keccak256", 32, false)]
    [InlineData("murmur32", 4, true)]
    public void Engine_ContractCallCryptoLibHashMethodsModelSymbolicBytesWithFixedLength(
        string method,
        int expectedLength,
        bool hasSeed)
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.DUP, (byte)NeoVm.OpCode.SIZE, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var payload = SymbolicValue.Symbol(Sort.Bytes, "payload");
        var args = state.Heap.NewArray(hasSeed
            ? new[] { payload, SymbolicValue.Int(123) }
            : new[] { payload });
        state.Push(SymbolicValue.Bytes(CryptoLibHashBytes()));
        state.Push(SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes(method)));
        state.Push(SymbolicValue.Int(NeoCallFlags.ReadStates));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        var hashValue = halted.EvaluationStack[0];
        hashValue.Sort.Should().Be(Sort.Bytes);
        hashValue.Expression.FreeSymbols().Should().Contain("payload");
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(expectedLength));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Theory]
    [InlineData("sha256", 32, false)]
    [InlineData("ripemd160", 20, false)]
    [InlineData("keccak256", 32, false)]
    [InlineData("murmur32", 4, true)]
    public void Engine_CalltCryptoLibHashMethodsModelSymbolicBytesWithFixedLength(
        string method,
        int expectedLength,
        bool hasSeed)
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: method,
            ParametersCount: hasSeed ? (ushort)2 : (ushort)1,
            HasReturnValue: true,
            CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.DUP, (byte)NeoVm.OpCode.SIZE, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var payload = SymbolicValue.Symbol(Sort.Bytes, "callt_payload");
        state.Push(payload);
        if (hasSeed)
            state.Push(SymbolicValue.Int(123));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        var hashValue = halted.EvaluationStack[0];
        hashValue.Sort.Should().Be(Sort.Bytes);
        hashValue.Expression.FreeSymbols().Should().Contain("callt_payload");
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(expectedLength));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be(method);
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibVerifyWithEd25519ModelsConcreteSignature()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("verifyWithEd25519"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString("E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B")),
            Pushdata1(Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")),
            Pushdata1(System.Array.Empty<byte>()),
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBool().Should().BeTrue();
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("verifyWithEd25519");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibVerifyWithEd25519ModelsSymbolicSignatureCheck()
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.ASSERT, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var message = SymbolicValue.Symbol(Sort.Bytes, "ed_message");
        var publicKey = SymbolicValue.Symbol(Sort.Bytes, "ed_pubkey");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "ed_signature");
        var args = state.Heap.NewArray(new[]
        {
            message,
            publicKey,
            signature,
        });
        state.Push(SymbolicValue.Bytes(CryptoLibHashBytes()));
        state.Push(SymbolicValue.Bytes("verifyWithEd25519"u8.ToArray()));
        state.Push(SymbolicValue.Int(NeoCallFlags.ReadStates));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.SignatureCheckOps.Should().ContainSingle().Which.Should().Match<SignatureCheckOp>(
            op => op.Offset == 0
                && op.PublicKeyOrKeys.Expression.Equals(publicKey.Expression)
                && op.SignatureOrSignatures.Expression.Equals(signature.Expression)
                && op.ResultSymbol == "sig_ok_0"
                && !op.IsMultisig);
        halted.Telemetry.SignatureCheckResultsEnforced.Should().Contain("sig_ok_0");
        halted.PathConditions.Should().Contain(Expr.Sym(Sort.Bool, "sig_ok_0"));
        halted.Telemetry.ExternalCalls.Should().ContainSingle().Which.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_CalltCryptoLibVerifyWithEd25519ModelsSymbolicSignatureCheck()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "verifyWithEd25519",
            ParametersCount: 3,
            HasReturnValue: true,
            CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.ASSERT, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var message = SymbolicValue.Symbol(Sort.Bytes, "callt_ed_message");
        var publicKey = SymbolicValue.Symbol(Sort.Bytes, "callt_ed_pubkey");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "callt_ed_signature");
        state.Push(message);
        state.Push(publicKey);
        state.Push(signature);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.SignatureCheckOps.Should().ContainSingle().Which.Should().Match<SignatureCheckOp>(
            op => op.Offset == 0
                && op.PublicKeyOrKeys.Expression.Equals(publicKey.Expression)
                && op.SignatureOrSignatures.Expression.Equals(signature.Expression)
                && op.ResultSymbol == "sig_ok_0"
                && !op.IsMultisig);
        halted.Telemetry.SignatureCheckResultsEnforced.Should().Contain("sig_ok_0");
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData(22, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED8", true)]
    [InlineData(23, "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "4497D608BA54548FE46C89E4E2B8D5D5B9EE8515AE40BF902D7171E8CDCED4306CBD0782AF220FF41990D3BC271535F65B05118E02F7683BDD1FCEB459176568", true)]
    [InlineData(122, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "97A4044840CC4A1CF31771B7ADE7401466269EEC1E7778FC9DCF49F6CB1F968D7448520369F03E466D8FDDB873E9C8A44675236958853C57E7A59861D4C83250", true)]
    [InlineData(123, "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "5B872BA92E1D39ACABC5C2B414A18537C65FA441252595BB887F1F071071A68FD73D814903CA970D4A19FBA0F3FEA987B63E39FF09169B4C6B1278B44899B863", true)]
    [InlineData(22, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED9", false)]
    public void Engine_ContractCallCryptoLibVerifyWithECDsaModelsConcreteSignature(
        int curveHash,
        string publicKeyHex,
        string signatureHex,
        bool expected)
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("verifyWithECDsa"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)curveHash },
            Pushdata1(Convert.FromHexString(signatureHex)),
            Pushdata1(Convert.FromHexString(publicKeyHex)),
            Pushdata1("neo-symbolic-executor"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH4, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().AsConcreteBool().Should().Be(expected);
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("verifyWithECDsa");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibVerifyWithECDsaConcreteInvalidCurveFaults()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("verifyWithECDsa"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHINT8, (byte)24 },
            Pushdata1(Convert.FromHexString("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED8")),
            Pushdata1(Convert.FromHexString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")),
            Pushdata1("neo-symbolic-executor"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH4, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.Halted.Should().BeEmpty();
        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("CryptoLib.verifyWithECDsa");
        faulted.TerminationReason.Should().Contain("curve");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibVerifyWithECDsaModelsSymbolicSignatureCheck()
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.ASSERT, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var message = SymbolicValue.Symbol(Sort.Bytes, "message");
        var publicKey = SymbolicValue.Symbol(Sort.Bytes, "pubkey");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "signature");
        var args = state.Heap.NewArray(new[]
        {
            message,
            publicKey,
            signature,
            SymbolicValue.Int(23),
        });
        state.Push(SymbolicValue.Bytes(CryptoLibHashBytes()));
        state.Push(SymbolicValue.Bytes("verifyWithECDsa"u8.ToArray()));
        state.Push(SymbolicValue.Int(NeoCallFlags.ReadStates));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.SignatureCheckOps.Should().ContainSingle().Which.Should().Match<SignatureCheckOp>(
            op => op.Offset == 0
                && op.PublicKeyOrKeys.Expression.Equals(publicKey.Expression)
                && op.SignatureOrSignatures.Expression.Equals(signature.Expression)
                && op.ResultSymbol == "sig_ok_0"
                && !op.IsMultisig);
        halted.Telemetry.SignatureCheckResultsEnforced.Should().Contain("sig_ok_0");
        halted.PathConditions.Should().Contain(Expr.Sym(Sort.Bool, "sig_ok_0"));
        halted.Telemetry.ExternalCalls.Should().ContainSingle().Which.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_CalltCryptoLibVerifyWithECDsaModelsSymbolicSignatureCheck()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "verifyWithECDsa",
            ParametersCount: 4,
            HasReturnValue: true,
            CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[] { (byte)NeoVm.OpCode.ASSERT, (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var message = SymbolicValue.Symbol(Sort.Bytes, "callt_message");
        var publicKey = SymbolicValue.Symbol(Sort.Bytes, "callt_pubkey");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "callt_signature");
        state.Push(message);
        state.Push(publicKey);
        state.Push(signature);
        state.Push(SymbolicValue.Int(23));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.SignatureCheckOps.Should().ContainSingle().Which.Should().Match<SignatureCheckOp>(
            op => op.Offset == 0
                && op.PublicKeyOrKeys.Expression.Equals(publicKey.Expression)
                && op.SignatureOrSignatures.Expression.Equals(signature.Expression)
                && op.ResultSymbol == "sig_ok_0"
                && !op.IsMultisig);
        halted.Telemetry.SignatureCheckResultsEnforced.Should().Contain("sig_ok_0");
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Theory]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED81B", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000CB2C41A74F0D72EFB85F016B0EBE6752F0E74B5A75319523E2A6E422676A0ED800", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("9394C0BF31A60A25CFE9067B4488B73856396C80B82281A9F9F2FDE8C4E0C000B4D3BE58B0F28D1047A0FE94F14198ABC9C7918C3A170B17DD2B7A6A68CC3269", "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("00", null)]
    public void Engine_ContractCallCryptoLibRecoverSecp256K1ModelsConcreteSignature(
        string signatureHex,
        string? expectedPublicKeyHex)
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("recoverSecp256K1"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString(signatureHex)),
            Pushdata1(Convert.FromHexString("533E60831C7DDFC12204218D58A6D785A3C32750EE4D98CAD7B954FE00A22AD1")),
            new[] { (byte)NeoVm.OpCode.PUSH2, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        if (expectedPublicKeyHex is null)
        {
            halted.EvaluationStack.Single().IsConcreteNull.Should().BeTrue();
        }
        else
        {
            halted.EvaluationStack.Single().AsConcreteBytes()
                .Should().Equal(Convert.FromHexString(expectedPublicKeyHex));
        }

        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("recoverSecp256K1");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibRecoverSecp256K1ModelsSymbolicNullablePublicKey()
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[]
            {
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.ISNULL,
                (byte)NeoVm.OpCode.NOT,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var messageHash = SymbolicValue.Symbol(Sort.Bytes, "recover_message_hash");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "recover_signature");
        var args = state.Heap.NewArray(new[]
        {
            messageHash,
            signature,
        });
        state.Push(SymbolicValue.Bytes(CryptoLibHashBytes()));
        state.Push(SymbolicValue.Bytes("recoverSecp256K1"u8.ToArray()));
        state.Push(SymbolicValue.Int(NeoCallFlags.ReadStates));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack[0].Expression.FreeSymbols().Should().Contain("recover_message_hash");
        halted.EvaluationStack[0].Expression.FreeSymbols().Should().Contain("recover_signature");
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(33));
        halted.Telemetry.FaultConditions.Should().Contain(fault =>
            fault.Reason.Contains("message hash length must be exactly 32 bytes", StringComparison.Ordinal));
        halted.Telemetry.FaultConditions.Should().Contain(fault =>
            fault.Reason.Contains("signature length must be 64 or 65 bytes", StringComparison.Ordinal));
        result.Faulted.Should().ContainSingle("the nullable recovery failure path is still represented");
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("recoverSecp256K1");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_CalltCryptoLibRecoverSecp256K1ModelsSymbolicNullablePublicKey()
    {
        var tokens = ImmutableArray.Create(new MethodToken(
            Hash: CryptoLibHashBytes(),
            Method: "recoverSecp256K1",
            ParametersCount: 2,
            HasReturnValue: true,
            CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.CALLT, (byte)0x00, (byte)0x00 },
            new[]
            {
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.ISNULL,
                (byte)NeoVm.OpCode.NOT,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var messageHash = SymbolicValue.Symbol(Sort.Bytes, "callt_recover_message_hash");
        var signature = SymbolicValue.Symbol(Sort.Bytes, "callt_recover_signature");
        state.Push(messageHash);
        state.Push(signature);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(33));
        result.Faulted.Should().ContainSingle("the nullable recovery failure path is still represented");
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("recoverSecp256K1");
        call.ReturnModeledNative.Should().BeTrue();
        call.ReturnValueDeclaredByMethodToken.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibBls12381DeserializeModelsConcreteG1Interop()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("bls12381Deserialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Which;
        var href = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        halted.Heap.Get(href.ObjectId).Sort.Should().Be(Sort.InteropInterface);
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("bls12381Deserialize");
        call.HasReturnValue.Should().BeTrue("modeled pure CryptoLib calls still return stack values");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibBls12381DeserializeConcreteInvalidInputFaults()
    {
        byte[] script = Concat(
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("bls12381Deserialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Enumerable.Repeat((byte)0x42, 47).ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("CryptoLib.bls12381Deserialize");
        faulted.TerminationReason.Should().Contain("48, 96, or 576");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ContractCallCryptoLibBls12381DeserializeModelsSymbolicInterop()
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });
        var state = NewState(0);
        var payload = SymbolicValue.Symbol(Sort.Bytes, "bls_payload");
        var args = state.Heap.NewArray(new[] { payload });
        state.Push(SymbolicValue.Bytes(CryptoLibHashBytes()));
        state.Push(SymbolicValue.Bytes("bls12381Deserialize"u8.ToArray()));
        state.Push(SymbolicValue.Int(NeoCallFlags.ReadStates));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var href = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        var interop = halted.Heap.Get<InteropObject>(href.ObjectId);
        interop.Kind.Should().Be("bls12381:any");
        halted.Telemetry.FaultConditions.Should().Contain(fault =>
            fault.Reason.Contains("BLS12-381 serialized input length must be 48, 96, or 576 bytes"));
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Which;
        call.Method.Should().Be("bls12381Deserialize");
        call.ReturnModeledNative.Should().BeTrue();
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381DeserializeSerializeModelsSymbolicPayload()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Serialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var payload = SymbolicValue.Symbol(Sort.Bytes, "callt_bls_payload");
        state.Push(payload);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Single().Expression.Should().Be(payload.Expression);
        halted.PathConditions.Should().Contain(Expr.NumEq(
            new UnaryExpr(Sort.Int, "size", payload.Expression),
            Expr.Int(48)));
        halted.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Serialize");
        halted.Telemetry.ExternalCalls.Should().OnlyContain(call => call.ReturnModeledNative);
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381DeserializeRecordsSymbolicEncodingFaultCondition()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var payload = SymbolicValue.Symbol(Sort.Bytes, "callt_bls_payload");
        state.Push(payload);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.FaultConditions.Should().Contain(fault =>
            fault.Operation == "CryptoLib.bls12381Deserialize"
            && fault.Reason.Contains("valid compressed G1", StringComparison.Ordinal)
            && fault.FaultCondition.FreeSymbols().Contains("callt_bls_payload"));
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381AddSerializesSymbolicG1Payload()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Add",
                ParametersCount: 2,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Serialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.INITSLOT,
                (byte)0x02,
                (byte)0x02,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC1,
                (byte)NeoVm.OpCode.LDLOC0,
                (byte)NeoVm.OpCode.LDLOC1,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x02,
                (byte)0x00,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var left = SymbolicValue.Symbol(Sort.Bytes, "left_g1");
        var right = SymbolicValue.Symbol(Sort.Bytes, "right_g1");
        state.Push(right);
        state.Push(left);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack[0].Expression.FreeSymbols().Should().Contain(new[] { "left_g1", "right_g1" });
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(48));
        halted.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Deserialize", "bls12381Add", "bls12381Serialize");
        halted.Telemetry.ExternalCalls.Should().OnlyContain(call => call.ReturnModeledNative);
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381MulSerializesSymbolicG1Payload()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Mul",
                ParametersCount: 3,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Serialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.INITSLOT,
                (byte)0x01,
                (byte)0x02,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)32,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.DROP,
                (byte)NeoVm.OpCode.LDLOC0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.PUSHF,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x02,
                (byte)0x00,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var point = SymbolicValue.Symbol(Sort.Bytes, "point_g1");
        var scalar = SymbolicValue.Symbol(Sort.Bytes, "scalar32");
        state.Push(scalar);
        state.Push(point);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack[0].Expression.FreeSymbols().Should().Contain(new[] { "point_g1", "scalar32" });
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(48));
        halted.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Mul", "bls12381Serialize");
        halted.Telemetry.ExternalCalls.Should().OnlyContain(call => call.ReturnModeledNative);
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381MulRecordsSymbolicScalarFaultCondition()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Mul",
                ParametersCount: 3,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            new[]
            {
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.SWAP,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)32,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.PUSHF,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var scalar = SymbolicValue.Symbol(Sort.Bytes, "callt_bls_scalar");
        state.Push(scalar);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.Telemetry.FaultConditions.Should().Contain(fault =>
            fault.Operation == "CryptoLib.bls12381Mul"
            && fault.Reason.Contains("valid BLS12-381 scalar", StringComparison.Ordinal)
            && fault.FaultCondition.FreeSymbols().Contains("callt_bls_scalar"));
    }

    [Fact]
    public void Engine_ContractCallCryptoLibBls12381MulConcreteInvalidScalarFaults()
    {
        byte[] invalidScalar = Enumerable.Repeat((byte)0xff, 32).ToArray();
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x01, (byte)0x00 },
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("bls12381Deserialize"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Pushdata1(Convert.FromHexString(BlsG1GeneratorHex)),
            new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.STLOC0 },
            Pushdata1(CryptoLibHashBytes()),
            Pushdata1("bls12381Mul"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            new[] { (byte)NeoVm.OpCode.PUSHF },
            Pushdata1(invalidScalar),
            new[] { (byte)NeoVm.OpCode.LDLOC0 },
            new[] { (byte)NeoVm.OpCode.PUSH3, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Which;
        faulted.TerminationReason.Should().Contain("CryptoLib.bls12381Mul");
        faulted.TerminationReason.Should().Contain("valid BLS12-381 scalar");
        faulted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381PairingSerializesSymbolicGtPayload()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Pairing",
                ParametersCount: 2,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Serialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.INITSLOT,
                (byte)0x02,
                (byte)0x02,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)96,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC1,
                (byte)NeoVm.OpCode.LDLOC0,
                (byte)NeoVm.OpCode.LDLOC1,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x02,
                (byte)0x00,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var g1 = SymbolicValue.Symbol(Sort.Bytes, "point_g1");
        var g2 = SymbolicValue.Symbol(Sort.Bytes, "point_g2");
        state.Push(g2);
        state.Push(g1);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack[0].Expression.FreeSymbols().Should().Contain(new[] { "point_g1", "point_g2" });
        halted.EvaluationStack[1].AsConcreteInt().Should().Be(new BigInteger(576));
        halted.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Deserialize", "bls12381Pairing", "bls12381Serialize");
        halted.Telemetry.ExternalCalls.Should().OnlyContain(call => call.ReturnModeledNative);
    }

    [Fact]
    public void Engine_CalltCryptoLibBls12381EqualKeepsDistinctSymbolicPayloadsSymbolic()
    {
        var tokens = ImmutableArray.Create(
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Deserialize",
                ParametersCount: 1,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates),
            new MethodToken(
                Hash: CryptoLibHashBytes(),
                Method: "bls12381Equal",
                ParametersCount: 2,
                HasReturnValue: true,
                CallFlags: NeoCallFlags.ReadStates));
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.INITSLOT,
                (byte)0x02,
                (byte)0x02,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.PUSHINT8,
                (byte)48,
                (byte)NeoVm.OpCode.NUMEQUAL,
                (byte)NeoVm.OpCode.ASSERT,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x00,
                (byte)0x00,
                (byte)NeoVm.OpCode.STLOC1,
                (byte)NeoVm.OpCode.LDLOC0,
                (byte)NeoVm.OpCode.LDLOC1,
                (byte)NeoVm.OpCode.CALLT,
                (byte)0x01,
                (byte)0x00,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(0);
        var left = SymbolicValue.Symbol(Sort.Bytes, "left_g1");
        var right = SymbolicValue.Symbol(Sort.Bytes, "right_g1");
        state.Push(right);
        state.Push(left);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script).WithTokens(tokens)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Which;
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
        var equality = halted.EvaluationStack.Should().ContainSingle().Subject;
        equality.Sort.Should().Be(Sort.Bool);
        equality.AsConcreteBool().Should().BeNull("two distinct symbolic BLS operands must not be collapsed to true");
        equality.Expression.Should().Be(Expr.Eq(left.Expression, right.Expression));
        halted.Telemetry.ExternalCalls.Select(call => call.Method)
            .Should().Equal("bls12381Deserialize", "bls12381Deserialize", "bls12381Equal");
        halted.Telemetry.ExternalCalls.Should().OnlyContain(call => call.ReturnModeledNative);
    }

    [Fact]
    public void Engine_GetCallFlagsReturnsCurrentContextFlags()
    {
        byte[] script = Concat(
            Syscall("System.Contract.GetCallFlags"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { InitialCallFlags = 0x05 }).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(new BigInteger(0x05));
    }

    [Fact]
    public void Engine_RuntimeLoadScriptExecutesConcreteNestedScript()
    {
        byte[] nestedScript =
        {
            (byte)NeoVm.OpCode.PUSH4,
            (byte)NeoVm.OpCode.RET,
        };
        byte[] script = Concat(
            Pushdata1(nestedScript),
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Runtime.LoadScript"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Should().ContainSingle()
            .Which.AsConcreteInt().Should().Be(new BigInteger(4));
        halted.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_RuntimeLoadScriptPassesArgumentsToConcreteNestedScript()
    {
        byte[] nestedScript =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.RET,
        };
        byte[] script = Concat(
            Pushdata1(nestedScript),
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            new[] { (byte)NeoVm.OpCode.PUSH7, (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Runtime.LoadScript"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Should().ContainSingle()
            .Which.AsConcreteInt().Should().Be(new BigInteger(7));
        halted.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_RuntimeLoadScriptSetsNestedCallingAndExecutingScriptHashes()
    {
        byte[] nestedScript = Concat(
            Syscall("System.Runtime.GetCallingScriptHash"),
            Syscall("System.Runtime.GetExecutingScriptHash"),
            new[] { (byte)NeoVm.OpCode.RET });
        byte[] script = Concat(
            Pushdata1(nestedScript),
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Runtime.LoadScript"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Should().HaveCount(2);
        halted.EvaluationStack[0].AsConcreteBytes().Should().Equal(ScriptHash(script));
        halted.EvaluationStack[1].AsConcreteBytes().Should().Equal(ScriptHash(nestedScript));
        halted.Telemetry.ExternalCalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_RuntimeGetNotificationsFiltersByNotificationScriptHash()
    {
        byte[] currentHash = Enumerable.Repeat((byte)0x11, 20).ToArray();
        byte[] otherHash = Enumerable.Repeat((byte)0x22, 20).ToArray();
        byte[] script = Concat(
            Pushdata1("Ping"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Runtime.Notify"),
            Pushdata1(otherHash),
            Syscall("System.Runtime.GetNotifications"),
            new[]
            {
                (byte)NeoVm.OpCode.SIZE,
                (byte)NeoVm.OpCode.RET,
            });
        var state = NewState(pc: 0);
        state.InteropContext["runtime:executing_script_hash"] = SymbolicValue.Bytes(currentHash);

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Should().ContainSingle()
            .Which.AsConcreteInt().Should().Be(BigInteger.Zero);
        halted.Telemetry.UnknownSyscalls.Should().BeEmpty();
    }

    [Fact]
    public void Engine_RuntimeNotifyRequiresAllowNotifyCallFlag()
    {
        byte[] script = Concat(
            Pushdata1("Ping"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
            Syscall("System.Runtime.Notify"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { InitialCallFlags = 0x05 }).Run();

        result.FinalStates.Should().ContainSingle();
        var faulted = result.FinalStates.Single();
        faulted.Status.Should().Be(TerminalStatus.Faulted);
        faulted.TerminationReason.Should().Contain("AllowNotify");
        faulted.Telemetry.Notifications.Should().BeEmpty();
    }

    [Fact]
    public void Engine_StoragePutRequiresWriteStatesCallFlag()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("key"u8.ToArray()),
            Pushdata1("value"u8.ToArray()),
            Syscall("System.Storage.Put"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { InitialCallFlags = 0x01 }).Run();

        result.FinalStates.Should().ContainSingle();
        var faulted = result.FinalStates.Single();
        faulted.Status.Should().Be(TerminalStatus.Faulted);
        faulted.TerminationReason.Should().Contain("WriteStates");
        faulted.Telemetry.StorageOps.Should().BeEmpty();
    }

    [Fact]
    public void Engine_BurnGasZeroFaults()
    {
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.PUSH0 },
            Syscall("System.Runtime.BurnGas"),
            new[] { (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
        result.FinalStates[0].TerminationReason.Should().Contain("BurnGas");
    }

    [Fact]
    public void DetectorEngine_ValidatesFindingsAgainstTheirSourcePathConditions()
    {
        var unsatState = NewState(pc: 0x10);
        unsatState.Path.Add(0x10);
        unsatState.PathConditions = ImmutableList.Create<Expression>(Expr.Sym(Sort.Bool, "impossible"));

        var satState = NewState(pc: 0x10);
        satState.Path.Add(0x10);
        satState.PathConditions = ImmutableList.Create<Expression>(Expr.Sym(Sort.Bool, "reachable"));

        var backend = new StubSmtBackend(
            expr => expr is Symbol { Name: "impossible" } ? SmtOutcome.Unsat : SmtOutcome.Sat,
            conditions => conditions.Any(c => c is Symbol { Name: "impossible" })
                ? SmtOutcome.Unsat
                : SmtOutcome.Sat);

        var findings = new DetectorEngine(new[] { new PathEchoDetector() }).Run(new AnalysisContext
        {
            States = new[] { unsatState, satState },
            SmtBackend = backend,
            DropUnsatFindings = true,
        });

        findings.Should().ContainSingle();
        findings[0].PathSatisfiable.Should().BeTrue();
    }

    [Fact]
    public void DetectorEngine_DoesNotDropStaticFindingsWithUnrelatedUnsatPath()
    {
        var unsatState = NewState(pc: 0x10);
        unsatState.Path.Add(0x10);
        unsatState.PathConditions = ImmutableList.Create<Expression>(Expr.Sym(Sort.Bool, "impossible"));

        var backend = new StubSmtBackend(
            _ => SmtOutcome.Unsat,
            conditions => conditions.Any(c => c is Symbol { Name: "impossible" })
                ? SmtOutcome.Unsat
                : SmtOutcome.Sat);

        var findings = new DetectorEngine(new[] { new StaticManifestDetector() }).Run(new AnalysisContext
        {
            States = new[] { unsatState },
            SmtBackend = backend,
            DropUnsatFindings = true,
        });

        findings.Should().ContainSingle("static manifest findings are not scoped to an execution path");
        findings[0].PathSatisfiable.Should().BeNull();
        findings[0].ConfidenceReason.Should().Contain("static rule");
    }

    [Fact]
    public void FuzzerWrapper_CapturesNonZeroWaitStatus()
    {
        string script = ReadRepoFile("scripts/run-fuzzer-forever.sh");

        script.Should().NotContain("wait $FUZZ_PID || true");
        script.Should().Contain("if wait \"$FUZZ_PID\"; then");
    }

    [Fact]
    public void DevPackTargets_MessageUsesNeoSymItemMetadata()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().NotContain("%(NefFile.");
        targets.Should().Contain("%(_NeoSymNefFile.Filename)");
    }

    [Fact]
    public void DevPackOutputDirDefaultIsDeferredUntilTargetsRun()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().NotContain("$(OutputPath)neo-sym/");
        targets.Should().Contain("<_NeoSymOutputDirRaw Condition=\"'$(NeoSymOutputDir)' == ''\">$(OutputPath)neo-sym/</_NeoSymOutputDirRaw>");
        targets.Should().Contain("<_NeoSymOutputDirRaw Condition=\"'$(NeoSymOutputDir)' != ''\">$(NeoSymOutputDir)</_NeoSymOutputDirRaw>");
        targets.Should().Contain("<_NeoSymOutputDir>$([MSBuild]::EnsureTrailingSlash('$(_NeoSymOutputDirRaw)'))</_NeoSymOutputDir>");
        targets.Should().Contain("&quot;$(_NeoSymOutputDir)%(_NeoSymNefFile.Filename)$(_NeoSymExtension)&quot;");
    }

    [Fact]
    public void DevPackTargets_PassesProjectSourceHintsByDefault()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().Contain("<NeoSymSourceDir Condition=\"'$(NeoSymSourceDir)' == ''\">$(MSBuildProjectDirectory)</NeoSymSourceDir>");
        targets.Should().Contain("<_NeoSymSourceFlag Condition=\"'$(NeoSymSourceDir)' != ''\"> --source &quot;$(NeoSymSourceDir)&quot;</_NeoSymSourceFlag>");
        // The Exec command must keep --source first, then --smt, then engine budgets, then the
        // gate flag last. Ordering matters because gate-failure exit codes only fire after the
        // analysis itself succeeded.
        targets.Should().Contain("$(_NeoSymSourceFlag)$(_NeoSymSmtFlag)$(_NeoSymSmtDropUnsatFlag)$(_NeoSymBudgetFlags)$(_NeoSymGateFlag)");
    }

    [Fact]
    public void DevPackTargets_WiresFailOnBudgetExceededIntoGateFlag()
    {
        // The CLI exposes --fail-on-budget-exceeded; the .targets file must surface it as an
        // MSBuild property so DevPack contracts can opt CI builds into incomplete-coverage
        // failures without wrapping the tool invocation by hand.
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().Contain(
            "<NeoSymFailOnBudgetExceeded Condition=\"'$(NeoSymFailOnBudgetExceeded)' == ''\">true</NeoSymFailOnBudgetExceeded>");
        targets.Should().Contain(
            "<_NeoSymGateBudgetFlag Condition=\"'$(NeoSymFailOnBudgetExceeded)' == 'true'\"> --fail-on-budget-exceeded</_NeoSymGateBudgetFlag>");
        targets.Should().Contain(
            "<_NeoSymGateFlag>$(_NeoSymGateSeverityFlag)$(_NeoSymGateBudgetFlag)$(_NeoSymGateCoverageFlag)</_NeoSymGateFlag>");
    }

    [Fact]
    public void DevPackTargets_WiresFailOnIncompleteCoverageIntoGateFlag()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().Contain(
            "<NeoSymFailOnIncompleteCoverage Condition=\"'$(NeoSymFailOnIncompleteCoverage)' == ''\">true</NeoSymFailOnIncompleteCoverage>");
        targets.Should().Contain(
            "<_NeoSymGateCoverageFlag Condition=\"'$(NeoSymFailOnIncompleteCoverage)' == 'true'\"> --fail-on-incomplete-coverage</_NeoSymGateCoverageFlag>");
        targets.Should().Contain(
            "<_NeoSymGateCoverageFlag Condition=\"'$(NeoSymFailOnIncompleteCoverage)' == 'false'\"> --allow-incomplete-coverage</_NeoSymGateCoverageFlag>");
        targets.Should().Contain(
            "<_NeoSymGateFlag>$(_NeoSymGateSeverityFlag)$(_NeoSymGateBudgetFlag)$(_NeoSymGateCoverageFlag)</_NeoSymGateFlag>");
    }

    [Fact]
    public void DevPackTargets_WiresMaxEntrypointsIntoAnalyzeAndVerify()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        props.Should().Contain("<NeoSymMaxEntrypoints Condition=\"'$(NeoSymMaxEntrypoints)' == ''\"></NeoSymMaxEntrypoints>");
        targets.Should().Contain("NeoSymMaxEntrypoints must be a positive integer.");
        targets.Should().Contain(
            "<_NeoSymMaxEntrypointsFlag Condition=\"'$(NeoSymMaxEntrypoints)' != ''\"> --max-entrypoints $(NeoSymMaxEntrypoints)</_NeoSymMaxEntrypointsFlag>");
        targets.Should().Contain("<_NeoSymBudgetFlags>$(_NeoSymMaxEntrypointsFlag)$(_NeoSymMaxPathsFlag)$(_NeoSymMaxStepsFlag)$(_NeoSymDeadlineFlag)</_NeoSymBudgetFlags>");
        readme.Should().Contain("`NeoSymMaxEntrypoints`");
        readme.Should().Contain("Manifest ABI entrypoint fanout cap");
    }

    [Fact]
    public void DevPackTargets_WiresSmtDropUnsatIntoCommandLine()
    {
        // The CLI exposes --smt-drop-unsat; without an MSBuild property, DevPack consumers had
        // to pass it manually. Now NeoSymSmtDropUnsat=true bound to NeoSymUseSmt=true threads
        // through into the analyze command line.
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().Contain(
            "<_NeoSymSmtDropUnsatFlag Condition=\"'$(NeoSymUseSmt)' == 'true' And '$(NeoSymSmtDropUnsat)' == 'true'\"> --smt-drop-unsat</_NeoSymSmtDropUnsatFlag>");
        targets.Should().Contain("$(_NeoSymSmtDropUnsatFlag)");
    }

    [Fact]
    public void DevPackTargets_UsesConfigurableNefDirectoryAndProjectBinScFallback()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().Contain("<_NeoSymNefFile Include=\"$([MSBuild]::EnsureTrailingSlash('$(NeoSymNefDir)'))*.nef\"");
        targets.Should().Contain("<_NeoSymPrimaryNefFile Include=\"$(OutputPath)sc/*.nef\"");
        targets.Should().Contain("<_NeoSymFallbackNefFile Include=\"$(MSBuildProjectDirectory)/bin/sc/*.nef\"");
        targets.Should().Contain("default NEF discovery found artifacts in both");
        targets.Should().Contain("neo-sym: no .nef artifacts found. Set NeoSymNefDir");
    }

    [Fact]
    public void DevPackTargets_FailsClosedWhenNoNefArtifactsAreFound()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        props.Should().Contain("<NeoSymRequireArtifacts Condition=\"'$(NeoSymRequireArtifacts)' == ''\">true</NeoSymRequireArtifacts>");
        targets.Should().Contain("<Error Text=\"neo-sym: no .nef artifacts found. Set NeoSymNefDir");
        targets.Should().Contain("Condition=\"'@(_NeoSymNefFile)' == '' And '$(NeoSymRequireArtifacts)' != 'false'\"");
        targets.Should().Contain("<Warning Text=\"neo-sym: no .nef artifacts found. Set NeoSymNefDir");
        targets.Should().Contain("Condition=\"'@(_NeoSymNefFile)' == '' And '$(NeoSymRequireArtifacts)' == 'false'\"");
        readme.Should().Contain("`NeoSymRequireArtifacts`");
        readme.Should().Contain("Build fails when no `.nef` artifact is found");
        readme.Should().Contain("<NeoSymRequireArtifacts>true</NeoSymRequireArtifacts>");
    }

    [Fact]
    public void DevPackTargets_WiresFormalVerificationIntoBuild()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        props.Should().Contain("<NeoSymVerifyEnabled Condition=\"'$(NeoSymVerifyEnabled)' == ''\">true</NeoSymVerifyEnabled>");
        props.Should().Contain("<NeoSymVerifyProfile Condition=\"'$(NeoSymVerifyProfile)' == ''\">neo-n3-security</NeoSymVerifyProfile>");
        props.Should().Contain("<NeoSymVerifyDependencyProofSummaries Condition=\"'$(NeoSymVerifyDependencyProofSummaries)' == ''\"></NeoSymVerifyDependencyProofSummaries>");
        props.Should().Contain("<NeoSymVerifyDependencyProofArtifacts Condition=\"'$(NeoSymVerifyDependencyProofArtifacts)' == ''\"></NeoSymVerifyDependencyProofArtifacts>");
        props.Should().Contain("<NeoSymVerifyTrustDependencyProofSummaries Condition=\"'$(NeoSymVerifyTrustDependencyProofSummaries)' == ''\">false</NeoSymVerifyTrustDependencyProofSummaries>");
        props.Should().Contain("<NeoSymVerifyAllowUnboundDependencyProofSummaries Condition=\"'$(NeoSymVerifyAllowUnboundDependencyProofSummaries)' == ''\">false</NeoSymVerifyAllowUnboundDependencyProofSummaries>");
        props.Should().Contain("<NeoSymVerifyEmitDependencyProofSummary Condition=\"'$(NeoSymVerifyEmitDependencyProofSummary)' == ''\"></NeoSymVerifyEmitDependencyProofSummary>");
        props.Should().Contain("<NeoSymVerifyRequireUnqualifiedProofs Condition=\"'$(NeoSymVerifyRequireUnqualifiedProofs)' == ''\">true</NeoSymVerifyRequireUnqualifiedProofs>");
        props.Should().Contain("<NeoSymVerifyAllowAssumptionBackedProofs Condition=\"'$(NeoSymVerifyAllowAssumptionBackedProofs)' == ''\">false</NeoSymVerifyAllowAssumptionBackedProofs>");
        targets.Should().Contain("<_NeoSymVerifySpecFlag Condition=\"'$(NeoSymVerifySpec)' != ''\"> --spec &quot;$(NeoSymVerifySpec)&quot;</_NeoSymVerifySpecFlag>");
        targets.Should().Contain("<_NeoSymVerifyProfileFlag Condition=\"'$(NeoSymVerifyProfile)' != ''\"> --profile &quot;$(NeoSymVerifyProfile)&quot;</_NeoSymVerifyProfileFlag>");
        targets.Should().NotContain(" --profile $(NeoSymVerifyProfile)");
        targets.Should().Contain("<_NeoSymDependencyProofSummary Include=\"$(NeoSymVerifyDependencyProofSummaries)\"");
        targets.Should().Contain("<_NeoSymDependencyProofArtifact Include=\"$(NeoSymVerifyDependencyProofArtifacts)\"");
        targets.Should().Contain("--dependency-proof-summary");
        targets.Should().Contain("--dependency-proof-artifact");
        targets.Should().Contain("--trust-dependency-proof-summaries");
        targets.Should().Contain("--allow-unbound-dependency-proof-summaries");
        targets.Should().Contain("--emit-dependency-proof-summary");
        targets.Should().Contain("<_NeoSymNefFileCount>@(_NeoSymNefFile->Count())</_NeoSymNefFileCount>");
        targets.Should().Contain("NeoSymVerifyEmitDependencyProofSummary can only be used when exactly one .nef artifact is discovered");
        targets.Should().Contain("<_NeoSymVerifyAllowUnprovedFlag Condition=\"'$(NeoSymVerifyAllowUnproved)' == 'true'\"> --allow-unproved</_NeoSymVerifyAllowUnprovedFlag>");
        targets.Should().Contain("<_NeoSymVerifyRequireExternalSmtFlag Condition=\"'$(NeoSymVerifyRequireExternalSmt)' == 'true'\"> --require-external-smt</_NeoSymVerifyRequireExternalSmtFlag>");
        targets.Should().Contain("<_NeoSymVerifyRequireUnqualifiedProofsFlag Condition=\"'$(NeoSymVerifyRequireUnqualifiedProofs)' == 'true'\"> --require-unqualified-proofs</_NeoSymVerifyRequireUnqualifiedProofsFlag>");
        targets.Should().Contain("<_NeoSymVerifyAllowAssumptionBackedProofsFlag Condition=\"'$(NeoSymVerifyAllowAssumptionBackedProofs)' == 'true'\"> --allow-assumption-backed-proofs</_NeoSymVerifyAllowAssumptionBackedProofsFlag>");
        targets.Should().Contain("$(_NeoSymVerifyRequireUnqualifiedProofsFlag)");
        targets.Should().Contain("$(_NeoSymVerifyAllowAssumptionBackedProofsFlag)");
        targets.Should().Contain("Condition=\"'@(_NeoSymNefFile)' != '' And '$(NeoSymVerifyEnabled)' == 'true'\"");
        targets.Should().Contain(" verify &quot;%(_NeoSymNefFile.FullPath)&quot; --manifest");
        targets.Should().Contain("%(_NeoSymNefFile.Filename).verify$(_NeoSymExtension)");
        targets.Should().Contain("IgnoreExitCode=\"true\"");
        targets.Should().Contain("Reports were written before failing the build.");
        readme.Should().Contain("`NeoSymVerifyRequireUnqualifiedProofs`");
        readme.Should().Contain("`NeoSymVerifyAllowAssumptionBackedProofs`");
        readme.Should().Contain("`NeoSymVerifyEnabled`");
        readme.Should().Contain("`NeoSymVerifyDependencyProofSummaries`");
        readme.Should().Contain("`NeoSymVerifyDependencyProofArtifacts`");
        readme.Should().Contain("`NeoSymVerifyTrustDependencyProofSummaries`");
        readme.Should().Contain("`NeoSymVerifyEmitDependencyProofSummary`");
        readme.Should().Contain("valid only when exactly one `.nef` artifact is discovered");
        readme.Should().Contain("`neo-n3-security` proof profile runs by default");
        readme.Should().Contain("explicit assumptions");
        readme.Should().Contain("the MSBuild target still writes `<contract>.verify.md` or `<contract>.verify.json`");
        readme.Should().Contain("both the detector report and the proof report");
    }

    [Fact]
    public void DevPackTargets_FailsClosedWhenVerifyEnabledWithoutProfileOrSpec()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        targets.Should().Contain("NeoSymVerifyEnabled=true requires NeoSymVerifyProfile or NeoSymVerifySpec");
        targets.Should().Contain("Set NeoSymVerifyEnabled=false for analyze-only builds.");
        targets.Should().NotContain("And ('$(NeoSymVerifySpec)' != '' Or '$(NeoSymVerifyProfile)' != '')");
        readme.Should().Contain("If `NeoSymVerifyEnabled=true`, either `NeoSymVerifyProfile` or `NeoSymVerifySpec` must be set");
    }

    [Fact]
    public void DevPackTargets_RejectsMalformedBooleanProperties()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        props.Should().Contain("<NeoSymSmtDropUnsat Condition=\"'$(NeoSymSmtDropUnsat)' == ''\">false</NeoSymSmtDropUnsat>");
        props.Should().Contain("<NeoSymVerifyAllowUnproved Condition=\"'$(NeoSymVerifyAllowUnproved)' == ''\">false</NeoSymVerifyAllowUnproved>");
        props.Should().Contain("<NeoSymVerifyRequireExternalSmt Condition=\"'$(NeoSymVerifyRequireExternalSmt)' == ''\">false</NeoSymVerifyRequireExternalSmt>");

        string[] boolProperties =
        {
            "NeoSymEnabled",
            "NeoSymFailOnIncompleteCoverage",
            "NeoSymFailOnBudgetExceeded",
            "NeoSymRequireArtifacts",
            "NeoSymUseSmt",
            "NeoSymSmtDropUnsat",
            "NeoSymVerifyEnabled",
            "NeoSymVerifyAllowUnproved",
            "NeoSymVerifyRequireExternalSmt",
            "NeoSymVerifyTrustDependencyProofSummaries",
            "NeoSymVerifyAllowUnboundDependencyProofSummaries",
            "NeoSymVerifyRequireUnqualifiedProofs",
            "NeoSymVerifyAllowAssumptionBackedProofs",
        };

        foreach (string property in boolProperties)
        {
            targets.Should().Contain($"{property} must be true or false.");
            targets.Should().Contain($"Condition=\"'$({property})' != 'true' And '$({property})' != 'false'\"");
        }

        readme.Should().Contain("Boolean properties must be exactly `true` or `false`");
    }

    [Fact]
    public void DevPackTargets_AggregatesBatchedExitCodesAcrossAllNefArtifacts()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().Contain("<Output TaskParameter=\"ExitCode\" ItemName=\"_NeoSymAnalyzeExitCode\" />");
        targets.Should().Contain("<Output TaskParameter=\"ExitCode\" ItemName=\"_NeoSymVerifyExitCode\" />");
        targets.Should().NotContain("PropertyName=\"_NeoSymAnalyzeExitCode\"");
        targets.Should().NotContain("PropertyName=\"_NeoSymVerifyExitCode\"");
        targets.Should().Contain("neo-sym analyze failed with exit code(s)");
        targets.Should().Contain("neo-sym verify failed with exit code(s)");
    }

    [Fact]
    public void DevPackTargets_WiresDeploySenderHashIntoFormalVerification()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");
        string readme = ReadRepoFile("devpack-integration/README.md");

        props.Should().Contain("<NeoSymDeploySenderHash Condition=\"'$(NeoSymDeploySenderHash)' == ''\"></NeoSymDeploySenderHash>");
        targets.Should().Contain("NeoSymDeploySenderHash must be a 20-byte UInt160 hex string.");
        targets.Should().Contain("<_NeoSymVerifyDeploySenderHashFlag Condition=\"'$(NeoSymDeploySenderHash)' != ''\"> --deploy-sender-hash &quot;$(NeoSymDeploySenderHash)&quot;</_NeoSymVerifyDeploySenderHashFlag>");
        targets.Should().Contain("$(_NeoSymVerifyDeploySenderHashFlag)");
        readme.Should().Contain("`NeoSymDeploySenderHash`");
        readme.Should().Contain("Passes `--deploy-sender-hash` to formal verification");
        readme.Should().Contain("required for the default proof gate to pass");
        readme.Should().Contain("records `security.contract_identity.*` as incomplete");
        readme.Should().Contain("Neo N3 contract hashes depend");
    }

    [Fact]
    public void DevPackTargets_RejectsUnsafeVerifyProfileProperty()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().Contain("NeoSymVerifyProfile must be empty or a single profile identifier.");
        targets.Should().Contain("Regex]::IsMatch('$(NeoSymVerifyProfile)', '^[A-Za-z0-9_.-]+$')");
    }

    [Fact]
    public void CliPackage_PacksDevPackBuildTransitiveAssets()
    {
        string project = ReadRepoFile("src/Neo.SymbolicExecutor.Cli/Neo.SymbolicExecutor.Cli.csproj");

        project.Should().Contain("PackagePath=\"buildTransitive\\Neo.SymbolicExecutor.Cli.props\"");
        project.Should().Contain("PackagePath=\"buildTransitive\\Neo.SymbolicExecutor.Cli.targets\"");
        project.Should().Contain("..\\..\\devpack-integration\\Neo.SymbolicExecutor.props");
        project.Should().Contain("..\\..\\devpack-integration\\Neo.SymbolicExecutor.targets");
    }

    [Fact]
    public void DevPackTargets_E2eRunsAnalyzeAndDefaultSecurityProfileVerifyAgainstNefAndManifest()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            const string deploySender = "0102030405060708090a0b0c0d0e0f1011121314";
            Directory.CreateDirectory(scDir);
            File.WriteAllBytes(
                Path.Combine(scDir, "Contract.nef"),
                BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
            File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            string toolPath = WriteNeoSymToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add($"/p:NeoSymDeploySenderHash={deploySender}");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().Be(0, stdout + stderr);
            string reportPath = Path.Combine(reportDir, "Contract.json");
            File.Exists(reportPath).Should().BeTrue(stdout + stderr);
            var report = JsonNode.Parse(File.ReadAllText(reportPath))!;
            report["meta"]!["coverage_incomplete"]!.GetValue<bool>().Should().BeFalse();
            report["findings"]!.AsArray().Should().BeEmpty();

            string verifyReportPath = Path.Combine(reportDir, "Contract.verify.json");
            File.Exists(verifyReportPath).Should().BeTrue("DevPack builds must run the default Neo N3 security proof profile: " + stdout + stderr);
            var verifyReport = JsonNode.Parse(File.ReadAllText(verifyReportPath))!;
            verifyReport["meta"]!["profiles"]!.AsArray()
                .Select(profile => profile!.GetValue<string>())
                .Should().Contain("neo-n3-security");
            verifyReport["results"]!.AsArray()
                .Select(result => result!["source_profile"]?.GetValue<string>())
                .Should().Contain("neo-n3-security");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eCanDisableDefaultFormalVerification()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            File.WriteAllBytes(
                Path.Combine(scDir, "Contract.nef"),
                BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
            File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            string toolPath = WriteNeoSymToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add("/p:NeoSymVerifyEnabled=false");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().Be(0, stdout + stderr);
            File.Exists(Path.Combine(reportDir, "Contract.json")).Should().BeTrue(stdout + stderr);
            File.Exists(Path.Combine(reportDir, "Contract.verify.json"))
                .Should().BeFalse("NeoSymVerifyEnabled=false is the explicit analyze-only escape hatch");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eFailsClosedWhenVerifyEnabledButNoProfileOrSpec()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            File.WriteAllBytes(
                Path.Combine(scDir, "Contract.nef"),
                BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
            File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            string toolPath = WriteNeoSymToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add("/p:NeoSymVerifyProfile=");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "proof-enabled builds must not silently skip verification when no profile/spec is configured");
            (stdout + stderr).Should().Contain("NeoSymVerifyEnabled=true requires NeoSymVerifyProfile or NeoSymVerifySpec");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eRejectsMalformedVerifyBooleanProperty()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            File.WriteAllBytes(
                Path.Combine(scDir, "Contract.nef"),
                BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
            File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            string toolPath = WriteNeoSymToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add("/p:NeoSymVerifyEnabled=false");
            psi.ArgumentList.Add("/p:NeoSymVerifyRequireExternalSmt=treu");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "misspelled boolean gate properties must not be silently treated as false");
            (stdout + stderr).Should().Contain("NeoSymVerifyRequireExternalSmt must be true or false.");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eDoesNotLoseEarlierAnalyzeExitCodeAcrossMultipleNefs()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            foreach (string contract in new[] { "00Fail", "99Pass" })
            {
                File.WriteAllBytes(
                    Path.Combine(scDir, contract + ".nef"),
                    BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
                File.WriteAllText(Path.Combine(scDir, contract + ".manifest.json"), $$"""
                    {
                      "name":"{{contract}}",
                      "groups":[],
                      "features":{},
                      "supportedstandards":[],
                      "abi":{
                        "methods":[
                          {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                        ],
                        "events":[]
                      },
                      "permissions":[],
                      "trusts":[]
                    }
                    """);
            }

            string toolPath = WriteNeoSymFailNamedAnalyzeToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add("/p:NeoSymVerifyEnabled=false");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "a later successful NEF must not overwrite an earlier failing analyze exit code");
            File.Exists(Path.Combine(reportDir, "00Fail.json")).Should().BeTrue(stdout + stderr);
            File.Exists(Path.Combine(reportDir, "99Pass.json")).Should().BeTrue(stdout + stderr);
            (stdout + stderr).Should().Contain("neo-sym analyze failed with exit code(s)");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eRejectsSingleDependencyProofSummaryOutputForMultipleNefs()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            foreach (string contract in new[] { "Alpha", "Beta" })
            {
                File.WriteAllBytes(
                    Path.Combine(scDir, contract + ".nef"),
                    BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
                File.WriteAllText(Path.Combine(scDir, contract + ".manifest.json"), $$"""
                    {
                      "name":"{{contract}}",
                      "groups":[],
                      "features":{},
                      "supportedstandards":[],
                      "abi":{
                        "methods":[
                          {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                        ],
                        "events":[]
                      },
                      "permissions":[],
                      "trusts":[]
                    }
                    """);
            }

            string proofSummaryPath = Path.Combine(dir, "dependency.neo-sym.proof.json");
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add($"/p:NeoSymVerifyEmitDependencyProofSummary={proofSummaryPath}");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "a multi-NEF DevPack verification must not let proof summaries overwrite each other");
            (stdout + stderr).Should().Contain("can only be used when exactly one .nef artifact is discovered");
            File.Exists(proofSummaryPath).Should().BeFalse(stdout + stderr);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eFailsClosedWhenDefaultDiscoveryFindsBothNefRoots()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string outputDir = Path.Combine(dir, "obj-output") + Path.DirectorySeparatorChar;
            string outputScDir = Path.Combine(outputDir, "sc");
            string fallbackScDir = Path.Combine(dir, "bin", "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(outputScDir);
            Directory.CreateDirectory(fallbackScDir);
            foreach (string scDir in new[] { outputScDir, fallbackScDir })
            {
                File.WriteAllBytes(
                    Path.Combine(scDir, "Contract.nef"),
                    BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
                File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                    {
                      "name":"Contract",
                      "groups":[],
                      "features":{},
                      "supportedstandards":[],
                      "abi":{
                        "methods":[
                          {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                        ],
                        "events":[]
                      },
                      "permissions":[],
                      "trusts":[]
                    }
                    """);
            }

            string toolPath = WriteNeoSymFailNamedAnalyzeToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:OutputPath={outputDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add("/p:NeoSymVerifyEnabled=false");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "default discovery must not let fallback bin/sc artifacts collide with current OutputPath reports");
            (stdout + stderr).Should().Contain("default NEF discovery found artifacts in both");
            File.Exists(Path.Combine(reportDir, "Contract.json"))
                .Should().BeFalse("ambiguous discovery must stop before report-writing Exec tasks run");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eVerifyPassesDeploySenderHashToComputeContractIdentity()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            string nefPath = Path.Combine(scDir, "Contract.nef");
            string manifestPath = Path.Combine(scDir, "Contract.manifest.json");
            string specPath = Path.Combine(dir, "contract.neo-sym.json");
            const string deploySender = "0102030405060708090a0b0c0d0e0f1011121314";

            byte[] nefBytes = BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllBytes(nefPath, nefBytes);
            File.WriteAllText(manifestPath, """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);
            File.WriteAllText(specPath, """
                {
                  "version": 1,
                  "properties": [
                    {
                      "id": "main_no_faults",
                      "method": "main",
                      "forbid_faults": true,
                      "ensures": []
                    }
                  ]
                }
                """);

            string toolPath = WriteNeoSymToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var manifest = ContractManifest.FromFile(manifestPath);
            var nef = NefFile.Parse(nefBytes, verifyChecksum: true);
            string expectedHash = ContractIdentity.ComputeContractHashHex(
                nef,
                manifest,
                ContractIdentity.ParseUInt160LittleEndianHex(deploySender));

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add($"/p:NeoSymVerifySpec={specPath}");
            psi.ArgumentList.Add($"/p:NeoSymDeploySenderHash={deploySender}");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().Be(0, stdout + stderr);
            string reportPath = Path.Combine(reportDir, "Contract.verify.json");
            File.Exists(reportPath).Should().BeTrue(stdout + stderr);
            var report = JsonNode.Parse(File.ReadAllText(reportPath))!;
            var identity = report["meta"]!["contract_identity"]!;
            identity["status"]!.GetValue<string>().Should().Be("computed");
            identity["deploy_sender_hash"]!.GetValue<string>().Should().Be(deploySender);
            identity["contract_hash"]!.GetValue<string>().Should().Be(expectedHash);
            identity["reason"].Should().BeNull();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DevPackTargets_E2eStillWritesVerifyReportWhenAnalyzeGateFails()
    {
        string dir = CreateTempDirectory();
        try
        {
            string repoRoot = FindRepoRoot();
            string scDir = Path.Combine(dir, "sc");
            string reportDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(scDir);
            File.WriteAllBytes(
                Path.Combine(scDir, "Contract.nef"),
                BuildNef("neo-sym-test", "", new[] { (byte)NeoVm.OpCode.RET }));
            File.WriteAllText(Path.Combine(scDir, "Contract.manifest.json"), """
                {
                  "name":"Contract",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"main","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);
            string specPath = Path.Combine(dir, "contract.neo-sym.json");
            File.WriteAllText(specPath, """
                {
                  "version": 1,
                  "properties": [
                    {
                      "id": "main_no_faults",
                      "method": "main",
                      "forbid_faults": true,
                      "ensures": []
                    }
                  ]
                }
                """);

            string toolPath = WriteNeoSymAnalyzeFailVerifyOkToolWrapper(dir);
            string projectPath = Path.Combine(dir, "Contract.csproj");
            File.WriteAllText(projectPath, $$"""
                <Project>
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.props")}}" />
                  <Import Project="{{Path.Combine(repoRoot, "devpack-integration", "Neo.SymbolicExecutor.targets")}}" />
                </Project>
                """);

            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("msbuild");
            psi.ArgumentList.Add(projectPath);
            psi.ArgumentList.Add("/nologo");
            psi.ArgumentList.Add("/v:minimal");
            psi.ArgumentList.Add("/t:NeoSymAnalyze");
            psi.ArgumentList.Add($"/p:NeoSymToolPath={toolPath}");
            psi.ArgumentList.Add("/p:NeoSymFormat=json");
            psi.ArgumentList.Add($"/p:NeoSymNefDir={scDir}");
            psi.ArgumentList.Add($"/p:NeoSymOutputDir={reportDir}");
            psi.ArgumentList.Add("/p:NeoSymSourceDir=");
            psi.ArgumentList.Add($"/p:NeoSymVerifySpec={specPath}");

            using var process = System.Diagnostics.Process.Start(psi)!;
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            process.ExitCode.Should().NotBe(0, "the analyze gate failure should still fail the build");
            File.Exists(Path.Combine(reportDir, "Contract.json")).Should().BeTrue(stdout + stderr);
            string verifyReportPath = Path.Combine(reportDir, "Contract.verify.json");
            File.Exists(verifyReportPath).Should().BeTrue("verification reports must still be written when analyze gates fail: " + stdout + stderr);
            JsonNode.Parse(File.ReadAllText(verifyReportPath))!["results"]![0]!["status"]!.GetValue<string>()
                .Should().Be("proved");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ReportJson_EscapesHtmlSensitiveFindingText()
    {
        var finding = new Finding(
            "xss_probe",
            Severity.High,
            "<script>alert(1)</script>",
            "desc",
            0x10,
            0.8,
            "test",
            ImmutableHashSet<string>.Empty);
        var findings = ImmutableArray.Create(finding);
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy().Evaluate(findings, risk);

        string json = ReportGenerator.ToJson(new AnalysisReport(findings, risk, gate, new AnalysisMeta()));

        json.Should().NotContain("<script>");
        json.Should().Contain("\\u003Cscript\\u003E");
        JsonNode.Parse(json)!["findings"]![0]!["title"]!.GetValue<string>()
            .Should().Be("<script>alert(1)</script>");
    }

    [Fact]
    public void NefParser_TruncatedVarBytesThrowsFormatException()
    {
        byte[] data = new byte[4 + 64 + 1];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), NefFile.MagicValue);
        data[^1] = 4; // Source varbytes claims four bytes, but none follow.

        var act = () => NefFile.Parse(data, verifyChecksum: false);

        act.Should().Throw<FormatException>().WithMessage("*VarBytes*truncated*");
    }

    [Fact]
    public async Task FuzzerCli_InvalidNumericOptionReturnsBadArguments()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var main = program.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;

        var task = (Task<int>)main.Invoke(null, new object[] { new[] { "--seconds", "not-an-int" } })!;
        int exitCode = await task;

        exitCode.Should().Be(2);
    }

    [Theory]
    [InlineData("--smt-timeout", "0")]
    [InlineData("--smt-timeout", "-1")]
    [InlineData("--smt-bytes-bound", "0")]
    [InlineData("--fail-on-total-findings", "-1")]
    [InlineData("--fail-on-weighted-score", "-1")]
    [InlineData("--fail-on-confidence-weighted-score", "-1")]
    [InlineData("--fail-on-severity-count", "high=-1")]
    public void CliAnalyze_RejectsInvalidNumericRanges(string option, string value)
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { "contract.nef", option, value } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>();
    }

    [Fact]
    public void CliAnalyze_RejectsDangerouslyLargeResourceCaps()
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;
        string[] options =
        {
            "--smt-timeout",
            "--smt-bytes-bound",
            "--max-queued-states",
            "--max-item-size",
            "--max-collection-size",
            "--max-heap-objects",
            "--max-pow-exponent",
        };

        foreach (string option in options)
        {
            var act = () => parse.Invoke(null, new object[] { new[] { "contract.nef", option, int.MaxValue.ToString() } });

            act.Should().Throw<TargetInvocationException>()
                .Which.InnerException.Should().BeOfType<ArgumentException>()
                .Which.Message.Should().Contain("expected <=");
        }
    }

    [Fact]
    public void CliVerify_RejectsDangerouslyLargeResourceCaps()
    {
        var verifyOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.VerifyOptions", throwOnError: true)!;
        var parse = verifyOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;
        string[] options =
        {
            "--smt-timeout",
            "--smt-bytes-bound",
            "--max-queued-states",
            "--max-item-size",
            "--max-collection-size",
            "--max-heap-objects",
            "--max-pow-exponent",
        };

        foreach (string option in options)
        {
            var args = new[]
            {
                "contract.nef",
                "--manifest",
                "contract.manifest.json",
                "--profile",
                "neo-n3-security",
                option,
                int.MaxValue.ToString(),
            };
            var act = () => parse.Invoke(null, new object[] { args });

            act.Should().Throw<TargetInvocationException>()
                .Which.InnerException.Should().BeOfType<ArgumentException>()
                .Which.Message.Should().Contain("expected <=");
        }
    }

    [Fact]
    public void CliVerify_RejectsBlankProfileName()
    {
        var verifyOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.VerifyOptions", throwOnError: true)!;
        var parse = verifyOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[]
        {
            new[]
            {
                "contract.nef",
                "--manifest",
                "contract.manifest.json",
                "--profile",
                "   ",
            },
        });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>()
            .Which.Message.Should().Contain("profile names must be non-empty");
    }

    [Fact]
    public void CliDecodeAndExploreRejectUnexpectedExtraArguments()
    {
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
                .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
            var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;

            ((int)main.Invoke(null, new object[] { new[] { "decode", scriptPath, "--ignored" } })!)
                .Should().Be(2, "decode must reject unknown trailing arguments instead of silently ignoring them");
            ((int)main.Invoke(null, new object[] { new[] { "explore", scriptPath, "--ignored" } })!)
                .Should().Be(2, "explore must reject unknown trailing arguments instead of silently ignoring them");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void VerificationSpec_FromFile_RejectsOversizedSpecFile()
    {
        string dir = CreateTempDirectory();
        try
        {
            string path = Path.Combine(dir, "oversized.neo-sym.spec.json");
            File.WriteAllText(path, new string(' ', VerificationSpec.MaxSpecBytes + 1));

            var act = () => VerificationSpec.FromFile(path);

            act.Should().Throw<FormatException>()
                .WithMessage("*exceeds max*");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void VerificationSpec_RejectsExcessiveProfilesPropertiesAndConditions()
    {
        var tooManyProfiles = new JsonArray();
        for (int i = 0; i <= VerificationSpec.MaxProfiles; i++)
            tooManyProfiles.Add($"profile-{i}");
        var profilesSpec = new JsonObject
        {
            ["version"] = 1,
            ["profiles"] = tooManyProfiles,
        };

        var parseProfiles = () => VerificationSpec.FromJson(profilesSpec);
        parseProfiles.Should().Throw<FormatException>()
            .WithMessage("*profiles count*");

        var tooManyProperties = new JsonArray();
        for (int i = 0; i <= VerificationSpec.MaxProperties; i++)
            tooManyProperties.Add(BuildMinimalProperty($"p{i}"));
        var propertiesSpec = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = tooManyProperties,
        };

        var parseProperties = () => VerificationSpec.FromJson(propertiesSpec);
        parseProperties.Should().Throw<FormatException>()
            .WithMessage("*properties count*");

        var tooManyConditions = new JsonArray();
        for (int i = 0; i <= VerificationSpec.MaxConditionsPerProperty; i++)
        {
            tooManyConditions.Add(new JsonObject
            {
                ["arg"] = "amount",
                ["op"] = ">=",
                ["value"] = 0,
            });
        }
        var conditionsSpec = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "too_many_conditions",
                    ["method"] = "transfer",
                    ["forbid_faults"] = true,
                    ["requires"] = tooManyConditions,
                    ["ensures"] = new JsonArray(),
                },
            },
        };

        var parseConditions = () => VerificationSpec.FromJson(conditionsSpec);
        parseConditions.Should().Throw<FormatException>()
            .WithMessage("*condition count*");
    }

    [Fact]
    public void VerificationSpec_RejectsUnknownFields()
    {
        var topLevelTypo = new JsonObject
        {
            ["version"] = 1,
            ["profiles"] = new JsonArray("neo-n3-security"),
            ["profile"] = "neo-n3-security",
        };
        var parseTopLevel = () => VerificationSpec.FromJson(topLevelTypo);
        parseTopLevel.Should().Throw<FormatException>()
            .WithMessage("*unknown verification spec field 'profile'*");

        var propertyTypo = BuildMinimalProperty("property_typo");
        propertyTypo["forbid_fault"] = true;
        var propertySpec = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray(propertyTypo),
        };
        var parseProperty = () => VerificationSpec.FromJson(propertySpec);
        parseProperty.Should().Throw<FormatException>()
            .WithMessage("*unknown verification property field 'properties[0].forbid_fault'*");

        var conditionTypo = new JsonObject
        {
            ["arg"] = "amount",
            ["op"] = ">=",
            ["value"] = 0,
            ["valeu"] = 0,
        };
        var conditionSpec = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "condition_typo",
                    ["method"] = "transfer",
                    ["ensures"] = new JsonArray(conditionTypo),
                },
            },
        };
        var parseCondition = () => VerificationSpec.FromJson(conditionSpec);
        parseCondition.Should().Throw<FormatException>()
            .WithMessage("*unknown verification condition field 'properties[0].ensures[0].valeu'*");
    }

    [Fact]
    public void VerificationSpec_RejectsUnsupportedVersion()
    {
        var spec = new JsonObject
        {
            ["version"] = 2,
            ["profiles"] = new JsonArray("neo-n3-security"),
        };

        var parse = () => VerificationSpec.FromJson(spec);

        parse.Should().Throw<FormatException>()
            .WithMessage("*version 2*supported version is 1*");
    }

    [Fact]
    public void VerificationSpec_RejectsWrongTypedScalarFieldsAsFormatException()
    {
        var wrongVersion = new JsonObject
        {
            ["version"] = "1",
            ["profiles"] = new JsonArray("neo-n3-security"),
        };
        var parseWrongVersion = () => VerificationSpec.FromJson(wrongVersion);
        parseWrongVersion.Should().Throw<FormatException>()
            .WithMessage("*verification spec 'version' must be an integer*");

        var wrongPropertyId = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = 123,
                    ["method"] = "transfer",
                    ["forbid_faults"] = true,
                },
            },
        };
        var parseWrongPropertyId = () => VerificationSpec.FromJson(wrongPropertyId);
        parseWrongPropertyId.Should().Throw<FormatException>()
            .WithMessage("*verification property 'id' must be a non-empty string*");

        var wrongConditionArg = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "wrong_condition_arg",
                    ["method"] = "transfer",
                    ["ensures"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["arg"] = 123,
                            ["op"] = ">=",
                            ["value"] = 0,
                        },
                    },
                },
            },
        };
        var parseWrongConditionArg = () => VerificationSpec.FromJson(wrongConditionArg);
        parseWrongConditionArg.Should().Throw<FormatException>()
            .WithMessage("*verification condition 'arg' must be a non-empty string*");

        var wrongConditionOp = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "wrong_condition_op",
                    ["method"] = "transfer",
                    ["ensures"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["arg"] = "amount",
                            ["op"] = false,
                            ["value"] = 0,
                        },
                    },
                },
            },
        };
        var parseWrongConditionOp = () => VerificationSpec.FromJson(wrongConditionOp);
        parseWrongConditionOp.Should().Throw<FormatException>()
            .WithMessage("*verification condition 'op' must be a non-empty string*");
    }

    [Fact]
    public void VerificationSpec_RejectsNonUInt160CallerHashLiteral()
    {
        var spec = new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "bad_caller_hash_literal",
                    ["method"] = "mint",
                    ["ensures"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["caller_hash"] = "0x010203",
                            ["metric"] = "enforced_count",
                            ["op"] = ">=",
                            ["value"] = 1,
                        },
                    },
                },
            },
        };

        var parse = () => VerificationSpec.FromJson(spec);

        parse.Should().Throw<FormatException>()
            .WithMessage("*caller_hash*20-byte UInt160*");
    }

    [Fact]
    public void FormalVerifier_StorageReadCoverageIgnoresPathsExcludedByRequires()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.DUP,          // 0
            (byte)NeoVm.OpCode.PUSH0,        // 1
            (byte)NeoVm.OpCode.EQUAL,        // 2
            (byte)NeoVm.OpCode.JMPIF, 0x0C,  // 3: flag == 0 skips the storage read
            (byte)NeoVm.OpCode.DROP,         // 5
            (byte)NeoVm.OpCode.PUSHDATA1,    // 6
            0x01,                            // 7
            (byte)'k',                       // 8
            (byte)NeoVm.OpCode.SYSCALL,      // 9
            0, 0, 0, 0,                      // patched below
            (byte)NeoVm.OpCode.RET,          // 14
            (byte)NeoVm.OpCode.DROP,         // 15
            (byte)NeoVm.OpCode.RET,          // 16
        };
        uint storageGet = SyscallRegistry.ComputeHash("System.Storage.Local.Get");
        BitConverter.GetBytes(storageGet).CopyTo(script, 10);
        var program = ScriptDecoder.Decode(script);
        program.Instructions.Single(i => i.Offset == 3).Target.Should().Be(15);

        var manifest = ContractManifest.FromJson("""
            {
              "name":"RequiresStorageRead",
              "groups":[],
              "features":{},
              "supportedstandards":[],
              "abi":{
                "methods":[
                  {
                    "name":"check",
                    "parameters":[{"name":"flag","type":"Integer"}],
                    "returntype":"Void",
                    "offset":0,
                    "safe":false
                  }
                ],
                "events":[]
              },
              "permissions":[],
              "trusts":[]
            }
            """);
        var spec = VerificationSpec.FromJson(new JsonObject
        {
            ["version"] = 1,
            ["properties"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "storage_read_requires",
                    ["method"] = "check",
                    ["forbid_faults"] = true,
                    ["requires"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["arg"] = "flag",
                            ["op"] = "!=",
                            ["value"] = 0,
                        },
                        new JsonObject
                        {
                            ["storage_read"] = 9,
                            ["metric"] = "size",
                            ["op"] = ">=",
                            ["value"] = 0,
                        },
                    },
                    ["ensures"] = new JsonArray(),
                },
            },
        });
        var flagEqZero = Expr.Eq(Expr.Sym(Sort.Int, "arg_flag"), Expr.Int(0));
        var flagNeZero = Expr.Not(flagEqZero);
        var smt = new StubSmtBackend(
            _ => SmtOutcome.Sat,
            conditions => conditions.Contains(flagEqZero) && conditions.Contains(flagNeZero)
                ? SmtOutcome.Unsat
                : SmtOutcome.Sat);

        var report = FormalVerifier.Verify(program, manifest, spec, ExecutionOptions.Default, smt);

        report.Results.Should().ContainSingle()
            .Which.Status.Should().Be(VerificationStatus.Proved);
        report.Meta.CoverageIncomplete.Should().BeFalse();
        report.Results.Single().Reason.Should().NotContain("unobserved Storage.Get");
    }

    [Fact]
    public void FormalVerifier_OpenBufferAbiReturnDoesNotUseSeedPrefixAsKnownLength()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var manifest = ContractManifest.FromJson("""
            {
              "name":"OpenBufferReturn",
              "groups":[],
              "features":{},
              "supportedstandards":[],
              "abi":{
                "methods":[
                  {
                    "name":"identity",
                    "parameters":[{"name":"scratch","type":"Buffer"}],
                    "returntype":"Hash160",
                    "offset":0,
                    "safe":true
                  }
                ],
                "events":[]
              },
              "permissions":[],
              "trusts":[]
            }
            """);
        var spec = VerificationSpec.FromJson(new JsonObject
        {
            ["version"] = 1,
            ["profiles"] = new JsonArray("neo-n3-security"),
        });

        var report = FormalVerifier.Verify(program, manifest, spec, ExecutionOptions.Default, smtBackend: null);

        var result = report.Results.Should().ContainSingle(r => r.Id == "security.abi_return_type.identity").Subject;
        result.Status.Should().Be(VerificationStatus.Incomplete);
        result.Reason.Should().Contain("returned ByteString length 20 bytes cannot be proven");
        result.Reason.Should().NotContain("length 4 bytes");
    }

    [Fact]
    public void FormalVerifier_ReturnReachabilityExcludesImplicitFaultPreconditions()
    {
        using var backend = new Neo.SymbolicExecutor.Smt.Z3.Z3Backend();
        var ok = Expr.Sym(Sort.Bool, "ok");
        var method = new ContractMethodDescriptor
        {
            Name = "transfer",
            ReturnType = "Boolean",
        };
        var state = NewState(pc: 0);
        state.Terminate(TerminalStatus.Halted);
        state.Push(SymbolicValue.Of(ok));
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            0x10,
            "SyntheticFault",
            ok,
            "the same condition would fault before the return can be observed",
            "implicit VM fault is unreachable on successful HALT"));

        var tryReturnMayBeTrue = typeof(FormalVerifier).GetMethod(
            "TryReturnMayBeTrue",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        object?[] args = { method, state, backend, true, "" };

        ((bool)tryReturnMayBeTrue.Invoke(null, args)!).Should().BeTrue();
        args[3].Should().Be(false,
            "successful return reachability must include not(fault_condition) guards");

        var buildTrueReturnReachabilityQuery = typeof(FormalVerifier).GetMethod(
            "BuildTrueReturnReachabilityQuery",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        var query = (ImmutableArray<Expression>)buildTrueReturnReachabilityQuery.Invoke(
            null,
            new object[] { method, state, BoolConst.True })!;

        backend.IsSatisfiable(query).Should().Be(
            SmtOutcome.Unsat,
            "the query must include both the true return and the implicit successful-HALT fault guard");
    }

    [Fact]
    public void FormalVerifier_ForbidFaultsUsesFaultInstructionPrefixPathConditions()
    {
        using var backend = new Neo.SymbolicExecutor.Smt.Z3.Z3Backend();
        var index = Expr.Sym(Sort.Int, "idx");
        var inRange = Expr.BoolAnd(
            Expr.Ge(index, Expr.Int(0)),
            Expr.Lt(index, Expr.Int(1)));
        var state = NewState(pc: 0);
        state.Terminate(TerminalStatus.Halted);
        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            0x10,
            "PICKITEM",
            Expr.Not(inRange),
            "closed array index may be negative or outside the runtime length",
            "array PICKITEM index is within range"));
        state.PathConditions = state.PathConditions.Add(inRange);

        var property = new VerificationProperty(
            "fault_prefix",
            "read",
            "Fault checks must use the path prefix from the faulting instruction.",
            ForbidFaults: true,
            ImmutableArray<VerificationCondition>.Empty,
            ImmutableArray<VerificationCondition>.Empty);
        var checkFaultPreconditions = typeof(FormalVerifier).GetMethod(
            "CheckFaultPreconditions",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        object?[] args =
        {
            property,
            state,
            ImmutableArray<Expression>.Empty,
            backend,
            1,
            0,
            0,
            0,
            new List<string>(),
            null,
            ImmutableArray<VerificationAssumption>.Empty,
        };

        var result = (VerificationPropertyResult?)checkFaultPreconditions.Invoke(null, args);

        result.Should().NotBeNull(
            "a guard learned after PICKITEM cannot prove that the earlier PICKITEM was fault-free");
        result!.Status.Should().Be(VerificationStatus.Violated);
        result.Reason.Should().Contain("PICKITEM");
    }

    [Fact]
    public void FormalVerifier_ForbidFaultsUsesArithmeticInstructionPrefixPathConditions()
    {
        using var backend = new Neo.SymbolicExecutor.Smt.Z3.Z3Backend();
        var divisor = SymbolicValue.Of(Expr.Sym(Sort.Int, "divisor"));
        var state = NewState(pc: 0);
        state.Terminate(TerminalStatus.Halted);
        state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            0x20,
            "DIV",
            SymbolicValue.Int(10),
            divisor,
            OverflowPossible: false,
            DivisorMaybeZero: true,
            Checked: false));
        state.PathConditions = state.PathConditions.Add(Expr.NumNe(divisor.Expression, Expr.Int(0)));

        var method = new ContractMethodDescriptor
        {
            Name = "divide",
            ReturnType = "Integer",
        };
        var property = new VerificationProperty(
            "arithmetic_prefix",
            "divide",
            "Arithmetic checks must use the path prefix from the arithmetic instruction.",
            ForbidFaults: true,
            ImmutableArray<VerificationCondition>.Empty,
            ImmutableArray<VerificationCondition>.Empty);
        var checkArithmeticDefinedness = typeof(FormalVerifier).GetMethod(
            "CheckArithmeticDefinedness",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        object?[] args =
        {
            method,
            property,
            state,
            ImmutableArray<Expression>.Empty,
            backend,
            1,
            0,
            0,
            0,
            new List<string>(),
        };

        var result = (VerificationPropertyResult?)checkArithmeticDefinedness.Invoke(null, args);

        result.Should().NotBeNull(
            "a guard learned after DIV cannot prove that the earlier divisor was non-zero");
        result!.Status.Should().Be(VerificationStatus.Violated);
        result.Reason.Should().Contain("zero divisor");
    }

    [Fact]
    public void CliAnalyze_RejectsInvalidFormatBeforeLoadingContract()
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { "missing.nef", "--format", "xml" } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>()
            .Which.Message.Should().Contain("unknown --format");
    }

    [Fact]
    public void CliAnalyze_ParsesSourceHintPaths()
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var opts = parse.Invoke(null, new object[] { new[] { "contract.nef", "--source", "Contract.cs", "--source", "src" } })!;
        var sourcePaths = (System.Collections.IEnumerable)opts.GetType()
            .GetProperty("SourcePaths")!
            .GetValue(opts)!;

        sourcePaths.Cast<string>().Should().Equal("Contract.cs", "src");
    }

    [Fact]
    public void CliAnalyze_UsesManifestSelfCallResolverForSameContractCalls()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            byte[] caller = Concat(
                Syscall("System.Runtime.GetExecutingScriptHash"),
                Pushdata1("callee"u8.ToArray()),
                new[] { (byte)NeoVm.OpCode.PUSH5, (byte)NeoVm.OpCode.PUSH0, (byte)NeoVm.OpCode.PACK },
                Syscall("System.Contract.Call"),
                new[] { (byte)NeoVm.OpCode.RET });
            int calleeOffset = caller.Length;
            byte[] script = Concat(caller, new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.RET });

            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, script);
            File.WriteAllText(manifestPath, $$"""
                {
                  "name":"SelfCall",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"caller","parameters":[],"returntype":"Integer","offset":0,"safe":false},
                      {"name":"callee","parameters":[],"returntype":"Integer","offset":{{calleeOffset}},"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(0);
            var root = JsonNode.Parse(File.ReadAllText(reportPath))!;
            root["findings"]!.AsArray().Should().BeEmpty(
                "same-contract calls resolved through the manifest are modeled, not treated as unchecked external calls");
            root["risk_profile"]!["total_findings"]!.GetValue<int>().Should().Be(0);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_FailsByDefaultOnHighSeverityFindings()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "missing-auth-storage-write.bin");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, Concat(
                Syscall("System.Storage.GetContext"),
                Pushdata1("key"u8.ToArray()),
                Pushdata1("value"u8.ToArray()),
                Syscall("System.Storage.Put"),
                new[] { (byte)NeoVm.OpCode.RET }));

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "high severity findings must fail the default analyze gate for CI use");
            var root = JsonNode.Parse(File.ReadAllText(reportPath))!;
            root["risk_profile"]!["overall_max_severity"]!.GetValue<string>().Should().Be("high");
            root["gate_evaluation"]!["passed"]!.GetValue<bool>().Should().BeFalse();
            root["gate_evaluation"]!["violations"]!.AsArray()
                .Select(v => v!.GetValue<string>())
                .Should().Contain(v => v.Contains("max severity high", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_FailsByDefaultWhenBudgetIsExceeded()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "budget.bin");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.PUSH1, (byte)NeoVm.OpCode.RET });

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--max-steps", "1",
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "budget-exceeded analysis is incomplete and must fail the default analyze gate");
            var root = JsonNode.Parse(File.ReadAllText(reportPath))!;
            root["meta"]!["budget_exceeded"]!.GetValue<bool>().Should().BeTrue();
            root["gate_evaluation"]!["passed"]!.GetValue<bool>().Should().BeFalse();
            root["gate_evaluation"]!["violations"]!.AsArray()
                .Select(v => v!.GetValue<string>())
                .Should().Contain(v => v.Contains("budget exceeded", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_FailsByDefaultWhenManifestEntrypointCoverageIsIncomplete()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllText(manifestPath, """
                {
                  "name":"StaleManifest",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"ok","parameters":[],"returntype":"Void","offset":0,"safe":false},
                      {"name":"stale","parameters":[],"returntype":"Void","offset":999,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "stale manifest entrypoints make analysis coverage incomplete");
            string reportJson = File.ReadAllText(reportPath);
            var meta = JsonNode.Parse(reportJson)!["meta"]!;
            meta["coverage_incomplete"]!.GetValue<bool>().Should().BeTrue();
            meta["coverage_reason"]!.GetValue<string>().Should().Contain("stale");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_FailsByDefaultWhenManifestEntrypointOffsetIsNotDecodedInstructionBoundary()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[]
            {
                (byte)NeoVm.OpCode.PUSHDATA1,
                (byte)0x01,
                (byte)NeoVm.OpCode.RET,
                (byte)NeoVm.OpCode.ABORT,
            });
            File.WriteAllText(manifestPath, """
                {
                  "name":"StaleManifest",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"stale","parameters":[],"returntype":"Void","offset":2,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "ABI entrypoints that land inside operand bytes are stale manifest coverage, not valid methods");
            string reportJson = File.ReadAllText(reportPath);
            var meta = JsonNode.Parse(reportJson)!["meta"]!;
            meta["coverage_incomplete"]!.GetValue<bool>().Should().BeTrue();
            meta["coverage_reason"]!.GetValue<string>().Should().Contain("decoded instruction boundary");
            meta["skipped_entrypoints"]!.AsArray().Select(n => n!.GetValue<string>())
                .Should().Equal("stale@2");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_AllowIncompleteCoverageKeepsCoverageMetadataWithoutFailingGate()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllText(manifestPath, """
                {
                  "name":"StaleManifest",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"ok","parameters":[],"returntype":"Void","offset":0,"safe":false},
                      {"name":"stale","parameters":[],"returntype":"Void","offset":999,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--format", "json",
                    "--out", reportPath,
                    "--allow-incomplete-coverage",
                }
            })!;

            exit.Should().Be(0, "the opt-out is for exploratory stale-manifest analysis");
            string reportJson = File.ReadAllText(reportPath);
            var root = JsonNode.Parse(reportJson)!;
            var meta = root["meta"]!;
            meta["coverage_incomplete"]!.GetValue<bool>().Should().BeTrue();
            meta["coverage_reason"]!.GetValue<string>().Should().Contain("stale");
            meta["skipped_entrypoints"]!.AsArray().Select(n => n!.GetValue<string>())
                .Should().Equal("stale@999");
            root["gate_evaluation"]!["passed"]!.GetValue<bool>().Should().BeTrue();
            root["gate_evaluation"]!["policies"]!.AsObject()
                .ContainsKey("fail-on-incomplete-coverage")
                .Should().BeFalse();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_ExpandsAnyAbiParameterShapesForManifestEntrypoints()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllText(manifestPath, """
                {
                  "name":"AnyEntrypoint",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {
                        "name":"check",
                        "parameters":[{"name":"data","type":"Any"}],
                        "returntype":"Void",
                        "offset":0,
                        "safe":false
                      }
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(0);
            var meta = JsonNode.Parse(File.ReadAllText(reportPath))!["meta"]!;
            meta["states_explored"]!.GetValue<int>().Should().Be(9);
            meta["coverage_incomplete"]!.GetValue<bool>().Should().BeFalse(
                "representative Any expansion is expected analysis breadth, not stale-manifest coverage loss");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliAnalyze_CapsManifestEntrypointsByDefaultBudgetOption()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "report.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllText(manifestPath, """
                {
                  "name":"ManyEntrypoints",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"m0","parameters":[],"returntype":"Void","offset":0,"safe":false},
                      {"name":"m1","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "analyze", scriptPath,
                    "--manifest", manifestPath,
                    "--max-entrypoints", "1",
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "manifest entrypoint caps must fail closed by default instead of silently skipping analysis");
            var meta = JsonNode.Parse(File.ReadAllText(reportPath))!["meta"]!;
            meta["coverage_incomplete"]!.GetValue<bool>().Should().BeTrue();
            meta["coverage_reason"]!.GetValue<string>().Should().Contain("max-entrypoints");
            meta["skipped_entrypoints"]!.AsArray().Select(n => n!.GetValue<string>())
                .Should().Contain("m1@0");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CliVerify_CapsNeoN3ProfileManifestEntrypoints()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var main = cliProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;
        string dir = CreateTempDirectory();
        try
        {
            string scriptPath = Path.Combine(dir, "contract.bin");
            string manifestPath = Path.Combine(dir, "contract.manifest.json");
            string reportPath = Path.Combine(dir, "verify.json");
            File.WriteAllBytes(scriptPath, new[] { (byte)NeoVm.OpCode.RET });
            File.WriteAllText(manifestPath, """
                {
                  "name":"ManyEntrypoints",
                  "groups":[],
                  "features":{},
                  "supportedstandards":[],
                  "abi":{
                    "methods":[
                      {"name":"m0","parameters":[],"returntype":"Void","offset":0,"safe":false},
                      {"name":"m1","parameters":[],"returntype":"Void","offset":0,"safe":false}
                    ],
                    "events":[]
                  },
                  "permissions":[],
                  "trusts":[]
                }
                """);

            var exit = (int)main.Invoke(null, new object[]
            {
                new[]
                {
                    "verify", scriptPath,
                    "--manifest", manifestPath,
                    "--profile", "neo-n3-security",
                    "--max-entrypoints", "1",
                    "--format", "json",
                    "--out", reportPath,
                }
            })!;

            exit.Should().Be(3, "profile verification must report skipped ABI methods instead of scaling work unboundedly");
            var root = JsonNode.Parse(File.ReadAllText(reportPath))!;
            root["meta"]!["coverage_incomplete"]!.GetValue<bool>().Should().BeTrue();
            var capResult = root["results"]!.AsArray()
                .Single(r => r!["id"]!.GetValue<string>() == "security.coverage.profile_entrypoint_cap")!;
            capResult["status"]!.GetValue<string>().Should().Be("incomplete");
            capResult["reason"]!.GetValue<string>().Should().Contain("max-entrypoints");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_LoadsProjectSourceFiles()
    {
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Contract.cs"), """
                public bool execute()
                {
                    var amountOutMin = 1;
                    return amountOutMin > 0;
                }
            """);

            SourceHints.FromPaths(new[] { dir })
                .MethodContainsAny("execute", new[] { "amountOutMin" })
                .Should().BeTrue();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_SkipsGeneratedAndDependencyDirectories()
    {
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Contract.cs"), """
                public bool execute()
                {
                    storage.Put("opaque", amountIn);
                    return true;
                }
            """);
            string objDir = Path.Combine(dir, "obj");
            Directory.CreateDirectory(objDir);
            File.WriteAllText(Path.Combine(objDir, "Generated.cs"), """
                public bool execute()
                {
                    var reserveAfter = pool.Reserve0 + amountIn;
                    return reserveAfter > 0;
                }
            """);

            SourceHints.FromPaths(new[] { dir })
                .MethodContainsAny("execute", new[] { "reserve" })
                .Should().BeFalse();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_IgnoresCommentsWhenMatchingHints()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                // TODO: add reserve accounting and amountOutMin checks.
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserve", "amountOutMin" })
            .Should().BeFalse();
    }

    [Fact]
    public void SourceHints_PreservesStringLiteralsForStateHintsWhenAllowed()
    {
        var sourceHints = SourceHints.FromText("""
            public bool doIt(UInt256 tokenId, UInt160 to)
            {
                storage.Put("owner:" + tokenId, to);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("doIt", new[] { "owner" })
            .Should().BeTrue();
        sourceHints.MethodContainsAny("doIt", new[] { "owner" }, includeStringLiterals: false)
            .Should().BeFalse();
    }

    [Fact]
    public void SourceHints_StringAndCommentBracesDoNotEndMethodBody()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var text = "{ not a block }";
                /* } */
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_CharLiteralBraceDoesNotEndMethodBody()
    {
        // FindCharLiteralEnd handles 'X' literals so an embedded } in a char literal
        // doesn't prematurely close the method body. Without this guard, the regex would
        // see the brace at the } in '}' and stop the body extraction early, missing
        // everything after.
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                char close = '}';
                var reserveAfter = pool.Reserve0;
                return close == '}' && reserveAfter > 0;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_RawStringBraceDoesNotEndMethodBody()
    {
        // C# 11 raw string literals: """..."""  — the parser must recognize these and treat
        // any embedded braces as opaque text. FindRawStringEnd handles this.
        var sourceHints = SourceHints.FromText("\n"
            + "public bool execute()\n"
            + "{\n"
            + "    var template = \"\"\"\n"
            + "        { embedded brace } in raw string\n"
            + "        { another } here\n"
            + "    \"\"\";\n"
            + "    var reserveAfter = pool.Reserve0;\n"
            + "    return reserveAfter > 0;\n"
            + "}\n");

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_SearchesAllBodiesForDuplicateMethodNames()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }

            public bool execute(BigInteger amountIn)
            {
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_CanRestrictDuplicateMethodNamesByParameterCount()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }

            public bool execute(BigInteger amountIn)
            {
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", parameterCount: 0, hints: new[] { "reserveAfter" })
            .Should().BeTrue();
        sourceHints.MethodContainsAny("execute", parameterCount: 1, hints: new[] { "reserveAfter" })
            .Should().BeFalse();
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_AliasesMethodToAbiName()
    {
        // Real Neo DevPack pattern: the C# method is named DoTransfer but exposed in the
        // manifest under a different ABI name via [DisplayName("transfer")]. Without alias
        // resolution, our protocol-risk detectors would look up "transfer" and miss the body.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            public class FooContract
            {
                [DisplayName("transfer")]
                public static bool DoTransfer(byte[] from, byte[] to, int amount)
                {
                    int amountOutMin = 0;
                    return amountOutMin >= 0;
                }
            }
        """);

        // ABI name resolves via the alias.
        hints.MethodContainsAny("transfer", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
        // C# identifier still resolves directly.
        hints.MethodContainsAny("DoTransfer", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_DisplayNameOnClass_DoesNotAliasFollowingMethod()
    {
        // A [DisplayName("X")] on a class declaration must not alias the next method to "X" —
        // the attribute targets the class itself. Without the blocking-declaration check
        // we would silently mis-bind. This regression-tests the precision of alias scoping.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            [DisplayName("ClassAlias")]
            public class FooContract
            {
                public static bool TransferImpl(byte[] from, byte[] to, int amount)
                {
                    int amountOutMin = 0;
                    return amountOutMin >= 0;
                }
            }
        """);

        hints.MethodContainsAny("ClassAlias", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeFalse();
        hints.MethodContainsAny("TransferImpl", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_ExposesIndexedMethodAndBodyCountsForDiagnostics()
    {
        // Two method names — one with two overloads, one with one body — for a total of
        // 3 bodies under 2 distinct names. The CLI surfaces these counters on stderr so users
        // who pass --source can confirm their path resolved to actual .cs content.
        var hints = SourceHints.FromText("""
            public void First(int x) { }
            public void First() { }
            public void Second() { }
        """);
        hints.MethodNameCount.Should().Be(2);
        hints.MethodBodyCount.Should().Be(3);

        SourceHints.FromText(string.Empty).MethodNameCount.Should().Be(0);
        SourceHints.FromText(string.Empty).MethodBodyCount.Should().Be(0);
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_AcceptsFullyQualifiedName()
    {
        // Some contracts skip the `using System.ComponentModel;` and apply the attribute as
        // [System.ComponentModel.DisplayName("foo")]. The regex's optional namespace prefix
        // handles this; lock it down so a future regex tweak that drops the prefix arm fails
        // loudly instead of silently regressing the alias path.
        var hints = SourceHints.FromText("""
            public class Foo
            {
                [System.ComponentModel.DisplayName("transfer")]
                public bool DoTransfer(int x) { int amountOutMin = 0; }
            }
        """);
        hints.MethodContainsAny("transfer", parameterCount: 1, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_BindsThroughInterleavedAttributes()
    {
        // Real Neo DevPack pattern stacks several attributes — DisplayName, Safe, others —
        // around a method. The alias must still bind to the next method declaration regardless
        // of attribute order or whether non-DisplayName attributes sit between the alias and
        // the method.
        var hintsBeforeSafe = SourceHints.FromText("""
            using System.ComponentModel;

            public class Foo
            {
                [DisplayName("transfer")]
                [Safe]
                public bool DoTransfer(int x) { int amountOutMin = 0; }
            }
        """);
        hintsBeforeSafe.MethodContainsAny("transfer", parameterCount: 1, hints: new[] { "amountOutMin" })
            .Should().BeTrue();

        var hintsAfterSafe = SourceHints.FromText("""
            using System.ComponentModel;

            public class Foo
            {
                [Safe]
                [DisplayName("transfer")]
                public bool DoTransfer(int x) { int amountOutMin = 0; }
            }
        """);
        hintsAfterSafe.MethodContainsAny("transfer", parameterCount: 1, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_DoesNotLeakAcrossFiles()
    {
        // Per-file scoping: a [DisplayName] in file A must not bind to the first method in
        // file B even though SourceHints.FromPaths processes them together. Concatenating
        // files before scanning would silently mis-bind. We use a stray-attribute layout in
        // FileA (which a careless paste could leave), and FileB starts with a method that
        // would have absorbed the alias under naive concatenation.
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "A.cs"), """
                using System.ComponentModel;

                public class A
                {
                    public static void Done() { }
                }

                [DisplayName("zombie")]
            """);
            File.WriteAllText(Path.Combine(dir, "B.cs"), """
                using System.ComponentModel;

                public class B
                {
                    public static void Other(int marker) { var leakedMarker = marker; }
                }
            """);

            var hints = SourceHints.FromPaths(new[] { dir });
            // The stray FileA attribute should NOT alias FileB's Other method.
            hints.MethodContainsAny("zombie", parameterCount: 1, hints: new[] { "leakedMarker" })
                .Should().BeFalse();
            // Sanity: Other resolves under its own name and the marker is found.
            hints.MethodContainsAny("Other", parameterCount: 1, hints: new[] { "leakedMarker" })
                .Should().BeTrue();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_DoesNotLeakToSubsequentMethod()
    {
        // The alias must bind to exactly one method (the first one after the attribute) and
        // never leak to later methods that have no DisplayName of their own. Walk-with-cursor
        // semantics guarantee at-most-one consumption per attribute.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            public class FooContract
            {
                [DisplayName("aliased")]
                public static void First(int x) { int firstMarker = x; }

                public static void Second(int x) { int secondMarker = x; }
            }
        """);

        hints.MethodContainsAny("aliased", parameterCount: 1, hints: new[] { "firstMarker" })
            .Should().BeTrue();
        hints.MethodContainsAny("aliased", parameterCount: 1, hints: new[] { "secondMarker" })
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("--seconds", "0")]
    [InlineData("--minutes", "-1")]
    [InlineData("--hours", "0")]
    [InlineData("--workers", "0")]
    [InlineData("--status-seconds", "0")]
    [InlineData("--max-memory-mb", "0")]
    public void FuzzerCli_RejectsInvalidNumericRanges(string option, string value)
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var parse = program.GetMethod("ParseArgs", BindingFlags.NonPublic | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { option, value } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>();
    }

    [Fact]
    public void FuzzerCli_HelpListsEveryAvailableTarget()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var printHelp = program.GetMethod("PrintHelp", BindingFlags.NonPublic | BindingFlags.Static)!;
        var targetNames = FuzzerTargetNames();

        using var output = new StringWriter();
        var originalOut = Console.Out;
        try
        {
            Console.SetOut(output);
            printHelp.Invoke(null, null);
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        string help = output.ToString();
        targetNames.Should().HaveCount(23);
        foreach (string targetName in targetNames)
            help.Should().Contain(targetName);
    }

    [Fact]
    public void FuzzerReadme_DocumentsEveryAvailableTarget()
    {
        string readme = ReadRepoFile("src/Neo.SymbolicExecutor.Fuzzer/README.md");

        foreach (string targetName in FuzzerTargetNames())
            readme.Should().Contain($"`{targetName}`");
    }

    [Fact]
    public void Readme_DocumentsEveryDefaultDetector()
    {
        // The repo root README enumerates every detector from DefaultDetectorSet; without a
        // meta-test the two drift the moment a new detector is wired in. Each name must appear
        // as `name` (the canonical Markdown-code form) somewhere in the README. Catches both
        // adds (missing in README) and rare renames (orphan in README still flags via the new
        // detector being absent).
        var detectorNames = Detectors.DefaultDetectorSet.All().Select(d => d.Name).ToList();
        string readme = ReadRepoFile("README.md");
        foreach (string name in detectorNames)
            readme.Should().Contain($"`{name}`", $"detector {name} should appear in README");
    }

    [Fact]
    public void DevPackReadme_DocumentsEveryDefaultDetector()
    {
        var detectorNames = Detectors.DefaultDetectorSet.All().Select(d => d.Name).ToList();
        string readme = ReadRepoFile("devpack-integration/README.md");

        readme.Should().Contain("37 detectors");
        readme.Should().NotContain("35 detectors");
        readme.Should().NotContain("33 detectors");
        readme.Should().NotContain("24 detectors");
        foreach (string name in detectorNames)
            readme.Should().Contain($"`{name}`", $"detector {name} should appear in DevPack README");
    }

    [Fact]
    public void Readme_DocumentsCoverageIntegrityAndCurrentTooling()
    {
        string readme = ReadRepoFile("README.md");

        readme.Should().Contain("1362 xUnit cases passing");
        readme.Should().NotContain("1359 xUnit cases passing");
        readme.Should().NotContain("1355 xUnit cases passing");
        readme.Should().NotContain("1354 xUnit cases passing");
        readme.Should().NotContain("1351 xUnit cases passing");
        readme.Should().NotContain("1349 xUnit cases passing");
        readme.Should().NotContain("1348 xUnit cases passing");
        readme.Should().NotContain("1344 xUnit cases passing");
        readme.Should().NotContain("1341 xUnit cases passing");
        readme.Should().NotContain("1339 xUnit cases passing");
        readme.Should().NotContain("1336 xUnit cases passing");
        readme.Should().NotContain("1334 xUnit cases passing");
        readme.Should().NotContain("1331 xUnit cases passing");
        readme.Should().NotContain("1329 xUnit cases passing");
        readme.Should().NotContain("1328 xUnit cases passing");
        readme.Should().NotContain("1325 xUnit cases passing");
        readme.Should().NotContain("1324 xUnit cases passing");
        readme.Should().NotContain("1323 xUnit cases passing");
        readme.Should().NotContain("1322 xUnit cases passing");
        readme.Should().NotContain("1321 xUnit cases passing");
        readme.Should().NotContain("1309 xUnit cases passing");
        readme.Should().NotContain("1307 xUnit cases passing");
        readme.Should().NotContain("1302 xUnit cases passing");
        readme.Should().NotContain("1299 xUnit cases passing");
        readme.Should().NotContain("1298 xUnit cases passing");
        readme.Should().NotContain("1297 xUnit cases passing");
        readme.Should().NotContain("1296 xUnit cases passing");
        readme.Should().NotContain("1295 xUnit cases passing");
        readme.Should().NotContain("1294 xUnit cases passing");
        readme.Should().NotContain("1293 xUnit cases passing");
        readme.Should().NotContain("1213 xUnit cases passing");
        readme.Should().NotContain("1212 xUnit cases passing");
        readme.Should().NotContain("1211 xUnit cases passing");
        readme.Should().NotContain("1210 xUnit cases passing");
        readme.Should().NotContain("1199 xUnit cases passing");
        readme.Should().NotContain("1195 xUnit cases passing");
        readme.Should().NotContain("1194 xUnit cases passing");
        readme.Should().NotContain("1193 xUnit cases passing");
        readme.Should().NotContain("1184 xUnit cases passing");
        readme.Should().NotContain("1182 xUnit cases passing");
        readme.Should().NotContain("1180 xUnit cases passing");
        readme.Should().NotContain("1178 xUnit cases passing");
        readme.Should().NotContain("1176 xUnit cases passing");
        readme.Should().NotContain("1174 xUnit cases passing");
        readme.Should().NotContain("1172 xUnit cases passing");
        readme.Should().NotContain("1171 xUnit cases passing");
        readme.Should().NotContain("1170 xUnit cases passing");
        readme.Should().NotContain("1168 xUnit cases passing");
        readme.Should().NotContain("1166 xUnit cases passing");
        readme.Should().NotContain("1164 xUnit cases passing");
        readme.Should().NotContain("1162 xUnit cases passing");
        readme.Should().NotContain("1160 xUnit cases passing");
        readme.Should().NotContain("1158 xUnit cases passing");
        readme.Should().NotContain("1155 xUnit cases passing");
        readme.Should().NotContain("1152 xUnit cases passing");
        readme.Should().NotContain("1148 xUnit cases passing");
        readme.Should().NotContain("1145 xUnit cases passing");
        readme.Should().NotContain("1141 xUnit cases passing");
        readme.Should().NotContain("1136 xUnit cases passing");
        readme.Should().NotContain("1135 xUnit cases passing");
        readme.Should().NotContain("1134 xUnit cases passing");
        readme.Should().NotContain("1133 xUnit cases passing");
        readme.Should().NotContain("1132 xUnit cases passing");
        readme.Should().NotContain("1131 xUnit cases passing");
        readme.Should().NotContain("1128 xUnit cases passing");
        readme.Should().NotContain("1126 xUnit cases passing");
        readme.Should().NotContain("1118 xUnit cases passing");
        readme.Should().NotContain("1117 xUnit cases passing");
        readme.Should().NotContain("1116 xUnit cases passing");
        readme.Should().NotContain("1115 xUnit cases passing");
        readme.Should().NotContain("1114 xUnit cases passing");
        readme.Should().NotContain("1113 xUnit cases passing");
        readme.Should().NotContain("1112 xUnit cases passing");
        readme.Should().NotContain("1111 xUnit cases passing");
        readme.Should().NotContain("1110 xUnit cases passing");
        readme.Should().NotContain("1109 xUnit cases passing");
        readme.Should().NotContain("1108 xUnit cases passing");
        readme.Should().NotContain("1107 xUnit cases passing");
        readme.Should().NotContain("1106 xUnit cases passing");
        readme.Should().NotContain("1105 xUnit cases passing");
        readme.Should().NotContain("1104 xUnit cases passing");
        readme.Should().NotContain("1103 xUnit cases passing");
        readme.Should().NotContain("1102 xUnit cases passing");
        readme.Should().NotContain("1101 xUnit cases passing");
        readme.Should().NotContain("1100 xUnit cases passing");
        readme.Should().NotContain("1099 xUnit cases passing");
        readme.Should().NotContain("1098 xUnit cases passing");
        readme.Should().NotContain("1097 xUnit cases passing");
        readme.Should().NotContain("1096 xUnit cases passing");
        readme.Should().NotContain("1095 xUnit cases passing");
        readme.Should().NotContain("1094 xUnit cases passing");
        readme.Should().NotContain("1093 xUnit cases passing");
        readme.Should().NotContain("1092 xUnit cases passing");
        readme.Should().NotContain("1091 xUnit cases passing");
        readme.Should().NotContain("1090 xUnit cases passing");
        readme.Should().NotContain("1088 xUnit cases passing");
        readme.Should().NotContain("1087 xUnit cases passing");
        readme.Should().NotContain("1086 xUnit cases passing");
        readme.Should().NotContain("1085 xUnit cases passing");
        readme.Should().NotContain("1084 xUnit cases passing");
        readme.Should().NotContain("1081 xUnit cases passing");
        readme.Should().NotContain("1080 xUnit cases passing");
        readme.Should().NotContain("1079 xUnit cases passing");
        readme.Should().NotContain("1078 xUnit cases passing");
        readme.Should().NotContain("1075 xUnit cases passing");
        readme.Should().NotContain("1072 xUnit cases passing");
        readme.Should().NotContain("1070 xUnit cases passing");
        readme.Should().NotContain("1069 xUnit cases passing");
        readme.Should().NotContain("1068 xUnit cases passing");
        readme.Should().NotContain("1067 xUnit cases passing");
        readme.Should().NotContain("1066 xUnit cases passing");
        readme.Should().NotContain("1065 xUnit cases passing");
        readme.Should().NotContain("1064 xUnit cases passing");
        readme.Should().NotContain("1063 xUnit cases passing");
        readme.Should().NotContain("1062 xUnit cases passing");
        readme.Should().NotContain("1061 xUnit cases passing");
        readme.Should().NotContain("1060 xUnit cases passing");
        readme.Should().NotContain("1059 xUnit cases passing");
        readme.Should().NotContain("1058 xUnit cases passing");
        readme.Should().NotContain("1057 xUnit cases passing");
        readme.Should().NotContain("1056 xUnit cases passing");
        readme.Should().NotContain("1055 xUnit cases passing");
        readme.Should().NotContain("1054 xUnit cases passing");
        readme.Should().NotContain("1053 xUnit cases passing");
        readme.Should().NotContain("1052 xUnit cases passing");
        readme.Should().NotContain("1051 xUnit cases passing");
        readme.Should().NotContain("1050 xUnit cases passing");
        readme.Should().NotContain("1049 xUnit cases passing");
        readme.Should().NotContain("1048 xUnit cases passing");
        readme.Should().NotContain("1047 xUnit cases passing");
        readme.Should().NotContain("1046 xUnit cases passing");
        readme.Should().NotContain("1045 xUnit cases passing");
        readme.Should().NotContain("1044 xUnit cases passing");
        readme.Should().NotContain("1043 xUnit cases passing");
        readme.Should().NotContain("1042 xUnit cases passing");
        readme.Should().NotContain("1041 xUnit cases passing");
        readme.Should().NotContain("1037 xUnit cases passing");
        readme.Should().NotContain("1036 xUnit cases passing");
        readme.Should().NotContain("1035 xUnit cases passing");
        readme.Should().NotContain("1034 xUnit cases passing");
        readme.Should().NotContain("1033 xUnit cases passing");
        readme.Should().NotContain("1032 xUnit cases passing");
        readme.Should().NotContain("1031 xUnit cases passing");
        readme.Should().NotContain("1030 xUnit cases passing");
        readme.Should().NotContain("1028 xUnit cases passing");
        readme.Should().NotContain("1026 xUnit cases passing");
        readme.Should().NotContain("1024 xUnit cases passing");
        readme.Should().NotContain("1022 xUnit cases passing");
        readme.Should().NotContain("1021 xUnit cases passing");
        readme.Should().NotContain("1020 xUnit cases passing");
        readme.Should().NotContain("1019 xUnit cases passing");
        readme.Should().NotContain("1018 xUnit cases passing");
        readme.Should().NotContain("1015 xUnit cases passing");
        readme.Should().NotContain("1011 xUnit cases passing");
        readme.Should().NotContain("1007 xUnit cases passing");
        readme.Should().NotContain("1005 xUnit cases passing");
        readme.Should().NotContain("1003 xUnit cases passing");
        readme.Should().NotContain("1001 xUnit cases passing");
        readme.Should().NotContain("999 xUnit cases passing");
        readme.Should().NotContain("997 xUnit cases passing");
        readme.Should().NotContain("995 xUnit cases passing");
        readme.Should().NotContain("993 xUnit cases passing");
        readme.Should().NotContain("992 xUnit cases passing");
        readme.Should().NotContain("989 xUnit cases passing");
        readme.Should().NotContain("987 xUnit cases passing");
        readme.Should().NotContain("985 xUnit cases passing");
        readme.Should().NotContain("982 xUnit cases passing");
        readme.Should().NotContain("977 xUnit cases passing");
        readme.Should().NotContain("971 xUnit cases passing");
        readme.Should().NotContain("969 xUnit cases passing");
        readme.Should().NotContain("966 xUnit cases passing");
        readme.Should().NotContain("965 xUnit cases passing");
        readme.Should().NotContain("963 xUnit cases passing");
        readme.Should().NotContain("962 xUnit cases passing");
        readme.Should().NotContain("961 xUnit cases passing");
        readme.Should().NotContain("960 xUnit cases passing");
        readme.Should().NotContain("959 xUnit cases passing");
        readme.Should().NotContain("958 xUnit cases passing");
        readme.Should().NotContain("957 xUnit cases passing");
        readme.Should().NotContain("956 xUnit cases passing");
        readme.Should().NotContain("955 xUnit cases passing");
        readme.Should().NotContain("954 xUnit cases passing");
        readme.Should().NotContain("953 xUnit cases passing");
        readme.Should().NotContain("952 xUnit cases passing");
        readme.Should().NotContain("951 xUnit cases passing");
        readme.Should().NotContain("950 xUnit cases passing");
        readme.Should().NotContain("949 xUnit cases passing");
        readme.Should().NotContain("946 xUnit cases passing");
        readme.Should().NotContain("945 xUnit cases passing");
        readme.Should().NotContain("944 xUnit cases passing");
        readme.Should().NotContain("943 xUnit cases passing");
        readme.Should().NotContain("942 xUnit cases passing");
        readme.Should().NotContain("941 xUnit cases passing");
        readme.Should().NotContain("939 xUnit cases passing");
        readme.Should().NotContain("935 xUnit cases passing");
        readme.Should().NotContain("934 xUnit cases passing");
        readme.Should().NotContain("933 xUnit cases passing");
        readme.Should().NotContain("932 xUnit cases passing");
        readme.Should().NotContain("931 xUnit cases passing");
        readme.Should().NotContain("930 xUnit cases passing");
        readme.Should().NotContain("929 xUnit cases passing");
        readme.Should().NotContain("928 xUnit cases passing");
        readme.Should().NotContain("927 xUnit cases passing");
        readme.Should().NotContain("926 xUnit cases passing");
        readme.Should().NotContain("925 xUnit cases passing");
        readme.Should().NotContain("924 xUnit cases passing");
        readme.Should().NotContain("923 xUnit cases passing");
        readme.Should().NotContain("922 xUnit cases passing");
        readme.Should().NotContain("921 xUnit cases passing");
        readme.Should().NotContain("920 xUnit cases passing");
        readme.Should().NotContain("919 xUnit cases passing");
        readme.Should().NotContain("915 xUnit cases passing");
        readme.Should().NotContain("914 xUnit cases passing");
        readme.Should().NotContain("913 xUnit cases passing");
        readme.Should().NotContain("912 xUnit cases passing");
        readme.Should().NotContain("911 xUnit cases passing");
        readme.Should().NotContain("910 xUnit cases passing");
        readme.Should().NotContain("909 xUnit cases passing");
        readme.Should().NotContain("908 xUnit cases passing");
        readme.Should().NotContain("907 xUnit cases passing");
        readme.Should().NotContain("906 xUnit cases passing");
        readme.Should().NotContain("905 xUnit cases passing");
        readme.Should().NotContain("904 xUnit cases passing");
        readme.Should().NotContain("903 xUnit cases passing");
        readme.Should().NotContain("902 xUnit cases passing");
        readme.Should().NotContain("900 xUnit cases passing");
        readme.Should().NotContain("898 xUnit cases passing");
        readme.Should().NotContain("896 xUnit cases passing");
        readme.Should().NotContain("895 xUnit cases passing");
        readme.Should().NotContain("893 xUnit cases passing");
        readme.Should().NotContain("890 xUnit cases passing");
        readme.Should().NotContain("889 xUnit cases passing");
        readme.Should().NotContain("886 xUnit cases passing");
        readme.Should().NotContain("883 xUnit cases passing");
        readme.Should().NotContain("879 xUnit cases passing");
        readme.Should().NotContain("876 xUnit cases passing");
        readme.Should().NotContain("873 xUnit cases passing");
        readme.Should().NotContain("870 xUnit cases passing");
        readme.Should().NotContain("866 xUnit cases passing");
        readme.Should().NotContain("864 xUnit cases passing");
        readme.Should().NotContain("861 xUnit cases passing");
        readme.Should().NotContain("858 xUnit cases passing");
        readme.Should().NotContain("841 xUnit cases passing");
        readme.Should().NotContain("837 xUnit cases passing");
        readme.Should().NotContain("836 xUnit cases passing");
        readme.Should().NotContain("835 xUnit cases passing");
        readme.Should().NotContain("832 xUnit cases passing");
        readme.Should().NotContain("830 xUnit cases passing");
        readme.Should().NotContain("829 xUnit cases passing");
        readme.Should().NotContain("824 xUnit cases passing");
        readme.Should().NotContain("823 xUnit cases passing");
        readme.Should().NotContain("813 xUnit cases passing");
        readme.Should().NotContain("812 xUnit cases passing");
        readme.Should().NotContain("809 xUnit cases passing");
        readme.Should().NotContain("807 xUnit cases passing");
        readme.Should().NotContain("805 xUnit cases passing");
        readme.Should().NotContain("803 xUnit cases passing");
        readme.Should().NotContain("801 xUnit cases passing");
        readme.Should().NotContain("800 xUnit cases passing");
        readme.Should().NotContain("799 xUnit cases passing");
        readme.Should().NotContain("798 xUnit cases passing");
        readme.Should().NotContain("794 xUnit cases passing");
        readme.Should().NotContain("793 xUnit cases passing");
        readme.Should().NotContain("790 xUnit cases passing");
        readme.Should().NotContain("789 xUnit cases passing");
        readme.Should().NotContain("788 xUnit cases passing");
        readme.Should().NotContain("786 xUnit cases passing");
        readme.Should().NotContain("769 xUnit cases passing");
        readme.Should().NotContain("767 xUnit cases passing");
        readme.Should().NotContain("764 xUnit cases passing");
        readme.Should().NotContain("763 xUnit cases passing");
        readme.Should().NotContain("762 xUnit cases passing");
        readme.Should().NotContain("761 xUnit cases passing");
        readme.Should().NotContain("760 xUnit cases passing");
        readme.Should().NotContain("759 xUnit cases passing");
        readme.Should().NotContain("758 xUnit cases passing");
        readme.Should().NotContain("757 xUnit cases passing");
        readme.Should().NotContain("756 xUnit cases passing");
        readme.Should().NotContain("755 xUnit cases passing");
        readme.Should().NotContain("754 xUnit cases passing");
        readme.Should().NotContain("752 xUnit cases passing");
        readme.Should().NotContain("750 xUnit cases passing");
        readme.Should().NotContain("749 xUnit cases passing");
        readme.Should().NotContain("746 xUnit cases passing");
        readme.Should().NotContain("745 xUnit cases passing");
        readme.Should().NotContain("742 xUnit cases passing");
        readme.Should().NotContain("739 xUnit cases passing");
        readme.Should().NotContain("735 xUnit cases passing");
        readme.Should().NotContain("732 xUnit cases passing");
        readme.Should().NotContain("730 xUnit cases passing");
        readme.Should().NotContain("728 xUnit cases passing");
        readme.Should().NotContain("726 xUnit cases passing");
        readme.Should().NotContain("725 xUnit cases passing");
        readme.Should().NotContain("723 xUnit cases passing");
        readme.Should().NotContain("721 xUnit cases passing");
        readme.Should().NotContain("720 xUnit cases passing");
        readme.Should().NotContain("713 xUnit cases passing");
        readme.Should().NotContain("712 xUnit cases passing");
        readme.Should().NotContain("711 xUnit cases passing");
        readme.Should().NotContain("709 xUnit cases passing");
        readme.Should().NotContain("708 xUnit cases passing");
        readme.Should().NotContain("707 xUnit cases passing");
        readme.Should().NotContain("706 xUnit cases passing");
        readme.Should().NotContain("703 xUnit cases passing");
        readme.Should().NotContain("701 xUnit cases passing");
        readme.Should().NotContain("695 xUnit cases passing");
        readme.Should().Contain("Malformed manifest object-array sections");
        readme.Should().Contain("fail closed instead of silently shrinking the analyzed contract surface");
        readme.Should().Contain("Explicitly invalid Neo manifest metadata");
        readme.Should().Contain("duplicate `supportedstandards`");
        readme.Should().Contain("duplicate ABI method selectors with the same method name and parameter");
        readme.Should().Contain("Declared ABI events must include a non-empty `name`");
        readme.Should().Contain("duplicate ABI event names");
        readme.Should().Contain("`supportedstandards`, `trusts`, and permission method lists must contain strings");
        readme.Should().Contain("wrong-typed scalar fields are normalized to `FormatException`");
        readme.Should().NotContain("689 xUnit cases passing");
        readme.Should().NotContain("679 xUnit cases passing");
        readme.Should().NotContain("677 xUnit cases passing");
        readme.Should().NotContain("671 xUnit cases passing");
        readme.Should().NotContain("663 xUnit cases passing");
        readme.Should().NotContain("659 xUnit cases passing");
        readme.Should().NotContain("653 xUnit cases passing");
        readme.Should().NotContain("650 xUnit cases passing");
        readme.Should().NotContain("648 xUnit cases passing");
        readme.Should().NotContain("642 xUnit cases passing");
        readme.Should().NotContain("638 xUnit cases passing");
        readme.Should().NotContain("636 xUnit cases passing");
        readme.Should().NotContain("634 xUnit cases passing");
        readme.Should().NotContain("633 xUnit cases passing");
        readme.Should().NotContain("631 xUnit cases passing");
        readme.Should().NotContain("629 xUnit cases passing");
        readme.Should().NotContain("628 xUnit cases passing");
        readme.Should().NotContain("626 xUnit cases passing");
        readme.Should().NotContain("624 xUnit cases passing");
        readme.Should().NotContain("622 xUnit cases passing");
        readme.Should().NotContain("620 xUnit cases passing");
        readme.Should().NotContain("617 xUnit cases passing");
        readme.Should().NotContain("616 xUnit cases passing");
        readme.Should().NotContain("614 xUnit cases passing");
        readme.Should().NotContain("610 xUnit cases passing");
        readme.Should().NotContain("609 xUnit cases passing");
        readme.Should().NotContain("605 xUnit cases passing");
        readme.Should().NotContain("604 xUnit cases passing");
        readme.Should().NotContain("589 xUnit cases passing");
        readme.Should().NotContain("588 xUnit cases passing");
        readme.Should().NotContain("587 xUnit cases passing");
        readme.Should().NotContain("586 xUnit cases passing");
        readme.Should().NotContain("585 xUnit cases passing");
        readme.Should().NotContain("584 xUnit cases passing");
        readme.Should().NotContain("583 xUnit cases passing");
        readme.Should().NotContain("582 xUnit cases passing");
        readme.Should().NotContain("581 xUnit cases passing");
        readme.Should().NotContain("579 xUnit cases passing");
        readme.Should().NotContain("578 xUnit cases passing");
        readme.Should().NotContain("577 xUnit cases passing");
        readme.Should().NotContain("571 xUnit cases passing");
        readme.Should().NotContain("570 xUnit cases passing");
        readme.Should().NotContain("569 xUnit cases passing");
        readme.Should().NotContain("567 xUnit cases passing");
        readme.Should().NotContain("564 xUnit cases passing");
        readme.Should().NotContain("561 xUnit cases passing");
        readme.Should().NotContain("558 xUnit cases passing");
        readme.Should().NotContain("555 xUnit cases passing");
        readme.Should().NotContain("549 xUnit cases passing");
        readme.Should().NotContain("546 xUnit cases passing");
        readme.Should().NotContain("545 xUnit cases passing");
        readme.Should().NotContain("544 xUnit cases passing");
        readme.Should().NotContain("543 xUnit cases passing");
        readme.Should().NotContain("542 xUnit cases passing");
        readme.Should().NotContain("541 xUnit cases passing");
        readme.Should().NotContain("540 xUnit cases passing");
        readme.Should().NotContain("539 xUnit cases passing");
        readme.Should().NotContain("538 xUnit cases passing");
        readme.Should().NotContain("537 xUnit cases passing");
        readme.Should().NotContain("536 xUnit cases passing");
        readme.Should().NotContain("535 xUnit cases passing");
        readme.Should().NotContain("534 xUnit cases passing");
        readme.Should().NotContain("533 xUnit cases passing");
        readme.Should().NotContain("532 xUnit cases passing");
        readme.Should().NotContain("531 xUnit cases passing");
        readme.Should().NotContain("530 xUnit cases passing");
        readme.Should().NotContain("529 xUnit cases passing");
        readme.Should().NotContain("528 xUnit cases passing");
        readme.Should().NotContain("527 xUnit cases passing");
        readme.Should().NotContain("526 xUnit cases passing");
        readme.Should().NotContain("525 xUnit cases passing");
        readme.Should().NotContain("524 xUnit cases passing");
        readme.Should().NotContain("523 xUnit cases passing");
        readme.Should().NotContain("522 xUnit cases passing");
        readme.Should().NotContain("521 xUnit cases passing");
        readme.Should().NotContain("520 xUnit cases passing");
        readme.Should().NotContain("519 xUnit cases passing");
        readme.Should().NotContain("518 xUnit cases passing");
        readme.Should().NotContain("517 xUnit cases passing");
        readme.Should().NotContain("516 xUnit cases passing");
        readme.Should().NotContain("515 xUnit cases passing");
        readme.Should().NotContain("514 xUnit cases passing");
        readme.Should().NotContain("513 xUnit cases passing");
        readme.Should().NotContain("512 xUnit cases passing");
        readme.Should().NotContain("511 xUnit cases passing");
        readme.Should().NotContain("510 xUnit cases passing");
        readme.Should().NotContain("509 xUnit cases passing");
        readme.Should().NotContain("508 xUnit cases passing");
        readme.Should().NotContain("507 xUnit cases passing");
        readme.Should().NotContain("506 xUnit cases passing");
        readme.Should().NotContain("505 xUnit cases passing");
        readme.Should().NotContain("504 xUnit cases passing");
        readme.Should().NotContain("503 xUnit cases passing");
        readme.Should().NotContain("502 xUnit cases passing");
        readme.Should().NotContain("501 xUnit cases passing");
        readme.Should().NotContain("499 xUnit cases passing");
        readme.Should().NotContain("498 xUnit cases passing");
        readme.Should().NotContain("496 xUnit cases passing");
        readme.Should().NotContain("492 xUnit cases passing");
        readme.Should().NotContain("486 xUnit cases passing");
        readme.Should().NotContain("482 xUnit cases passing");
        readme.Should().NotContain("480 xUnit cases passing");
        readme.Should().NotContain("475 xUnit cases passing");
        readme.Should().NotContain("472 xUnit cases passing");
        readme.Should().NotContain("470 xUnit cases passing");
        readme.Should().NotContain("469 xUnit cases passing");
        readme.Should().NotContain("467 xUnit cases passing");
        readme.Should().NotContain("465 xUnit cases passing");
        readme.Should().NotContain("462 xUnit cases passing");
        readme.Should().NotContain("461 xUnit cases passing");
        readme.Should().NotContain("460 xUnit cases passing");
        readme.Should().NotContain("459 xUnit cases passing");
        readme.Should().NotContain("458 xUnit cases passing");
        readme.Should().NotContain("454 xUnit cases passing");
        readme.Should().NotContain("453 xUnit cases passing");
        readme.Should().NotContain("452 xUnit cases passing");
        readme.Should().NotContain("451 xUnit cases passing");
        readme.Should().NotContain("450 xUnit cases passing");
        readme.Should().NotContain("449 xUnit cases passing");
        readme.Should().NotContain("448 xUnit cases passing");
        readme.Should().NotContain("447 xUnit cases passing");
        readme.Should().NotContain("446 xUnit cases passing");
        readme.Should().NotContain("445 xUnit cases passing");
        readme.Should().NotContain("444 xUnit cases passing");
        readme.Should().NotContain("443 xUnit cases passing");
        readme.Should().NotContain("441 xUnit cases passing");
        readme.Should().NotContain("440 xUnit cases passing");
        readme.Should().NotContain("439 xUnit cases passing");
        readme.Should().NotContain("438 xUnit cases passing");
        readme.Should().NotContain("437 xUnit cases passing");
        readme.Should().NotContain("436 xUnit cases passing");
        readme.Should().NotContain("435 xUnit cases passing");
        readme.Should().NotContain("434 xUnit cases passing");
        readme.Should().NotContain("433 xUnit cases passing");
        readme.Should().NotContain("432 xUnit cases passing");
        readme.Should().NotContain("431 xUnit cases passing");
        readme.Should().NotContain("430 xUnit cases passing");
        readme.Should().NotContain("429 xUnit cases passing");
        readme.Should().NotContain("428 xUnit cases passing");
        readme.Should().NotContain("427 xUnit cases passing");
        readme.Should().NotContain("426 xUnit cases passing");
        readme.Should().NotContain("425 xUnit cases passing");
        readme.Should().NotContain("424 xUnit cases passing");
        readme.Should().NotContain("423 xUnit cases passing");
        readme.Should().NotContain("422 xUnit cases passing");
        readme.Should().NotContain("421 xUnit cases passing");
        readme.Should().NotContain("420 xUnit cases passing");
        readme.Should().NotContain("419 xUnit cases passing");
        readme.Should().NotContain("418 xUnit cases passing");
        readme.Should().NotContain("417 xUnit cases passing");
        readme.Should().NotContain("416 xUnit cases passing");
        readme.Should().NotContain("415 xUnit cases passing");
        readme.Should().NotContain("414 xUnit cases passing");
        readme.Should().NotContain("413 xUnit cases passing");
        readme.Should().NotContain("412 xUnit cases passing");
        readme.Should().NotContain("411 xUnit cases passing");
        readme.Should().NotContain("410 xUnit cases passing");
        readme.Should().NotContain("409 xUnit cases passing");
        readme.Should().NotContain("408 xUnit cases passing");
        readme.Should().NotContain("407 xUnit cases passing");
        readme.Should().NotContain("406 xUnit cases passing");
        readme.Should().NotContain("405 xUnit cases passing");
        readme.Should().NotContain("404 xUnit cases passing");
        readme.Should().NotContain("399 xUnit cases passing");
        readme.Should().NotContain("395 xUnit cases passing");
        readme.Should().NotContain("394 xUnit cases passing");
        readme.Should().NotContain("393 xUnit cases passing");
        readme.Should().NotContain("392 xUnit cases passing");
        readme.Should().NotContain("391 xUnit cases passing");
        readme.Should().NotContain("390 xUnit cases passing");
        readme.Should().NotContain("389 xUnit cases passing");
        readme.Should().NotContain("388 xUnit cases passing");
        readme.Should().NotContain("387 xUnit cases passing");
        readme.Should().NotContain("386 xUnit cases passing");
        readme.Should().NotContain("385 xUnit cases passing");
        readme.Should().NotContain("384 xUnit cases passing");
        readme.Should().NotContain("383 xUnit cases passing");
        readme.Should().NotContain("382 xUnit cases passing");
        readme.Should().NotContain("381 xUnit cases passing");
        readme.Should().NotContain("380 xUnit cases passing");
        readme.Should().NotContain("377 xUnit cases passing");
        readme.Should().NotContain("374 xUnit cases passing");
        readme.Should().NotContain("371 xUnit cases passing");
        readme.Should().NotContain("369 xUnit cases passing");
        readme.Should().NotContain("368 xUnit cases passing");
        readme.Should().NotContain("366 xUnit cases passing");
        readme.Should().NotContain("364 xUnit cases passing");
        readme.Should().NotContain("357 xUnit cases passing");
        readme.Should().Contain("Neo N3 C# coverage is first-class");
        readme.Should().Contain("`Integer` parameters carry NeoVM StackItem integer range constraints");
        readme.Should().Contain("fixed-size");
        readme.Should().Contain("ABI primitives such as `Hash160`, `Hash256`, `PublicKey`, and `Signature`");
        readme.Should().Contain("byte-length constraints at method entry");
        readme.Should().Contain("ABI `PublicKey` method-entry parameters prove 33-byte");
        readme.Should().Contain("valid secp256r1 ECPoint encoding");
        readme.Should().Contain("ABI returntype conformance for `PublicKey`");
        readme.Should().Contain("also requires a valid ECPoint encoding");
        readme.Should().Contain("ABI `Array`, `Map`, and `Struct` parameters");
        readme.Should().Contain("ABI `Any` parameters used by analyze and verification are explored across representative");
        readme.Should().Contain("`Null`,");
        readme.Should().Contain("`InteropInterface` method-entry states");
        readme.Should().Contain("reports still mark the surface non-exhaustive");
        readme.Should().Contain("normalized through NeoVM truthiness before SMT solving");
        readme.Should().Contain("`GetInvocationCounter` is stable within one invocation and");
        readme.Should().Contain("increments across modeled same-contract self-calls");
        readme.Should().Contain("Common Runtime environment syscalls");
        readme.Should().Contain("`Contract.Call` and NEF `CALLT` calls to the native StdLib `serialize`, `deserialize`,");
        readme.Should().Contain("`jsonSerialize`, and `jsonDeserialize`");
        readme.Should().Contain("closed symbolic StackItem summaries");
        readme.Should().Contain("manifest-permission telemetry");
        readme.Should().Contain("Concrete StdLib scalar conversions such as `itoa`, `atoi`, `strLen`, `stringSplit`,");
        readme.Should().Contain("`base64UrlEncode`, `base64UrlDecode`, `base58Encode`,");
        readme.Should().Contain("`base58Decode`, `base58CheckEncode`, `base58CheckDecode`, `hexEncode`, and `hexDecode`");
        readme.Should().Contain("two-argument `itoa`/`atoi` base-10/base-16 calls");
        readme.Should().Contain("concrete `memoryCompare` / `memorySearch` byte utilities");
        readme.Should().Contain("Concrete invalid decode text for");
        readme.Should().Contain("base64/base64Url, base58/base58Check, and hex decode methods");
        readme.Should().Contain("reported as a reachable VM");
        readme.Should().Contain("concrete invalid `atoi` text");
        readme.Should().Contain("unsupported concrete `itoa`/`atoi` bases fault");
        readme.Should().Contain("Concrete invalid strict-UTF8 strings");
        readme.Should().Contain("concrete StdLib");
        readme.Should().Contain("inputs over 1024 bytes");
        readme.Should().Contain("Native StdLib `itoa`/`atoi`, `strLen`, `stringSplit`, base64/base64Url");
        readme.Should().Contain("Native CryptoLib `sha256`, `ripemd160`, `keccak256`, and `murmur32` calls with concrete");
        readme.Should().Contain("symbolic ByteString hash inputs return stable");
        readme.Should().Contain("proof-grade 32-byte `sha256`/`keccak256`, 20-byte");
        readme.Should().Contain("`verifyWithEd25519`");
        readme.Should().Contain("concrete message/public-key/signature");
        readme.Should().Contain("symbolic ByteString");
        readme.Should().Contain("32-byte Ed25519 public key");
        readme.Should().Contain("`verifyWithECDsa` calls over Neo's");
        readme.Should().Contain("secp256k1/secp256r1 SHA256/Keccak256");
        readme.Should().Contain("proof-grade symbolic message/public-key/signature inputs");
        readme.Should().Contain("concrete invalid `murmur32`");
        readme.Should().Contain("unsupported ECDSA curve hashes");
        readme.Should().Contain("`recoverSecp256K1`");
        readme.Should().Contain("concrete 32-byte message hashes");
        readme.Should().Contain("recovery id is encoded as 0..3 or 27..30");
        readme.Should().Contain("symbolic ByteString inputs constrained to");
        readme.Should().Contain("32-byte message hash and 64/65-byte signature");
        readme.Should().Contain("concrete BLS12-381");
        readme.Should().Contain("deserialize/serialize/equal/add/mul/pairing");
        readme.Should().Contain("guarded");
        readme.Should().Contain("symbolic BLS12-381 deserialize/serialize round trips with valid compressed G1/G2/Gt encoding fault obligations");
        readme.Should().Contain("same-kind equal/add/mul results with valid scalar fault obligations for symbolic `mul`");
        readme.Should().Contain("G1-by-G2 pairing results");
        readme.Should().Contain("48-byte");
        readme.Should().Contain("G1, 96-byte G2, or 576-byte Gt");
        readme.Should().Contain("33-byte recovered compressed public key");
        readme.Should().Contain("verification result, proof-grade");
        readme.Should().Contain("nullable recovery failure");
        readme.Should().Contain("opaque external symbol");
        readme.Should().Contain("Native NEO/GAS NEP-17 read-only calls");
        readme.Should().Contain("`symbol`, `decimals`, `totalSupply`, and `balanceOf`, plus NEO `getGasPerBlock()`, `unclaimedGas(account,end)`, `getRegisterPrice()`, `getCandidateVote(pubkey)`, `getCandidates()`, `getAccountState(account)`, `getCommitteeAddress()`, `getCommittee()`, and `getNextBlockValidators()`");
        readme.Should().Contain("account-state balance/height/last-gas-per-vote fields, and governance prices return stable non-negative symbolic");
        readme.Should().Contain("`unclaimedGas(account,end)` enforces `end == Ledger.currentIndex + 1` and returns stable non-negative symbolic GAS");
        readme.Should().Contain("`getCandidateVote(pubkey)` enforces valid ECPoint public-key arguments and returns a stable integer bounded below by Neo's missing-candidate sentinel `-1`");
        readme.Should().Contain("`getCandidates()` returns an open array of candidate tuples with valid ECPoint keys and non-negative vote counts");
        readme.Should().Contain("`getAccountState(account)` returns null or Neo's four-field NeoAccountState struct with nullable valid-ECPoint `VoteTo` and non-negative `LastGasPerVote`");
        readme.Should().Contain("committee address returns a stable UInt160 witness principal");
        readme.Should().Contain("committee/validator reads return open arrays of valid ECPoint public keys");
        readme.Should().Contain("NEO/GAS `transfer(from,to,amount,data)` is modeled separately as a write-capable sensitive native");
        readme.Should().Contain("requires `CallFlags.All`, enforces UInt160 sender/recipient arguments and a non-negative");
        readme.Should().Contain("NeoVM integer amount within the 32-byte input limit");
        readme.Should().Contain("returns a symbolic Boolean result that must still be checked by the caller");
        readme.Should().Contain("remains a sensitive asset-moving call for access-control and manifest-permission proofs");
        readme.Should().Contain("stable non-negative symbolic");
        readme.Should().Contain("Stable native read keys include a structural expression fingerprint");
        readme.Should().Contain("effective call flags");
        readme.Should().Contain("dynamic flags remain");
        readme.Should().Contain("conservative incomplete surface instead of a proved native read");
        readme.Should().Contain("Ledger `currentIndex`, `currentHash`, `getBlockHash(index)`, `getBlock(hash/index)`, `getTransactionFromBlock(block,index)`, `getTransaction(hash)`, `getTransactionHeight(hash)`, `getTransactionSigners(hash)`, and `getTransactionVMState(hash)`");
        readme.Should().Contain("stable UInt32 block index");
        readme.Should().Contain("stable 32-byte Hash256");
        readme.Should().Contain("nullable block structs with Hash256 links, non-negative timestamp/index fields, Int32-bounded transaction counts, UInt160 next-consensus hashes");
        readme.Should().Contain("native UInt32 block-index and Int32 transaction-index preconditions");
        readme.Should().Contain("nullable transaction structs from either transaction hashes or block/index lookups with UInt160 senders, non-negative fees, bounded scripts, stable transaction height in `[-1, currentIndex]`, nullable signer arrays with UInt160 account fields and bounded witness scopes, and stable VMState enum value with UInt256 hash preconditions");
        readme.Should().Contain("ContractManagement `getMinimumDeploymentFee()`");
        readme.Should().Contain("stable non-negative chain-configuration integer");
        readme.Should().Contain("ContractManagement `hasMethod`");
        readme.Should().Contain("stable boolean query");
        readme.Should().Contain("non-negative Int32 parameter count");
        readme.Should().Contain("returning");
        readme.Should().Contain("false when path-local existence facts prove the target contract is missing");
        readme.Should().Contain("true");
        readme.Should().Contain("`hasMethod(target,...)` result proves target contract existence");
        readme.Should().Contain("`getContract`");
        readme.Should().Contain("`getContractById(id)`");
        readme.Should().Contain("nullable contract interop results");
        readme.Should().Contain("through both");
        readme.Should().Contain("`Contract.Call` and NEF `CALLT`");
        readme.Should().Contain("contract id fits Neo's native Int32 conversion");
        readme.Should().Contain("a non-null `getContract(target)` result");
        readme.Should().Contain("proves `isContract(target)` on that same path");
        readme.Should().Contain("prior `isContract(target)` facts constrain");
        readme.Should().Contain("later `getContract(target)` results to null/non-null consistently");
        readme.Should().Contain("`isContract` forks stable");
        readme.Should().Contain("true/false existence");
        readme.Should().Contain("`getContractHashes()`");
        readme.Should().Contain("StorageIterator");
        readme.Should().Contain("`RemovePrefix` option");
        readme.Should().Contain("key/value pair results");
        readme.Should().Contain("ContractManagement `deploy(nef,manifest,data)` returns a");
        readme.Should().Contain("`Contract` interop result while remaining a write-capable sensitive external call");
        readme.Should().Contain("strict-UTF8 manifest validation");
        readme.Should().Contain("non-Void MethodToken stack semantics");
        readme.Should().Contain("ContractManagement `update(nef,manifest,data)` and");
        readme.Should().Contain("`destroy()` lifecycle calls are recognized as write-capable sensitive native calls");
        readme.Should().Contain("lifecycle calls do not count as");
        readme.Should().Contain("read-only modeled native calls");
        readme.Should().Contain("security-profile proofs must still prove authorization and");
        readme.Should().Contain("manifest-permission posture");
        readme.Should().Contain("receiver is not a contract");
        readme.Should().Contain("Policy `getFeePerByte`, `getExecFeeFactor`");
        readme.Should().Contain("`getStoragePrice`, `getAttributeFee(attributeType)`, and Oracle");
        readme.Should().Contain("valid `TransactionAttributeType` enum values");
        readme.Should().Contain("Policy `isBlocked(account)`");
        readme.Should().Contain("stable boolean query with a UInt160 account precondition");
        readme.Should().Contain("Oracle `getPrice`");
        readme.Should().Contain("stable non-negative");
        readme.Should().Contain("chain-configuration integers");
        readme.Should().Contain("Oracle `request(url,filter,callback,userData,gasForResponse)`");
        readme.Should().Contain("sensitive");
        readme.Should().Contain("write-capable no-return native call");
        readme.Should().Contain("`States|AllowNotify` flags");
        readme.Should().Contain("public callback-name enforcement");
        readme.Should().Contain("512-byte userData bounds");
        readme.Should().Contain("10,000,000 datoshi response-gas floor");
        readme.Should().Contain("success paths");
        readme.Should().Contain("proof-visible `Transfer(from,to,amount)` notification payload");
        readme.Should().Contain("native token balance changes and receiver callback side effects");
        readme.Should().Contain("native NEO/GAS `transfer` as incomplete VM surface");
        readme.Should().Contain("RoleManagement `getDesignatedByRole(role, index)`");
        readme.Should().Contain("native UInt32 index conversion");
        readme.Should().Contain("designated-public-key array");
        readme.Should().Contain("33-byte");
        readme.Should().Contain("valid ECPoint");
        readme.Should().Contain("remaining unmodeled ContractManagement methods");
        readme.Should().Contain("unmodeled RoleManagement methods");
        readme.Should().Contain("unmodeled Policy/Oracle methods");
        readme.Should().Contain("method-specific proof model is missing");
        readme.Should().Contain("recognized Neo N3 native contract methods");
        readme.Should().Contain("incomplete proof surface");
        readme.Should().Contain("`CONVERT` preserves symbolic Boolean branches");
        readme.Should().Contain("fixed-length symbolic `ByteString` values");
        readme.Should().Contain("mutable heap-backed `Buffer` objects");
        readme.Should().Contain("`ISTYPE` guards on unknown external returns refine subsequent `CONVERT` operations");
        readme.Should().Contain("Stable runtime values such as `GetNetwork` and `GetAddressVersion` reuse the same symbolic");
        readme.Should().Contain("`CurrentSigners` exposes an open transaction-signer array");
        readme.Should().Contain("including a 20-byte account");
        readme.Should().Contain("same signer-array reference within one invocation");
        readme.Should().Contain("`GetScriptContainer` / `Runtime.Transaction` returns a modeled transaction structure");
        readme.Should().Contain("20-byte sender");
        readme.Should().Contain("transaction hash is modeled as 32 bytes");
        readme.Should().Contain("script is a bounded byte string");
        readme.Should().Contain("same transaction-container reference within one invocation");
        readme.Should().Contain("`GetNotifications` returns the path-local invocation notification list");
        readme.Should().Contain("each recorded notification's own script hash");
        readme.Should().Contain("Concrete non-matching filters return an empty array");
        readme.Should().Contain("symbolic filters that cannot be proven to match or miss");
        readme.Should().Contain("`CallingScriptHash`, `ExecutingScriptHash`, and `EntryScriptHash`");
        readme.Should().Contain("`CallingScriptHash` may be `null` in entry context");
        readme.Should().Contain("every non-null");
        readme.Should().Contain("runtime script hash carries Neo's 20-byte UInt160 shape");
        readme.Should().Contain("`Runtime.GetExecutingScriptHash` is bound to the computed deployed");
        readme.Should().Contain("`Runtime.GetTrigger` defaults to `Application`");
        readme.Should().Contain("ABI `verify` methods run with the `Verification`");
        readme.Should().Contain("verification artifacts record `default_runtime_trigger`");
        readme.Should().Contain("`Runtime.GetTime` requires");
        readme.Should().Contain("stable non-negative");
        readme.Should().Contain("produce a reachable VM fault");
        readme.Should().Contain("`Runtime.GetRandom` returns a fresh non-negative symbolic integer");
        readme.Should().Contain("without incorrectly treating repeated calls as stable");
        readme.Should().Contain("Unknown syscall hashes stop exploration conservatively");
        readme.Should().Contain("executing following bytecode with an unreliable stack");
        readme.Should().Contain("Direct `NativeOnPersist` and `NativePostPersist` use from user contracts faults");
        readme.Should().Contain("native lifecycle hooks require the matching system trigger");
        readme.Should().Contain("`Runtime.LoadScript` executes concrete nested script payloads");
        readme.Should().Contain("effective read-only call flags");
        readme.Should().Contain("nested caller/executing script-hash context");
        readme.Should().Contain("NeoVM return-stack merging");
        readme.Should().Contain("Dynamic payloads, open argument lists, and excessive nesting remain conservative incomplete proof");
        readme.Should().Contain("open argument lists");
        readme.Should().Contain("scoped by the property's");
        readme.Should().Contain("infeasible or excluded dynamic-load path");
        readme.Should().Contain("Custom proofs execute concrete same-contract `Contract.Call` self-calls");
        readme.Should().Contain("same-contract NEF");
        readme.Should().Contain("current script hash/token hash");
        readme.Should().Contain("method selector, effective call");
        readme.Should().Contain("argument list, and unique manifest ABI");
        readme.Should().Contain("unique manifest ABI");
        readme.Should().Contain("Dynamic self-calls");
        readme.Should().Contain("non-modeled-native external `Contract.Call` / NEF");
        readme.Should().Contain("remain incomplete until the");
        readme.Should().Contain("callee implementation semantics");
        readme.Should().Contain("postcondition proofs");
        readme.Should().Contain("manifest");
        readme.Should().Contain("permissions authorize a call");
        readme.Should().Contain("do not prove external");
        readme.Should().Contain("callee semantics for fault-freedom");
        readme.Should().Contain("postcondition proofs");
        readme.Should().Contain("--dependency-proof-summary <path.json>");
        readme.Should().Contain("--dependency-proof-artifact <hash=program,manifest>");
        readme.Should().Contain("--trust-dependency-proof-summaries");
        readme.Should().Contain("--allow-unbound-dependency-proof-summaries");
        readme.Should().Contain("--emit-dependency-proof-summary <path.json>");
        readme.Should().Contain("security.vm_surface");
        readme.Should().Contain("security.vm_fault_free");
        readme.Should().Contain("security.abi_return_type");
        readme.Should().Contain("built-in `neo-n3-security` profile");
        readme.Should().Contain("Custom specs that reuse");
        readme.Should().Contain("`security.*` result ids cannot emit trusted dependency summaries");
        readme.Should().Contain("`--allow-unproved`");
        readme.Should().Contain("cannot emit trusted dependency summaries");
        readme.Should().Contain("explicitly trusted for this verification run");
        readme.Should().Contain("trusted dependency proof summary");
        readme.Should().Contain("type-sensitive `EQUAL` / `NOTEQUAL` path condition");
        readme.Should().Contain("an `Array` parameter proof does not cover a caller that passes a `Struct`");
        readme.Should().Contain("public `DependencyProofSummarySet` construction default to untrusted summaries");
        readme.Should().Contain("SDK callers must");
        readme.Should().Contain("explicitly set `TrustedForExternalCalls`");
        readme.Should().Contain("reusable v3 proof summary");
        readme.Should().Contain("`unbound_dependency_proof_summary` assumption-backed proofs");
        readme.Should().Contain("fail the default unqualified-proof");
        readme.Should().Contain("cannot be emitted from reports that trusted unbound transitive dependency summaries");
        readme.Should().Contain("`initial_runtime_trigger`");
        readme.Should().Contain("Verification-trigger proofs for `verify` methods cannot close Application-trigger external calls");
        readme.Should().Contain("If a summary claims `require_external_smt`");
        readme.Should().Contain("non-portable external solver version");
        readme.Should().Contain("fail-on-unproved");
        readme.Should().Contain("unqualified-proof gate");
        readme.Should().Contain("`meta.inputs.dependency_proof_policy`");
        readme.Should().Contain("legacy unbound v1");
        readme.Should().Contain("mismatched proof identity metadata");
        readme.Should().Contain("assumption-backed proof metadata");
        readme.Should().Contain("invalid checksum/hash bindings");
        readme.Should().Contain("recomputes the Neo N3 contract hash");
        readme.Should().Contain("unused dependency proof artifact bindings");
        readme.Should().Contain("legacy/offline unbound summaries");
        readme.Should().Contain("missing typed parameters for");
        readme.Should().Contain("missing or invalid `initial_runtime_trigger`");
        readme.Should().Contain("forged external-SMT claims");
        readme.Should().Contain("unknown schema fields");
        readme.Should().Contain("duplicate external-call");
        readme.Should().Contain("selectors or contract hashes are rejected");
        readme.Should().Contain("`meta.inputs.dependency_proof_summaries`");
        readme.Should().Contain("deterministic symbolic account-hash");
        readme.Should().Contain("account creation enforces Neo's");
        readme.Should().Contain("`1 <= m <= publicKeys.Count <= 1024` precondition");
        readme.Should().Contain("Current Neo call flags are modeled");
        readme.Should().Contain("`System.Contract.GetCallFlags` returns the active context");
        readme.Should().Contain("ReadStates");
        readme.Should().Contain("WriteStates");
        readme.Should().Contain("AllowCall");
        readme.Should().Contain("AllowNotify");
        readme.Should().Contain("Direct `System.Contract.CallNative` use from user contracts faults");
        readme.Should().Contain("Native read-only allowlist (`Ledger`, `StdLib`, current `CryptoLib` hash/signature methods, etc.)");
        readme.Should().Contain("DevPack `Storage.Local.*`");
        readme.Should().Contain("`security.vm_fault_free.<method>`");
        readme.Should().Contain("unexpected reachable");
        readme.Should().Contain("NeoVM faults");
        readme.Should().Contain("satisfiable syscall precondition faults");
        readme.Should().Contain("Explicit rejection faults from `ASSERT` and `ABORT` paths");
        readme.Should().Contain("malformed witness targets are VM/syscall faults");
        readme.Should().Contain("custom `forbid_faults` for absolute");
        readme.Should().Contain("path-condition snapshot captured at the instruction");
        readme.Should().Contain("later `ASSERT` statements or branch refinements cannot retroactively");
        readme.Should().Contain("prove an earlier `PICKITEM`, native precondition, or arithmetic operation fault-free");
        readme.Should().Contain("Stable `CheckWitness` principals include 20-byte UInt160");
        readme.Should().Contain("valid 33-byte compressed secp256r1 public keys");
        readme.Should().Contain("`CreateStandardAccount` /");
        readme.Should().Contain("`CreateMultisigAccount` account hashes derived from stable valid ECPoint public keys");
        readme.Should().Contain("Stable caller-hash principals include the current executing script hash");
        readme.Should().Contain("`CallingScriptHash == ExecutingScriptHash`");
        readme.Should().Contain("Stable `CheckSig` /");
        readme.Should().Contain("`CheckMultisig` / CryptoLib signature principals include valid");
        readme.Should().Contain("33-byte compressed or 65-byte uncompressed secp256r1 public keys");
        readme.Should().Contain("65-byte uncompressed secp256r1 public keys");
        readme.Should().Contain("CryptoLib signature principals");
        readme.Should().Contain("32-byte Ed25519 public keys");
        readme.Should().Contain("stable `CheckMultisig`");
        readme.Should().Contain("public-key arrays must");
        readme.Should().Contain("must be closed, non-empty");
        readme.Should().Contain("non-empty, and contain only valid ECPoint public keys");
        readme.Should().Contain("CryptoLib signatures over an explicit message also require");
        readme.Should().Contain("signed message to be");
        readme.Should().Contain("operation-bound");
        readme.Should().Contain("valid signature over an unrelated message does not authorize");
        readme.Should().Contain("Caller-provided signature");
        readme.Should().Contain("derived accounts that are unrelated to the mutation");
        readme.Should().Contain("Non-transfer methods do not get authorization credit merely because a parameter is named");
        readme.Should().Contain("NEP-17/NEP-11 transfer sender semantics are handled by the dedicated token proofs");
        readme.Should().Contain("concrete byte-equivalent symbolic storage model");
        readme.Should().Contain("neo-sym verify");
        readme.Should().Contain("--profile neo-n3-security");
        readme.Should().Contain("--require-external-smt");
        readme.Should().Contain("`decode` and `explore` accept exactly one script/NEF path");
        readme.Should().Contain("unexpected trailing arguments fail");
        readme.Should().Contain("reject paths that");
        readme.Should().Contain("would overwrite input artifacts");
        readme.Should().Contain("symlink targets for input artifacts");
        readme.Should().Contain("sibling verification");
        readme.Should().Contain("output");
        readme.Should().Contain("meta.inputs");
        readme.Should().Contain("meta.inputs.dependency_proof_summaries");
        readme.Should().Contain("meta.inputs.dependency_proof_artifacts");
        readme.Should().Contain("meta.inputs.dependency_proof_policy");
        readme.Should().Contain("dependency proof artifact contract hashes");
        readme.Should().Contain("meta.smt_solver_version");
        readme.Should().Contain("meta.engine_options.initial_call_flags");
        readme.Should().Contain("meta.engine_options.default_runtime_trigger");
        readme.Should().NotContain("meta.default_runtime_trigger");
        readme.Should().Contain("meta.engine_options");
        readme.Should().Contain("`security.contract_identity.*` as `incomplete`");
        readme.Should().Contain("fail the default proof gate until the deployed");
        readme.Should().Contain("Raw `.bin` scripts have no NEF checksum");
        readme.Should().Contain("Per-property verification results include the resolved");
        readme.Should().Contain("overload-specific proofs and");
        readme.Should().Contain("profile obligations remain auditable");
        readme.Should().Contain("`source_profile: \"neo-n3-security\"`");
        readme.Should().Contain("required when emitting dependency proof summaries");
        readme.Should().Contain("`assumptions` array");
        readme.Should().Contain("`nep_token_storage_integer_encoding`");
        readme.Should().Contain("Storage.Get values used as NEP token integers");
        readme.Should().Contain("assumed to be present and encoded as NeoVM integers");
        readme.Should().Contain("`nep11_owner_storage_hash160_encoding`");
        readme.Should().Contain("Storage.Get values used as token owners");
        readme.Should().Contain("20-byte UInt160 owner values");
        readme.Should().Contain("limited to complete exact-standard NEP-17/NEP-11 ABI manifests");
        readme.Should().Contain("standard token storage methods such as `transfer`, `balanceOf`, `totalSupply`, and");
        readme.Should().Contain("recognized balance/account-token and returned `totalSupply()` storage reads");
        readme.Should().Contain("while auxiliary");
        readme.Should().Contain("storage integers keep the ordinary conversion fault obligations");
        readme.Should().Contain("non-divisible `ownerOf`");
        readme.Should().Contain("Malformed same-name ABI methods keep");
        readme.Should().Contain("the ordinary conversion fault obligations");
        readme.Should().Contain("`status: \"proved_with_assumptions\"`");
        readme.Should().Contain("`base_status: \"proved\"`");
        readme.Should().Contain("`proved_under_assumptions: true`");
        readme.Should().Contain("`proved_without_assumptions`");
        readme.Should().Contain("`proved_with_assumptions`");
        readme.Should().Contain("`all_proved_without_assumptions`");
        readme.Should().Contain("default verification gate requires unqualified proofs");
        readme.Should().Contain("assumption-backed profile results fail the gate");
        readme.Should().Contain("--allow-assumption-backed-proofs");
        readme.Should().Contain("Markdown verification reports order");
        readme.Should().Contain("Markdown verification reports include each result's");
        readme.Should().Contain("per-property source profile");
        readme.Should().Contain("dependency proof artifact provenance");
        readme.Should().Contain("dependency proof trust policy");
        readme.Should().Contain("failing proof obligations early");
        readme.Should().Contain("gate_evaluation");
        readme.Should().Contain("policies.fail_on_unproved");
        readme.Should().Contain("policies.unproved_allowed");
        readme.Should().Contain("policies.require_external_smt");
        readme.Should().Contain("policies.require_unqualified_proofs");
        readme.Should().Contain("assumption_backed_proofs");
        readme.Should().Contain("initial_call_flags");
        readme.Should().Contain("exact effective call flags");
        readme.Should().Contain("legacy v1/v2 summaries");
        readme.Should().Contain("individual property was proved");
        readme.Should().Contain("--allow-unproved");
        readme.Should().Contain("default analyze gate fails on `high`/`critical` findings");
        readme.Should().Contain("Use `--fail-on-max-severity <sev>`");
        readme.Should().Contain("Budget-aware gating is on by default");
        readme.Should().Contain("--max-visits-per-offset");
        readme.Should().Contain("--max-queued-states");
        readme.Should().Contain("budget_exceeded");
        readme.Should().Contain("budget_reason");
        readme.Should().Contain("{ \"return\": true");
        readme.Should().Contain("no_implicit_vm_faults");
        readme.Should().Contain("Postconditions are never proved");
        readme.Should().Contain("vacuously: a property with `ensures`");
        readme.Should().Contain("at least one successful HALT path");
        readme.Should().Contain("feasible under the full `requires`");
        readme.Should().Contain("implicit VM fault preconditions are excluded");
        readme.Should().Contain("return-scoped predicates");
        readme.Should().Contain("{ \"return\": true }");
        readme.Should().Contain("Before evaluating return-targeted predicates");
        readme.Should().Contain("non-return `requires` clauses filter HALT paths");
        readme.Should().Contain("different runtime StackItem type");
        readme.Should().Contain("Input-targeted `requires` are also checked against ABI method-entry constraints");
        readme.Should().Contain("empty ABI input domain");
        readme.Should().Contain("instead of proving fault freedom");
        readme.Should().Contain("Solver `Unknown` never counts as proof of path feasibility");
        readme.Should().Contain("concrete byte-pick facts for `first_byte` / `PICKITEM` expressions");
        readme.Should().Contain("\"metric\": \"size\"");
        readme.Should().Contain("\"metric\": \"first_byte\"");
        readme.Should().Contain("ByteString length metric");
        readme.Should().Contain("`storage_read` conditions must reference a `Storage.Get` / `Storage.Local.Get` offset");
        readme.Should().Contain("Exact ByteString-like spec values use the same byte-sequence equality model");
        readme.Should().Contain("symbolic VM");
        readme.Should().Contain("`EQUAL` path conditions");
        readme.Should().Contain("value_arg");
        readme.Should().Contain("{ \"return\": true, \"op\": \"==\", \"value_arg\": \"owner\" }");
        readme.Should().Contain("{ \"storage_put\": 64, \"op\": \"==\", \"value_arg\": \"amount\" }");
        readme.Should().Contain("Integer-to-Integer");
        readme.Should().Contain("Boolean-to-Boolean");
        readme.Should().Contain("ByteString-like exact byte equality");
        readme.Should().Contain("notification_arg");
        readme.Should().Contain("{ \"notification_arg\": \"Transfer\", \"index\": 2, \"op\": \"==\", \"value_arg\": \"amount\" }");
        readme.Should().Contain("\"notification_emitter\": \"current\"");
        readme.Should().Contain("\"notification_script_hash\"");
        readme.Should().Contain("same-name events such as native GAS/NEO");
        readme.Should().Contain("versus a user contract's own");
        readme.Should().Contain("`Transfer` event");
        readme.Should().Contain("`notification`, `notification_arg`, and `external_call_after_notification` can add");
        readme.Should().Contain("Add");
        readme.Should().Contain("`notification_emitter` when the ordering must be relative to the current contract's event");
        readme.Should().Contain("native NEO/GAS `Transfer` notifications with matching payloads do not satisfy");
        readme.Should().Contain("A missing event or missing payload index violates the condition");
        readme.Should().Contain("repeated matching events");
        readme.Should().Contain("open symbolic payload arrays");
        readme.Should().Contain("unobserved storage-read offsets or");
        readme.Should().Contain("ambiguous repeated reads at");
        readme.Should().Contain("the same offset are reported as `incomplete`");
        readme.Should().Contain("`storage_put` conditions are postconditions for `ensures`");
        readme.Should().Contain("unobserved write offsets or ambiguous repeated writes are reported");
        readme.Should().Contain("storage-write invariants such as non-negative balances");
        readme.Should().Contain("native NEO/GAS `transfer` balance");
        readme.Should().Contain("reachable native storage mutation");
        readme.Should().Contain("{ \"notification\": \"Transfer\", \"metric\": \"count\"");
        readme.Should().Contain("`notification` count conditions are postconditions for `ensures`");
        readme.Should().Contain("emits the expected concrete event count");
        readme.Should().Contain("dynamic or unknown event name");
        readme.Should().Contain("{ \"external_call\": \"onNEP17Payment\", \"metric\": \"count\"");
        readme.Should().Contain("\"external_call_contract\": \"gas\"");
        readme.Should().Contain("\"external_call_script_hash\"");
        readme.Should().Contain("native GAS/NEO `transfer` does not satisfy a user-token");
        readme.Should().Contain("dynamic or unresolved target");
        readme.Should().Contain("external_call_target");
        readme.Should().Contain("{ \"external_call_target\": \"onNEP17Payment\", \"op\": \"==\", \"value_arg\": \"to\" }");
        readme.Should().Contain("external_call_arg");
        readme.Should().Contain("{ \"external_call_arg\": \"onNEP17Payment\", \"index\": 1, \"op\": \"==\", \"value_arg\": \"amount\" }");
        readme.Should().Contain("external_call_after_notification");
        readme.Should().Contain("{ \"external_call_after_notification\": \"onNEP17Payment\", \"notification_before\": \"Transfer\", \"op\": \"==\", \"value\": true }");
        readme.Should().Contain("`external_call` count conditions are also postconditions for `ensures`");
        readme.Should().Contain("count successful-path");
        readme.Should().Contain("concrete method");
        readme.Should().Contain("selector");
        readme.Should().Contain("external call targets and payload arguments");
        readme.Should().Contain("A missing call or missing argument index");
        readme.Should().Contain("violates the condition");
        readme.Should().Contain("dynamic method selectors or repeated matching external calls");
        readme.Should().Contain("prove callback");
        readme.Should().Contain("ordering relative to emitted events");
        readme.Should().Contain("emit `Transfer` before `onNEP17Payment`");
        readme.Should().Contain("Missing calls");
        readme.Should().Contain("missing prior notifications");
        readme.Should().Contain("`\"require_external_call_completeness\": false`");
        readme.Should().Contain("{ \"witness\": \"owner\", \"metric\": \"enforced_count\"");
        readme.Should().Contain("`witness` enforced-count conditions can be used as state-scoped `requires`");
        readme.Should().Contain("count only");
        readme.Should().Contain("`Runtime.CheckWitness` results");
        readme.Should().Contain("consumed by an `ASSERT`");
        readme.Should().Contain("dropping the result does not satisfy the condition");
        readme.Should().Contain("scope proofs to paths where a Neo witness");
        readme.Should().Contain("`Hash256` or `Signature` are rejected as witness targets");
        readme.Should().Contain("{ \"caller_hash\": \"owner\", \"metric\": \"enforced_count\"");
        readme.Should().Contain("`caller_hash` enforced-count conditions can be used as state-scoped `requires`");
        readme.Should().Contain("scope fault-freedom, side-effect, and");
        readme.Should().Contain("return proofs");
        readme.Should().Contain("`Runtime.GetCallingScriptHash() == target` checks");
        readme.Should().Contain("consumed by `ASSERT` or a branch");
        readme.Should().Contain("Reading the caller hash and dropping it");
        readme.Should().Contain("does not satisfy the condition");
        readme.Should().Contain("`Hash256`,");
        readme.Should().Contain("are rejected as caller-hash targets");
        readme.Should().Contain("{ \"signature_check\": \"pubkey\", \"metric\": \"enforced_count\"");
        readme.Should().Contain("`signature_check` enforced-count conditions can be used as state-scoped `requires`");
        readme.Should().Contain("`System.Crypto.CheckSig` /");
        readme.Should().Contain("`System.Crypto.CheckMultisig`, `CryptoLib.verifyWithECDsa`, or `CryptoLib.verifyWithEd25519`");
        readme.Should().Contain("results consumed by `ASSERT`");
        readme.Should().Contain("scope proofs to paths where a signature or multisignature authorization");
        readme.Should().Contain("CryptoLib verification and dropping the result does not satisfy the condition");
        readme.Should().Contain("32-byte Ed25519 public key");
        readme.Should().Contain("Constant");
        readme.Should().Contain("public-key targets also match closed `CheckMultisig` public-key arrays only when");
        readme.Should().Contain("partial multi-signature arrays remain");
        readme.Should().Contain("conservative `incomplete`");
        readme.Should().Contain("Open ABI `Array` inputs");
        readme.Should().Contain("dynamic");
        readme.Should().Contain("`CheckMultisig` public-key lists");
        readme.Should().Contain("Argument conditions are ABI type checked");
        readme.Should().Contain("Boolean` parameters accept only `==` / `!=` boolean comparisons");
        readme.Should().Contain("variable-byte ABI");
        readme.Should().Contain("`ByteString`, `ByteArray`, and `String`");
        readme.Should().Contain("`0 <= size <= MaxItemSize`");
        readme.Should().Contain("ABI `String` parameters additionally carry strict UTF-8 validity facts");
        readme.Should().Contain("may use a metric such as `size` or `first_byte`");
        readme.Should().Contain("{ \"arg\": \"to\", \"op\": \"!=\", \"value\": \"0x0000000000000000000000000000000000000000\" }");
        readme.Should().Contain("`0x...` / `hex:...` byte constants");
        readme.Should().Contain("zero addresses, owner accounts, and known script hashes");
        readme.Should().Contain("Custom specs must name a unique ABI method");
        readme.Should().Contain("`parameter_types`");
        readme.Should().Contain("`method_offset`");
        readme.Should().Contain("C# overloads or display-name attributes");
        readme.Should().Contain("same-named methods with different parameter counts");
        readme.Should().Contain("with the same parameter");
        readme.Should().Contain("count are rejected as malformed");
        readme.Should().Contain("dispatches `Contract.Call` by method name and");
        readme.Should().Contain("parameter count, not by ABI parameter type");
        readme.Should().Contain("multiple matching methods");
        readme.Should().Contain("duplicate ABI parameter names");
        readme.Should().Contain("cannot bind");
        readme.Should().Contain("ambiguous arguments soundly");
        readme.Should().Contain("Argument conditions must use manifest ABI parameter names");
        readme.Should().Contain("`Void` is treated as a return-only ABI type");
        readme.Should().Contain("`Void` parameters fail closed");
        readme.Should().Contain("synthetic ByteString inputs");
        readme.Should().Contain("Return-targeted conditions require a non-`Void` manifest return type");
        readme.Should().Contain("stray value left on the");
        readme.Should().Contain("Void` method is not treated as a proof-grade method return value");
        readme.Should().Contain("Return-targeted conditions are currently proof-grade for manifest `Boolean`, `Integer`,");
        readme.Should().Contain("ByteString-like returns with metrics or exact byte-string values");
        readme.Should().Contain("closed `Array` /");
        readme.Should().Contain("`Struct` / `Map` returns with `count` metrics");
        readme.Should().Contain("{ \"return\": true, \"metric\": \"count\", \"op\": \">=\", \"value\": 1 }");
        readme.Should().Contain("JSON `value` kind must match the manifest return type");
        readme.Should().Contain("`Hash160` / `Hash256` / `String` / `ByteString` returns must use a metric");
        readme.Should().Contain("byte-string value for `==` / `!=`");
        readme.Should().Contain("For manifest `Integer` returns, successful HALT paths must also return an Integer StackItem");
        readme.Should().Contain("coerced into numeric proof conditions");
        readme.Should().Contain("For ByteString-like return metrics and byte-string values, successful HALT paths must return a ByteString StackItem");
        readme.Should().Contain("open collection returns are reported as `incomplete`");
        readme.Should().Contain("\"forbid_storage_mutation\": true");
        readme.Should().Contain("\"forbid_external_calls\": true");
        readme.Should().Contain("\"forbid_notifications\": true");
        readme.Should().Contain("reachable");
        readme.Should().Contain("`Storage.Put` / `Storage.Delete`");
        readme.Should().Contain("remaining non-inlined `Contract.Call` / NEF `CALLT`");
        readme.Should().Contain("`Runtime.Notify` events are reported as concrete violations");
        readme.Should().Contain("ContractManagement lifecycle calls");
        readme.Should().Contain("Oracle.request");
        readme.Should().Contain("native NEO/GAS `transfer` balance");
        readme.Should().Contain("reachable native");
        readme.Should().Contain("storage mutation and native notification effects");
        readme.Should().Contain("Same-contract calls already");
        readme.Should().Contain("treated as internal execution");
        readme.Should().Contain("\"forbid_faults\": true");
        readme.Should().Contain("Return-scoped `requires`");
        readme.Should().Contain("evaluated only on successful HALT paths");
        readme.Should().Contain("residual stack items cannot hide reachable VM faults");
        readme.Should().Contain("Verification specs are bounded external inputs");
        readme.Should().Contain("at most 16");
        readme.Should().Contain("256 properties");
        readme.Should().Contain("128 conditions");
        readme.Should().Contain("wrong-typed scalar fields");
        readme.Should().Contain("`version`,");
        readme.Should().Contain("`id`, `method`, `arg`, `metric`, or `op`");
        readme.Should().Contain("produce `FormatException` diagnostics");
        readme.Should().Contain("Custom specs targeting unknown ABI types, missing ABI parameters, or `Any`/compound/");
        readme.Should().Contain("`InteropInterface` ABI inputs");
        readme.Should().Contain("`Any` is explored across");
        readme.Should().Contain("does not claim every collection length");
        readme.Should().Contain("nested compound object graph");
        readme.Should().Contain("concrete interop object kind");
        readme.Should().Contain("For non-standard methods, the built-in `neo-n3-security` profile records the same entrypoint");
        readme.Should().Contain("`security.coverage.<method>`");
        readme.Should().Contain("best-effort security obligations");
        readme.Should().Contain("deterministic violations are not hidden");
        readme.Should().Contain("Manifest ABI method offsets used by `analyze` and `verify` must point");
        readme.Should().Contain("decoded instruction boundary");
        readme.Should().Contain("offsets into operand bytes are reported as incomplete");
        readme.Should().Contain("Exact-standard");
        readme.Should().Contain("NEP-17 and NEP-11 `transfer` `data: Any` payloads");
        readme.Should().Contain("also report the finite representative-shape");
        readme.Should().Contain("coverage gap as `security.coverage.transfer`");
        readme.Should().Contain("while still running the dedicated token-profile");
        readme.Should().Contain("non-standard overloads still report");
        readme.Should().Contain("Manifest-declared `supportedstandards` outside the profile's dedicated proof set");
        readme.Should().Contain("`security.standard_coverage.<standard>` `incomplete` results");
        readme.Should().Contain("does not claim proof-grade coverage of that unsupported standard's");
        readme.Should().Contain("full token coverage from ABI-only standard");
        readme.Should().Contain("`standard-coverage` / `abi-only`");
        readme.Should().Contain("that lane checks manifest ABI rules only");
        readme.Should().Contain("Proof-grade behavior checks live");
        readme.Should().Contain("NEP-26/NEP-27 receiver callbacks prove");
        readme.Should().Contain("NEP-24 `royaltyInfo` proves");
        readme.Should().Contain("returned-amount salePrice dependence");
        readme.Should().Contain("methods that emit concrete");
        readme.Should().Contain("`RoyaltiesTransferred` events prove the observed payload");
        readme.Should().Contain("Marketplace payment");
        readme.Should().Contain("in-range offsets into operand");
        readme.Should().Contain("JIT-decoded entrypoint");
        readme.Should().Contain("Token balance-delta arithmetic exemptions are likewise limited");
        readme.Should().Contain("manifest-declared standard NEP-17/NEP-11 transfer methods");
        readme.Should().Contain("non-standard `transfer` methods keep");
        readme.Should().Contain("generic unchecked-overflow obligations");
        readme.Should().Contain("Methods with duplicate ABI parameter names make profile entrypoint coverage `incomplete`");
        readme.Should().Contain("name-based method-entry symbols would otherwise collide");
        readme.Should().Contain("SMT concretization of symbolic runtime operands");
        readme.Should().Contain("repeated opaque integer-expression bounds");
        readme.Should().Contain("small finite integer intervals fully excluded by `!=` constraints");
        readme.Should().Contain("OR branches whose every disjunct contradicts the current integer domain");
        readme.Should().Contain("Integer arithmetic is translated as mathematical SMT `Int`");
        readme.Should().Contain("NeoVM's 32-byte signed integer");
        readme.Should().Contain("result range as an explicit fault condition");
        readme.Should().Contain("symbolic `DIV`/`MOD`");
        readme.Should().Contain("symbolic arithmetic results stay inside NeoVM's 32-byte");
        readme.Should().Contain("symbolic ByteString/Buffer inputs consumed by NeoVM `GetInteger`");
        readme.Should().Contain("including direct numeric opcodes");
        readme.Should().Contain("explicit ByteString-to-Integer");
        readme.Should().Contain("Array, Struct, Map, Pointer, and InteropInterface");
        readme.Should().Contain("numeric-conversion VM faults");
        readme.Should().Contain("symbolic ByteString/ByteArray `PICKITEM` indices stay within `0 <= index < size(value)`");
        readme.Should().Contain("`HASKEY` modeled as that same bounds predicate");
        readme.Should().Contain("ABI `Array`, `Struct`, and `Map` inputs use open symbolic models");
        readme.Should().Contain("open ABI `Array` and `Struct` `PICKITEM` reads prove `0 <= index < array_size`");
        readme.Should().Contain("open ABI `Array` and `Struct` symbolic `SETITEM` writes update seeded same-sort prefixes");
        readme.Should().Contain("open ABI `Array` and `Struct` symbolic `REMOVE` operations shift seeded same-sort prefixes");
        readme.Should().Contain("closed `Array` and `Struct` symbolic `PICKITEM` reads use finite same-sort ITE values");
        readme.Should().Contain("closed `Array` and `Struct` symbolic `SETITEM` writes over same-sort slots");
        readme.Should().Contain("closed `Array` and `Struct` symbolic `REMOVE` operations over same-sort slots");
        readme.Should().Contain("symbolic `Buffer` `PICKITEM` reads prove `0 <= index < buffer.Length`");
        readme.Should().Contain("symbolic `Buffer` `SETITEM` writes update each cell with finite ITE expressions");
        readme.Should().Contain("closed `Map` symbolic `PICKITEM` reads over same-sort known entries");
        readme.Should().Contain("concrete closed/open `Map` key lookup uses NeoVM StackItem equality");
        readme.Should().Contain("Boolean keys do not alias");
        readme.Should().Contain("closed `Map` symbolic `SETITEM` writes under a proven known-key guard");
        readme.Should().Contain("closed `Map` symbolic `REMOVE` operations under a proven known-key guard");
        readme.Should().Contain("Unknown open-map `PICKITEM` reads record a key-exists");
        readme.Should().Contain("unknown open ABI `Map` `PICKITEM` reads prove the selected key exists");
        readme.Should().Contain("dynamic expression keys receive distinct stable lookup symbols");
        readme.Should().Contain("open ABI `Map` symbolic `SETITEM` writes record key/value overlays");
        readme.Should().Contain("open ABI `Map` symbolic `REMOVE` operations record ordered remove overlays");
        readme.Should().Contain("symbolic ByteString `SUBSTR`, `LEFT`, and `RIGHT` sources with concrete or symbolic slice");
        readme.Should().Contain("fixed-length splice results discharge ABI fixed-byte return and notification");
        readme.Should().Contain("symbolic splice expressions can be sliced or copied again");
        readme.Should().Contain("symbolic ByteString `MEMCPY` sources with concrete or symbolic source/destination indexes");
        readme.Should().Contain("symbolic `SQRT` inputs are non-negative");
        readme.Should().Contain("symbolic `POW` exponents");
        readme.Should().Contain("concrete-base symbolic `POW` and `SHL` result overflows");
        readme.Should().Contain("`SHL`/`SHR` shift counts");
        readme.Should().Contain("successful `MODMUL`/`MODPOW` returns carry NeoVM integer range facts");
        readme.Should().Contain("symbolic `MODMUL`/`MODPOW` moduli are non-zero");
        readme.Should().Contain("symbolic `MODPOW` exponents");
        readme.Should().Contain("`MODPOW` modular-inverse (`exp == -1`) paths");
        readme.Should().Contain("positive base and modulus at least 2");
        readme.Should().Contain("search for reachable non-coprime witnesses");
        readme.Should().Contain("non-coprime uncertainty");
        readme.Should().Contain("Storage keys are non-null");
        readme.Should().Contain("`Contract.Call` receives a 20-byte");
        readme.Should().Contain("UInt160 target hash");
        readme.Should().Contain("`Contract.Call` receives a method name");
        readme.Should().Contain("method name");
        readme.Should().Contain("does not start with `_`");
        readme.Should().Contain("symbolic method selectors remain fault obligations");
        readme.Should().Contain("Neo call flags in the `0..0x0F` range");
        readme.Should().Contain("current execution context must also have the Neo-required call flags");
        readme.Should().Contain("`ReadStates | AllowCall` for `Contract.Call` / `CALLT`");
        readme.Should().Contain("`Runtime.CheckWitness` receives either a 20-byte UInt160 hash or a valid 33-byte compressed");
        readme.Should().Contain("secp256r1 public key");
        readme.Should().Contain("constraining an arbitrary `ByteString` to 33 bytes");
        readme.Should().Contain("not enough to prove");
        readme.Should().Contain("Manifest `PublicKey` ABI entry parameters carry");
        readme.Should().Contain("ECPoint-validity facts at method entry");
        readme.Should().Contain("`Runtime.GetCallingScriptHash`, `Runtime.GetExecutingScriptHash`, and `Runtime.GetEntryScriptHash`");
        readme.Should().Contain("are stable within an invocation");
        readme.Should().Contain("`CallingScriptHash` covers both Neo's entry-context `null`");
        readme.Should().Contain("contract-caller branch with a stable 20-byte UInt160 hash");
        readme.Should().Contain("ABI method named `verify`");
        readme.Should().Contain("runs under the `Verification` trigger");
        readme.Should().Contain("`Contract.Call` self-calls to the current executing script hash");
        readme.Should().Contain("must resolve to a manifest ABI");
        readme.Should().Contain("matching arity and argument types");
        readme.Should().Contain("parser rejects duplicate same-name/same-arity ABI methods");
        readme.Should().Contain("name-plus-parameter-count dispatch key");
        readme.Should().Contain("the verifier executes the self-call");
        readme.Should().Contain("callee body with nested caller/executing script-hash context");
        readme.Should().Contain("nested caller/executing script-hash context");
        readme.Should().Contain("nested faults, state");
        readme.Should().Contain("changes, and return-stack results");
        readme.Should().Contain("return-stack results");
        readme.Should().Contain("Dynamic method selectors or target hashes");
        readme.Should().Contain("argument arrays");
        readme.Should().Contain("ambiguous or missing ABI targets");
        readme.Should().Contain("excessive self-call depth");
        readme.Should().NotContain("`incomplete` until callee execution is modeled");
        readme.Should().Contain("Custom `requires`");
        readme.Should().Contain("predicates scope self-call ABI");
        readme.Should().Contain("callee-execution completeness");
        readme.Should().Contain("`Runtime.Notify` manifest checks");
        readme.Should().Contain("paths excluded by the specification");
        readme.Should().Contain("do not cause false");
        readme.Should().Contain("same-contract NEF `CALLT`");
        readme.Should().Contain("MethodToken hash equals the");
        readme.Should().Contain("current script hash");
        readme.Should().Contain("NEF `CALLT` follows the MethodToken `HasReturnValue`");
        readme.Should().Contain("return-valued CALLT calls must prove a non-Void callee");
        readme.Should().Contain("External `Contract.Call` and external NEF `CALLT` targets");
        readme.Should().Contain("not modeled native contract methods");
        readme.Should().Contain("make custom properties `incomplete`");
        readme.Should().Contain("concrete target hash");
        readme.Should().Contain("target contract existence");
        readme.Should().Contain("method name");
        readme.Should().Contain("trusted dependency proof summary");
        readme.Should().Contain("parameter count");
        readme.Should().Contain("declared parameter ABI types");
        readme.Should().Contain("caller argument compatibility");
        readme.Should().Contain("ABI `return_type` compatibility");
        readme.Should().Contain("caller-inferred return expectation");
        readme.Should().Contain("`return_type: \"Void\"` can");
        readme.Should().Contain("path-constrained");
        readme.Should().Contain("ASSERT(to == knownReceiverHash)");
        readme.Should().Contain("effective call flags");
        readme.Should().Contain("consumed");
        readme.Should().Contain("--require-external-smt");
        readme.Should().Contain("`fault_free: true`");
        readme.Should().Contain("\"version\": 3");
        readme.Should().Contain("\"proof\"");
        readme.Should().Contain("\"source_profile\": \"neo-n3-security\"");
        readme.Should().Contain("\"gate_passed\": true");
        readme.Should().Contain("\"require_unqualified_proofs\": true");
        readme.Should().Contain("\"assumption_backed_proofs\": 0");
        readme.Should().Contain("\"program_sha256\"");
        readme.Should().Contain("\"manifest_sha256\"");
        readme.Should().Contain("\"contract_hash\"");
        readme.Should().Contain("\"nef_checksum_hex\"");
        readme.Should().Contain("\"initial_call_flags\"");
        readme.Should().Contain("legacy v1/v2 summaries");
        readme.Should().Contain("mismatched `proof.contract_hash`");
        readme.Should().Contain("disabled");
        readme.Should().Contain("non-zero");
        readme.Should().Contain("`assumption_backed_proofs`");
        readme.Should().Contain("binds the requested summary contract hash to the verification report's");
        readme.Should().Contain("cannot be re-packaged as proof for a different");
        readme.Should().Contain("unknown schema fields");
        readme.Should().Contain("missing typed parameters for");
        readme.Should().Contain("duplicate contract hash");
        readme.Should().Contain("mismatched ABI `return_type`");
        readme.Should().Contain("duplicate method selector");
        readme.Should().Contain("`fault_free: false`");
        readme.Should().Contain("does not close the");
        readme.Should().Contain("fault-freedom or postcondition proofs");
        readme.Should().Contain("\"require_external_call_completeness\": false");
        readme.Should().Contain("local NeoVM/syscall fault obligations");
        readme.Should().Contain("not a proof of dynamic self-call or external callee semantics");
        readme.Should().Contain("NEF `CALLT` method-token names are parsed as strict UTF-8");
        readme.Should().Contain("cannot target `_`-prefixed private methods");
        readme.Should().Contain("`Runtime.Log` messages stay within Neo's 1024-byte notification payload limit");
        readme.Should().Contain("`Runtime.Notify` event names stay within Neo's 32-byte event-name limit");
        readme.Should().Contain("`Runtime.Notify` events must be declared in the manifest ABI");
        readme.Should().Contain("declared number of event");
        readme.Should().Contain("`Runtime.Log` messages, `Runtime.Notify` event names, and `Contract.Call` method names must be valid strict UTF-8");
        readme.Should().Contain("symbolic ByteString inputs remain fault obligations");
        readme.Should().Contain("`Runtime.Notify` payloads must serialize within Neo's 1024-byte notification payload limit");
        readme.Should().Contain("`Runtime.Notify` event arguments must match Neo's manifest ABI type checks");
        readme.Should().Contain("strict");
        readme.Should().Contain("UTF-8 for `String`");
        readme.Should().Contain("`Struct` compatibility for `Array`");
        readme.Should().Contain("proof of fixed byte lengths");
        readme.Should().Contain("`Hash160`, `Hash256`, `PublicKey`, and `Signature`");
        readme.Should().Contain("`CreateStandardAccount` and `CreateMultisigAccount` receive ECPoint public keys");
        readme.Should().Contain("valid secp256r1");
        readme.Should().Contain("33-byte compressed");
        readme.Should().Contain("65-byte uncompressed");
        readme.Should().Contain("CreateMultisigAccount` receives valid");
        readme.Should().Contain("`CheckSig` receives an ECPoint public key");
        readme.Should().Contain("64-byte signature");
        readme.Should().Contain("`CheckMultisig` receives non-empty public-key and signature arrays");
        readme.Should().Contain("`signatures.Count <= publicKeys.Count`");
        readme.Should().Contain("curve and shape checks");
        readme.Should().Contain("`Storage.Find`/`Storage.Local.Find` receive only Neo-supported `FindOptions`");
        readme.Should().Contain("legal flag combinations");
        readme.Should().Contain("`Iterator.Value` is valid only after a successful");
        readme.Should().Contain("the engine forks true/false iterator-advance paths");
        readme.Should().Contain("`Iterator.Value` follows the active `FindOptions`");
        readme.Should().Contain("iteration returns a key/value");
        readme.Should().Contain("key/value `Struct` pair");
        readme.Should().Contain("plain `ValuesOnly` return");
        readme.Should().Contain("Native StdLib `serialize`/`deserialize` calls through `Contract.Call` or NEF `CALLT`");
        readme.Should().Contain("Closed symbolic primitive, Buffer, Array, Struct, and Map StackItems");
        readme.Should().Contain("symbolic byte lengths emit");
        readme.Should().Contain("`jsonSerialize`/`jsonDeserialize` calls cover concrete");
        readme.Should().Contain("ByteString/Buffer");
        readme.Should().Contain("string-key Map shapes");
        readme.Should().Contain("Closed symbolic");
        readme.Should().Contain("Array/Struct-as-Array");
        readme.Should().Contain("JSON output-size fault conditions");
        readme.Should().Contain("malformed JSON");
        readme.Should().Contain("invalid UTF-8 bytes");
        readme.Should().Contain("Native StdLib `itoa`/`atoi`, `strLen`, `stringSplit`, base64/base64Url");
        readme.Should().Contain("Neo's supported bases, checksums, search bounds, strict UTF-8 string requirements, and input limits");
        readme.Should().Contain("Concrete invalid decode text for base64/base64Url");
        readme.Should().Contain("reported as a reachable VM fault");
        readme.Should().Contain("Concrete invalid `atoi` text and unsupported concrete");
        readme.Should().Contain("concrete invalid strict-UTF8");
        readme.Should().Contain("concrete `atoi` results outside NeoVM's integer range");
        readme.Should().Contain("out-of-bounds `memorySearch`");
        readme.Should().Contain("concrete StdLib inputs over 1024 bytes");
        readme.Should().Contain("symbolic inputs and checksum-failing symbolic");
        readme.Should().Contain("inputs remain incomplete rather than being treated as proof");
        readme.Should().Contain("Native CryptoLib `sha256`, `ripemd160`, `keccak256`, and `murmur32` calls are modeled");
        readme.Should().Contain("ByteString inputs produce stable fixed-length digest expressions");
        readme.Should().Contain("`ripemd160` 20 bytes, `murmur32` 4 bytes");
        readme.Should().Contain("`verifyWithEd25519`");
        readme.Should().Contain("symbolic ByteString");
        readme.Should().Contain("32-byte public-key and");
        readme.Should().Contain("64-byte signature requirements");
        readme.Should().Contain("for symbolic verification paths");
        readme.Should().Contain("`verifyWithECDsa` is modeled for concrete");
        readme.Should().Contain("secp256k1SHA256");
        readme.Should().Contain("secp256r1Keccak256");
        readme.Should().Contain("symbolic");
        readme.Should().Contain("stable `signature_check` authorization result");
        readme.Should().Contain("Concrete invalid");
        readme.Should().Contain("`murmur32` seeds");
        readme.Should().Contain("unsupported ECDSA curve hashes");
        readme.Should().Contain("unknown native-call surface");
        readme.Should().Contain("`Contract.Call`, and NEF `CALLT`");
        readme.Should().Contain("`recoverSecp256K1` is modeled for concrete 32-byte message hashes");
        readme.Should().Contain("recovery id is encoded as 0..3 or 27..30");
        readme.Should().Contain("Symbolic ByteString recovery inputs");
        readme.Should().Contain("non-null paths return a proof-grade");
        readme.Should().Contain("33-byte compressed secp256k1 public key");
        readme.Should().Contain("null recovery paths remain visible");
        readme.Should().Contain("concrete null");
        readme.Should().Contain("Concrete BLS12-381 `deserialize`, `serialize`, `equal`, `add`, `mul`, and `pairing` calls");
        readme.Should().Contain("Concrete `deserialize` rejects lengths other than");
        readme.Should().Contain("invalid encodings are reported as reachable VM");
        readme.Should().Contain("faults instead of unknown native-call surface");
        readme.Should().Contain("Concrete `bls12381Mul` rejects scalar lengths other");
        readme.Should().Contain("invalid scalar encodings are reported as reachable VM faults");
        readme.Should().Contain("Symbolic BLS12-381 `deserialize` preserves a guarded");
        readme.Should().Contain("records valid compressed G1/G2/Gt encoding fault obligations");
        readme.Should().Contain("`security.vm_fault_free` cannot be proved from byte length alone");
        readme.Should().Contain("custom specs can prove G1/G2/Gt byte-size round trips");
        readme.Should().Contain("`bls12381Equal` preserves a symbolic equality predicate");
        readme.Should().Contain("collapsing unrelated symbolic points to `true`");
        readme.Should().Contain("`bls12381Add` also preserves the guarded same-kind G1/G2/Gt shape");
        readme.Should().Contain("Symbolic `bls12381Mul` preserves the guarded G1/G2/Gt");
        readme.Should().Contain("scalar is proved to be a 32-byte ByteString");
        readme.Should().Contain("records a valid BLS12-381 scalar");
        readme.Should().Contain("fault obligation");
        readme.Should().Contain("Symbolic `bls12381Pairing` preserves the guarded G1-by-G2-to-Gt shape");
        readme.Should().Contain("serialized pairing");
        readme.Should().NotContain("Symbolic BLS `pairing`");
        readme.Should().NotContain("Symbolic BLS `mul`, `pairing`");
        readme.Should().NotContain("BLS arithmetic, pairing");
        readme.Should().NotContain("Symbolic recovery/BLS inputs");
        readme.Should().NotContain("Symbolic Ed25519 verification, symbolic recovery/BLS inputs");
        readme.Should().Contain("Invalid Ed25519/ECDSA/recovery shapes");
        readme.Should().Contain("symbolic BLS inputs require concrete validity facts or trusted preconditions");
        readme.Should().Contain("unsupported future CryptoLib methods");
        readme.Should().Contain("Native NEO/GAS read-only token calls are modeled");
        readme.Should().Contain("`balanceOf`, and NEO `getGasPerBlock()` / `unclaimedGas(account,end)` / `getRegisterPrice()` / `getCandidateVote(pubkey)` / `getCandidates()` / `getAccountState(account)` / `getCommitteeAddress()` / `getCommittee()` / `getNextBlockValidators()`");
        readme.Should().Contain("NEO account-state balance/height/last-gas-per-vote fields, plus NEO gas-per-block and register-price configuration");
        readme.Should().Contain("`unclaimedGas(account,end)` enforces `end == Ledger.currentIndex + 1` and returns stable non-negative symbolic GAS");
        readme.Should().Contain("`getCandidateVote(pubkey)` enforces a valid ECPoint public key and returns a stable integer in `[-1, +inf)`");
        readme.Should().Contain("`getCandidates()` returns open candidate tuples with valid ECPoint keys and non-negative votes");
        readme.Should().Contain("`getAccountState(account)` returns null or Neo's four-field NeoAccountState struct whose `VoteTo` field is null or a valid ECPoint and whose `LastGasPerVote` field is non-negative");
        readme.Should().Contain("committee address is a stable UInt160 witness principal");
        readme.Should().Contain("`getCommittee()` / `getNextBlockValidators()` return open arrays with representative valid ECPoint public keys");
        readme.Should().Contain("NEO/GAS `transfer(from,to,amount,data)` is modeled as a sensitive write-capable native call requiring `CallFlags.All`");
        readme.Should().Contain("non-negative NeoVM integer amount within the 32-byte input limit");
        readme.Should().Contain("returns a symbolic Boolean success value, and still participates in access-control, manifest-permission, and external-return checks");
        readme.Should().Contain("UInt160 account preconditions");
        readme.Should().Contain("structural expression fingerprint for symbolic arguments");
        readme.Should().Contain("native token read models require effective `ReadStates`");
        readme.Should().Contain("missing flags are faulted and dynamic");
        readme.Should().Contain("Ledger `currentIndex`, `currentHash`,");
        readme.Should().Contain("`getBlockHash(index)`, `getBlock(hash/index)`, `getTransactionFromBlock(block,index)`, `getTransaction(hash)`, `getTransactionHeight(hash)`, `getTransactionSigners(hash)`, and `getTransactionVMState(hash)` read models return stable UInt32 heights");
        readme.Should().Contain("nullable block structs with Hash256 links, non-negative timestamp/index fields, Int32-bounded transaction counts, UInt160 next-consensus hashes");
        readme.Should().Contain("native UInt32 block-index and Int32 transaction-index preconditions");
        readme.Should().Contain("nullable transaction structs from either transaction hashes or block/index lookups with UInt160 senders, non-negative fees, bounded scripts, stable transaction heights in `[-1, currentIndex]`, nullable open signer arrays with UInt160 accounts and bounded witness scopes, and stable VMState enum values");
        readme.Should().Contain("with UInt256 hash preconditions");
        readme.Should().Contain("ContractManagement");
        readme.Should().Contain("`getMinimumDeploymentFee()` returns a stable non-negative chain-configuration integer");
        readme.Should().Contain("`hasMethod` returns a stable boolean query result");
        readme.Should().Contain("non-negative Int32 parameter-count preconditions");
        readme.Should().Contain("returns false when path-local existence");
        readme.Should().Contain("facts prove the target contract is missing");
        readme.Should().Contain("true `hasMethod(target,...)` results make same-path");
        readme.Should().Contain("`isContract(target)` and `getContract(target)` existence checks provable");
        readme.Should().Contain("`getContract` and `getContractById(id)` return forked");
        readme.Should().Contain("nullable contract interop results");
        readme.Should().Contain("through both `Contract.Call` and NEF `CALLT`");
        readme.Should().Contain("proving the id fits Neo's native Int32 conversion");
        readme.Should().Contain("non-null `getContract(target)` results make same-path `isContract(target)` checks provably true");
        readme.Should().Contain("prior true/false `isContract(target)` facts make same-path `getContract(target)` return");
        readme.Should().Contain("non-null/null consistently");
        readme.Should().Contain("`isContract` returns forked stable true/false results");
        readme.Should().Contain("`getContractHashes()` returns a modeled `StorageIterator`");
        readme.Should().Contain("`FindOptions.RemovePrefix`");
        readme.Should().Contain("`Iterator.Next` / `Iterator.Value` proofs see key/value pair");
        readme.Should().Contain("ContractManagement `deploy(nef,manifest,data)` returns a contract");
        readme.Should().Contain("non-null NEF/manifest payload checks");
        readme.Should().Contain("strict-UTF8 manifest validation");
        readme.Should().Contain("non-Void MethodToken stack behavior");
        readme.Should().Contain("ContractManagement");
        readme.Should().Contain("`update(nef,manifest,data)` and `destroy()`");
        readme.Should().Contain("payload-shape checks");
        readme.Should().Contain("Void MethodToken stack behavior");
        readme.Should().Contain("deploy/upgrade/destroy authorization and");
        readme.Should().Contain("manifest permissions proof-visible");
        readme.Should().Contain("success paths");
        readme.Should().Contain("proof-visible `Transfer(from,to,amount)` notification payload");
        readme.Should().Contain("native balance changes and receiver callback side effects are not yet modeled end to end");
        readme.Should().Contain("Policy");
        readme.Should().Contain("`getAttributeFee(attributeType)` requires a valid `TransactionAttributeType`");
        readme.Should().Contain("Policy `isBlocked(account)` returns a stable boolean result");
        readme.Should().Contain("proving the account argument is UInt160");
        readme.Should().Contain("Oracle `getPrice` read models");
        readme.Should().Contain("`request(url,filter,callback,userData,gasForResponse)` is modeled as a sensitive");
        readme.Should().Contain("URL/filter/callback strict-UTF8 and size preconditions");
        readme.Should().Contain("callback");
        readme.Should().Contain("private-method rejection");
        readme.Should().Contain("serializable userData size checks");
        readme.Should().Contain("`gasForResponse` minimum");
        readme.Should().Contain("Int64 conversion bounds");
        readme.Should().Contain("authorization and");
        readme.Should().Contain("manifest-permission proof-visible");
        readme.Should().Contain("RoleManagement `getDesignatedByRole(role, index)` enforces valid Role enum values");
        readme.Should().Contain("native UInt32 index conversion");
        readme.Should().Contain("representative 33-byte valid ECPoint public keys");
        readme.Should().Contain("Concrete path-local writes can appear as iterator candidates");
        readme.Should().Contain("unknown persisted-storage branches");
        readme.Should().Contain("`DeserializeValues` and `PickField0`/`PickField1` decode concrete path-local values");
        readme.Should().Contain("closed symbolic `StdLib.serialize` StackItem summaries");
        readme.Should().Contain("`DeserializeValues`/`PickField0`/`PickField1` consume");
        readme.Should().Contain("Neo's BinarySerializer");
        readme.Should().Contain("malformed payloads");
        readme.Should().Contain("remain conservative incomplete surface");
        readme.Should().Contain("Storage keys are non-null");
        readme.Should().Contain("`Storage.Put`/`Storage.Local.Put`");
        readme.Should().Contain("64-byte write limit");
        readme.Should().Contain("Storage values are");
        readme.Should().Contain("65535-byte limit");
        readme.Should().Contain("Integer and Boolean storage values use their NeoVM serialized byte");
        readme.Should().Contain("normalized to their persisted ByteString encoding");
        readme.Should().Contain("Concrete or symbolic unknown");
        readme.Should().Contain("`Storage.Get`/`Storage.Local.Get` reads cover both");
        readme.Should().Contain("same opcode but with different keys receive distinct");
        readme.Should().Contain("present unknown values carry the `0 <= size <= 65535` domain");
        readme.Should().Contain("repeated unknown");
        readme.Should().Contain("path-stable");
        readme.Should().Contain("path-condition-proved byte-equality key aliases");
        readme.Should().Contain("numeric-equality branch guards do not alias storage keys");
        readme.Should().Contain("deletes produce path-local tombstones");
        readme.Should().Contain("Neo's missing-key");
        readme.Should().Contain("`null` result");
        readme.Should().Contain("arithmetic over `null` operands is modeled as a VM fault");
        readme.Should().Contain("Storage syscalls that take a context require a proof-grade StorageContext");
        readme.Should().Contain("non-storage interop objects are modeled as VM faults");
        readme.Should().Contain("arbitrary `InteropInterface`");
        readme.Should().Contain("rather than being accepted as writable storage contexts");
        readme.Should().Contain("security.manifest_permissions.*");
        readme.Should().Contain("malformed group public keys/signatures");
        readme.Should().Contain("Group public keys must be valid");
        readme.Should().Contain("group signatures must decode to 64 bytes");
        readme.Should().Contain("group signatures must verify that");
        readme.Should().Contain("NEF profile proofs must be bound to the deployed Neo N3");
        readme.Should().Contain("without `--deploy-sender-hash`, the profile remains");
        readme.Should().Contain("reported as `incomplete` until the");
        readme.Should().Contain("standard receiver callbacks required by complete");
        readme.Should().Contain("exact-standard manifest-declared token ABIs");
        readme.Should().Contain("matching standard `transfer` ABI");
        readme.Should().Contain("security.manifest_call_permissions.<method>");
        readme.Should().Contain("every reachable");
        readme.Should().Contain("including modeled native contract calls");
        readme.Should().Contain("return values are otherwise");
        readme.Should().Contain("precise");
        readme.Should().Contain("later `ASSERT`/`ABORT` rejects the path");
        readme.Should().Contain("byte-for-byte");
        readme.Should().Contain("reversed-byte");
        readme.Should().Contain("path-constrained dynamic symbols");
        readme.Should().Contain("ASSERT(to == knownReceiverHash)");
        readme.Should().Contain("Unresolved dynamic targets are provable only");
        readme.Should().Contain("Group-based contract descriptors");
        readme.Should().Contain("target group membership is not modeled");
        readme.Should().Contain("not a proof of target contract");
        readme.Should().Contain("security.vm_fault_free.<method>");
        readme.Should().Contain("security.vm_surface.<method>");
        readme.Should().Contain("security.access_control.<method>");
        readme.Should().Contain("security.entrypoint_reaches_halt.<method>");
        readme.Should().Contain("Runtime profile properties that are defined over successful paths");
        readme.Should().Contain("when the entrypoint has no successful HALT path");
        readme.Should().Contain("security.abi_return_type.<method>");
        readme.Should().Contain("compatible with the manifest ABI `returntype`");
        readme.Should().Contain("`PublicKey` returns must prove");
        readme.Should().Contain("valid ECPoint encoding");
        readme.Should().Contain("Runtime type mismatches are violations");
        readme.Should().Contain("security.manifest_safe.<method>");
        readme.Should().Contain("every modeled non-void external call return value");
        readme.Should().Contain("proven false return must not still reach a");
        readme.Should().Contain("successful Boolean result");
        readme.Should().Contain("nullable-return `ISNULL`");
        readme.Should().Contain("`ISTYPE`");
        readme.Should().Contain("`ext_ret_*`");
        readme.Should().Contain("precise modeled native");
        readme.Should().Contain("provenance through `ISNULL`/`NOT` and `ISTYPE` checks");
        readme.Should().Contain("CALLT MethodToken `HasReturnValue`");
        readme.Should().Contain("modeled native");
        readme.Should().Contain("method return shapes");
        readme.Should().Contain("overrides the standard receiver-callback Void exemption");
        readme.Should().Contain("treated as `Void`");
        readme.Should().Contain("target contract existence and ABI proof surface is");
        readme.Should().Contain("matching dependency proof summary");
        readme.Should().Contain("the callback also makes `security.external_returns.<method>`");
        readme.Should().Contain("security.nep17.abi.*");
        readme.Should().Contain("standard parameter names by ordinal");
        readme.Should().Contain("Transfer(Hash160 from, Hash160 to, Integer amount)");
        readme.Should().Contain("security.nep17.symbol_value.symbol");
        readme.Should().Contain("stable concrete non-empty ASCII token symbol");
        readme.Should().Contain("without whitespace or control characters");
        readme.Should().Contain("security.nep17.decimals_value.decimals");
        readme.Should().Contain("C# byte-compatible (`0..255`)");
        readme.Should().Contain("storage-backed, or multi-valued precision results");
        readme.Should().Contain("security.nep17.transfer_success_feasible.transfer");
        readme.Should().Contain("feasible non-self successful path");
        readme.Should().Contain("can only return true for `from == to`");
        readme.Should().Contain("every valid `from == to` path");
        readme.Should().Contain("non-zero account and non-negative amount");
        readme.Should().Contain("security.nep17.sender_authorized.transfer");
        readme.Should().Contain("security.nep17.zero_address.transfer");
        readme.Should().Contain("security.nep17.failure_no_state_change.transfer");
        readme.Should().Contain("`Runtime.Notify`, or non-read-only external side-effect calls");
        readme.Should().Contain("receiver callbacks");
        readme.Should().Contain("security.nep17.total_supply_unchanged.transfer");
        readme.Should().Contain("fixed-length symbolic account-key expressions");
        readme.Should().Contain("other splice-derived 20-byte C# `Hash160`");
        readme.Should().Contain("proved non-aliasing by length");
        readme.Should().Contain("security.nep17.lifecycle_event.<mint|burn>");
        readme.Should().Contain("Transfer(null, to, amount)` / `Transfer(from, null, amount)");
        readme.Should().Contain("security.nep17.lifecycle_amount_non_negative.<mint|burn>");
        readme.Should().Contain("must prove `amount >= 0` before changing");
        readme.Should().Contain("security.nep17.lifecycle_zero_address.<mint|burn>");
        readme.Should().Contain("is not `UInt160.Zero` before changing supply");
        readme.Should().Contain("security.nep17.lifecycle_balance.<mint|burn>");
        readme.Should().Contain("mint credits the recipient by `amount`");
        readme.Should().Contain("burn proves the sender balance is at");
        readme.Should().Contain("security.nep17.lifecycle_failure_no_state_change.<mint|burn>");
        readme.Should().Contain("methods that can return");
        readme.Should().Contain("false must not reach `Storage.Put`, `Storage.Delete`, `Runtime.Notify`");
        readme.Should().Contain("external side-effect calls on the false-return path");
        readme.Should().Contain("security.nep17.totalsupply_return_consistency.totalSupply");
        readme.Should().Contain("totalSupply()` may be a fixed constant");
        readme.Should().Contain("return the supply storage value it reads");
        readme.Should().Contain("security.nep17.balance_delta.transfer");
        readme.Should().Contain("full-length Hash160 slice account balance keys");
        readme.Should().Contain("`LEFT(from, 20)`");
        readme.Should().Contain("security.nep17.totalsupply_non_negative.totalSupply");
        readme.Should().Contain("`NEP-17`, every successful `totalSupply()` path must return a non-negative integer");
        readme.Should().Contain("security.nep17.balanceof_non_negative.balanceOf");
        readme.Should().Contain("`NEP-17`, every successful `balanceOf(account)` path must return a non-negative integer");
        readme.Should().Contain("every proven non-self `transfer` path with `from balance < amount` must");
        readme.Should().Contain("at least one clean false-return");
        readme.Should().Contain("security.nep17.balanceof_storage_consistency.balanceOf");
        readme.Should().Contain("security.nep17.balanceof_return_consistency.balanceOf");
        readme.Should().Contain("balanceOf(account)` must return the balance storage value it reads");
        readme.Should().Contain("security.nep17.transfer_event.transfer");
        readme.Should().Contain("security.nep17.callback_order_payload.transfer");
        readme.Should().Contain("A true-return path with no observed receiver callback is also");
        readme.Should().Contain("ContractManagement.getContract(to) == null");
        readme.Should().Contain("guard proves");
        readme.Should().Contain("receiver is not a contract");
        readme.Should().Contain("security.nep11.abi.*");
        readme.Should().Contain("`symbol`, `decimals`, `totalSupply`, `tokensOf`");
        readme.Should().Contain("non-divisible or divisible");
        readme.Should().Contain("`balanceOf` / `ownerOf` / `transfer` method shapes");
        readme.Should().Contain("required `ownerOf`");
        readme.Should().Contain("exact `Transfer` event conformance");
        readme.Should().Contain("Optional `properties(tokenId)` and `tokens()`");
        readme.Should().Contain("validated when declared");
        readme.Should().Contain("not required for core NEP-11 compliance");
        readme.Should().Contain("Transfer(Hash160 from, Hash160 to, Integer");
        readme.Should().Contain("amount, ByteString tokenId)");
        readme.Should().Contain("source-level `ByteString` token IDs");
        readme.Should().Contain("manifest `ByteArray` ABI parameters/events");
        readme.Should().Contain("accept either");
        readme.Should().Contain("security.nep24.abi.*");
        readme.Should().Contain("royaltyInfo(ByteString tokenId, Hash160 royaltyToken, Integer salePrice): Array safe=true");
        readme.Should().Contain("RoyaltiesTransferred(Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer");
        readme.Should().Contain("complete NEP-11 base NFT");
        readme.Should().Contain("required `balanceOf` / `ownerOf`");
        readme.Should().Contain("NEP-24");
        readme.Should().Contain("manifest `ByteArray`");
        readme.Should().Contain("security.nep24.behavior.royaltyInfo");
        readme.Should().Contain("every successful");
        readme.Should().Contain("royalty entries");
        readme.Should().Contain("Hash160-compatible");
        readme.Should().Contain("security.nep24.behavior.sale_price.royaltyInfo");
        readme.Should().Contain("MUST NOT ignore salePrice");
        readme.Should().Contain("security.nep24.behavior.royalties_transferred.<method>");
        readme.Should().Contain("observed payload must be a closed five-field array");
        readme.Should().Contain("payment-flow modeling");
        readme.Should().NotContain("security.nep24.behavior.royalty_policy");
        readme.Should().Contain("security.nep27.abi.*");
        readme.Should().Contain("onNEP17Payment(Hash160 from, Integer amount, Any data): Void");
        readme.Should().Contain("security.nep27.behavior.onNEP17Payment");
        readme.Should().Contain("NEP-27 receiver callbacks prove the built-in");
        readme.Should().Contain("passive receiver obligation");
        readme.Should().Contain("security.nep26.abi.*");
        readme.Should().Contain("onNEP11Payment(Hash160 from, Integer amount, ByteString tokenId, Any data): Void");
        readme.Should().Contain("Manifest `ByteArray` tokenId is accepted");
        readme.Should().Contain("manifest `String` tokenId is accepted");
        readme.Should().Contain("Neo.SmartContract.Framework INEP26");
        readme.Should().Contain("NEP compliance detectors scan every same-named ABI overload");
        readme.Should().Contain("C# helper overloads appear first");
        readme.Should().Contain("released Neo.SmartContract.Framework `String` tokenId callback shape");
        readme.Should().Contain("security.nep26.behavior.onNEP11Payment");
        readme.Should().Contain("NEP-26 receiver callbacks prove the built-in");
        readme.Should().Contain("Storage.Put` / `Storage.Delete");
        readme.Should().Contain("security.nep11.symbol_value.symbol");
        readme.Should().Contain("symbolic, multi-valued, non-ASCII, or empty");
        readme.Should().Contain("security.nep11.iterator_returns.*");
        readme.Should().Contain("declared `tokens()`");
        readme.Should().Contain("must actually return");
        readme.Should().Contain("Neo iterator `InteropInterface` values");
        readme.Should().Contain("storage");
        readme.Should().Contain("context");
        readme.Should().Contain("`tokensOf(owner)` must additionally return an owner-scoped");
        readme.Should().Contain("concrete owner-token namespace before the owner bytes");
        readme.Should().Contain("`KeysOnly | RemovePrefix`");
        readme.Should().Contain("declared `tokens()` must return a");
        readme.Should().Contain("non-empty concrete token namespace");
        readme.Should().Contain("divisible");
        readme.Should().Contain("`ownerOf(tokenId)` must return a tokenId-scoped");
        readme.Should().Contain("concrete owner namespace before tokenId");
        readme.Should().Contain("raw-parameter or unrelated");
        readme.Should().Contain("iterators are not treated as proof-grade NEP-11 enumeration");
        readme.Should().Contain("security.nep11.decimals_consistency.decimals");
        readme.Should().Contain("non-divisible `decimals()` must return integer `0`");
        readme.Should().Contain("divisible `decimals()` must");
        readme.Should().Contain("non-zero integer");
        readme.Should().Contain("security.nep11.transfer_success_feasible.transfer");
        readme.Should().Contain("can only reject transfers is treated as non-functional");
        readme.Should().Contain("security.nep11.tokenid_length.transfer");
        readme.Should().Contain("security.nep11.tokenid_length.*");
        readme.Should().Contain("`ownerOf(tokenId)`, divisible `balanceOf(owner, tokenId)`, declared `properties(tokenId)`");
        readme.Should().Contain("every successful return path must prove `tokenId` length");
        readme.Should().Contain("`tokenId` length is at most 64 bytes");
        readme.Should().Contain("security.nep11.owner_authorized.transfer");
        readme.Should().Contain("security.nep11.sender_authorized.transfer");
        readme.Should().Contain("security.nep11.amount_non_negative.transfer");
        readme.Should().Contain("security.nep11.amount_lte_decimals.transfer");
        readme.Should().Contain("amount <= 10^decimals()");
        readme.Should().Contain("unique concrete");
        readme.Should().Contain("security.nep11.total_supply_unchanged.transfer");
        readme.Should().Contain("true-return paths must not mutate concrete storage keys");
        readme.Should().Contain("fixed-length symbolic owner/token-key expressions");
        readme.Should().Contain("security.nep11.lifecycle_event.<mint|burn>");
        readme.Should().Contain("mint(to, amount, tokenId)");
        readme.Should().Contain("+amount` / `-amount");
        readme.Should().Contain("security.nep11.lifecycle_amount_non_negative.<mint|burn>");
        readme.Should().Contain("public `mint(to, amount, tokenId)` / `burn(from, amount, tokenId)`");
        readme.Should().Contain("must prove `amount >= 0` before changing");
        readme.Should().Contain("security.nep11.lifecycle_zero_address.<mint|burn>");
        readme.Should().Contain("NEP-11 lifecycle methods that mutate concrete storage keys");
        readme.Should().Contain("recipient/sender account is not `UInt160.Zero`");
        readme.Should().Contain("security.nep11.lifecycle_balance.<mint|burn>");
        readme.Should().Contain("update the `balanceOf(owner)` storage template");
        readme.Should().Contain("mint credits the recipient by `1` or");
        readme.Should().Contain("burn proves the sender balance is sufficient");
        readme.Should().Contain("security.nep11.lifecycle_failure_no_state_change.<mint|burn>");
        readme.Should().Contain("rejection paths must not reach");
        readme.Should().Contain("`Storage.Put`, `Storage.Delete`, `Runtime.Notify`, or non-read-only external side-effect");
        readme.Should().Contain("security.nep11.lifecycle_index.<mint|burn>");
        readme.Should().Contain("successful mint paths");
        readme.Should().Contain("declared `tokens()` and `tokensOf(to)` enumeration");
        readme.Should().Contain("successful burn paths");
        readme.Should().Contain("`tokens()` and `tokensOf(from)` enumeration");
        readme.Should().Contain("security.nep11.lifecycle_owner_storage.<mint|burn>");
        readme.Should().Contain("mint paths must write `ownerOf(tokenId)` storage to the recipient");
        readme.Should().Contain("paths must delete `ownerOf(tokenId)` storage");
        readme.Should().Contain("security.nep11.lifecycle_ownerof_index.<mint|burn>");
        readme.Should().Contain("tokenId-scoped owner index used by `ownerOf(tokenId)`");
        readme.Should().Contain("final account/token balances");
        readme.Should().Contain("security.nep11.totalsupply_non_negative.totalSupply");
        readme.Should().Contain("NEP-11 contracts, every successful `totalSupply()` path must return a non-negative");
        readme.Should().Contain("negative constants or reachable negative symbolic returns are `violated`");
        readme.Should().Contain("security.nep11.balanceof_non_negative.balanceOf");
        readme.Should().Contain("every successful `balanceOf(owner)` or `balanceOf(owner, tokenId)`");
        readme.Should().Contain("path must return a non-negative integer");
        readme.Should().Contain("security.nep11.totalsupply_return_consistency.totalSupply");
        readme.Should().Contain("security.nep11.owner_update.transfer");
        readme.Should().Contain("write the same tokenId-indexed owner storage key to `to`");
        readme.Should().Contain("security.nep11.owner_balance_delta.transfer");
        readme.Should().Contain("same owner balance key template");
        readme.Should().Contain("current owner balance is");
        readme.Should().Contain("security.nep11.tokensof_index.transfer");
        readme.Should().Contain("previous owner/tokenId key");
        readme.Should().Contain("recipient/tokenId key");
        readme.Should().Contain("concrete `tokensOf(owner)` `Storage.Find` index template");
        readme.Should().Contain("self-transfer paths must leave that enumeration index unchanged");
        readme.Should().Contain("security.nep11.ownerof_storage_consistency.ownerOf");
        readme.Should().Contain("ownerOf(tokenId)` must read the same token owner storage key template");
        readme.Should().Contain("security.nep11.ownerof_return_consistency.ownerOf");
        readme.Should().Contain("ownerOf(tokenId)` must return the token owner storage value it reads");
        readme.Should().Contain("security.nep11.failure_no_state_change.transfer");
        readme.Should().Contain("divisible NEP-11 `transfer` methods");
        readme.Should().Contain("non-read-only external");
        readme.Should().Contain("side-effect calls such as receiver callbacks");
        readme.Should().Contain("security.nep11.invalid_token_false.transfer");
        readme.Should().Contain("every proven path where `tokenId` has no current owner");
        readme.Should().Contain("security.nep11.insufficient_balance_false.transfer");
        readme.Should().Contain("every proven non-self path where `from` token balance is below `amount`");
        readme.Should().Contain("without observable side effects");
        readme.Should().Contain("security.nep11.balance_delta.transfer");
        readme.Should().Contain("same tokenId-indexed from/to account");
        readme.Should().Contain("security.nep11.ownerof_index.transfer");
        readme.Should().Contain("tokenId-scoped owner index used by");
        readme.Should().Contain("sender/tokenId owner index entry deleted");
        readme.Should().Contain("recipient/tokenId owner index entry written");
        readme.Should().Contain("security.nep11.balanceof_storage_consistency.balanceOf");
        readme.Should().Contain("balanceOf(owner)` must read the same owner balance key template");
        readme.Should().Contain("same owner/tokenId balance storage key template");
        readme.Should().Contain("security.nep11.balanceof_return_consistency.balanceOf");
        readme.Should().Contain("balanceOf(owner)` must return that owner balance storage value");
        readme.Should().Contain("balanceOf(owner, tokenId)` must return that token balance storage value");
        readme.Should().Contain("security.nep11.transfer_event.transfer");
        readme.Should().Contain("Transfer(from, to, amount, tokenId)");
        readme.Should().Contain("security.nep11.callback_order_payload.transfer");
        readme.Should().Contain("(from, amount, tokenId, data)");
        readme.Should().Contain("observed receiver callback remain `incomplete`");
        readme.Should().Contain("guard proves recipient contract absence");
        readme.Should().Contain("--fail-on-unproved");
        readme.Should().Contain("\"coverage_incomplete\"");
        readme.Should().Contain("\"coverage_reason\"");
        readme.Should().Contain("\"skipped_entrypoints\"");
        readme.Should().Contain("--allow-incomplete-coverage");
        readme.Should().Contain("inside another instruction's operand bytes");
        readme.Should().Contain("--max-entrypoints");
        readme.Should().Contain("default 128");
        readme.Should().Contain("packages.lock.json");
        readme.Should().Contain("--locked-mode");
        readme.Should().Contain("Roslyn");
        readme.Should().NotContain("no Roslyn");
    }

    [Fact]
    public void CliHelp_DocumentsCoverageGateFlagsAndExitCodes()
    {
        var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
        var printUsage = cliProgram.GetMethod("PrintUsage", BindingFlags.NonPublic | BindingFlags.Static)!;

        using var output = new StringWriter();
        var originalOut = Console.Out;
        try
        {
            Console.SetOut(output);
            printUsage.Invoke(null, null);
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        string help = output.ToString();
        help.Should().Contain("--fail-on-max-severity <sev>");
        help.Should().Contain("default: high");
        help.Should().Contain("--fail-on-budget-exceeded");
        help.Should().Contain("default");
        help.Should().Contain("--fail-on-incomplete-coverage");
        help.Should().Contain("--allow-incomplete-coverage");
        help.Should().Contain("--max-entrypoints");
        help.Should().Contain("Engine budget flags above also apply to verify");
        help.Should().Contain("external Z3 or portable fallback");
        help.Should().Contain("Exit codes:");
        help.Should().Contain("3   Gate violation");
    }

    [Fact]
    public void DevPackReadme_RecommendsShaPinnedActionsInCiExample()
    {
        string readme = ReadRepoFile("devpack-integration/README.md");

        readme.Should().NotContain("@v4");
        readme.Should().Contain("Pin GitHub Actions to reviewed full commit SHAs");
        readme.Should().Contain("uses: actions/upload-artifact@<full-commit-sha>");
    }

    [Fact]
    public void CiWorkflow_PinsActionsToCommitShasAndRunsFormatCheck()
    {
        string workflow = ReadRepoFile(".github/workflows/ci.yml");

        workflow.Should().Contain("dotnet restore Neo.SymbolicExecutor.sln --locked-mode");
        workflow.Should().Contain("dotnet format Neo.SymbolicExecutor.sln --verify-no-changes --verbosity minimal");
        workflow.Should().NotContain("@v4");

        var actionPins = Regex.Matches(
                workflow,
                @"^\s*uses:\s*(?<action>[^@\s]+)@(?<pin>\S+)",
                RegexOptions.Multiline)
            .Cast<Match>()
            .ToDictionary(
                match => match.Groups["action"].Value,
                match => match.Groups["pin"].Value);

        actionPins.Keys.Should().BeEquivalentTo(
            new[] { "actions/checkout", "actions/setup-dotnet", "actions/upload-artifact" });
        foreach (string pin in actionPins.Values)
            pin.Should().MatchRegex("^[0-9a-f]{40}$");
    }

    [Fact]
    public void Gitignore_ExcludesPackArtifactsDirectory()
    {
        ReadRepoFile(".gitignore")
            .Split('\n')
            .Should().Contain("artifacts/");
    }

    [Fact]
    public void Engine_CreateMethodEntryState_SeedsArgsAtMethodOffset()
    {
        // Realistic DevPack-shaped bytecode: a dispatcher prelude that reads stack arg 0 then
        // jumps, plus a method body that takes 2 parameters via INITSLOT and adds them. Without
        // method-entry seeding the engine starts at offset 0, faults at LDARG0 with no args, and
        // never reaches the method body — exactly the production gap this regression locks down.
        byte[] script =
        {
            // 0..2: dispatcher prelude (1 arg = method-name string)
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.RET,
            // 6..end: method "add"(a, b) => a + b
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x02, // 0 locals, 2 args
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var add = new ContractMethodDescriptor
        {
            Name = "add",
            Offset = 6,
            Parameters = new[]
            {
                new ContractParameterDefinition("a", "Integer"),
                new ContractParameterDefinition("b", "Integer"),
            },
        };

        var state = engine.CreateMethodEntryState(add.Offset, add.Parameters);
        var result = engine.Run(state);

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Should().ContainSingle();
        halted.EvaluationStack.Single().Expression.Should()
            .BeOfType<BinaryExpr>().Which.Op.Should().Be("+");
        // Both symbolic args reach the body in declared order.
        halted.EvaluationStack.Single().Expression.FreeSymbols().Should()
            .BeEquivalentTo(new[] { "arg_a", "arg_b" });
        halted.EvaluationStack.Single().Taints.Should()
            .BeEquivalentTo(new[] { "arg_a", "arg_b" });
    }

    [Fact]
    public void Engine_ConvertSymbolicBooleanToByteStringPreservesBothBooleanValues()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT,
            SymbolicEngine.StackItemTypeCodes.ByteString,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var state = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("flag", "Boolean"),
        });

        var result = engine.Run(state);

        result.FinalStates.Should().ContainSingle();
        var value = result.FinalStates.Single().EvaluationStack.Single();
        // Round-3 audit fix: NeoVM's Boolean.GetSpan() is [0x01] for true and [0x00] for false, so the
        // symbolic conversion selects between [1] and [0] (not an empty ByteString).
        value.AsConcreteBytes().Should().BeNull("symbolic true converts to [1] while false converts to [0]");
        var choice = value.Expression.Should().BeOfType<TernaryExpr>().Which;
        choice.Op.Should().Be("ite");
        choice.A.Should().Be(Expr.Sym(Sort.Bool, "arg_flag"));
        choice.B.Should().Be(Expr.Bytes(new byte[] { 1 }));
        choice.C.Should().Be(Expr.Bytes(new byte[] { 0 }));
    }

    [Fact]
    public void Engine_ConvertSymbolicBooleanToBufferForksTrueAndFalseBuffers()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT,
            SymbolicEngine.StackItemTypeCodes.Buffer,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var state = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("flag", "Boolean"),
        });

        var result = engine.Run(state);

        result.FinalStates.Should().HaveCount(2);
        var trueState = result.FinalStates.Single(s => s.PathConditions.Contains(Expr.Sym(Sort.Bool, "arg_flag")));
        var falseState = result.FinalStates.Single(s => s.PathConditions.Contains(Expr.Not(Expr.Sym(Sort.Bool, "arg_flag"))));
        BufferObject trueBuffer = trueState.Heap.Get<BufferObject>(
            trueState.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which.ObjectId);
        BufferObject falseBuffer = falseState.Heap.Get<BufferObject>(
            falseState.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which.ObjectId);

        // Round-3 audit fix: Boolean false converts to a single zero byte [0x00], not an empty buffer.
        trueBuffer.Cells.Should().Equal(new[] { Expr.Int(1) });
        falseBuffer.Cells.Should().Equal(new[] { Expr.Int(0) });
    }

    [Fact]
    public void Engine_CallingScriptHashEqualityBranchMarksCallerAuthorization()
    {
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x01 },
            Syscall("System.Runtime.GetCallingScriptHash"),
            new[]
            {
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.EQUAL,
                (byte)NeoVm.OpCode.JMPIF,
                (byte)0x04,
                (byte)NeoVm.OpCode.PUSH0,
                (byte)NeoVm.OpCode.RET,
                (byte)NeoVm.OpCode.PUSH1,
                (byte)NeoVm.OpCode.RET,
            });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("from", "Hash160"),
        });

        var result = engine.Run(entry);

        var truePath = result.Halted.Single(state => state.EvaluationStack.Single().AsConcreteInt() == 1);
        truePath.PathConditions.Any(condition => condition is BinaryExpr
        {
            Op: "==",
            Left: Symbol { Name: "calling_script_hash" },
            Right: Symbol { Name: "arg_from" },
        } || condition is BinaryExpr
        {
            Op: "==",
            Left: Symbol { Name: "arg_from" },
            Right: Symbol { Name: "calling_script_hash" },
        }).Should().BeTrue();
        truePath.Telemetry.CallerHashCheckOps.Should().ContainSingle()
            .Which.Target.Expression.Should().Be(new Symbol(Sort.Bytes, "arg_from"));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_HandlesZeroAndManyParameters()
    {
        // Bare RET method: no INITSLOT, no params. Seeded with 0 args should HALT immediately.
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var engine = new SymbolicEngine(program);

        var noArgs = engine.CreateMethodEntryState(offset: 0, parameters: Array.Empty<ContractParameterDefinition>());
        noArgs.EvaluationStack.Should().BeEmpty("no parameters means no seeded symbolic values");
        engine.Run(noArgs).FinalStates.Single().Status.Should().Be(TerminalStatus.Halted);

        // Null parameters should behave like an empty list (degenerate but defined input).
        var nullParams = new SymbolicEngine(program).CreateMethodEntryState(offset: 0, parameters: null);
        nullParams.EvaluationStack.Should().BeEmpty();

        // Many params + unfamiliar Type strings should not throw and should land within the
        // engine's stack budget. 64 is well under the 2048 default MaxStackSize.
        var manyParams = new List<ContractParameterDefinition>();
        for (int i = 0; i < 64; i++)
            manyParams.Add(new ContractParameterDefinition($"p{i}",
                Type: i % 2 == 0 ? "Integer" : "ExoticUnseenType"));
        var seededWithMany = new SymbolicEngine(program).CreateMethodEntryState(offset: 0, parameters: manyParams);
        seededWithMany.EvaluationStack.Should().HaveCount(64);
        // Param index 63 has Type "ExoticUnseenType" -> unmapped -> Sort.Bytes; pushed first
        // (reverse order), so it sits at the bottom of the stack.
        seededWithMany.EvaluationStack[0].Expression.Sort.Should().Be(Sort.Bytes);
        // Param index 0 ("p0", "Integer") pushed last -> top of stack -> Sort.Int.
        seededWithMany.EvaluationStack[^1].Expression.Sort.Should().Be(Sort.Int);
    }

    [Fact]
    public void Engine_CreateMethodEntryStates_ExpandsAnyAbiParameterShapes()
    {
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var states = new SymbolicEngine(program).CreateMethodEntryStates(0, new[]
        {
            new ContractParameterDefinition("data", "Any"),
        });

        states.Should().HaveCount(9);
        states.Select(state => state.EvaluationStack.Single().Sort).Should().BeEquivalentTo(new[]
        {
            Sort.Null,
            Sort.Bool,
            Sort.Int,
            Sort.Bytes,
            Sort.Buffer,
            Sort.Array,
            Sort.Struct,
            Sort.Map,
            Sort.InteropInterface,
        });

        var integerState = states.Single(state => state.EvaluationStack.Single().Sort == Sort.Int);
        var data = Expr.Sym(Sort.Int, "arg_data");
        integerState.PathConditions.Should().Contain(Expr.Ge(data, Expr.Int(Expr.NeoVmIntegerMin)));
        integerState.PathConditions.Should().Contain(Expr.Le(data, Expr.Int(Expr.NeoVmIntegerMax)));

        var bytesState = states.Single(state => state.EvaluationStack.Single().Sort == Sort.Bytes);
        var dataSize = new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "arg_data"));
        bytesState.PathConditions.Should().Contain(Expr.Ge(dataSize, Expr.Int(0)));
        bytesState.PathConditions.Should().Contain(Expr.Le(dataSize, Expr.Int(bytesState.Heap.MaxItemSize)));
    }

    [Fact]
    public void Engine_ConvertFixedLengthSymbolicBytesToMutableBuffer()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT, SymbolicEngine.StackItemTypeCodes.Buffer,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.CONVERT, SymbolicEngine.StackItemTypeCodes.ByteString,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("account", "Hash160"),
        });

        var result = engine.Run(entry);

        result.Faulted.Should().BeEmpty("Hash160 has a fixed 20-byte size, so converting it to Buffer yields a mutable buffer");
        var halted = result.Halted.Should().ContainSingle().Which;
        halted.EvaluationStack.Single().Expression.Should().BeOfType<UnaryExpr>()
            .Which.Op.Should().Be("buf2bytes");
        var buffer = halted.Heap.Objects.Values.OfType<BufferObject>().Should().ContainSingle().Which;
        buffer.Cells.Should().HaveCount(20);
        buffer.Cells[0].Should().Be(Expr.Int(1));
    }

    [Fact]
    public void Engine_ConvertNonEmptyVariableLengthSymbolicBytesToMutableBuffer()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT, SymbolicEngine.StackItemTypeCodes.Buffer,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("data", "ByteString"),
        });
        var data = Expr.Sym(Sort.Bytes, "arg_data");
        entry.PathConditions = entry.PathConditions.Add(Expr.Ge(
            new UnaryExpr(Sort.Int, "size", data),
            Expr.Int(1)));

        var result = engine.Run(entry);

        result.Faulted.Should().BeEmpty("a proven non-empty ByteString converts to a heap-backed mutable Buffer");
        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Int(1));
        var buffer = halted.Heap.Objects.Values.OfType<BufferObject>().Should().ContainSingle().Which;
        buffer.Cells[0].Should().Be(Expr.Int(1));
    }

    [Fact]
    public void Engine_ConvertSymbolicIntegerToMutableBufferRecordsRuntimeBounds()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.CONVERT, SymbolicEngine.StackItemTypeCodes.Buffer,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("amount", "Integer"),
        });

        var result = engine.Run(entry);

        result.Faulted.Should().BeEmpty("symbolic Integer to Buffer conversion must still produce a heap-backed mutable Buffer");
        var halted = result.Halted.Should().ContainSingle().Subject;
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Which;
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.IsSymbolicOpen.Should().BeTrue("a symbolic Integer has runtime-dependent little-endian byte length");
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "SETITEM"
            && fault.FailedCondition.Contains("buffer SETITEM index is within runtime length"));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_AddsIntegerAbiRangeConditions()
    {
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var state = new SymbolicEngine(program).CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("amount", "Integer"),
        });

        var amount = Expr.Sym(Sort.Int, "arg_amount");
        state.EvaluationStack.Should().ContainSingle();
        state.EvaluationStack.Single().Expression.Should().Be(amount);
        state.PathConditions.Should().Contain(Expr.Ge(amount, Expr.Int(Expr.NeoVmIntegerMin)));
        state.PathConditions.Should().Contain(Expr.Le(amount, Expr.Int(Expr.NeoVmIntegerMax)));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_AddsFixedByteAbiPathConditions()
    {
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var state = new SymbolicEngine(program).CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("account", "Hash160"),
            new ContractParameterDefinition("hash", "Hash256"),
            new ContractParameterDefinition("pubkey", "PublicKey"),
            new ContractParameterDefinition("sig", "Signature"),
        });

        state.EvaluationStack.Should().HaveCount(4);
        state.PathConditions.Should().Contain(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "arg_account")),
            Expr.Int(20)));
        state.PathConditions.Should().Contain(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "arg_hash")),
            Expr.Int(32)));
        state.PathConditions.Should().Contain(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "arg_pubkey")),
            Expr.Int(33)));
        state.PathConditions.Should().Contain(Expr.IsValidEcPoint(Expr.Sym(Sort.Bytes, "arg_pubkey")));
        state.PathConditions.Should().Contain(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, "arg_sig")),
            Expr.Int(64)));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_AddsVariableByteAbiSizeDomainConditions()
    {
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var options = ExecutionOptions.Default with { MaxItemSize = 4096 };
        var state = new SymbolicEngine(program, options).CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("data", "ByteString"),
            new ContractParameterDefinition("payload", "ByteArray"),
            new ContractParameterDefinition("label", "String"),
        });

        state.EvaluationStack.Should().HaveCount(3);
        foreach (string symbol in new[] { "arg_data", "arg_payload", "arg_label" })
        {
            var size = new UnaryExpr(Sort.Int, "size", Expr.Sym(Sort.Bytes, symbol));
            state.PathConditions.Should().Contain(Expr.Ge(size, Expr.Int(0)));
            state.PathConditions.Should().Contain(Expr.Le(size, Expr.Int(options.MaxItemSize)));
        }
        state.PathConditions.Should().Contain(Expr.IsStrictUtf8(Expr.Sym(Sort.Bytes, "arg_label")));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_SeedsNeoN3CSharpCompoundAbiParametersAsHeapObjects()
    {
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var state = new SymbolicEngine(program).CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("items", "Array"),
            new ContractParameterDefinition("meta", "Map"),
            new ContractParameterDefinition("row", "Struct"),
            new ContractParameterDefinition("scratch", "Buffer"),
        });

        state.EvaluationStack.Should().HaveCount(4);
        var arrayRef = state.Peek(0).Expression.Should().BeOfType<HeapRef>().Which;
        var mapRef = state.Peek(1).Expression.Should().BeOfType<HeapRef>().Which;
        var structRef = state.Peek(2).Expression.Should().BeOfType<HeapRef>().Which;
        var bufferRef = state.Peek(3).Expression.Should().BeOfType<HeapRef>().Which;

        arrayRef.RefSort.Should().Be(Sort.Array);
        var array = state.Heap.Get<ArrayObject>(arrayRef.ObjectId);
        array.IsSymbolicOpen.Should().BeTrue("ABI Array parameters represent unknown runtime arrays");
        array.MinCount.Should().Be(0, "method entry cannot assume a runtime Array argument has any element");
        array.Items.Should().HaveCount(4);
        state.Peek(0).Taints.Should().Contain("arg_items");
        array.Items.Should().OnlyContain(item => item.Taints.Contains("arg_items"));

        mapRef.RefSort.Should().Be(Sort.Map);
        var map = state.Heap.Get<MapObject>(mapRef.ObjectId);
        map.IsSymbolicOpen.Should().BeTrue("ABI Map parameters represent unknown runtime maps");
        map.Entries.Should().HaveCount(4);
        state.Peek(1).Taints.Should().Contain("arg_meta");
        map.Entries.Should().OnlyContain(entry => entry.Value.Taints.Contains("arg_meta"));

        structRef.RefSort.Should().Be(Sort.Struct);
        var structure = state.Heap.Get<StructObject>(structRef.ObjectId);
        structure.IsSymbolicOpen.Should().BeTrue("ABI Struct parameters represent unknown runtime structs");
        structure.MinCount.Should().Be(0, "method entry cannot assume a runtime Struct argument has any field");
        structure.Fields.Should().HaveCount(4);
        state.Peek(2).Taints.Should().Contain("arg_row");
        structure.Fields.Should().OnlyContain(field => field.Taints.Contains("arg_row"));

        bufferRef.RefSort.Should().Be(Sort.Buffer);
        var buffer = state.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.IsSymbolicOpen.Should().BeTrue("ABI Buffer parameters represent unknown runtime buffers");
        buffer.MinLength.Should().Be(0, "method entry cannot assume a runtime Buffer argument has any byte");
        buffer.Cells.Should().HaveCount(4);
        state.Peek(3).Taints.Should().Contain("arg_scratch");
        buffer.SymbolicLength.Should().Be(Expr.Sym(Sort.Int, "arg_scratch_size"));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_CoversCSharpArrayParameterPickItem()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("items", "Array"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.FreeSymbols().Should().Contain("arg_items[0]");
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("open array");
        fault.FailedCondition.Should().Contain("array PICKITEM index is within runtime length");
        fault.FaultCondition.FreeSymbols().Should().Contain(name => name.StartsWith("array_size_", StringComparison.Ordinal));
    }

    [Fact]
    public void Engine_OpenCSharpArrayParameterPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.JMPIF,
            0x05,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("items", "Array"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state =>
            state.Status == TerminalStatus.Halted
            && state.EvaluationStack.Single().Expression.FreeSymbols().Contains("arg_items[0]"));
        var fault = guardedPath.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        var missingIndexCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingIndexCondition.Op.Should().Be("not");

        guardedPath.PathConditions.Should().Contain(missingIndexCondition.Operand);
    }

    [Fact]
    public void Engine_CreateMethodEntryState_CoversCSharpStructParameterPickItem()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("row", "Struct"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.FreeSymbols().Should().Contain("arg_row[0]");
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("open struct");
        fault.FailedCondition.Should().Contain("struct PICKITEM index is within runtime length");
        fault.FaultCondition.FreeSymbols().Should().Contain(name => name.StartsWith("struct_size_", StringComparison.Ordinal));
    }

    [Fact]
    public void Engine_OpenCSharpStructParameterPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.JMPIF,
            0x05,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("row", "Struct"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state =>
            state.Status == TerminalStatus.Halted
            && state.EvaluationStack.Single().Expression.FreeSymbols().Contains("arg_row[0]"));
        var fault = guardedPath.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        var missingIndexCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingIndexCondition.Op.Should().Be("not");

        guardedPath.PathConditions.Should().Contain(missingIndexCondition.Operand);
    }

    [Fact]
    public void Engine_BufferPickItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH4,
            (byte)NeoVm.OpCode.NEWBUFFER,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().BeOfType<BinaryExpr>()
            .Which.Op.Should().Be("buffer_pick");
        halted.EvaluationStack.Single().Expression.FreeSymbols().Should().Contain("arg_index");
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("buffer");
        fault.FailedCondition.Should().Contain("buffer PICKITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("arg_index");
    }

    [Fact]
    public void Engine_BufferPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH4,
            (byte)NeoVm.OpCode.NEWBUFFER,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.JMPIF,
            0x05,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state =>
            state.Status == TerminalStatus.Halted
            && state.EvaluationStack.Single().Expression is BinaryExpr { Op: "buffer_pick" });
        var fault = guardedPath.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        var missingIndexCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingIndexCondition.Op.Should().Be("not");

        guardedPath.PathConditions.Should().Contain(missingIndexCondition.Operand);
    }

    [Fact]
    public void Engine_ClosedArrayPickItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH3,
            (byte)NeoVm.OpCode.NEWARRAY_T,
            SymbolicEngine.StackItemTypeCodes.Integer,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Int(0));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("array");
        fault.FailedCondition.Should().Contain("array PICKITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("arg_index");
    }

    [Fact]
    public void Engine_ClosedArrayPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH3,
            (byte)NeoVm.OpCode.NEWARRAY_T,
            SymbolicEngine.StackItemTypeCodes.Integer,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.JMPIF,
            0x05,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state =>
            state.Status == TerminalStatus.Halted
            && state.EvaluationStack.Single().Expression.Equals(Expr.Int(0)));
        var fault = guardedPath.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        var missingIndexCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingIndexCondition.Op.Should().Be("not");

        guardedPath.PathConditions.Should().Contain(missingIndexCondition.Operand);
    }

    [Fact]
    public void Engine_ClosedStructPickItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH3,
            (byte)NeoVm.OpCode.NEWSTRUCT,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Null());
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("struct");
        fault.FailedCondition.Should().Contain("struct PICKITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("arg_index");
    }

    [Fact]
    public void Engine_ClosedStructPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.PUSH3,
            (byte)NeoVm.OpCode.NEWSTRUCT,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.JMPIF,
            0x05,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("index", "Integer"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state => state.Telemetry.FaultConditions.Count == 1);
        var fault = guardedPath.Telemetry.FaultConditions.Single();
        var missingIndexCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingIndexCondition.Op.Should().Be("not");

        guardedPath.PathConditions.Should().Contain(missingIndexCondition.Operand);
    }

    [Fact]
    public void Engine_ClosedArraySetItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var array = state.Heap.NewArray(new[]
        {
            SymbolicValue.Int(1),
            SymbolicValue.Int(2),
        });
        var index = SymbolicValue.Symbol(Sort.Int, "i");
        state.Push(SymbolicValue.HeapRef(Sort.Array, array.Id));
        state.Push(index);
        state.Push(SymbolicValue.Int(9));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<ArrayObject>(array.Id);
        updated.Items[0].Expression.Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(0)), Expr.Int(9), Expr.Int(1)));
        updated.Items[1].Expression.Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(1)), Expr.Int(9), Expr.Int(2)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SETITEM");
        fault.Reason.Should().Contain("array");
        fault.FailedCondition.Should().Contain("array SETITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("i");
    }

    [Fact]
    public void Engine_ClosedStructSetItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var structure = state.Heap.NewStruct(new[]
        {
            SymbolicValue.Int(1),
            SymbolicValue.Int(2),
        });
        var index = SymbolicValue.Symbol(Sort.Int, "i");
        state.Push(SymbolicValue.HeapRef(Sort.Struct, structure.Id));
        state.Push(index);
        state.Push(SymbolicValue.Int(9));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<StructObject>(structure.Id);
        updated.Fields[0].Expression.Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(0)), Expr.Int(9), Expr.Int(1)));
        updated.Fields[1].Expression.Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(1)), Expr.Int(9), Expr.Int(2)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SETITEM");
        fault.Reason.Should().Contain("struct");
        fault.FailedCondition.Should().Contain("struct SETITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("i");
    }

    [Fact]
    public void Engine_OpenCSharpArrayParameterSetItemWithSymbolicIndexSupportsReadAfterWrite()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x03,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.LDARG2,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("items", "Array"),
            new ContractParameterDefinition("index", "Integer"),
            new ContractParameterDefinition("value", "ByteString"),
        });
        var arrayRef = entry.Peek(0).Expression.Should().BeOfType<HeapRef>().Which;

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var index = Expr.Sym(Sort.Int, "arg_index");
        var value = Expr.Sym(Sort.Bytes, "arg_value");
        halted.EvaluationStack.Single().Expression.Should().Be(value);
        var updated = halted.Heap.Get<ArrayObject>(arrayRef.ObjectId);
        for (int i = 0; i < updated.Items.Count; i++)
        {
            updated.Items[i].Expression.Should().Be(Expr.Ite(
                Expr.Eq(index, Expr.Int(i)),
                value,
                Expr.Sym(Sort.Bytes, $"arg_items[{i}]")));
        }
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "SETITEM"
            && fault.FailedCondition.Contains("array SETITEM index is within runtime length")
            && fault.FaultCondition.FreeSymbols().Contains("arg_index")
            && fault.FaultCondition.FreeSymbols().Any(name => name.StartsWith("array_size_", StringComparison.Ordinal)));
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "PICKITEM"
            && fault.FailedCondition.Contains("array PICKITEM index is within runtime length"));
    }

    [Fact]
    public void Engine_OpenCSharpStructParameterSetItemWithSymbolicIndexSupportsReadAfterWrite()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x03,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.LDARG2,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("row", "Struct"),
            new ContractParameterDefinition("index", "Integer"),
            new ContractParameterDefinition("value", "ByteString"),
        });
        var structRef = entry.Peek(0).Expression.Should().BeOfType<HeapRef>().Which;

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var index = Expr.Sym(Sort.Int, "arg_index");
        var value = Expr.Sym(Sort.Bytes, "arg_value");
        halted.EvaluationStack.Single().Expression.Should().Be(value);
        var updated = halted.Heap.Get<StructObject>(structRef.ObjectId);
        for (int i = 0; i < updated.Fields.Count; i++)
        {
            updated.Fields[i].Expression.Should().Be(Expr.Ite(
                Expr.Eq(index, Expr.Int(i)),
                value,
                Expr.Sym(Sort.Bytes, $"arg_row[{i}]")));
        }
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "SETITEM"
            && fault.FailedCondition.Contains("struct SETITEM index is within runtime length")
            && fault.FaultCondition.FreeSymbols().Contains("arg_index")
            && fault.FaultCondition.FreeSymbols().Any(name => name.StartsWith("struct_size_", StringComparison.Ordinal)));
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "PICKITEM"
            && fault.FailedCondition.Contains("struct PICKITEM index is within runtime length"));
    }

    [Fact]
    public void Engine_BufferSetItemWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var buffer = state.Heap.NewBuffer(new byte[] { 1, 2 });
        var index = SymbolicValue.Symbol(Sort.Int, "i");
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));
        state.Push(index);
        state.Push(SymbolicValue.Int(9));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<BufferObject>(buffer.Id);
        updated.Cells[0].Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(0)), Expr.Int(9), Expr.Int(1)));
        updated.Cells[1].Should().Be(Expr.Ite(Expr.Eq(index.Expression, Expr.Int(1)), Expr.Int(9), Expr.Int(2)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SETITEM");
        fault.Reason.Should().Contain("buffer");
        fault.FailedCondition.Should().Contain("buffer SETITEM index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("i");
    }

    [Fact]
    public void Engine_BufferSetItemStoresNegativePrimitiveAsUnsignedByte()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var buffer = state.Heap.NewBuffer(new byte[] { 0 });
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));
        state.Push(SymbolicValue.Int(0));
        state.Push(SymbolicValue.Int(-1));

        var result = new SymbolicEngine(program).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.Heap.Get<BufferObject>(buffer.Id).Cells[0].Should().Be(Expr.Int(255));
    }

    [Fact]
    public void Engine_BufferSetItemFaultsWhenPrimitiveValueExceedsByteRange()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var buffer = state.Heap.NewBuffer(new byte[] { 0 });
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));
        state.Push(SymbolicValue.Int(0));
        state.Push(SymbolicValue.Int(256));

        var result = new SymbolicEngine(program).Run(state);

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("byte");
        faulted.TerminationReason.Should().Contain("SETITEM");
    }

    [Fact]
    public void Engine_PrimitivePickItemFaultsWhenByteStringIndexExceedsNeoVmIntegerSize()
    {
        byte[] script = Concat(
            Pushdata1(new byte[] { 0xAA }),
            Pushdata1(new byte[33]),
            new[] { (byte)NeoVm.OpCode.PICKITEM, (byte)NeoVm.OpCode.RET });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("PICKITEM");
        faulted.TerminationReason.Should().Contain("32-byte");
    }

    [Fact]
    public void Engine_PackMapFaultsWhenKeyIsNotPrimitive()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.NEWARRAY0,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PACKMAP,
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("PACKMAP");
        faulted.TerminationReason.Should().Contain("primitive");
    }

    [Fact]
    public void Engine_PackPreservesNeoVmPopOrder()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PACK,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().AsConcreteInt().Should()
            .Be(new BigInteger(2), "NeoVM PACK stores the first popped stack item at array index 0");
    }

    [Fact]
    public void Engine_PackStructPreservesNeoVmPopOrder()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PACKSTRUCT,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().AsConcreteInt().Should()
            .Be(new BigInteger(2), "NeoVM PACKSTRUCT stores the first popped stack item at struct index 0");
    }

    [Fact]
    public void Engine_ArrayAppendClonesStructValues()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.APPEND,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        var array = state.Heap.NewArray();
        var structure = state.Heap.NewStruct(new[] { SymbolicValue.Int(1) });
        state.Push(SymbolicValue.HeapRef(Sort.Array, array.Id));
        state.Push(SymbolicValue.HeapRef(Sort.Struct, structure.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        var stored = halted.Heap.Get<ArrayObject>(array.Id).Items.Should().ContainSingle().Subject;
        var storedRef = stored.Expression.Should().BeOfType<HeapRef>().Subject;
        storedRef.ObjectId.Should().NotBe(structure.Id);
        halted.Heap.Get<StructObject>(storedRef.ObjectId).Fields.Single().AsConcreteInt().Should().Be(new BigInteger(1));
    }

    [Fact]
    public void Engine_ArraySetItemClonesStructValues()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        var array = state.Heap.NewArray(new[] { SymbolicValue.Null() });
        var structure = state.Heap.NewStruct(new[] { SymbolicValue.Int(1) });
        state.Push(SymbolicValue.HeapRef(Sort.Array, array.Id));
        state.Push(SymbolicValue.Int(0));
        state.Push(SymbolicValue.HeapRef(Sort.Struct, structure.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        var stored = halted.Heap.Get<ArrayObject>(array.Id).Items.Should().ContainSingle().Subject;
        var storedRef = stored.Expression.Should().BeOfType<HeapRef>().Subject;
        storedRef.ObjectId.Should().NotBe(structure.Id);
        halted.Heap.Get<StructObject>(storedRef.ObjectId).Fields.Single().AsConcreteInt().Should().Be(new BigInteger(1));
    }

    [Fact]
    public void Engine_ClearItemsFaultsOnBuffer()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.CLEARITEMS,
            (byte)NeoVm.OpCode.RET,
        };
        var state = NewState(pc: 0);
        var buffer = state.Heap.NewBuffer(new byte[] { 1, 2, 3 });
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("CLEARITEMS");
        faulted.TerminationReason.Should().Contain("Buffer");
    }

    [Fact]
    public void Engine_ContractCallWithOpenArgsArrayDoesNotCloseArityFromSeedPrefix()
    {
        byte[] script = Concat(
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });
        var state = NewState(pc: 0);
        var args = state.Heap.NewArray(
            new[] { SymbolicValue.Int(1) },
            isSymbolicOpen: true,
            minCount: 1);
        state.Push(SymbolicValue.Bytes(Enumerable.Repeat((byte)0x11, 20).ToArray()));
        state.Push(SymbolicValue.Bytes("callback"u8.ToArray()));
        state.Push(SymbolicValue.Int(NeoCallFlags.All));
        state.Push(SymbolicValue.HeapRef(Sort.Array, args.Id));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        var call = halted.Telemetry.ExternalCalls.Should().ContainSingle().Subject;
        call.Args.Should().BeEmpty("an open ABI Array may contain more runtime arguments than its seeded prefix");
    }

    [Fact]
    public void VerificationSpec_ReturnByteStringMetricAcceptsBufferRuntimeReturn()
    {
        var method = new ContractMethodDescriptor
        {
            Name = "symbol",
            ReturnType = "String",
        };
        var state = NewState(pc: 0);
        var buffer = state.Heap.NewBuffer("neo"u8.ToArray());
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));
        var condition = new VerificationCondition(
            "$return",
            "==",
            IntegerValue: 3,
            BooleanValue: null,
            IsReturn: true,
            Metric: "size");

        var expression = condition.ToExpression(method, state);

        var returnedBytes = Expr.Bytes("neo"u8.ToArray());
        expression.Should().Be(Expr.Eq(
            new UnaryExpr(Sort.Int, "size", returnedBytes),
            Expr.Int(3)));
    }

    [Fact]
    public void VerificationSpec_ReturnByteStringComparisonAcceptsBufferRuntimeReturn()
    {
        var method = new ContractMethodDescriptor
        {
            Name = "symbol",
            ReturnType = "String",
        };
        var state = NewState(pc: 0);
        var buffer = state.Heap.NewBuffer("neo"u8.ToArray());
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, buffer.Id));
        var condition = new VerificationCondition(
            "$return",
            "==",
            IntegerValue: null,
            BooleanValue: null,
            IsReturn: true,
            ByteValue: "neo"u8.ToArray().ToImmutableArray(),
            HasByteValue: true);

        var expression = condition.ToExpression(method, state);

        var returnedBytes = Expr.Bytes("neo"u8.ToArray());
        expression.Should().Be(Expr.BoolAnd(
            Expr.Eq(new UnaryExpr(Sort.Int, "size", returnedBytes), Expr.Int(3)),
            Expr.Eq(new UnaryExpr(Sort.Int, "b2i", returnedBytes), Expr.Int(Expr.BytesToInteger("neo"u8.ToArray())))));
    }

    [Fact]
    public void Engine_ClosedArrayRemoveWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var array = state.Heap.NewArray(new[]
        {
            SymbolicValue.Int(1),
            SymbolicValue.Int(2),
            SymbolicValue.Int(3),
        });
        var index = SymbolicValue.Symbol(Sort.Int, "i");
        state.Push(SymbolicValue.HeapRef(Sort.Array, array.Id));
        state.Push(index);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<ArrayObject>(array.Id);
        updated.Items.Should().HaveCount(2);
        updated.Items[0].Expression.Should().Be(Expr.Ite(Expr.Le(index.Expression, Expr.Int(0)), Expr.Int(2), Expr.Int(1)));
        updated.Items[1].Expression.Should().Be(Expr.Ite(Expr.Le(index.Expression, Expr.Int(1)), Expr.Int(3), Expr.Int(2)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("REMOVE");
        fault.Reason.Should().Contain("array");
        fault.FailedCondition.Should().Contain("array REMOVE index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("i");
    }

    [Fact]
    public void Engine_ClosedStructRemoveWithSymbolicIndexRecordsBoundsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var structure = state.Heap.NewStruct(new[]
        {
            SymbolicValue.Int(1),
            SymbolicValue.Int(2),
            SymbolicValue.Int(3),
        });
        var index = SymbolicValue.Symbol(Sort.Int, "i");
        state.Push(SymbolicValue.HeapRef(Sort.Struct, structure.Id));
        state.Push(index);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<StructObject>(structure.Id);
        updated.Fields.Should().HaveCount(2);
        updated.Fields[0].Expression.Should().Be(Expr.Ite(Expr.Le(index.Expression, Expr.Int(0)), Expr.Int(2), Expr.Int(1)));
        updated.Fields[1].Expression.Should().Be(Expr.Ite(Expr.Le(index.Expression, Expr.Int(1)), Expr.Int(3), Expr.Int(2)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("REMOVE");
        fault.Reason.Should().Contain("struct");
        fault.FailedCondition.Should().Contain("struct REMOVE index is within range");
        fault.FaultCondition.FreeSymbols().Should().Contain("i");
    }

    [Fact]
    public void Engine_OpenCSharpArrayParameterRemoveWithSymbolicIndexUpdatesSeededPrefix()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x02,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("items", "Array"),
            new ContractParameterDefinition("index", "Integer"),
        });
        var arrayRef = entry.Peek(0).Expression.Should().BeOfType<HeapRef>().Which;

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var index = Expr.Sym(Sort.Int, "arg_index");
        var updated = halted.Heap.Get<ArrayObject>(arrayRef.ObjectId);
        updated.Items.Should().HaveCount(4);
        updated.Items[0].Expression.Should().Be(Expr.Ite(
            Expr.Le(index, Expr.Int(0)),
            Expr.Sym(Sort.Bytes, "arg_items[1]"),
            Expr.Sym(Sort.Bytes, "arg_items[0]")));
        updated.Items[3].Expression.Should().Be(Expr.Ite(
            Expr.Le(index, Expr.Int(3)),
            Expr.Sym(Sort.Bytes, $"array_{arrayRef.ObjectId}_item_4"),
            Expr.Sym(Sort.Bytes, "arg_items[3]")));
        halted.EvaluationStack.Single().Expression.Should().Be(updated.Items[0].Expression);
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "REMOVE"
            && fault.FailedCondition.Contains("array REMOVE index is within runtime length")
            && fault.FaultCondition.FreeSymbols().Contains("arg_index")
            && fault.FaultCondition.FreeSymbols().Any(name => name.StartsWith("array_size_", StringComparison.Ordinal)));
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "PICKITEM"
            && fault.FailedCondition.Contains("array PICKITEM index is within runtime length"));
    }

    [Fact]
    public void Engine_OpenCSharpStructParameterRemoveWithSymbolicIndexUpdatesSeededPrefix()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x02,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("row", "Struct"),
            new ContractParameterDefinition("index", "Integer"),
        });
        var structRef = entry.Peek(0).Expression.Should().BeOfType<HeapRef>().Which;

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var index = Expr.Sym(Sort.Int, "arg_index");
        var updated = halted.Heap.Get<StructObject>(structRef.ObjectId);
        updated.Fields.Should().HaveCount(4);
        updated.Fields[0].Expression.Should().Be(Expr.Ite(
            Expr.Le(index, Expr.Int(0)),
            Expr.Sym(Sort.Bytes, "arg_row[1]"),
            Expr.Sym(Sort.Bytes, "arg_row[0]")));
        updated.Fields[3].Expression.Should().Be(Expr.Ite(
            Expr.Le(index, Expr.Int(3)),
            Expr.Sym(Sort.Bytes, $"struct_{structRef.ObjectId}_item_4"),
            Expr.Sym(Sort.Bytes, "arg_row[3]")));
        halted.EvaluationStack.Single().Expression.Should().Be(updated.Fields[0].Expression);
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "REMOVE"
            && fault.FailedCondition.Contains("struct REMOVE index is within runtime length")
            && fault.FaultCondition.FreeSymbols().Contains("arg_index")
            && fault.FaultCondition.FreeSymbols().Any(name => name.StartsWith("struct_size_", StringComparison.Ordinal)));
        halted.Telemetry.FaultConditions.Should().ContainSingle(fault =>
            fault.Operation == "PICKITEM"
            && fault.FailedCondition.Contains("struct PICKITEM index is within runtime length"));
    }

    [Fact]
    public void Engine_CreateMethodEntryState_CoversCSharpMapParameterKeysAndUnknownLookup()
    {
        byte[] keysScript =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.KEYS,
            (byte)NeoVm.OpCode.RET,
        };
        var keysEngine = new SymbolicEngine(ScriptDecoder.Decode(keysScript));
        var keysEntry = keysEngine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
        });

        var keysResult = keysEngine.Run(keysEntry);

        // Review fix (#5): KEYS over an open (unknown-size) Map parameter cannot soundly enumerate
        // the runtime key set — the previous behavior returned only the seeded keys plus one fresh
        // symbol, which under-approximates the true key array length. The engine now terminates as a
        // modeling limit (coverage incomplete) so the verifier downgrades instead of proving over a
        // seeded key set.
        keysResult.CoverageIncomplete.Should().BeTrue();
        keysResult.CoverageReason.Should().Contain("KEYS over open symbolic Map");
        var keysStopped = keysResult.FinalStates.Single();
        keysStopped.Status.Should().Be(TerminalStatus.Stopped);

        byte[] lookupScript = Concat(
            new byte[]
            {
                (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
                (byte)NeoVm.OpCode.LDARG0,
            },
            Pushdata1(System.Text.Encoding.UTF8.GetBytes("owner")),
            new byte[]
            {
                (byte)NeoVm.OpCode.PICKITEM,
                (byte)NeoVm.OpCode.RET,
            });
        var lookupEngine = new SymbolicEngine(ScriptDecoder.Decode(lookupScript));
        var lookupEntry = lookupEngine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
        });

        var lookupResult = lookupEngine.Run(lookupEntry);

        lookupResult.CoverageIncomplete.Should().BeFalse(lookupResult.CoverageReason);
        var lookupHalted = lookupResult.FinalStates.Single();
        lookupHalted.Status.Should().Be(TerminalStatus.Halted);
        var lookupSymbol = lookupHalted.EvaluationStack.Single().Expression.Should().BeOfType<Symbol>().Which;
        lookupSymbol.Name.Should().Contain("open_map_");

        var fault = lookupHalted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("Map");
        fault.Reason.Should().Contain("key");
        fault.FailedCondition.Should().Contain("Map PICKITEM key exists");
        fault.FaultCondition.FreeSymbols().Should().Contain(name => name.StartsWith("open_map_", StringComparison.Ordinal));
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterPickItemFaultConditionUsesHasKeyGuardPredicate()
    {
        byte[] script = Concat(
            new byte[]
            {
                (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.DUP,
            },
            Pushdata1(System.Text.Encoding.UTF8.GetBytes("owner")),
            new byte[]
            {
                (byte)NeoVm.OpCode.HASKEY,
                (byte)NeoVm.OpCode.JMPIF,
                0x05,
                (byte)NeoVm.OpCode.DROP,
                (byte)NeoVm.OpCode.PUSHNULL,
                (byte)NeoVm.OpCode.RET,
            },
            Pushdata1(System.Text.Encoding.UTF8.GetBytes("owner")),
            new byte[]
            {
                (byte)NeoVm.OpCode.PICKITEM,
                (byte)NeoVm.OpCode.RET,
            });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().HaveCount(2);
        var guardedPath = result.FinalStates.Single(state =>
            state.Status == TerminalStatus.Halted
            && state.EvaluationStack.Single().Expression is Symbol symbol
            && symbol.Name.Contains("_value_", StringComparison.Ordinal));
        var fault = guardedPath.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        var missingKeyCondition = fault.FaultCondition.Should().BeOfType<UnaryExpr>().Which;
        missingKeyCondition.Op.Should().Be("not");
        var hasKeyPredicate = missingKeyCondition.Operand.Should().BeOfType<Symbol>().Which;

        guardedPath.PathConditions.Should().Contain(hasKeyPredicate);
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterSetItemWithSymbolicKeySupportsReadAfterWrite()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x03,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.LDARG2,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
            new ContractParameterDefinition("key", "ByteString"),
            new ContractParameterDefinition("value", "ByteString"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Sym(Sort.Bytes, "arg_value"));
        halted.Telemetry.FaultConditions.Should().BeEmpty("the just-written open Map key is known to exist");
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterDynamicExpressionKeysUseDistinctLookupSymbols()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.LDLOC0,
            (byte)NeoVm.OpCode.LDLOC1,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.LDLOC0,
            (byte)NeoVm.OpCode.LDLOC2,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.CurrentFrame.InitSlots(localsCount: 3, argsCount: 0);
        var map = state.Heap.NewMap(isSymbolicOpen: true);
        var x = Expr.Sym(Sort.Int, "x");
        state.CurrentFrame.Locals[0] = SymbolicValue.HeapRef(Sort.Map, map.Id);
        state.CurrentFrame.Locals[1] = SymbolicValue.Of(Expr.Add(x, Expr.Int(1)), new[] { "x" });
        state.CurrentFrame.Locals[2] = SymbolicValue.Of(Expr.Add(x, Expr.Int(2)), new[] { "x" });

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Should().HaveCount(2);
        var first = halted.EvaluationStack[0].Expression.Should().BeOfType<Symbol>().Which;
        var second = halted.EvaluationStack[1].Expression.Should().BeOfType<Symbol>().Which;
        first.Name.Should().StartWith("open_map_");
        second.Name.Should().StartWith("open_map_");
        first.Name.Should().NotBe(second.Name,
            "different dynamic Map key expressions may have different runtime values");
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterSetItemWithSymbolicKeyMakesHasKeyTrue()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x03,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.LDARG2,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
            new ContractParameterDefinition("key", "ByteString"),
            new ContractParameterDefinition("value", "ByteString"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Bool(true));
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterRemoveWithSymbolicKeyMakesHasKeyFalse()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x02,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
            new ContractParameterDefinition("key", "ByteString"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Bool(false));
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_OpenCSharpMapParameterRemoveWithSymbolicKeyOverridesPriorSetItem()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x03,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.LDARG2,
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.RET,
        };
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("meta", "Map"),
            new ContractParameterDefinition("key", "ByteString"),
            new ContractParameterDefinition("value", "ByteString"),
        });

        var result = engine.Run(entry);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().Expression.Should().Be(Expr.Bool(false));
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ClosedMapHasKeyWithSymbolicKeyUsesKnownKeyPredicate()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var ownerKey = SymbolicValue.Bytes("owner"u8.ToArray());
        var adminKey = SymbolicValue.Bytes("admin"u8.ToArray());
        var map = state.Heap.NewMap(new[]
        {
            (ownerKey, SymbolicValue.Int(1)),
            (adminKey, SymbolicValue.Int(2)),
        });
        var key = SymbolicValue.Symbol(Sort.Bytes, "k");
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(key);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var expected = Expr.BoolOr(
            Expr.Eq(key.Expression, ownerKey.Expression),
            Expr.Eq(key.Expression, adminKey.Expression));
        halted.EvaluationStack.Single().Expression.Should().Be(expected);
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ClosedMapConcreteLookupDoesNotAliasBooleanAndIntegerKeys()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.HASKEY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var map = state.Heap.NewMap(new[]
        {
            (SymbolicValue.Bool(true), SymbolicValue.Bytes("bool"u8.ToArray())),
        });
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(SymbolicValue.Int(1));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteBool().Should().BeFalse(
            "NeoVM Map keys use StackItem equality, so Boolean true and Integer 1 are distinct keys");
    }

    [Fact]
    public void Engine_ClosedMapPickItemWithSymbolicKeyRecordsKeyExistsFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var ownerKey = SymbolicValue.Bytes("owner"u8.ToArray());
        var adminKey = SymbolicValue.Bytes("admin"u8.ToArray());
        var map = state.Heap.NewMap(new[]
        {
            (ownerKey, SymbolicValue.Int(1)),
            (adminKey, SymbolicValue.Int(2)),
        });
        var key = SymbolicValue.Symbol(Sort.Bytes, "k");
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(key);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var ownerMatch = Expr.Eq(key.Expression, ownerKey.Expression);
        var adminMatch = Expr.Eq(key.Expression, adminKey.Expression);
        halted.EvaluationStack.Single().Expression.Should().Be(
            Expr.Ite(ownerMatch, Expr.Int(1), Expr.Ite(adminMatch, Expr.Int(2), Expr.Int(1))));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("PICKITEM");
        fault.Reason.Should().Contain("closed Map");
        fault.FailedCondition.Should().Contain("Map PICKITEM key exists");
        fault.FaultCondition.Should().Be(Expr.Not(Expr.BoolOr(ownerMatch, adminMatch)));
        fault.FaultCondition.FreeSymbols().Should().Contain("k");
    }

    [Fact]
    public void Engine_ClosedMapSetItemWithGuardedSymbolicKeyUpdatesKnownEntries()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SETITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var ownerKey = SymbolicValue.Bytes("owner"u8.ToArray());
        var adminKey = SymbolicValue.Bytes("admin"u8.ToArray());
        var map = state.Heap.NewMap(new[]
        {
            (ownerKey, SymbolicValue.Int(1)),
            (adminKey, SymbolicValue.Int(2)),
        });
        var key = SymbolicValue.Symbol(Sort.Bytes, "k");
        var ownerMatch = Expr.Eq(key.Expression, ownerKey.Expression);
        var adminMatch = Expr.Eq(key.Expression, adminKey.Expression);
        state.PathConditions = state.PathConditions.Add(Expr.BoolOr(ownerMatch, adminMatch));
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(key);
        state.Push(SymbolicValue.Int(9));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<MapObject>(map.Id);
        updated.Entries.Should().HaveCount(2);
        updated.Entries[0].Key.Should().Be(ownerKey);
        updated.Entries[1].Key.Should().Be(adminKey);
        updated.Entries[0].Value.Expression.Should().Be(Expr.Ite(ownerMatch, Expr.Int(9), Expr.Int(1)));
        updated.Entries[1].Value.Expression.Should().Be(Expr.Ite(adminMatch, Expr.Int(9), Expr.Int(2)));
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_ClosedMapRemoveWithGuardedSymbolicKeyShrinksKnownEntries()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var ownerKey = SymbolicValue.Bytes("owner"u8.ToArray());
        var adminKey = SymbolicValue.Bytes("admin"u8.ToArray());
        var map = state.Heap.NewMap(new[]
        {
            (ownerKey, SymbolicValue.Int(1)),
            (adminKey, SymbolicValue.Int(2)),
        });
        var key = SymbolicValue.Symbol(Sort.Bytes, "k");
        var ownerMatch = Expr.Eq(key.Expression, ownerKey.Expression);
        var adminMatch = Expr.Eq(key.Expression, adminKey.Expression);
        state.PathConditions = state.PathConditions.Add(Expr.BoolOr(ownerMatch, adminMatch));
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(key);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var updated = halted.Heap.Get<MapObject>(map.Id);
        updated.Entries.Should().HaveCount(1);
        updated.Entries[0].Key.Expression.Should().Be(Expr.Ite(ownerMatch, adminKey.Expression, ownerKey.Expression));
        updated.Entries[0].Value.Expression.Should().Be(Expr.Ite(ownerMatch, Expr.Int(2), Expr.Int(1)));
        halted.Telemetry.FaultConditions.Should().BeEmpty();
    }

    [Fact]
    public void Engine_SubstrWithSymbolicByteStringSourceRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SUBSTR,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        state.Push(source);
        state.Push(SymbolicValue.Int(1));
        state.Push(SymbolicValue.Int(2));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        bufferRef.RefSort.Should().Be(Sort.Buffer);
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new TernaryExpr(Sort.Bytes, "substr", source.Expression, Expr.Int(1), Expr.Int(2)));
        buffer.SymbolicLength.Should().Be(Expr.Int(2));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SUBSTR");
        fault.FailedCondition.Should().Contain("SUBSTR range is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain("data");
    }

    [Fact]
    public void Engine_LeftWithSymbolicByteStringSourceRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.LEFT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        state.Push(source);
        state.Push(SymbolicValue.Int(2));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        bufferRef.RefSort.Should().Be(Sort.Buffer);
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new BinaryExpr(Sort.Bytes, "left", source.Expression, Expr.Int(2)));
        buffer.SymbolicLength.Should().Be(Expr.Int(2));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("LEFT");
        fault.FailedCondition.Should().Contain("LEFT count is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain("data");
    }

    [Fact]
    public void Engine_RightWithSymbolicByteStringSourceRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.RIGHT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        state.Push(source);
        state.Push(SymbolicValue.Int(2));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        bufferRef.RefSort.Should().Be(Sort.Buffer);
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new BinaryExpr(Sort.Bytes, "right", source.Expression, Expr.Int(2)));
        buffer.SymbolicLength.Should().Be(Expr.Int(2));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("RIGHT");
        fault.FailedCondition.Should().Contain("RIGHT count is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain("data");
    }

    [Fact]
    public void Engine_SubstrWithSymbolicIndexAndCountRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SUBSTR,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        var start = SymbolicValue.Symbol(Sort.Int, "start");
        var count = SymbolicValue.Symbol(Sort.Int, "count");
        state.Push(source);
        state.Push(start);
        state.Push(count);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new TernaryExpr(Sort.Bytes, "substr", source.Expression, start.Expression, count.Expression));
        buffer.SymbolicLength.Should().Be(count.Expression);
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("SUBSTR");
        fault.FailedCondition.Should().Contain("SUBSTR range is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain(new[] { "data", "start", "count" });
    }

    [Fact]
    public void Engine_SubstrOfSymbolicSubstrKeepsRangeFaultConditions()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.SUBSTR,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.SUBSTR,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        state.Push(source);
        state.Push(SymbolicValue.Int(1));
        state.Push(SymbolicValue.Int(4));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var firstSlice = new TernaryExpr(Sort.Bytes, "substr", source.Expression, Expr.Int(1), Expr.Int(4));
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new TernaryExpr(Sort.Bytes, "substr", firstSlice, Expr.Int(1), Expr.Int(2)));
        buffer.SymbolicLength.Should().Be(Expr.Int(2));
        halted.Telemetry.FaultConditions.Should().HaveCount(2);
        halted.Telemetry.FaultConditions.Select(f => f.Operation).Should().AllBeEquivalentTo("SUBSTR");
        halted.Telemetry.FaultConditions.SelectMany(f => f.FaultCondition.FreeSymbols()).Should().Contain("data");
    }

    [Fact]
    public void Engine_LeftWithSymbolicCountRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.LEFT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        var count = SymbolicValue.Symbol(Sort.Int, "count");
        state.Push(source);
        state.Push(count);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new BinaryExpr(Sort.Bytes, "left", source.Expression, count.Expression));
        buffer.SymbolicLength.Should().Be(count.Expression);
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("LEFT");
        fault.FailedCondition.Should().Contain("LEFT count is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain(new[] { "data", "count" });
    }

    [Fact]
    public void Engine_RightWithSymbolicCountRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.RIGHT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        var count = SymbolicValue.Symbol(Sort.Int, "count");
        state.Push(source);
        state.Push(count);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var bufferRef = halted.EvaluationStack.Single().Expression.Should().BeOfType<HeapRef>().Subject;
        var buffer = halted.Heap.Get<BufferObject>(bufferRef.ObjectId);
        buffer.SourceBytes.Should().Be(new BinaryExpr(Sort.Bytes, "right", source.Expression, count.Expression));
        buffer.SymbolicLength.Should().Be(count.Expression);
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("RIGHT");
        fault.FailedCondition.Should().Contain("RIGHT count is within source size");
        fault.FaultCondition.FreeSymbols().Should().Contain(new[] { "data", "count" });
    }

    [Fact]
    public void Engine_MemCpyWithSymbolicByteStringSourceRecordsRangeFaultCondition()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.MEMCPY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var destination = state.Heap.NewBuffer(new byte[] { 0, 0, 0, 0 });
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, destination.Id));
        state.Push(SymbolicValue.Int(1));
        state.Push(source);
        state.Push(SymbolicValue.Int(2));
        state.Push(SymbolicValue.Int(2));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var buffer = halted.Heap.Get<BufferObject>(destination.Id);
        buffer.Cells[0].Should().Be(Expr.Int(0));
        buffer.Cells[1].Should().Be(new BinaryExpr(Sort.Int, "pick", source.Expression, Expr.Int(2)));
        buffer.Cells[2].Should().Be(new BinaryExpr(Sort.Int, "pick", source.Expression, Expr.Int(3)));
        buffer.Cells[3].Should().Be(Expr.Int(0));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("MEMCPY");
        fault.FailedCondition.Should().Contain("MEMCPY ranges are within source and destination sizes");
        fault.FaultCondition.FreeSymbols().Should().Contain("data");
    }

    [Fact]
    public void Engine_MemCpyWithSymbolicByteStringSourceAndCountUpdatesFiniteDestinationCells()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.MEMCPY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var destination = state.Heap.NewBuffer(new byte[] { 0, 0, 0, 0 });
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        var count = SymbolicValue.Symbol(Sort.Int, "n");
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, destination.Id));
        state.Push(SymbolicValue.Int(1));
        state.Push(source);
        state.Push(SymbolicValue.Int(0));
        state.Push(count);

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var buffer = halted.Heap.Get<BufferObject>(destination.Id);
        buffer.Cells[0].Should().Be(Expr.Int(0));
        buffer.Cells[1].Should().Be(Expr.Ite(
            Expr.Gt(count.Expression, Expr.Int(0)),
            new BinaryExpr(Sort.Int, "pick", source.Expression, Expr.Int(0)),
            Expr.Int(0)));
        buffer.Cells[2].Should().Be(Expr.Ite(
            Expr.Gt(count.Expression, Expr.Int(1)),
            new BinaryExpr(Sort.Int, "pick", source.Expression, Expr.Int(1)),
            Expr.Int(0)));
        buffer.Cells[3].Should().Be(Expr.Ite(
            Expr.Gt(count.Expression, Expr.Int(2)),
            new BinaryExpr(Sort.Int, "pick", source.Expression, Expr.Int(2)),
            Expr.Int(0)));
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("MEMCPY");
        fault.FailedCondition.Should().Contain("MEMCPY ranges are within source and destination sizes");
        fault.FaultCondition.FreeSymbols().Should().Contain(new[] { "data", "n" });
    }

    [Fact]
    public void Engine_MemCpyWithSymbolicByteStringIndexesUpdatesFiniteDestinationCells()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.MEMCPY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var destination = state.Heap.NewBuffer(new byte[] { 0, 0, 0, 0 });
        var source = SymbolicValue.Symbol(Sort.Bytes, "data");
        var sourceIndex = SymbolicValue.Symbol(Sort.Int, "s");
        var destinationIndex = SymbolicValue.Symbol(Sort.Int, "d");
        state.Push(SymbolicValue.HeapRef(Sort.Buffer, destination.Id));
        state.Push(destinationIndex);
        state.Push(source);
        state.Push(sourceIndex);
        state.Push(SymbolicValue.Int(2));

        var result = new SymbolicEngine(program).Run(state);

        result.CoverageIncomplete.Should().BeFalse(result.CoverageReason);
        var halted = result.FinalStates.Should().ContainSingle().Subject;
        halted.Status.Should().Be(TerminalStatus.Halted);
        var buffer = halted.Heap.Get<BufferObject>(destination.Id);
        for (int i = 0; i < buffer.Length; i++)
        {
            var sourceOffset = Expr.Add(sourceIndex.Expression, Expr.Sub(Expr.Int(i), destinationIndex.Expression));
            var copyThisCell = Expr.Within(Expr.Int(i), destinationIndex.Expression, Expr.Add(destinationIndex.Expression, Expr.Int(2)));
            buffer.Cells[i].Should().Be(Expr.Ite(
                copyThisCell,
                new BinaryExpr(Sort.Int, "pick", source.Expression, sourceOffset),
                Expr.Int(0)));
        }
        var fault = halted.Telemetry.FaultConditions.Should().ContainSingle().Subject;
        fault.Operation.Should().Be("MEMCPY");
        fault.FailedCondition.Should().Contain("MEMCPY ranges are within source and destination sizes");
        fault.FaultCondition.FreeSymbols().Should().Contain(new[] { "data", "s", "d" });
    }

    private static ExecutionState NewState(int pc)
    {
        var state = new ExecutionState { Pc = pc };
        state.CallStack.Add(new CallFrame(returnPc: -1));
        return state;
    }

    private static byte[] ScriptHash(byte[] script)
    {
        byte[] sha256 = System.Security.Cryptography.SHA256.HashData(script);
        var digest = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
        digest.BlockUpdate(sha256, 0, sha256.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }

    private static bool IsNotSymbol(Expression expr, string name) =>
        expr is UnaryExpr { Op: "not", Operand: Symbol s } && s.Name == name;

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

    private static byte[] PushData(byte[] data)
    {
        if (data.Length <= byte.MaxValue)
            return Pushdata1(data);

        if (data.Length > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(data), "test push helper supports up to PUSHDATA2");

        byte[] result = new byte[data.Length + 3];
        result[0] = (byte)NeoVm.OpCode.PUSHDATA2;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(1, 2), (ushort)data.Length);
        System.Array.Copy(data, 0, result, 3, data.Length);
        return result;
    }

    private static byte[] IteratorValueAfterSuccessfulNextAndReturn() =>
        Concat(
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

    private static byte[] StdLibHashBytes() =>
        Convert.FromHexString("ACCE6FD80D44E1796AA0C2C625E9E4E0CE39EFC0");

    private static byte[] CryptoLibHashBytes() =>
        Convert.FromHexString("726CB6E0CD8628A1350A611384688911AB75F51B");

    private const string BlsG1GeneratorHex =
        "97F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB";

    private static byte[] Syscall(string name)
    {
        uint hash = SyscallRegistry.ComputeHash(name);
        byte[] hashBytes = System.BitConverter.GetBytes(hash);
        return new[]
        {
            (byte)NeoVm.OpCode.SYSCALL,
            hashBytes[0],
            hashBytes[1],
            hashBytes[2],
            hashBytes[3],
        };
    }

    private static JsonObject BuildMinimalProperty(string id) => new()
    {
        ["id"] = id,
        ["method"] = "transfer",
        ["ensures"] = new JsonArray
        {
            new JsonObject
            {
                ["arg"] = "amount",
                ["op"] = ">=",
                ["value"] = 0,
            },
        },
    };

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Neo.SymbolicExecutor.sln")))
            dir = dir.Parent;
        dir.Should().NotBeNull("the test assembly should run under the repository tree");
        return dir!.FullName;
    }

    private static string ReadRepoFile(string relativePath)
    {
        return File.ReadAllText(Path.Combine(FindRepoRoot(), relativePath));
    }

    private static string WriteNeoSymToolWrapper(string dir)
    {
        string cliDll = Path.Combine(AppContext.BaseDirectory, "neo-sym.dll");
        File.Exists(cliDll).Should().BeTrue("the CLI project should be built before DevPack target e2e runs");
        if (OperatingSystem.IsWindows())
        {
            string cmdPath = Path.Combine(dir, "neo-sym-test.cmd");
            File.WriteAllText(cmdPath, $"@echo off\r\ndotnet \"{cliDll}\" %*\r\n");
            return cmdPath;
        }

        string path = Path.Combine(dir, "neo-sym-test");
        File.WriteAllText(path, $"#!/bin/sh\nexec dotnet \"{cliDll}\" \"$@\"\n");
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherExecute);
        return path;
    }

    private static string WriteNeoSymAnalyzeFailVerifyOkToolWrapper(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            string cmdPath = Path.Combine(dir, "neo-sym-analyze-fail-verify-ok.cmd");
            File.WriteAllText(cmdPath, """
                @echo off
                setlocal enabledelayedexpansion
                set mode=%1
                set out=
                set prev=
                for %%A in (%*) do (
                  if "!prev!"=="--out" (
                    set out=%%~A
                  )
                  set prev=%%~A
                )
                for %%I in ("!out!") do if not exist "%%~dpI" mkdir "%%~dpI"
                if "%mode%"=="analyze" (
                  >"!out!" echo {"meta":{"coverage_incomplete":false},"findings":[{"id":"gate","severity":"high"}]}
                  exit /b 3
                )
                if "%mode%"=="verify" (
                  >"!out!" echo {"results":[{"id":"main_no_faults","status":"proved"}]}
                  exit /b 0
                )
                exit /b 2
                """);
            return cmdPath;
        }

        string path = Path.Combine(dir, "neo-sym-analyze-fail-verify-ok");
        File.WriteAllText(path, """
            #!/bin/sh
            mode="$1"
            out=""
            prev=""
            for arg in "$@"; do
              if [ "$prev" = "--out" ]; then
                out="$arg"
                break
              fi
              prev="$arg"
            done
            mkdir -p "$(dirname "$out")"
            if [ "$mode" = "analyze" ]; then
              printf '%s\n' '{"meta":{"coverage_incomplete":false},"findings":[{"id":"gate","severity":"high"}]}' > "$out"
              exit 3
            fi
            if [ "$mode" = "verify" ]; then
              printf '%s\n' '{"results":[{"id":"main_no_faults","status":"proved"}]}' > "$out"
              exit 0
            fi
            exit 2
            """);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherExecute);
        return path;
    }

    private static string WriteNeoSymFailNamedAnalyzeToolWrapper(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            string cmdPath = Path.Combine(dir, "neo-sym-fail-named-analyze.cmd");
            File.WriteAllText(cmdPath, """
                @echo off
                setlocal enabledelayedexpansion
                set mode=%~1
                set program=%~2
                set out=
                set prev=
                for %%A in (%*) do (
                  if "!prev!"=="--out" (
                    set out=%%~A
                  )
                  set prev=%%~A
                )
                for %%I in ("!out!") do if not exist "%%~dpI" mkdir "%%~dpI"
                for %%F in ("!program!") do set contract=%%~nF
                if "%mode%"=="analyze" (
                  >"!out!" echo {"meta":{"coverage_incomplete":false},"findings":[]}
                  if "!contract!"=="00Fail" exit /b 3
                  exit /b 0
                )
                if "%mode%"=="verify" (
                  >"!out!" echo {"results":[{"id":"main_no_faults","status":"proved"}]}
                  exit /b 0
                )
                exit /b 2
                """);
            return cmdPath;
        }

        string path = Path.Combine(dir, "neo-sym-fail-named-analyze");
        File.WriteAllText(path, """
            #!/bin/sh
            mode="$1"
            program="$2"
            out=""
            prev=""
            for arg in "$@"; do
              if [ "$prev" = "--out" ]; then
                out="$arg"
                break
              fi
              prev="$arg"
            done
            mkdir -p "$(dirname "$out")"
            if [ "$mode" = "analyze" ]; then
              printf '%s\n' '{"meta":{"coverage_incomplete":false},"findings":[]}' > "$out"
              if [ "$(basename "$program" .nef)" = "00Fail" ]; then
                exit 3
              fi
              exit 0
            fi
            if [ "$mode" = "verify" ]; then
              printf '%s\n' '{"results":[{"id":"main_no_faults","status":"proved"}]}' > "$out"
              exit 0
            fi
            exit 2
            """);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherExecute);
        return path;
    }

    private static byte[] BuildNef(string compiler, string source, byte[] script)
    {
        using var ms = new MemoryStream();
        using (var writer = new BinaryWriter(ms, System.Text.Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(NefFile.MagicValue);
            var compilerBytes = new byte[64];
            byte[] compilerString = System.Text.Encoding.ASCII.GetBytes(compiler);
            Array.Copy(compilerString, compilerBytes, Math.Min(compilerString.Length, compilerBytes.Length));
            writer.Write(compilerBytes);
            WriteVarBytes(writer, System.Text.Encoding.ASCII.GetBytes(source));
            writer.Write((byte)0);
            WriteVarInt(writer, 0);
            writer.Write((ushort)0);
            WriteVarBytes(writer, script);
        }

        byte[] prefix = ms.ToArray();
        uint checksum = NefFile.ComputeChecksum(prefix);
        byte[] full = new byte[prefix.Length + 4];
        Array.Copy(prefix, full, prefix.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(full.AsSpan(prefix.Length), checksum);
        return full;
    }

    private static void WriteVarBytes(BinaryWriter writer, byte[] bytes)
    {
        WriteVarInt(writer, (ulong)bytes.Length);
        writer.Write(bytes);
    }

    private static void WriteVarInt(BinaryWriter writer, ulong value)
    {
        if (value < 0xFD)
            writer.Write((byte)value);
        else if (value <= 0xFFFF)
        {
            writer.Write((byte)0xFD);
            writer.Write((ushort)value);
        }
        else if (value <= 0xFFFFFFFF)
        {
            writer.Write((byte)0xFE);
            writer.Write((uint)value);
        }
        else
        {
            writer.Write((byte)0xFF);
            writer.Write(value);
        }
    }

    private static string CreateTempDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "neo-sym-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string[] FuzzerTargetNames()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var parse = program.GetMethod("ParseArgs", BindingFlags.NonPublic | BindingFlags.Static)!;
        var opts = parse.Invoke(null, new object[] { System.Array.Empty<string>() })!;
        var targets = (System.Collections.IEnumerable)opts.GetType()
            .GetProperty("Targets")!
            .GetValue(opts)!;
        return targets.Cast<object>()
            .Select(target => (string)target.GetType().GetProperty("Name")!.GetValue(target)!)
            .ToArray();
    }

    private sealed class PathEchoDetector : BaseDetector
    {
        public override string Name => "path_echo";

        public override IEnumerable<Finding> Analyze(AnalysisContext context)
        {
            foreach (var state in context.States)
            {
                yield return MakeFinding(
                    title: "Path-sensitive finding",
                    description: "Finding used to verify SMT validation keeps source path conditions.",
                    offset: 0x10,
                    severity: Severity.Medium,
                    state: state);
            }
        }
    }

    private sealed class StaticManifestDetector : BaseDetector
    {
        public override string Name => "static_manifest";

        public override IEnumerable<Finding> Analyze(AnalysisContext context)
        {
            yield return MakeFinding(
                title: "Static manifest issue",
                description: "Finding used to verify SMT filtering does not attach unrelated paths.",
                offset: 0,
                severity: Severity.High,
                state: null);
        }
    }

    private sealed class StubSmtBackend : ISmtBackend
    {
        private readonly Func<Expression, SmtOutcome> _extraOutcome;
        private readonly Func<IReadOnlyList<Expression>, SmtOutcome> _conditionsOutcome;

        public StubSmtBackend(
            Func<Expression, SmtOutcome> extraOutcome,
            Func<IReadOnlyList<Expression>, SmtOutcome>? conditionsOutcome = null)
        {
            _extraOutcome = extraOutcome;
            _conditionsOutcome = conditionsOutcome ?? (_ => SmtOutcome.Sat);
        }

        public bool IsAvailable => true;
        public string Version => "stub";
        public int TimeoutMs => 1;

        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra) =>
            _extraOutcome(extra);

        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions) =>
            _conditionsOutcome(conditions);

        public IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions) =>
            new Dictionary<string, object>();

        public BigInteger? ConcretizeInt(
            IReadOnlyList<Expression> conditions,
            Expression target,
            BigInteger? lo = null,
            BigInteger? hi = null) => null;

        public SmtStats GetStats() => new(0, 0, 0, 0, 0, 0);
    }
}
