"""Tests for symbolic execution engine."""
import struct

from neo_sym.engine.state import ExecutionState, ExternalCall, SymbolicValue
from neo_sym.engine.symbolic import SymbolicEngine
from neo_sym.nef.opcodes import OpCode
from neo_sym.nef.parser import MethodToken, NefFile, disassemble
from neo_sym.nef.syscalls import SYSCALLS_BY_NAME


def _make_engine(script: bytes) -> SymbolicEngine:
    nef = NefFile(script=script, instructions=disassemble(script))
    return SymbolicEngine(nef)


def test_push_and_add():
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.ADD, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) >= 1
    assert len(states[0].stack) == 1


def test_conditional_branch():
    # PUSH1, JMPIF +2, PUSH0, RET, PUSH1, RET
    script = bytes([
        OpCode.PUSH1,
        OpCode.JMPIF, 0x04,  # jump forward 4 from JMPIF offset(1)
        OpCode.PUSH0,
        OpCode.RET,
        OpCode.PUSH1,
        OpCode.RET,
    ])
    eng = _make_engine(script)
    states = eng.run()
    # Should explore both branches
    assert len(states) >= 1


def test_slot_operations():
    script = bytes([
        OpCode.INITSLOT, 0x01, 0x01,  # 1 local, 1 arg
        OpCode.LDARG0,
        OpCode.STLOC0,
        OpCode.LDLOC0,
        OpCode.RET,
    ])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) >= 1
    assert len(states[0].stack) == 1


def test_extended_slot_operations_with_implicit_indexes():
    script = bytes(
        [
            OpCode.INITSLOT,
            0x02,
            0x02,  # 2 locals, 2 args
            OpCode.LDARG1,
            OpCode.STLOC1,
            OpCode.LDLOC0,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].stack) == 1
    assert states[0].stack[0].name == "loc0"


def test_operand_indexed_slot_operations():
    script = bytes(
        [
            OpCode.INITSLOT,
            0x01,
            0x03,  # 1 local, 3 args
            OpCode.LDARG,
            0x02,
            OpCode.STLOC,
            0x00,
            OpCode.LDLOC,
            0x00,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].stack) == 1
    assert states[0].stack[0].name == "arg2"


def test_dup_drop():
    script = bytes([OpCode.PUSH5, OpCode.DUP, OpCode.DROP, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states[0].stack) == 1


def test_push_boolean_and_signed_integer_variants():
    script = bytes(
        [
            OpCode.PUSHM1,
            OpCode.PUSHT,
            OpCode.PUSHF,
            OpCode.PUSHINT8,
            0x80,  # -128
            OpCode.PUSHINT16,
            0x34,
            0x12,  # 0x1234
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [-1, True, False, -128, 0x1234]


def test_call_executes_subroutine_and_returns():
    # CALL +4 => jump to PUSH1, RET back to PUSH0, RET
    script = bytes([OpCode.CALL, 0x04, OpCode.PUSH0, OpCode.RET, OpCode.PUSH1, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 0]


def test_nested_calls_track_max_call_stack_depth():
    # CALL +4 => CALL +4 => PUSH2, RET => PUSH1, RET => PUSH0, RET
    script = bytes(
        [
            OpCode.CALL,
            0x04,
            OpCode.PUSH0,
            OpCode.RET,
            OpCode.CALL,
            0x04,
            OpCode.PUSH1,
            OpCode.RET,
            OpCode.PUSH2,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [2, 1, 0]
    assert states[0].max_call_stack_depth == 2


def test_calla_with_concrete_target():
    script = bytes(
        [
            OpCode.PUSHINT8,
            0x06,  # target absolute offset
            OpCode.CALLA,
            OpCode.PUSH0,
            OpCode.RET,
            OpCode.NOP,
            OpCode.PUSH1,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 0]


def test_jmpeq_branches_on_concrete_values():
    # PUSH1, PUSH1, JMPEQ +4 => jump to PUSH2 path.
    script = bytes([OpCode.PUSH1, OpCode.PUSH1, OpCode.JMPEQ, 0x04, OpCode.PUSH0, OpCode.RET, OpCode.PUSH2, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [2]


def test_jmpeq_l_branches_with_long_offset():
    # PUSH1, PUSH1, JMPEQ_L +7 => jump to PUSH2 path.
    script = bytes([OpCode.PUSH1, OpCode.PUSH1, OpCode.JMPEQ_L]) + (7).to_bytes(4, "little", signed=True) + bytes(
        [OpCode.PUSH0, OpCode.RET, OpCode.PUSH2, OpCode.RET]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [2]


def test_try_catch_handles_throw():
    script = bytes(
        [
            OpCode.TRY,
            0x07,  # catch @ +7 from TRY offset
            0x00,  # no finally
            OpCode.PUSH1,
            OpCode.THROW,
            OpCode.PUSH0,  # unreachable
            OpCode.RET,
            OpCode.PUSH2,  # catch block
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 2]


def test_try_finally_runs_on_endtry():
    script = bytes(
        [
            OpCode.TRY,
            0x00,  # no catch
            0x06,  # finally @ +6 from TRY offset
            OpCode.PUSH1,
            OpCode.ENDTRY,
            0x04,  # end @ +4 from ENDTRY offset => RET
            OpCode.PUSH2,  # finally block
            OpCode.ENDFINALLY,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 2]


def test_try_finally_propagates_unhandled_throw():
    script = bytes(
        [
            OpCode.TRY,
            0x00,  # no catch
            0x07,  # finally @ +7
            OpCode.PUSH1,
            OpCode.THROW,
            OpCode.PUSH0,  # unreachable
            OpCode.RET,
            OpCode.PUSH2,  # finally block
            OpCode.ENDFINALLY,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].halted is True
    assert states[0].error is not None
    assert "Unhandled throw" in states[0].error


def test_abort_faults_immediately():
    script = bytes([OpCode.PUSH1, OpCode.ABORT, OpCode.PUSH2, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].halted is True
    assert states[0].error is not None
    assert "ABORT" in states[0].error
    assert [v.concrete for v in states[0].stack] == [1]


def test_abortmsg_faults_with_message():
    message = b"fatal"
    script = b"".join(
        [
            bytes([OpCode.PUSHDATA1, len(message)]),
            message,
            bytes([OpCode.ABORTMSG]),
            bytes([OpCode.RET]),
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].halted is True
    assert states[0].error is not None
    assert "ABORTMSG" in states[0].error
    assert "fatal" in states[0].error


def test_abort_not_caught_by_try_catch():
    script = bytes(
        [
            OpCode.TRY,
            0x07,  # catch @ +7 from TRY offset
            0x00,  # no finally
            OpCode.PUSH1,
            OpCode.ABORT,
            OpCode.PUSH0,  # unreachable
            OpCode.RET,
            OpCode.PUSH2,  # catch block should not run
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].halted is True
    assert states[0].error is not None
    assert "ABORT" in states[0].error
    assert [v.concrete for v in states[0].stack] == [1]


def test_try_l_catch_handles_throw():
    script = (
        bytes([OpCode.TRY_L])
        + (13).to_bytes(4, "little", signed=True)  # catch @ +13 from TRY_L offset
        + (0).to_bytes(4, "little", signed=True)  # no finally
        + bytes(
            [
                OpCode.PUSH1,
                OpCode.THROW,
                OpCode.PUSH0,  # unreachable
                OpCode.RET,
                OpCode.PUSH2,  # catch block
                OpCode.RET,
            ]
        )
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 2]


def test_endtry_l_runs_finally():
    script = (
        bytes([OpCode.TRY_L])
        + (0).to_bytes(4, "little", signed=True)  # no catch
        + (15).to_bytes(4, "little", signed=True)  # finally @ +15 from TRY_L offset
        + bytes([OpCode.PUSH1, OpCode.ENDTRY_L])
        + (7).to_bytes(4, "little", signed=True)  # continuation @ +7 from ENDTRY_L offset => RET
        + bytes(
            [
                OpCode.PUSH2,  # finally block
                OpCode.ENDFINALLY,
                OpCode.RET,
            ]
        )
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert [v.concrete for v in states[0].stack] == [1, 2]


def test_nested_finally_propagates_to_outer_catch():
    script = bytes(
        [
            OpCode.TRY,
            0x0C,  # outer catch @ +12
            0x00,  # no outer finally
            OpCode.TRY,
            0x00,  # no inner catch
            0x07,  # inner finally @ +7
            OpCode.PUSH1,
            OpCode.THROW,
            OpCode.PUSH0,  # unreachable
            OpCode.RET,
            OpCode.PUSH2,  # inner finally block
            OpCode.ENDFINALLY,
            OpCode.PUSH3,  # outer catch block
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].error is None
    assert [v.concrete for v in states[0].stack] == [1, 2, 3]


def test_syscall_checkwitness_uses_real_id():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes([OpCode.PUSH0, OpCode.SYSCALL]) + struct.pack("<I", syscall_id) + bytes([OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].witness_checks == [1]
    assert len(states[0].stack) == 1


def test_syscall_checkwitness_result_is_symbolic():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes([OpCode.PUSH0, OpCode.SYSCALL]) + struct.pack("<I", syscall_id) + bytes([OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].stack) == 1
    assert states[0].stack[0].name == "witness_ok_1"
    assert states[0].stack[0].concrete is None


def test_checkwitness_condition_explores_both_branches():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes(
        [
            OpCode.PUSH0,  # witness target
            OpCode.SYSCALL,
        ]
    ) + struct.pack("<I", syscall_id) + bytes(
        [
            OpCode.JMPIF,
            0x04,  # jump to PUSH2 path
            OpCode.PUSH1,
            OpCode.RET,
            OpCode.PUSH2,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 2
    concretized = sorted(v.concrete for state in states for v in state.stack)
    assert concretized == [1, 2]


def test_checkwitness_branch_marks_enforcement():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes(
        [
            OpCode.PUSH0,
            OpCode.SYSCALL,
        ]
    ) + struct.pack("<I", syscall_id) + bytes(
        [
            OpCode.JMPIF,
            0x04,
            OpCode.PUSH1,
            OpCode.RET,
            OpCode.PUSH2,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 2
    for state in states:
        assert state.witness_checks_enforced == [1]


def test_checkwitness_drop_does_not_mark_enforcement():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes([OpCode.PUSH0, OpCode.SYSCALL]) + struct.pack("<I", syscall_id) + bytes(
        [OpCode.DROP, OpCode.PUSH1, OpCode.RET]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert states[0].witness_checks == [1]
    assert states[0].witness_checks_enforced == []


def test_checkwitness_jmpeq_marks_enforcement():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes(
        [
            OpCode.PUSH0,
            OpCode.SYSCALL,
        ]
    ) + struct.pack("<I", syscall_id) + bytes(
        [
            OpCode.PUSHT,
            OpCode.JMPEQ,
            0x04,
            OpCode.PUSH1,
            OpCode.RET,
            OpCode.PUSH2,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 2
    for state in states:
        assert state.witness_checks == [1]
        assert state.witness_checks_enforced == [1]


def test_checkwitness_jmpne_marks_enforcement():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes(
        [
            OpCode.PUSH0,
            OpCode.SYSCALL,
        ]
    ) + struct.pack("<I", syscall_id) + bytes(
        [
            OpCode.PUSHF,
            OpCode.JMPNE,
            0x04,
            OpCode.PUSH1,
            OpCode.RET,
            OpCode.PUSH2,
            OpCode.RET,
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 2
    for state in states:
        assert state.witness_checks == [1]
        assert state.witness_checks_enforced == [1]


def test_syscall_contract_call_extracts_method_and_hash():
    syscall_id = SYSCALLS_BY_NAME["System.Contract.Call"].syscall_id
    method = b"update"
    contract_hash = bytes(range(20))
    script = b"".join(
        [
            bytes([OpCode.PUSH0]),  # args
            bytes([OpCode.PUSH0]),  # call flags
            bytes([OpCode.PUSHDATA1, len(method)]),
            method,
            bytes([OpCode.PUSHDATA1, len(contract_hash)]),
            contract_hash,
            bytes([OpCode.SYSCALL]),
            struct.pack("<I", syscall_id),
            bytes([OpCode.RET]),
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].method == "Contract.Call:update"
    assert states[0].external_calls[0].contract_hash == contract_hash
    assert states[0].external_calls[0].target_hash_dynamic is False
    assert states[0].external_calls[0].method_dynamic is False
    assert states[0].external_calls[0].call_flags == 0
    assert states[0].external_calls[0].call_flags_dynamic is False


def test_syscall_contract_call_marks_dynamic_hash_target():
    syscall_id = SYSCALLS_BY_NAME["System.Contract.Call"].syscall_id
    method = b"update"
    script = b"".join(
        [
            bytes([OpCode.INITSLOT, 0x00, 0x01]),  # 0 locals, 1 arg
            bytes([OpCode.PUSH0]),  # args
            bytes([OpCode.PUSH0]),  # call flags
            bytes([OpCode.PUSHDATA1, len(method)]),
            method,
            bytes([OpCode.LDARG0]),  # dynamic hash
            bytes([OpCode.SYSCALL]),
            struct.pack("<I", syscall_id),
            bytes([OpCode.RET]),
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].target_hash_dynamic is True
    assert states[0].external_calls[0].method_dynamic is False
    assert states[0].external_calls[0].call_flags == 0
    assert states[0].external_calls[0].call_flags_dynamic is False


def test_syscall_contract_call_marks_dynamic_method_target():
    syscall_id = SYSCALLS_BY_NAME["System.Contract.Call"].syscall_id
    contract_hash = bytes(range(20))
    script = b"".join(
        [
            bytes([OpCode.INITSLOT, 0x00, 0x01]),  # 0 locals, 1 arg
            bytes([OpCode.PUSH0]),  # args
            bytes([OpCode.PUSH0]),  # call flags
            bytes([OpCode.LDARG0]),  # dynamic method
            bytes([OpCode.PUSHDATA1, len(contract_hash)]),
            contract_hash,
            bytes([OpCode.SYSCALL]),
            struct.pack("<I", syscall_id),
            bytes([OpCode.RET]),
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].target_hash_dynamic is False
    assert states[0].external_calls[0].method_dynamic is True
    assert states[0].external_calls[0].call_flags == 0
    assert states[0].external_calls[0].call_flags_dynamic is False


def test_syscall_contract_call_marks_dynamic_call_flags():
    syscall_id = SYSCALLS_BY_NAME["System.Contract.Call"].syscall_id
    method = b"update"
    contract_hash = bytes(range(20))
    script = b"".join(
        [
            bytes([OpCode.INITSLOT, 0x00, 0x01]),  # 0 locals, 1 arg
            bytes([OpCode.PUSH0]),  # args
            bytes([OpCode.LDARG0]),  # dynamic call flags
            bytes([OpCode.PUSHDATA1, len(method)]),
            method,
            bytes([OpCode.PUSHDATA1, len(contract_hash)]),
            contract_hash,
            bytes([OpCode.SYSCALL]),
            struct.pack("<I", syscall_id),
            bytes([OpCode.RET]),
        ]
    )
    eng = _make_engine(script)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].call_flags is None
    assert states[0].external_calls[0].call_flags_dynamic is True


def test_callt_uses_method_token_metadata():
    script = bytes([OpCode.CALLT, 0x00, 0x00, OpCode.RET])
    nef = NefFile(
        script=script,
        instructions=disassemble(script),
        tokens=[
            MethodToken(
                hash=b"\x11" * 20,
                method="destroy",
                parameters_count=0,
                has_return_value=True,
                call_flags=0x0F,
            )
        ],
    )
    eng = SymbolicEngine(nef)
    states = eng.run()

    assert len(states) == 1
    assert states[0].external_calls[0].method == "CALLT:destroy"
    assert states[0].external_calls[0].contract_hash == b"\x11" * 20
    assert states[0].external_calls[0].call_flags == 0x0F
    assert states[0].external_calls[0].call_flags_dynamic is False


def test_execution_state_clone_isolated_external_calls():
    original = ExecutionState()
    original.external_calls = [ExternalCall(contract_hash=None, method="Contract.Call", offset=10, return_checked=False)]
    clone = original.clone()

    clone.external_calls[0].return_checked = True
    assert original.external_calls[0].return_checked is False


def test_assert_marks_matching_external_call_not_last():
    script = bytes([OpCode.ASSERT, OpCode.RET])
    nef = NefFile(script=script, instructions=disassemble(script))
    eng = SymbolicEngine(nef)

    state = ExecutionState(pc=0)
    state.external_calls = [
        ExternalCall(contract_hash=None, method="first", offset=10, return_checked=False),
        ExternalCall(contract_hash=None, method="second", offset=20, return_checked=False),
    ]
    state.stack.append(SymbolicValue(name="ext_ret_10", concrete=True))

    eng._execute_instruction(state, nef.instructions[0])

    assert state.external_calls[0].return_checked is True
    assert state.external_calls[1].return_checked is False


def test_jmpif_marks_matching_external_call_checked():
    script = bytes(
        [
            OpCode.CALLT,
            0x00,
            0x00,
            OpCode.JMPIF,
            0x04,
            OpCode.PUSH0,
            OpCode.RET,
            OpCode.PUSH1,
            OpCode.RET,
        ]
    )
    nef = NefFile(
        script=script,
        instructions=disassemble(script),
        tokens=[
            MethodToken(
                hash=b"\x33" * 20,
                method="transfer",
                parameters_count=0,
                has_return_value=True,
                call_flags=0x0F,
            )
        ],
    )
    eng = SymbolicEngine(nef)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].return_checked is True


def test_jmpeq_marks_matching_external_call_checked():
    script = bytes(
        [
            OpCode.CALLT,
            0x00,
            0x00,
            OpCode.PUSHT,
            OpCode.JMPEQ,
            0x04,
            OpCode.PUSH0,
            OpCode.RET,
            OpCode.PUSH1,
            OpCode.RET,
        ]
    )
    nef = NefFile(
        script=script,
        instructions=disassemble(script),
        tokens=[
            MethodToken(
                hash=b"\x44" * 20,
                method="balanceOf",
                parameters_count=0,
                has_return_value=True,
                call_flags=0x0F,
            )
        ],
    )
    eng = SymbolicEngine(nef)
    states = eng.run()

    assert len(states) == 1
    assert len(states[0].external_calls) == 1
    assert states[0].external_calls[0].return_checked is True


def test_assertmsg_halts_on_false_condition():
    msg = b"bad"
    script = bytes([OpCode.PUSHF, OpCode.PUSHDATA1, len(msg)]) + msg + bytes([
        OpCode.ASSERTMSG, OpCode.RET,
    ])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) == 1
    assert states[0].halted is True
    assert "ASSERTMSG failed" in states[0].error
    assert "bad" in states[0].error


def test_assertmsg_passes_on_true_condition():
    msg = b"ok"
    script = bytes([OpCode.PUSHT, OpCode.PUSHDATA1, len(msg)]) + msg + bytes([
        OpCode.ASSERTMSG, OpCode.PUSH1, OpCode.RET,
    ])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) == 1
    assert states[0].error is None
    assert states[0].stack[0].concrete == 1


def test_swap_over_nip_opcodes():
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.SWAP, OpCode.RET])
    states = _make_engine(script).run()
    assert [v.concrete for v in states[0].stack] == [2, 1]

    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.OVER, OpCode.RET])
    states = _make_engine(script).run()
    assert [v.concrete for v in states[0].stack] == [1, 2, 1]

    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.NIP, OpCode.RET])
    states = _make_engine(script).run()
    assert [v.concrete for v in states[0].stack] == [2]


def test_comparison_opcodes():
    # LT: 1 < 2 == True
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.LT, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete is True

    # GT: 1 > 2 == False
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.GT, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete is False


def test_unary_opcodes():
    # NEGATE: -3
    script = bytes([OpCode.PUSH3, OpCode.NEGATE, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == -3

    # ABS: |-1| = 1
    script = bytes([OpCode.PUSHM1, OpCode.ABS, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 1

    # INC: 5+1 = 6
    script = bytes([OpCode.PUSH5, OpCode.INC, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 6

    # DEC: 5-1 = 4
    script = bytes([OpCode.PUSH5, OpCode.DEC, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 4


def test_stack_overflow_halts_execution():
    # Push values in a tight loop to exceed MAX_STACK
    eng = _make_engine(bytes([OpCode.PUSH1, OpCode.RET]))
    eng.MAX_STACK = 4
    from neo_sym.engine.state import ExecutionState
    state = ExecutionState(pc=0)
    state.stack = [SymbolicValue(concrete=i) for i in range(5)]
    # Simulate: engine checks after instruction execution
    script = bytes([OpCode.PUSH1] * 6 + [OpCode.RET])
    eng2 = _make_engine(script)
    eng2.MAX_STACK = 4
    states = eng2.run()
    assert any(s.halted and "stack overflow" in (s.error or "") for s in states)


def test_unknown_opcode_tracked():
    # CONVERT (0xDB) is not handled by the engine — should be tracked
    script = bytes([OpCode.PUSH1, OpCode.CONVERT, 0x21, OpCode.RET])
    eng = _make_engine(script)
    states = eng.run()
    assert len(states) >= 1
    assert any(len(s.unknown_opcodes) > 0 for s in states)


def test_div_and_mod():
    script = bytes([OpCode.PUSH8, OpCode.PUSH3, OpCode.DIV, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 2

    script = bytes([OpCode.PUSH8, OpCode.PUSH3, OpCode.MOD, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 2


def test_bitwise_and_or_xor():
    # 0x0F & 0x03 == 0x03
    script = bytes([OpCode.PUSHINT8, 0x0F, OpCode.PUSH3, OpCode.AND, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 3

    # 0x01 | 0x02 == 0x03
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.OR, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 3

    # 0x03 ^ 0x01 == 0x02
    script = bytes([OpCode.PUSH3, OpCode.PUSH1, OpCode.XOR, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 2


def test_shl_shr():
    script = bytes([OpCode.PUSH1, OpCode.PUSH3, OpCode.SHL, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 8

    script = bytes([OpCode.PUSH8, OpCode.PUSH2, OpCode.SHR, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 2


def test_min_max():
    script = bytes([OpCode.PUSH3, OpCode.PUSH5, OpCode.MIN, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 3

    script = bytes([OpCode.PUSH3, OpCode.PUSH5, OpCode.MAX, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete == 5


def test_rot_reverse3():
    # ROT: [a, b, c] -> [b, c, a]
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.PUSH3, OpCode.ROT, OpCode.RET])
    states = _make_engine(script).run()
    assert [v.concrete for v in states[0].stack] == [2, 3, 1]

    # REVERSE3: [a, b, c] -> [c, b, a]
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.PUSH3, OpCode.REVERSE3, OpCode.RET])
    states = _make_engine(script).run()
    assert [v.concrete for v in states[0].stack] == [3, 2, 1]


def test_within():
    # 3 WITHIN [2, 5) == True
    script = bytes([OpCode.PUSH3, OpCode.PUSH2, OpCode.PUSH5, OpCode.WITHIN, OpCode.RET])
    states = _make_engine(script).run()
    assert states[0].stack[0].concrete is True
