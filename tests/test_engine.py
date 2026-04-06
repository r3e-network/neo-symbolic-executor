from __future__ import annotations

import unittest

from neo_symbolic_executor.assembly import parse_program
from neo_symbolic_executor.engine import ExecutionOptions, explore_program
from neo_symbolic_executor.expr import bool_symbol, bytes_symbol, int_const, int_symbol, render_expr
from neo_symbolic_executor.interop import CALL_FLAGS_READ_STATES, interop_hash
from neo_symbolic_executor.model import Program


def _syscall(name: str) -> int:
    return interop_hash(name)


class EngineTests(unittest.TestCase):
    def test_execution_options_validate_positive_limits(self) -> None:
        with self.assertRaises(ValueError):
            ExecutionOptions(max_steps=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_states=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_visits_per_instruction=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_item_size=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_collection_size=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_heap_objects=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_invocation_stack=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_try_nesting_depth=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(max_shift=0)
        with self.assertRaises(ValueError):
            ExecutionOptions(script_hash=b"\x01")

    def test_initial_stack_length_cannot_exceed_max_stack_depth(self) -> None:
        stack = tuple(int_symbol(f"item{i}") for i in range(3))
        with self.assertRaises(ValueError):
            ExecutionOptions(initial_stack=stack, max_stack_depth=2)

    def test_initslot_branching_program_explores_return_and_fault_paths(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            JMPLT reject
            LDARG0
            PUSH10
            JMPGT high
            LDARG0
            RET
            high:
            LDARG0
            PUSH1
            ADD
            RET
            reject:
            ABORT
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("amount"),)))

        self.assertGreaterEqual(len(report.returned), 2)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(len(report.stopped), 0)

        returned_paths = {tuple(render_expr(cond) for cond in state.path_conditions) for state in report.returned}
        self.assertIn(("(amount >= 0)", "(amount <= 10)"), returned_paths)
        self.assertIn(("(amount >= 0)", "(amount > 10)"), returned_paths)

        fault = report.faulted[0]
        self.assertEqual(render_expr(fault.path_conditions[0]), "(amount < 0)")
        self.assertEqual(render_expr(fault.arguments[0]), "amount")

    def test_assert_splits_symbolic_condition(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            DUP
            PUSH0
            GE
            ASSERT
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("value"),)))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(render_expr(report.returned[0].path_conditions[0]), "(value >= 0)")
        self.assertEqual(render_expr(report.faulted[0].path_conditions[0]), "(value < 0)")

    def test_division_by_zero_is_split(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 2
            LDARG0
            LDARG1
            DIV
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("denominator"), int_symbol("numerator"))),
        )
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(render_expr(report.returned[0].path_conditions[0]), "(denominator != 0)")
        self.assertEqual(report.faulted[0].reason, "DIV by zero")

    def test_div_and_mod_follow_neovm_signed_integer_semantics(self) -> None:
        div_report = explore_program(
            parse_program(
                """
                PUSH -3
                PUSH2
                DIV
                RET
                """
            )
        )
        self.assertEqual(len(div_report.returned), 1)
        self.assertEqual(render_expr(div_report.returned[0].stack[0]), "-1")

        mod_report = explore_program(
            parse_program(
                """
                PUSH -3
                PUSH2
                MOD
                RET
                """
            )
        )
        self.assertEqual(len(mod_report.returned), 1)
        self.assertEqual(render_expr(mod_report.returned[0].stack[0]), "-1")

    def test_min_and_max_split_symbolic_operands(self) -> None:
        min_program = parse_program(
            """
            INITSLOT 0 2
            LDARG0
            LDARG1
            MIN
            RET
            """
        )
        max_program = parse_program(
            """
            INITSLOT 0 2
            LDARG0
            LDARG1
            MAX
            RET
            """
        )

        min_report = explore_program(
            min_program,
            ExecutionOptions(initial_stack=(int_symbol("right"), int_symbol("left"))),
        )
        self.assertEqual(len(min_report.returned), 2)
        min_paths = {
            (tuple(render_expr(cond) for cond in state.path_conditions), render_expr(state.stack[0]))
            for state in min_report.returned
        }
        self.assertIn((("(left <= right)",), "left"), min_paths)
        self.assertIn((("(left > right)",), "right"), min_paths)

        max_report = explore_program(
            max_program,
            ExecutionOptions(initial_stack=(int_symbol("right"), int_symbol("left"))),
        )
        self.assertEqual(len(max_report.returned), 2)
        max_paths = {
            (tuple(render_expr(cond) for cond in state.path_conditions), render_expr(state.stack[0]))
            for state in max_report.returned
        }
        self.assertIn((("(left >= right)",), "left"), max_paths)
        self.assertIn((("(left < right)",), "right"), max_paths)

    def test_static_and_local_slots_initialize_to_null(self) -> None:
        program = parse_program(
            """
            INITSSLOT 1
            INITSLOT 1 0
            LDSFLD0
            LDLOC0
            EQUAL
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_loop_budget_produces_stopped_state(self) -> None:
        program = parse_program(
            """
            start:
            JMP start
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(max_steps=10, max_states=32, max_visits_per_instruction=3),
        )
        self.assertEqual(len(report.stopped), 1)
        self.assertIn("visit budget", report.stopped[0].reason or "")

    def test_call_restores_caller_slots_and_shares_stack(self) -> None:
        program = parse_program(
            """
            INITSLOT 1 1
            LDARG0
            STLOC0
            LDLOC0
            CALL add_one
            LDLOC0
            ADD
            RET

            add_one:
            PUSH1
            ADD
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("amount"),)))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "((amount + 1) + amount)")
        self.assertEqual(render_expr(report.returned[0].local_variables[0]), "amount")
        self.assertEqual(report.returned[0].call_depth, 0)

    def test_throw_is_caught_in_same_frame(self) -> None:
        program = parse_program(
            """
            TRY 5 0
            PUSH1
            THROW
            DROP
            PUSH2
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "2")

    def test_throw_unwinds_into_caller_catch(self) -> None:
        program = parse_program(
            """
            TRY 6 0
            CALL 6
            RET
            DROP
            PUSH2
            RET
            PUSH1
            THROW
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "2")
        self.assertEqual(report.returned[0].call_depth, 0)

    def test_endtry_runs_finally_before_returning(self) -> None:
        program = parse_program(
            """
            TRY 0 6
            PUSH1
            ENDTRY 5
            PUSH2
            ADD
            ENDFINALLY
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "3")

    def test_finally_rethrows_unhandled_exceptions(self) -> None:
        program = parse_program(
            """
            TRY 0 6
            PUSH1
            THROW
            NOP
            PUSH2
            DROP
            ENDFINALLY
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 0)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("An unhandled exception was thrown.", report.faulted[0].reason or "")

    def test_pickitem_catchable_exception_is_caught(self) -> None:
        program = parse_program(
            """
            TRY 7 0
            NEWARRAY0
            PUSH0
            PICKITEM
            RET
            DROP
            PUSH2
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "2")

    def test_setitem_catchable_exception_is_caught(self) -> None:
        program = parse_program(
            """
            TRY 8 0
            NEWARRAY0
            PUSH0
            PUSH1
            SETITEM
            RET
            DROP
            PUSH2
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "2")

    def test_symbolic_map_pickitem_miss_is_catchable(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            TRY 11 0
            NEWMAP
            DUP
            PUSH1
            PUSH10
            SETITEM
            LDARG0
            PICKITEM
            RET
            DROP
            PUSH2
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertGreaterEqual(len(report.returned), 2)
        self.assertEqual(len(report.faulted), 0)
        by_path = {tuple(render_expr(cond) for cond in state.path_conditions): state for state in report.returned}
        self.assertEqual(render_expr(by_path[("(key == 1)",)].stack[0]), "10")
        self.assertEqual(render_expr(by_path[("(key != 1)",)].stack[0]), "2")

    def test_unhandled_catchable_exception_uses_neovm_reason(self) -> None:
        report = explore_program(
            parse_program(
                """
                NEWARRAY0
                PUSH0
                PICKITEM
                """
            )
        )
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(
            report.faulted[0].reason,
            "An unhandled exception was thrown. The index of VMArray is out of range, 0/[0, 0).",
        )

    def test_calla_uses_pointer_target(self) -> None:
        program = parse_program(
            """
            PUSHA callee
            CALLA
            RET

            callee:
            PUSH1
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_callee_initslot_does_not_clobber_caller_locals(self) -> None:
        program = parse_program(
            """
            INITSLOT 1 1
            LDARG0
            STLOC0
            CALL worker
            LDLOC0
            RET

            worker:
            INITSLOT 1 0
            PUSH1
            STLOC0
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("amount"),)))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "amount")
        self.assertEqual(render_expr(report.returned[0].local_variables[0]), "amount")

    def test_array_aliasing_preserves_mutations(self) -> None:
        program = parse_program(
            """
            NEWARRAY0
            DUP
            PUSH1
            APPEND
            SIZE
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")
        self.assertEqual(report.returned[0].heap["array#1"], ["1"])

    def test_pickitem_reads_mutated_array_value(self) -> None:
        program = parse_program(
            """
            NEWARRAY0
            DUP
            PUSH1
            APPEND
            PUSH0
            PICKITEM
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_map_setitem_and_pickitem(self) -> None:
        program = parse_program(
            """
            NEWMAP
            DUP
            PUSH1
            PUSH2
            SETITEM
            PUSH1
            PICKITEM
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "2")
        self.assertEqual(report.returned[0].heap["map#1"], [{"key": "1", "value": "2"}])

    def test_haskey_splits_symbolic_map_lookup(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            NEWMAP
            DUP
            PUSH1
            PUSH10
            SETITEM
            LDARG0
            HASKEY
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertGreaterEqual(len(report.returned), 2)
        outcomes = {
            (tuple(render_expr(cond) for cond in state.path_conditions), render_expr(state.stack[0]))
            for state in report.returned
        }
        self.assertIn((("(key == 1)",), "true"), outcomes)
        self.assertIn((("(key != 1)",), "false"), outcomes)

    def test_pickitem_splits_symbolic_map_lookup(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            NEWMAP
            DUP
            PUSH1
            PUSH10
            SETITEM
            LDARG0
            PICKITEM
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(render_expr(report.returned[0].path_conditions[0]), "(key == 1)")
        self.assertEqual(render_expr(report.returned[0].stack[0]), "10")
        self.assertEqual(render_expr(report.faulted[0].path_conditions[0]), "(key != 1)")

    def test_setitem_splits_symbolic_map_update(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            NEWMAP
            DUP
            PUSH1
            PUSH10
            SETITEM
            DUP
            LDARG0
            PUSH 20
            SETITEM
            SIZE
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertEqual(len(report.returned), 2)
        by_path = {tuple(render_expr(cond) for cond in state.path_conditions): state for state in report.returned}
        self.assertEqual(render_expr(by_path[("(key == 1)",)].stack[0]), "1")
        self.assertEqual(by_path[("(key == 1)",)].heap["map#1"], [{"key": "1", "value": "20"}])
        self.assertEqual(render_expr(by_path[("(key != 1)",)].stack[0]), "2")
        self.assertEqual(
            by_path[("(key != 1)",)].heap["map#1"],
            [{"key": "1", "value": "10"}, {"key": "key", "value": "20"}],
        )

    def test_remove_splits_symbolic_map_update(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            NEWMAP
            DUP
            PUSH1
            PUSH10
            SETITEM
            DUP
            LDARG0
            REMOVE
            SIZE
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertEqual(len(report.returned), 2)
        by_path = {tuple(render_expr(cond) for cond in state.path_conditions): state for state in report.returned}
        self.assertEqual(render_expr(by_path[("(key == 1)",)].stack[0]), "0")
        self.assertEqual(by_path[("(key == 1)",)].heap["map#1"], [])
        self.assertEqual(render_expr(by_path[("(key != 1)",)].stack[0]), "1")
        self.assertEqual(by_path[("(key != 1)",)].heap["map#1"], [{"key": "1", "value": "10"}])

    def test_packmap_overwrites_duplicate_concrete_keys(self) -> None:
        program = parse_program(
            """
            PUSH 20
            PUSH1
            PUSH10
            PUSH1
            PUSH2
            PACKMAP
            DUP
            SIZE
            SWAP
            PUSH1
            PICKITEM
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["1", "20"])
        self.assertEqual(report.returned[0].heap["map#1"], [{"key": "1", "value": "20"}])

    def test_packmap_splits_symbolic_duplicate_keys(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            PUSH 20
            LDARG0
            PUSH10
            PUSH1
            PUSH2
            PACKMAP
            DUP
            SIZE
            SWAP
            PUSH1
            PICKITEM
            RET
            """
        )

        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("key"),)))
        self.assertEqual(len(report.returned), 2)
        by_path = {tuple(render_expr(cond) for cond in state.path_conditions): state for state in report.returned}
        self.assertEqual([render_expr(item) for item in by_path[("(key == 1)",)].stack], ["1", "20"])
        self.assertEqual(by_path[("(key == 1)",)].heap["map#1"], [{"key": "1", "value": "20"}])
        self.assertEqual([render_expr(item) for item in by_path[("(key != 1)",)].stack], ["2", "10"])
        self.assertEqual(
            by_path[("(key != 1)",)].heap["map#1"],
            [{"key": "1", "value": "10"}, {"key": "key", "value": "20"}],
        )

    def test_pack_unpack_and_size_follow_neovm_order(self) -> None:
        program = parse_program(
            """
            PUSH1
            PUSH2
            PUSH2
            PACK
            DUP
            SIZE
            SWAP
            UNPACK
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["2", "1", "2", "2"])
        self.assertEqual(report.returned[0].heap["array#1"], ["2", "1"])

    def test_newarray_t_uses_boolean_default_values(self) -> None:
        program = parse_program(
            """
            PUSH3
            NEWARRAY_T BOOLEAN
            DUP
            PUSH0
            PICKITEM
            SWAP
            SIZE
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["false", "3"])
        self.assertEqual(report.returned[0].heap["array#1"], ["false", "false", "false"])

    def test_isnull_distinguishes_null_and_compound_refs(self) -> None:
        program = parse_program(
            """
            PUSHNULL
            ISNULL
            NEWARRAY0
            ISNULL
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["true", "false"])

    def test_append_clones_struct_values_by_value(self) -> None:
        program = parse_program(
            """
            INITSLOT 2 0
            NEWSTRUCT0
            DUP
            STLOC0
            NEWARRAY0
            DUP
            STLOC1
            SWAP
            APPEND
            LDLOC0
            PUSH1
            APPEND
            LDLOC1
            PUSH0
            PICKITEM
            SIZE
            LDLOC0
            SIZE
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["0", "1"])
        self.assertEqual(report.returned[0].heap["array#2"], ["struct#3"])
        self.assertEqual(report.returned[0].heap["struct#1"], ["1"])
        self.assertEqual(report.returned[0].heap["struct#3"], [])

    def test_newbuffer_setitem_and_pickitem(self) -> None:
        program = parse_program(
            """
            PUSH2
            NEWBUFFER
            DUP
            PUSH1
            PUSH -1
            SETITEM
            DUP
            SIZE
            SWAP
            PUSH1
            PICKITEM
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["2", "255"])
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x00ff")

    def test_memcpy_mutates_destination_buffer(self) -> None:
        program = parse_program(
            """
            PUSH4
            NEWBUFFER
            DUP
            PUSH0
            PUSHDATA 0x112233
            PUSH0
            PUSH3
            MEMCPY
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "buffer#1")
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x11223300")

    def test_cat_substr_and_right_produce_buffers(self) -> None:
        program = parse_program(
            """
            PUSHDATA 0x11223344
            PUSH2
            LEFT
            PUSHDATA 0xaabb
            CAT
            DUP
            PUSH1
            PUSH2
            SUBSTR
            SWAP
            PUSH2
            RIGHT
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["buffer#3", "buffer#4"])
        self.assertEqual(report.returned[0].heap["buffer#2"], "0x1122aabb")
        self.assertEqual(report.returned[0].heap["buffer#3"], "0x22aa")
        self.assertEqual(report.returned[0].heap["buffer#4"], "0xaabb")

    def test_convert_and_istype_support_buffers(self) -> None:
        program = parse_program(
            """
            PUSHDATA 0x0102
            CONVERT BUFFER
            DUP
            ISTYPE BUFFER
            SWAP
            CONVERT BYTESTRING
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["true", "0x0102"])
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x0102")

    def test_symbolic_primitive_size_and_pickitem(self) -> None:
        size_program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            SIZE
            RET
            """
        )
        bytes_report = explore_program(size_program, ExecutionOptions(initial_stack=(bytes_symbol("payload"),)))
        self.assertEqual(len(bytes_report.returned), 1)
        self.assertEqual(render_expr(bytes_report.returned[0].stack[0]), "size(payload)")

        int_report = explore_program(size_program, ExecutionOptions(initial_stack=(int_symbol("value"),)))
        self.assertEqual(len(int_report.returned), 1)
        self.assertEqual(render_expr(int_report.returned[0].stack[0]), "size(value)")

        pickitem_program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            PICKITEM
            RET
            """
        )
        pickitem_report = explore_program(pickitem_program, ExecutionOptions(initial_stack=(bytes_symbol("payload"),)))
        self.assertEqual(len(pickitem_report.returned), 1)
        self.assertEqual(len(pickitem_report.faulted), 1)
        self.assertEqual(render_expr(pickitem_report.returned[0].path_conditions[0]), "(size(payload) > 0)")
        self.assertEqual(render_expr(pickitem_report.returned[0].stack[0]), "payload[0]")
        self.assertEqual(render_expr(pickitem_report.faulted[0].path_conditions[0]), "(size(payload) <= 0)")

        bool_pickitem_report = explore_program(
            pickitem_program,
            ExecutionOptions(initial_stack=(bool_symbol("flag"),)),
        )
        self.assertEqual(len(bool_pickitem_report.returned), 1)
        self.assertEqual(len(bool_pickitem_report.faulted), 0)
        self.assertEqual(render_expr(bool_pickitem_report.returned[0].stack[0]), "int(flag)")

    def test_haskey_supports_symbolic_byte_strings(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH1
            HASKEY
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(bytes_symbol("payload"),)))
        self.assertEqual(len(report.returned), 2)
        outcomes = {
            (tuple(render_expr(cond) for cond in state.path_conditions), render_expr(state.stack[0]))
            for state in report.returned
        }
        self.assertIn((("(size(payload) > 1)",), "true"), outcomes)
        self.assertIn((("(size(payload) <= 1)",), "false"), outcomes)

    def test_convert_supports_symbolic_primitive_values(self) -> None:
        int_program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            CONVERT INTEGER
            RET
            """
        )
        int_report = explore_program(int_program, ExecutionOptions(initial_stack=(bytes_symbol("payload"),)))
        self.assertEqual(len(int_report.returned), 1)
        self.assertEqual(len(int_report.faulted), 1)
        self.assertEqual(render_expr(int_report.returned[0].path_conditions[0]), "(size(payload) <= 32)")
        self.assertEqual(render_expr(int_report.returned[0].stack[0]), "int(payload)")
        self.assertEqual(render_expr(int_report.faulted[0].path_conditions[0]), "(size(payload) > 32)")

        bytes_program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            CONVERT BYTESTRING
            RET
            """
        )
        bytes_report = explore_program(bytes_program, ExecutionOptions(initial_stack=(int_symbol("value"),)))
        self.assertEqual(len(bytes_report.returned), 1)
        self.assertEqual(render_expr(bytes_report.returned[0].stack[0]), "bytes(value)")

        buffer_program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            CONVERT BUFFER
            CONVERT BYTESTRING
            RET
            """
        )
        buffer_report = explore_program(buffer_program, ExecutionOptions(initial_stack=(bool_symbol("flag"),)))
        self.assertEqual(len(buffer_report.returned), 2)
        outcomes = {
            (tuple(render_expr(cond) for cond in state.path_conditions), render_expr(state.stack[0]))
            for state in buffer_report.returned
        }
        self.assertIn((("flag",), "0x01"), outcomes)
        self.assertIn((("not(flag)",), "0x00"), outcomes)

    def test_abortmsg_and_assertmsg_produce_fault_reasons(self) -> None:
        abort_report = explore_program(parse_program('PUSHDATA "boom"\nABORTMSG'))
        self.assertEqual(len(abort_report.faulted), 1)
        self.assertIn("boom", abort_report.faulted[0].reason or "")

        assert_report = explore_program(parse_program('PUSHF\nPUSHDATA "bad"\nASSERTMSG'))
        self.assertEqual(len(assert_report.faulted), 1)
        self.assertIn("bad", assert_report.faulted[0].reason or "")

    def test_callt_uses_nef_method_token_metadata(self) -> None:
        base_program = parse_program("CALLT 0")
        program = Program(
            instructions=base_program.instructions,
            script=base_program.script,
            labels=base_program.labels,
            metadata={
                "method_tokens": [
                    {
                        "hash": "0x33221100ffeeddccbbaa99887766554433221100",
                        "method": "transfer",
                        "parameters_count": 2,
                        "has_return_value": True,
                        "call_flags": 5,
                    }
                ]
            },
        )

        report = explore_program(program)
        self.assertEqual(len(report.stopped), 1)
        self.assertIn("transfer", report.stopped[0].reason or "")
        self.assertIn("0x33221100ffeeddccbbaa99887766554433221100", report.stopped[0].reason or "")

    def test_missing_callt_token_faults(self) -> None:
        base_program = parse_program("CALLT 1")
        program = Program(
            instructions=base_program.instructions,
            script=base_program.script,
            labels=base_program.labels,
            metadata={"method_tokens": []},
        )

        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("CALLT token 1 is not defined", report.faulted[0].reason or "")

    def test_concrete_integer_overflow_faults(self) -> None:
        max_positive = (1 << 255) - 1
        report = explore_program(
            parse_program(
                f"""
                PUSHINT256 {max_positive}
                PUSH1
                ADD
                RET
                """
            )
        )
        self.assertEqual(len(report.returned), 0)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("ADD integer result exceeds 32 bytes", report.faulted[0].reason or "")

    def test_numeric_protocol_limits_and_extended_ops(self) -> None:
        shift_report = explore_program(
            parse_program(
                """
                PUSH1
                PUSH 257
                SHL
                RET
                """
            ),
            ExecutionOptions(max_shift=256),
        )
        self.assertEqual(len(shift_report.faulted), 1)
        self.assertIn("Invalid shift value: 257/256", shift_report.faulted[0].reason or "")

        pow_limit_report = explore_program(
            parse_program(
                """
                PUSH2
                PUSH 257
                POW
                RET
                """
            ),
            ExecutionOptions(max_shift=256),
        )
        self.assertEqual(len(pow_limit_report.faulted), 1)
        self.assertIn("Invalid shift value: 257/256", pow_limit_report.faulted[0].reason or "")

        symbolic_pow_report = explore_program(
            parse_program(
                """
                INITSLOT 0 1
                LDARG0
                PUSH3
                POW
                RET
                """
            ),
            ExecutionOptions(initial_stack=(int_symbol("value"),)),
        )
        self.assertEqual(len(symbolic_pow_report.returned), 1)
        self.assertEqual(render_expr(symbolic_pow_report.returned[0].stack[0]), "(value * (value * value))")

        sqrt_report = explore_program(parse_program("PUSH16\nSQRT\nRET"))
        self.assertEqual(len(sqrt_report.returned), 1)
        self.assertEqual(render_expr(sqrt_report.returned[0].stack[0]), "4")

        modmul_report = explore_program(parse_program("PUSH2\nPUSH3\nPUSH5\nMODMUL\nRET"))
        self.assertEqual(len(modmul_report.returned), 1)
        self.assertEqual(render_expr(modmul_report.returned[0].stack[0]), "1")

        modpow_report = explore_program(parse_program("PUSH2\nPUSH5\nPUSH13\nMODPOW\nRET"))
        self.assertEqual(len(modpow_report.returned), 1)
        self.assertEqual(render_expr(modpow_report.returned[0].stack[0]), "6")

        inverse_report = explore_program(parse_program("PUSH3\nPUSHM1\nPUSH11\nMODPOW\nRET"))
        self.assertEqual(len(inverse_report.returned), 1)
        self.assertEqual(render_expr(inverse_report.returned[0].stack[0]), "4")

    def test_pow_splits_symbolic_exponent_range(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            PUSH2
            LDARG0
            POW
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("exponent"),), max_shift=256),
        )

        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(len(report.stopped), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "pow(2, exponent)")
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.returned[0].path_conditions),
            ("((exponent >= 0) and (exponent <= 256))",),
        )
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.faulted[0].path_conditions),
            ("((exponent < 0) or (exponent > 256))",),
        )
        self.assertEqual(report.faulted[0].reason, "Invalid shift value: outside [0, 256]")

    def test_sqrt_splits_symbolic_negative_inputs(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            SQRT
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("value"),)),
        )

        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(len(report.stopped), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "sqrt(value)")
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.returned[0].path_conditions),
            ("(value >= 0)",),
        )
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.faulted[0].path_conditions),
            ("(value < 0)",),
        )
        self.assertEqual(report.faulted[0].reason, "value can not be negative")

    def test_modmul_splits_symbolic_modulus_zero(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            PUSH2
            PUSH3
            LDARG0
            MODMUL
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("modulus"),)),
        )

        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(len(report.stopped), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "(6 % modulus)")
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.returned[0].path_conditions),
            ("(modulus != 0)",),
        )
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.faulted[0].path_conditions),
            ("(modulus == 0)",),
        )
        self.assertEqual(report.faulted[0].reason, "MODMUL by zero")

    def test_modpow_splits_symbolic_positive_modulus(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            PUSH2
            PUSH3
            LDARG0
            MODPOW
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("modulus"),)),
        )

        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 1)
        self.assertEqual(len(report.stopped), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "(8 % modulus)")
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.returned[0].path_conditions),
            ("(modulus > 0)",),
        )
        self.assertEqual(
            tuple(render_expr(cond) for cond in report.faulted[0].path_conditions),
            ("(modulus <= 0)",),
        )
        self.assertEqual(report.faulted[0].reason, "MODPOW modulus must be positive")

    def test_modpow_symbolic_base_with_concrete_exponent_and_modulus_returns_expression(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH3
            PUSH5
            MODPOW
            RET
            """
        )
        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("value"),)),
        )
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.stopped), 0)
        result = render_expr(report.returned[0].stack[0])
        self.assertIn("value", result)
        self.assertIn("%", result)

    def test_execution_limits_produce_stopped_states(self) -> None:
        buffer_report = explore_program(
            parse_program(
                """
                PUSH5
                NEWBUFFER
                RET
                """
            ),
            ExecutionOptions(max_item_size=4),
        )
        self.assertEqual(len(buffer_report.stopped), 1)
        self.assertIn("item size limit", buffer_report.stopped[0].reason or "")

        collection_report = explore_program(
            parse_program(
                """
                PUSH5
                NEWARRAY
                RET
                """
            ),
            ExecutionOptions(max_collection_size=4),
        )
        self.assertEqual(len(collection_report.stopped), 1)
        self.assertIn("collection limit", collection_report.stopped[0].reason or "")

        heap_report = explore_program(
            parse_program(
                """
                NEWARRAY0
                NEWARRAY0
                RET
                """
            ),
            ExecutionOptions(max_heap_objects=1),
        )
        self.assertEqual(len(heap_report.stopped), 1)
        self.assertIn("heap object limit", heap_report.stopped[0].reason or "")

    def test_protocol_depth_limits_fault(self) -> None:
        invocation_report = explore_program(
            parse_program(
                """
                CALL 3
                RET
                NOP
                RET
                """
            ),
            ExecutionOptions(max_invocation_stack=1),
        )
        self.assertEqual(len(invocation_report.faulted), 1)
        self.assertIn("invocation stack exceeds limit", invocation_report.faulted[0].reason or "")

        try_report = explore_program(
            parse_program(
                """
                TRY 8 0
                TRY 5 0
                PUSH1
                RET
                DROP
                RET
                """
            ),
            ExecutionOptions(max_try_nesting_depth=1),
        )
        self.assertEqual(len(try_report.faulted), 1)
        self.assertIn("try nesting depth exceeds limit", try_report.faulted[0].reason or "")

    def test_selected_syscalls_execute_with_context(self) -> None:
        program = parse_program(
            f"""
            SYSCALL {_syscall("System.Runtime.Platform")}
            SYSCALL {_syscall("System.Runtime.GetTrigger")}
            SYSCALL {_syscall("System.Runtime.GetNetwork")}
            SYSCALL {_syscall("System.Runtime.GetAddressVersion")}
            SYSCALL {_syscall("System.Runtime.GetTime")}
            SYSCALL {_syscall("System.Runtime.GasLeft")}
            SYSCALL {_syscall("System.Contract.GetCallFlags")}
            SYSCALL {_syscall("System.Runtime.GetExecutingScriptHash")}
            SYSCALL {_syscall("System.Runtime.GetEntryScriptHash")}
            SYSCALL {_syscall("System.Runtime.GetCallingScriptHash")}
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(
                trigger=0x20,
                network_magic=12345,
                address_version=42,
                time=99,
                gas_left=500,
                call_flags=5,
                script_hash=bytes.fromhex("11" * 20),
            ),
        )
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(
            [render_expr(item) for item in report.returned[0].stack],
            [
                "0x4e454f",
                "32",
                "12345",
                "42",
                "99",
                "500",
                "5",
                "0x1111111111111111111111111111111111111111",
                "0x1111111111111111111111111111111111111111",
                "null",
            ],
        )

    def test_syscall_hashes_and_runtime_values_can_be_symbolic(self) -> None:
        program = parse_program(
            f"""
            SYSCALL {_syscall("System.Runtime.GetTime")}
            SYSCALL {_syscall("System.Runtime.GasLeft")}
            SYSCALL {_syscall("System.Runtime.GetRandom")}
            SYSCALL {_syscall("System.Runtime.GetExecutingScriptHash")}
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        rendered = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(rendered[0], "sys_time")
        self.assertTrue(rendered[1].startswith("sys_gas_left_"))
        self.assertTrue(rendered[2].startswith("sys_random_"))
        self.assertEqual(rendered[3], "current_script_hash")

    def test_get_calling_script_hash_inside_internal_call_uses_current_hash(self) -> None:
        program = parse_program(
            f"""
            CALL callee
            RET

            callee:
            SYSCALL {_syscall("System.Runtime.GetCallingScriptHash")}
            RET
            """
        )

        report = explore_program(
            program,
            ExecutionOptions(script_hash=bytes.fromhex("22" * 20)),
        )
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "0x2222222222222222222222222222222222222222")

    def test_log_and_notify_syscalls_continue_execution(self) -> None:
        program = parse_program(
            f"""
            PUSHDATA hello
            SYSCALL {_syscall("System.Runtime.Log")}
            NEWARRAY0
            PUSHDATA Transfer
            SYSCALL {_syscall("System.Runtime.Notify")}
            PUSH1
            RET
            """
        )

        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")
        self.assertTrue(any(entry == "LOG hello" for entry in report.returned[0].trace))
        self.assertTrue(any(entry == "NOTIFY Transfer array#1" for entry in report.returned[0].trace))

    def test_syscall_required_call_flags_are_enforced(self) -> None:
        report = explore_program(
            parse_program(
                f"""
                PUSHDATA hello
                SYSCALL {_syscall("System.Runtime.Log")}
                """
            ),
            ExecutionOptions(call_flags=CALL_FLAGS_READ_STATES),
        )
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("System.Runtime.Log", report.faulted[0].reason or "")

    # --- Stack manipulation opcodes ---

    def test_nop_does_nothing(self) -> None:
        report = explore_program(parse_program("NOP\nPUSH1\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_pick_copies_nth_element(self) -> None:
        report = explore_program(parse_program("PUSH3\nPUSH2\nPUSH1\nPUSH2\nPICK\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["3", "2", "1", "3"])

    def test_tuck_inserts_top_below_second(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nTUCK\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["2", "1", "2"])

    def test_roll_moves_nth_to_top(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nPUSH2\nROLL\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["2", "3", "1"])

    def test_reverse3_reverses_top_three(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nREVERSE3\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["3", "2", "1"])

    def test_reverse4_reverses_top_four(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nPUSH4\nREVERSE4\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["4", "3", "2", "1"])

    def test_reversen_reverses_top_n(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nPUSH4\nPUSH3\nREVERSEN\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "4", "3", "2"])

    def test_xdrop_removes_nth_element(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nPUSH1\nXDROP\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "3"])

    def test_clear_empties_stack(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH2\nPUSH3\nCLEAR\nPUSH10\nPUSH5\nADD\nRET"))
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["15"])

    # --- Arithmetic and logic opcodes ---

    def test_sub_works(self) -> None:
        report = explore_program(parse_program("PUSH10\nPUSH3\nSUB\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "7")

    def test_mul_works(self) -> None:
        report = explore_program(parse_program("PUSH6\nPUSH7\nMUL\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "42")

    def test_invert_bitwise_not(self) -> None:
        report = explore_program(parse_program("PUSH0\nINVERT\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "-1")

    def test_sign_of_negative(self) -> None:
        report = explore_program(parse_program("PUSHM1\nSIGN\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "-1")

    def test_abs_of_negative(self) -> None:
        report = explore_program(parse_program("PUSHM1\nABS\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_negate(self) -> None:
        report = explore_program(parse_program("PUSH5\nNEGATE\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "-5")

    def test_inc(self) -> None:
        report = explore_program(parse_program("PUSH9\nINC\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "10")

    def test_dec(self) -> None:
        report = explore_program(parse_program("PUSH10\nDEC\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "9")

    def test_not_boolean_not(self) -> None:
        report = explore_program(parse_program("PUSH0\nNOT\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_booland(self) -> None:
        report = explore_program(parse_program("PUSH1\nPUSH1\nBOOLAND\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_boolor(self) -> None:
        report = explore_program(parse_program("PUSH0\nPUSH1\nBOOLOR\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_numequal(self) -> None:
        report = explore_program(parse_program("PUSH5\nPUSH5\nNUMEQUAL\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_numnotequal(self) -> None:
        report = explore_program(parse_program("PUSH3\nPUSH5\nNUMNOTEQUAL\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_within_true(self) -> None:
        # WITHIN pops upper, lower, value; checks lower <= value < upper
        # Stack push order: value, lower, upper -> pops upper, lower, value
        report = explore_program(parse_program("PUSH5\nPUSH0\nPUSH 10\nWITHIN\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_within_false_on_boundary(self) -> None:
        report = explore_program(parse_program("PUSH 10\nPUSH0\nPUSH 10\nWITHIN\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "false")

    def test_bitwise_and(self) -> None:
        report = explore_program(parse_program("PUSH12\nPUSH10\nAND\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "8")

    def test_bitwise_or(self) -> None:
        report = explore_program(parse_program("PUSH12\nPUSH10\nOR\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "14")

    def test_bitwise_xor(self) -> None:
        report = explore_program(parse_program("PUSH12\nPUSH10\nXOR\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "6")

    # --- Collection opcodes ---

    def test_keys_returns_map_keys(self) -> None:
        # PACKMAP pops count, then 2*count items (key-value pairs)
        report = explore_program(parse_program(
            """
            PUSH2
            PUSH1
            PUSH1
            PACKMAP
            DUP
            KEYS
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)
        stack = report.returned[0].stack
        self.assertGreaterEqual(len(stack), 2)

    def test_values_returns_map_values(self) -> None:
        report = explore_program(parse_program(
            """
            PUSH2
            PUSH1
            PUSH1
            PACKMAP
            DUP
            VALUES
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)
        stack = report.returned[0].stack
        self.assertGreaterEqual(len(stack), 2)

    def test_reverseitems_reverses_array(self) -> None:
        report = explore_program(parse_program(
            """
            PUSH3
            PUSH2
            PUSH1
            PACK
            DUP
            REVERSEITEMS
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)

    def test_clearitems_empties_array(self) -> None:
        # Create array with 2 elements, DUP, clear one ref, check size of other
        report = explore_program(parse_program(
            """
            PUSH2
            PUSH1
            PUSH2
            PACK
            DUP
            SWAP
            CLEARITEMS
            SIZE
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)
        # Stack should be: [size_of_cleared_array]
        self.assertEqual(render_expr(report.returned[0].stack[0]), "0")

    def test_popitem_removes_last(self) -> None:
        report = explore_program(parse_program(
            """
            PUSH3
            PUSH2
            PUSH1
            PACK
            POPITEM
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "3")

    # --- Jump opcodes ---

    def test_unconditional_jmp(self) -> None:
        report = explore_program(parse_program("JMP skip\nABORT\nskip:\nPUSH1\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_jmpif_taken(self) -> None:
        report = explore_program(parse_program("PUSH1\nJMPIF target\nABORT\ntarget:\nPUSH 42\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "42")

    def test_jmpifnot_taken(self) -> None:
        report = explore_program(parse_program("PUSH0\nJMPIFNOT target\nABORT\ntarget:\nPUSH 42\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "42")

    # --- ISTYPE for various types ---

    def test_istype_integer(self) -> None:
        report = explore_program(parse_program("PUSH5\nISTYPE INTEGER\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_istype_boolean(self) -> None:
        report = explore_program(parse_program("PUSH1\nISTYPE BOOLEAN\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "false")

    def test_istype_array(self) -> None:
        report = explore_program(parse_program("NEWARRAY0\nISTYPE ARRAY\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_istype_map(self) -> None:
        report = explore_program(parse_program("NEWMAP\nISTYPE MAP\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    def test_istype_struct(self) -> None:
        report = explore_program(parse_program("NEWSTRUCT0\nISTYPE STRUCT\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "true")

    # --- CONVERT ---

    def test_convert_null_to_any_type(self) -> None:
        report = explore_program(parse_program("PUSHNULL\nCONVERT INTEGER\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "null")

    def test_convert_bool_to_integer(self) -> None:
        report = explore_program(parse_program("PUSH1\nCONVERT INTEGER\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_convert_integer_to_bytes(self) -> None:
        report = explore_program(parse_program("PUSH5\nCONVERT BYTESTRING\nRET"))
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "0x05")

    def test_convert_struct_to_array(self) -> None:
        report = explore_program(parse_program(
            """
            PUSH1
            NEWSTRUCT
            CONVERT ARRAY
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)

    def test_convert_array_to_struct(self) -> None:
        report = explore_program(parse_program(
            """
            PUSH1
            NEWARRAY
            CONVERT STRUCT
            RET
            """
        ))
        self.assertEqual(len(report.returned), 1)

    # --- State deduplication ---

    def test_state_deduplication_skips_duplicate_paths(self) -> None:
        # Both branches converge to same state (PUSH1 then RET), so dedup should skip one
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            JMPEQ same
            PUSH1
            JMP done
            same:
            PUSH1
            done:
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_const(0),)))
        self.assertEqual(len(report.returned), 1)
        # With int_const(0), JMPEQ is always true, so only one path
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")


    # --- Struct nesting and recursion ---

    def test_deep_struct_nesting_with_clone(self) -> None:
        """Test struct cloning with nested structs."""
        # Create struct with 1 item, append to array (clones), append to clone in array
        # This tests that struct cloning works when the struct is in an array
        program = parse_program(
            """
            NEWSTRUCT0
            DUP
            PUSH1
            APPEND
            NEWARRAY0
            DUP
            ROT
            APPEND
            DUP
            PUSH0
            PICKITEM
            PUSH2
            APPEND
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        # Verify heap: cloned struct in array should now have 2 items
        heap = report.returned[0].heap
        # Find the cloned struct (referenced by array)
        cloned_struct_key = None
        for key, value in heap.items():
            if key.startswith("array#") and value and len(value) > 0:
                cloned_struct_key = value[0]
                break
        self.assertIsNotNone(cloned_struct_key, "Array should contain a struct reference")
        self.assertIn(cloned_struct_key, heap, "Cloned struct should be in heap")
        self.assertEqual(len(heap[cloned_struct_key]), 2, "Cloned struct should have 2 items")

    def test_struct_append_creates_value_copy(self) -> None:
        """Test that appending a struct to an array clones it by value."""
        # Create struct with 1 item, append to array (clones), append to original
        # Clone in array should still have 1 item, original should have 2
        # Verify by checking heap contents
        program = parse_program(
            """
            NEWSTRUCT0
            DUP
            PUSH1
            APPEND
            DUP
            NEWARRAY0
            DUP
            ROT
            APPEND
            SWAP
            PUSH2
            APPEND
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        # Verify heap: original struct should have 2 items, cloned struct should have 1
        heap = report.returned[0].heap
        # Find the original struct (the one with 2 items)
        original_size = None
        cloned_size = None
        for key, value in heap.items():
            if key.startswith("struct#"):
                if len(value) == 2:
                    original_size = len(value)
                elif len(value) == 1:
                    cloned_size = len(value)
        self.assertEqual(original_size, 2, "Original struct should have 2 items")
        self.assertEqual(cloned_size, 1, "Cloned struct should have 1 item")

    # --- Buffer operations edge cases ---

    def test_memcpy_with_zero_count_is_noop(self) -> None:
        """Test MEMCPY with count=0 doesn't modify buffer."""
        program = parse_program(
            """
            PUSH4
            NEWBUFFER
            DUP
            PUSH0
            PUSHDATA 0x11223344
            PUSH0
            PUSH0
            MEMCPY
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x00000000")

    def test_memcpy_out_of_bounds_faults(self) -> None:
        """Test MEMCPY faults when source range is out of bounds."""
        program = parse_program(
            """
            PUSH4
            NEWBUFFER
            DUP
            PUSH0
            PUSHDATA 0x1122
            PUSH1
            PUSH2
            MEMCPY
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("out of bounds", report.faulted[0].reason or "")

    def test_newbuffer_respects_item_size_limit_without_allocating(self) -> None:
        program = parse_program(
            """
            PUSHINT16 2048
            NEWBUFFER
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(max_item_size=1024))
        self.assertEqual(len(report.returned), 0)
        self.assertEqual(len(report.faulted), 0)
        self.assertEqual(len(report.stopped), 1)
        self.assertIn("buffer size 2048 exceeds item size limit 1024", report.stopped[0].reason or "")

    def test_cat_empty_buffers(self) -> None:
        """Test CAT with empty buffers."""
        program = parse_program(
            """
            PUSHDATA 0x
            PUSHDATA 0x
            CAT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x")

    def test_substr_at_start(self) -> None:
        """Test SUBSTR at index 0."""
        program = parse_program(
            """
            PUSHDATA 0x11223344
            PUSH0
            PUSH2
            SUBSTR
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x1122")

    def test_substr_at_end(self) -> None:
        """Test SUBSTR at end of buffer."""
        program = parse_program(
            """
            PUSHDATA 0x11223344
            PUSH2
            PUSH2
            SUBSTR
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x3344")

    def test_substr_out_of_bounds_faults(self) -> None:
        """Test SUBSTR faults when range exceeds buffer."""
        program = parse_program(
            """
            PUSHDATA 0x1122
            PUSH1
            PUSH2
            SUBSTR
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("out of bounds", report.faulted[0].reason or "")

    def test_substr_negative_index_faults(self) -> None:
        """Test SUBSTR faults with negative index."""
        program = parse_program(
            """
            PUSHDATA 0x1122
            PUSH -1
            PUSH1
            SUBSTR
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("invalid", report.faulted[0].reason or "")

    def test_left_entire_buffer(self) -> None:
        """Test LEFT with count equal to buffer size."""
        program = parse_program(
            """
            PUSHDATA 0x112233
            PUSH3
            LEFT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x112233")

    def test_left_zero_bytes(self) -> None:
        """Test LEFT with count=0 returns empty buffer."""
        program = parse_program(
            """
            PUSHDATA 0x112233
            PUSH0
            LEFT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x")

    def test_right_entire_buffer(self) -> None:
        """Test RIGHT with count equal to buffer size."""
        program = parse_program(
            """
            PUSHDATA 0x112233
            PUSH3
            RIGHT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x112233")

    def test_right_zero_bytes(self) -> None:
        """Test RIGHT with count=0 returns empty buffer."""
        program = parse_program(
            """
            PUSHDATA 0x112233
            PUSH0
            RIGHT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(report.returned[0].heap["buffer#1"], "0x")

    def test_left_right_out_of_bounds_faults(self) -> None:
        """Test LEFT faults when count exceeds buffer size."""
        program = parse_program(
            """
            PUSHDATA 0x1122
            PUSH3
            LEFT
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("out of bounds", report.faulted[0].reason or "")

    # --- TRY/CATCH/FINALLY edge cases ---

    def test_try_with_catch_only(self) -> None:
        """Test TRY with only catch block (no finally)."""
        # TRY 6 0: catch is at offset+6 (PUSH2)
        # 0: TRY (3 bytes), 3: PUSH1 (1), 4: THROW (1), 5: DROP (1), 6: PUSH2 (1), 7: RET (1)
        # When THROW executes, exception value 1 is pushed onto stack in catch block at offset 6
        program = parse_program(
            """
            TRY 6 0
            PUSH1
            THROW
            DROP
            PUSH2
            RET
            DROP
            PUSH2
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        # Stack has [1, 2] - exception value 1 pushed by catch, 2 pushed by PUSH2
        self.assertEqual([render_expr(item) for item in report.returned[0].stack], ["1", "2"])

    def test_try_with_finally_only(self) -> None:
        """Test TRY with only finally block (no catch)."""
        # TRY 0 6: no catch, finally at offset+6 (PUSH2)
        # 0: TRY (3 bytes), 3: PUSH1 (1), 4: ENDTRY 5 (2), 6: PUSH2 (1) - finally,
        # 7: ADD (1), 8: ENDFINALLY (1), 9: RET (1)
        # ENDTRY 5: end_ip = 4+5=9 (RET)
        program = parse_program(
            """
            TRY 0 6
            PUSH1
            ENDTRY 5
            PUSH2
            ADD
            ENDFINALLY
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "3")

    def test_try_catch_finally_all_present(self) -> None:
        """Test TRY with both catch and finally blocks."""
        # TRY 5 11: catch at offset+5 (DROP), finally at offset+11 (ENDFINALLY)
        # 0: TRY (3 bytes), 3: PUSH1 (1), 4: THROW (1), 5: DROP (1) - catch
        # 6: PUSH2 (1), 7: ENDTRY 3 (2), 9: PUSH3 (1), 10: THROW (1)
        # 11: ENDFINALLY (1) - finally
        # 12: RET (1)
        program = parse_program(
            """
            TRY 5 11
            PUSH1
            THROW
            DROP
            PUSH2
            ENDTRY 3
            PUSH3
            THROW
            ENDFINALLY
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("unhandled exception", report.faulted[0].reason or "")

    def test_try_without_catch_or_finally_rejected_at_parse(self) -> None:
        """Test TRY with no catch or finally is rejected at parse time."""
        from neo_symbolic_executor.assembly import ParseError

        with self.assertRaises(ParseError):
            parse_program(
                """
                TRY 0 0
                PUSH1
                RET
                """
            )

    def test_endtry_without_try_faults(self) -> None:
        """Test ENDTRY without active TRY block faults."""
        # ENDTRY -1 targets offset 0 (PUSH1)
        # PUSH1 (1 byte) at offset 0, ENDTRY (2 bytes) at offset 1
        program = parse_program(
            """
            PUSH1
            ENDTRY -1
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("requires an active TRY block", report.faulted[0].reason or "")

    def test_endfinally_without_try_faults(self) -> None:
        """Test ENDFINALLY without active TRY block faults."""
        program = parse_program(
            """
            PUSH1
            ENDFINALLY
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("requires an active FINALLY block", report.faulted[0].reason or "")

    def test_throw_without_try_faults(self) -> None:
        """Test THROW without any try block faults the program."""
        program = parse_program(
            """
            PUSH1
            THROW
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("unhandled exception", report.faulted[0].reason or "")

    def test_nested_try_blocks(self) -> None:
        """Test nested TRY blocks with exception in inner block."""
        # Outer TRY at 0, catch at 11 (NOP)
        # Inner TRY at 3, catch at 10 (RET)
        # When THROW executes, inner catch at 10 handles it and returns
        program = parse_program(
            """
            TRY 11 0
            TRY 7 0
            PUSH1
            THROW
            DROP
            PUSH2
            RET
            NOP
            DROP
            PUSH3
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        # Inner catch receives exception value 1 and returns it
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_try_nesting_depth_limit(self) -> None:
        """Test that exceeding max_try_nesting_depth faults."""
        # First TRY at 0, second TRY at 3
        # Inner catch at 6+5=11 (NOP), outer catch at 3+8=11 (NOP)
        program = parse_program(
            """
            TRY 8 0
            TRY 5 0
            PUSH1
            RET
            NOP
            NOP
            NOP
            NOP
            NOP
            RET
            """
        )
        report = explore_program(
            program,
            ExecutionOptions(max_try_nesting_depth=1),
        )
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("try nesting depth exceeds limit", report.faulted[0].reason or "")

    def test_finally_rethrows_after_catch(self) -> None:
        """Test that exception in finally rethrows after catch."""
        # TRY at 0: catch at 0+5=5 (DROP), finally at 0+11=11 (ENDFINALLY)
        program = parse_program(
            """
            TRY 5 11
            PUSH1
            THROW
            DROP
            PUSH2
            ENDTRY 2
            PUSH3
            THROW
            ENDFINALLY
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("unhandled exception", report.faulted[0].reason or "")

    # --- Additional syscall tests ---

    def test_get_invocation_counter_syscall(self) -> None:
        """Test System.Runtime.GetInvocationCounter returns concrete value."""
        program = parse_program(
            f"""
            SYSCALL {_syscall("System.Runtime.GetInvocationCounter")}
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_unimplemented_syscall_stops_execution(self) -> None:
        """Test that unimplemented syscalls stop with stopped state."""
        # System.Runtime.CheckWitness is defined but not fully implemented
        program = parse_program(
            f"""
            PUSHDATA 0x11223344
            SYSCALL {_syscall("System.Runtime.CheckWitness")}
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.stopped), 1)
        self.assertIn("CheckWitness", report.stopped[0].reason or "")

    def test_syscall_with_missing_required_call_flags(self) -> None:
        """Test syscall fails without required call flags."""
        # System.Contract.Call requires AllowCall flag
        program = parse_program(
            f"""
            PUSHDATA 0x1122
            PUSHDATA 0x3344
            PUSHDATA method
            SYSCALL {_syscall("System.Contract.Call")}
            RET
            """
        )
        report = explore_program(
            program,
            ExecutionOptions(call_flags=0),  # No flags set
        )
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("System.Contract.Call", report.faulted[0].reason or "")

    def test_unknown_syscall_faults(self) -> None:
        """Test unknown syscall hash faults."""
        program = parse_program(
            """
            SYSCALL 0xDEADBEEF
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("not found", report.faulted[0].reason or "")

    # --- Expression simplification edge cases ---

    def test_subtraction_simplification(self) -> None:
        """Test that subtraction expressions are simplified correctly."""
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            SUB
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("x"),)))
        self.assertEqual(len(report.returned), 1)
        # x - 0 should simplify to x
        self.assertEqual(render_expr(report.returned[0].stack[0]), "x")

    def test_addition_with_zero_simplification(self) -> None:
        """Test that addition with zero is simplified."""
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            ADD
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("x"),)))
        self.assertEqual(len(report.returned), 1)
        # x + 0 should simplify to x
        self.assertEqual(render_expr(report.returned[0].stack[0]), "x")

    def test_multiplication_by_zero_simplification(self) -> None:
        """Test that multiplication by zero simplifies to zero."""
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH0
            MUL
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("x"),)))
        self.assertEqual(len(report.returned), 1)
        # x * 0 should simplify to 0
        self.assertEqual(render_expr(report.returned[0].stack[0]), "0")

    def test_multiplication_by_one_simplification(self) -> None:
        """Test that multiplication by one is simplified."""
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            PUSH1
            MUL
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("x"),)))
        self.assertEqual(len(report.returned), 1)
        # x * 1 should simplify to x
        self.assertEqual(render_expr(report.returned[0].stack[0]), "x")

    def test_double_negation_produces_correct_expression(self) -> None:
        """Test that double negation produces the correct expression.

        Note: Full simplification of -(-x) to x is not currently implemented.
        """
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            NEGATE
            NEGATE
            RET
            """
        )
        report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("x"),)))
        self.assertEqual(len(report.returned), 1)
        # The expression should be present (simplification to x is not implemented)
        result = render_expr(report.returned[0].stack[0])
        self.assertIn("neg", result)
        self.assertIn("x", result)

    # --- Stack manipulation edge cases ---

    def test_roll_with_zero(self) -> None:
        """Test ROLL with n=0 is a no-op."""
        program = parse_program(
            """
            PUSH1
            PUSH2
            PUSH3
            PUSH0
            ROLL
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "2", "3"])

    def test_pick_with_zero(self) -> None:
        """Test PICK with n=0 picks top element."""
        program = parse_program(
            """
            PUSH1
            PUSH2
            PUSH3
            PUSH0
            PICK
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "2", "3", "3"])

    def test_xdrop_with_zero(self) -> None:
        """Test XDROP with n=0 removes top element."""
        program = parse_program(
            """
            PUSH1
            PUSH2
            PUSH3
            PUSH0
            XDROP
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "2"])

    def test_reversen_with_two(self) -> None:
        """Test REVERSEN with n=2 swaps top two elements."""
        program = parse_program(
            """
            PUSH1
            PUSH2
            PUSH3
            PUSH2
            REVERSEN
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["1", "3", "2"])

    # --- Conversion edge cases ---

    def test_convert_null_stays_null(self) -> None:
        """Test converting null to any type stays null."""
        program = parse_program(
            """
            PUSHNULL
            CONVERT INTEGER
            PUSHNULL
            CONVERT BYTESTRING
            PUSHNULL
            CONVERT BOOLEAN
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["null", "null", "null"])

    def test_convert_boolean_to_bytes(self) -> None:
        """Test converting boolean to bytes."""
        program = parse_program(
            """
            PUSHT
            CONVERT BYTESTRING
            PUSHF
            CONVERT BYTESTRING
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["0x01", "0x00"])

    def test_convert_integer_to_bool(self) -> None:
        """Test converting integer to boolean."""
        program = parse_program(
            """
            PUSH5
            CONVERT BOOLEAN
            PUSH0
            CONVERT BOOLEAN
            PUSHM1
            CONVERT BOOLEAN
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        stack = [render_expr(item) for item in report.returned[0].stack]
        self.assertEqual(stack, ["true", "false", "true"])

    # --- PUSHA edge cases ---

    def test_pusha_valid_target(self) -> None:
        """Test PUSHA with valid label target."""
        program = parse_program(
            """
            PUSHA target
            CALLA
            RET

            target:
            PUSH1
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.returned), 1)
        self.assertEqual(render_expr(report.returned[0].stack[0]), "1")

    def test_calla_with_invalid_pointer_faults(self) -> None:
        """Test CALLA with invalid pointer faults."""
        program = parse_program(
            """
            PUSH 999
            CALLA
            RET
            """
        )
        report = explore_program(program)
        self.assertEqual(len(report.faulted), 1)
        self.assertIn("not a valid instruction offset", report.faulted[0].reason or "")

    def test_calla_symbolic_pointer_branches_to_known_targets(self) -> None:
        program = parse_program(
            """
            INITSLOT 0 1
            LDARG0
            CALLA
            RET

            target_one:
            PUSH1
            RET

            target_two:
            PUSH2
            RET
            """
        )
        report = explore_program(
            program,
            ExecutionOptions(initial_stack=(int_symbol("pointer"),)),
        )
        self.assertGreaterEqual(len(report.returned), 2)
        self.assertEqual(len(report.stopped), 0)
        returned_values = {
            render_expr(state.stack[0])
            for state in report.returned
            if state.stack
        }
        self.assertEqual(returned_values, {"1", "2"})
        offsets = {
            program.labels["target_one"],
            program.labels["target_two"],
        }
        condition_exprs = [
            render_expr(cond)
            for state in report.returned
            for cond in state.path_conditions
        ]
        for offset in offsets:
            self.assertTrue(
                any(f"pointer == {offset}" in expr for expr in condition_exprs),
                f"pointer equality for offset {offset} missing from path conditions",
            )


if __name__ == "__main__":
    unittest.main()
