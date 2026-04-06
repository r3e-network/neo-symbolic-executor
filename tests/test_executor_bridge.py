"""Compatibility tests for the programmatic executor bridge."""

from __future__ import annotations

from neo_sym.executor import ExecutionOptions, explore_program, int_symbol, parse_program, render_expr


def test_executor_bridge_exposes_standalone_executor() -> None:
    program = parse_program(
        """
        INITSLOT 0 1
        LDARG0
        PUSH0
        JMPLT reject
        LDARG0
        RET
        reject:
        ABORT
        """
    )

    report = explore_program(program, ExecutionOptions(initial_stack=(int_symbol("amount"),)))

    assert len(report.returned) == 1
    assert len(report.faulted) == 1
    assert render_expr(report.faulted[0].path_conditions[0]) == "(amount < 0)"
