from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .assembly import ParseError
from .bytecode import DecodeError
from .engine import ExecutionOptions, explore_program
from .expr import (
    Expression,
    bool_const,
    bool_symbol,
    bytes_const,
    bytes_symbol,
    int_const,
    int_symbol,
    null_const,
    render_expr,
)
from .interop import (
    CALL_FLAG_NAME_TO_VALUE,
    CALL_FLAGS_ALL,
    DEFAULT_ADDRESS_VERSION,
    DEFAULT_NETWORK_MAGIC,
    TRIGGER_NAME_TO_VALUE,
)
from .nef import NefParseError
from .source import load_program_file


def _get_version() -> str:
    try:
        return _pkg_version("neo-symbolic-executor")
    except PackageNotFoundError:
        return "0.1.0 (dev)"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neo-symbolic-executor",
        description="Explore NeoVM bytecode symbolically.",
    )
    parser.add_argument("--version", action="version", version=f"neo-symbolic-executor {_get_version()}")
    parser.add_argument("path", help="Path to a NeoVM source file, raw script, JSON script, or .nef container")
    parser.add_argument(
        "--source-type",
        default="auto",
        choices=("auto", "assembly", "hex", "binary", "nef", "json"),
        help="Override automatic source-type detection",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--disassemble", action="store_true", help="Print decoded NeoVM instructions before execution")
    parser.add_argument("--max-steps", type=int, default=256, help="Maximum steps per path")
    parser.add_argument("--max-states", type=int, default=512, help="Maximum processed states")
    parser.add_argument(
        "--max-visits",
        type=int,
        default=12,
        help="Maximum visits to one instruction along a path",
    )
    parser.add_argument(
        "--max-item-size",
        type=int,
        default=1_048_576,
        help="Maximum concrete byte/buffer allocation size during execution",
    )
    parser.add_argument(
        "--max-collection-size",
        type=int,
        default=16_384,
        help="Maximum array/struct/map element count during execution",
    )
    parser.add_argument(
        "--max-heap-objects",
        type=int,
        default=4_096,
        help="Maximum live heap-backed objects during execution",
    )
    parser.add_argument(
        "--max-invocation-stack",
        type=int,
        default=1_024,
        help="Maximum NeoVM invocation stack depth during execution",
    )
    parser.add_argument(
        "--max-stack-depth",
        type=int,
        default=1_024,
        help="Maximum NeoVM data stack depth during execution",
    )
    parser.add_argument(
        "--max-try-nesting-depth",
        type=int,
        default=16,
        help="Maximum nested TRY depth during execution",
    )
    parser.add_argument(
        "--max-shift",
        type=int,
        default=256,
        help="Maximum NeoVM shift/exponent value for SHL, SHR, and POW",
    )
    parser.add_argument(
        "--stack-item",
        action="append",
        default=[],
        help="Push an initial evaluation-stack item. Bare identifiers become symbolic integers.",
    )
    parser.add_argument(
        "--arg",
        action="append",
        default=[],
        help="Seed argument values for a forthcoming INITSLOT. Values are pushed in NeoVM argument-pop order.",
    )
    parser.add_argument(
        "--trigger",
        default="application",
        help="Trigger type for runtime syscalls, for example application, verification, onpersist, or 0x40",
    )
    parser.add_argument(
        "--network-magic",
        default=str(DEFAULT_NETWORK_MAGIC),
        help="Network magic for runtime syscalls",
    )
    parser.add_argument(
        "--address-version",
        default=str(DEFAULT_ADDRESS_VERSION),
        help="Address version for runtime syscalls",
    )
    parser.add_argument(
        "--call-flags",
        default="all",
        help="Current Neo call flags, for example all, readonly, readstates, or 0x0f",
    )
    parser.add_argument(
        "--script-hash",
        default=None,
        help="Current contract script hash as a 20-byte 0x-prefixed value",
    )
    parser.add_argument(
        "--gas-left",
        default=None,
        help="Concrete System.Runtime.GasLeft value",
    )
    parser.add_argument(
        "--time",
        default=None,
        help="Concrete System.Runtime.GetTime value",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        program = load_program_file(args.path, source_type=args.source_type)
        initial_stack = tuple(
            [_parse_value_spec(spec) for spec in args.stack_item]
            + list(reversed([_parse_value_spec(spec) for spec in args.arg]))
        )
        report = explore_program(
            program,
            ExecutionOptions(
                max_steps=args.max_steps,
                max_states=args.max_states,
                max_visits_per_instruction=args.max_visits,
                initial_stack=initial_stack,
                max_item_size=args.max_item_size,
                max_collection_size=args.max_collection_size,
                max_heap_objects=args.max_heap_objects,
                max_invocation_stack=args.max_invocation_stack,
                max_stack_depth=args.max_stack_depth,
                max_try_nesting_depth=args.max_try_nesting_depth,
                max_shift=args.max_shift,
                trigger=_parse_trigger_spec(args.trigger),
                network_magic=_parse_int_literal(args.network_magic, "network magic"),
                address_version=_parse_int_literal(args.address_version, "address version"),
                call_flags=_parse_call_flags_spec(args.call_flags),
                script_hash=_parse_hash160(args.script_hash) if args.script_hash is not None else None,
                gas_left=None if args.gas_left is None else _parse_int_literal(args.gas_left, "gas left"),
                time=None if args.time is None else _parse_int_literal(args.time, "time"),
            ),
        )
    except (ParseError, DecodeError, NefParseError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.json:
        payload = report.to_dict()
        payload["program"] = {
            "length": program.length,
            "instruction_count": len(program.instructions),
            "metadata": program.metadata,
        }
        json.dump(payload, sys.stdout, indent=2)
        print()
        return 0

    if args.disassemble:
        _print_disassembly(program)
        print()
    _print_human_report(program, report)
    return 0


def _parse_value_spec(spec: str) -> Expression:
    lowered = spec.lower()
    if lowered == "null":
        return null_const()
    if lowered == "true":
        return bool_const(True)
    if lowered == "false":
        return bool_const(False)
    if spec.startswith(("0x", "0X")):
        return bytes_const(bytes.fromhex(spec[2:]))
    if ":" in spec:
        value_type, raw_value = spec.split(":", 1)
        value_type = value_type.lower()
        if value_type == "int":
            return int_symbol(raw_value) if _looks_like_identifier(raw_value) else int_const(int(raw_value, 0))
        if value_type == "bool":
            if raw_value.lower() in {"true", "false"}:
                return bool_const(raw_value.lower() == "true")
            return bool_symbol(raw_value)
        if value_type == "bytes":
            if raw_value.startswith(("0x", "0X")):
                return bytes_const(bytes.fromhex(raw_value[2:]))
            if _looks_like_identifier(raw_value):
                return bytes_symbol(raw_value)
            return bytes_const(raw_value.encode("utf-8"))
        raise ValueError(f"Unsupported value type '{value_type}'")
    try:
        return int_const(int(spec, 0))
    except ValueError:
        pass
    return int_symbol(spec)


def _looks_like_identifier(value: str) -> bool:
    return bool(value) and (value[0].isalpha() or value[0] == "_") and all(
        character.isalnum() or character == "_" for character in value
    )


def _parse_int_literal(value: str, label: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}: {value}") from exc


def _parse_trigger_spec(value: str) -> int:
    lowered = value.lower()
    if lowered in TRIGGER_NAME_TO_VALUE:
        return TRIGGER_NAME_TO_VALUE[lowered]
    parsed = _parse_int_literal(value, "trigger")
    if not 0 <= parsed <= 0xFF:
        raise ValueError("trigger must fit in one byte")
    return parsed


def _parse_call_flags_spec(value: str) -> int:
    lowered = value.lower()
    if lowered in CALL_FLAG_NAME_TO_VALUE:
        return CALL_FLAG_NAME_TO_VALUE[lowered]
    try:
        parsed = int(value, 0)
    except ValueError:
        flags = 0
        for part in [entry.strip().lower() for entry in value.split(",") if entry.strip()]:
            if part not in CALL_FLAG_NAME_TO_VALUE:
                raise ValueError(f"Unknown call flag: {part}") from None
            flags |= CALL_FLAG_NAME_TO_VALUE[part]
        return flags
    if not 0 <= parsed <= CALL_FLAGS_ALL:
        raise ValueError("call_flags must fit in Neo CallFlags")
    return parsed


def _parse_hash160(value: str) -> bytes:
    if not value.startswith(("0x", "0X")):
        raise ValueError("script_hash must start with 0x")
    try:
        data = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError("script_hash must be hex-encoded") from exc
    if len(data) != 20:
        raise ValueError("script_hash must be exactly 20 bytes")
    return data


def _print_disassembly(program) -> None:
    print("Disassembly:")
    for instruction in program.instructions:
        line = f"  {instruction.offset:04x}: {instruction.display}"
        if instruction.target is not None:
            line += f" -> 0x{instruction.target:04x}"
        print(line)


def _print_human_report(program, report) -> None:
    print(f"Program length: {program.length} bytes")
    print(f"Instructions: {len(program.instructions)}")
    if program.metadata:
        for key, value in sorted(program.metadata.items()):
            print(f"{key}: {value}")
    print(f"Explored states: {report.explored_states}")
    print(f"Returned paths: {len(report.returned)}")
    print(f"Faulted paths: {len(report.faulted)}")
    print(f"Stopped paths: {len(report.stopped)}")

    for title, states in (
        ("Returned", report.returned),
        ("Faulted", report.faulted),
        ("Stopped", report.stopped),
    ):
        if not states:
            continue
        print()
        print(f"{title}:")
        for index, state in enumerate(states, start=1):
            print(f"  [{index}] ip={state.ip} steps={state.steps}")
            if state.call_depth:
                print(f"    call_depth: {state.call_depth}")
            if state.reason:
                print(f"    reason: {state.reason}")
            if state.path_conditions:
                rendered = ", ".join(render_expr(cond) for cond in state.path_conditions)
                print(f"    path: {rendered}")
            if state.stack:
                rendered = ", ".join(render_expr(item) for item in state.stack)
                print(f"    stack: [{rendered}]")
            if state.arguments is not None:
                rendered = ", ".join(
                    f"{slot}={render_expr(value)}" for slot, value in enumerate(state.arguments)
                )
                print(f"    args: {rendered}")
            if state.local_variables is not None:
                rendered = ", ".join(
                    f"{slot}={render_expr(value)}" for slot, value in enumerate(state.local_variables)
                )
                print(f"    locals: {rendered}")
            if state.static_fields is not None:
                rendered = ", ".join(
                    f"{slot}={render_expr(value)}" for slot, value in enumerate(state.static_fields)
                )
                print(f"    statics: {rendered}")
            if state.heap:
                print(f"    heap: {json.dumps(state.heap, sort_keys=True)}")
            if state.call_stack:
                rendered = ", ".join(
                    f"return_ip={return_ip}"
                    for return_ip, _arguments, _locals in state.call_stack
                )
                print(f"    call_stack: {rendered}")


if __name__ == "__main__":
    raise SystemExit(main())
