"""Load real z3 if available, else provide a lightweight fallback stub."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _load_real_z3() -> bool:
    """Try loading the real z3 module without importing this fallback recursively."""
    current_file = Path(__file__).resolve()
    current_dir = current_file.parent.resolve()
    search_paths: list[str] = []
    for path in sys.path:
        if not path:
            continue
        try:
            resolved = Path(path).resolve()
        except OSError:
            continue
        if resolved == current_dir:
            continue
        search_paths.append(path)

    spec = importlib.machinery.PathFinder.find_spec("z3", search_paths)
    if spec is None or spec.loader is None or spec.origin is None:
        return False
    try:
        if Path(spec.origin).resolve() == current_file:
            return False
    except OSError:
        return False

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals().update(module.__dict__)
    return True


if not _load_real_z3():
    class ExprRef:
        """Base expression object."""

        def __init__(self, op: str, args: tuple[Any, ...], bits: int | None = None) -> None:
            self.op = op
            self.args = args
            self.bits = bits

        def __repr__(self) -> str:
            inner = ", ".join(repr(a) for a in self.args)
            return f"{self.op}({inner})"


    class BoolRef(ExprRef):
        """Boolean expression."""

        def __bool__(self) -> bool:
            raise TypeError("Symbolic booleans cannot be cast to bool")


    @dataclass(frozen=True)
    class BitVecRef:
        """Symbolic bit-vector value."""

        name: str
        bits: int

        def _wrap(self, value: int) -> int:
            return value & ((1 << self.bits) - 1)

        def _binary(self, op: str, other: Any) -> ExprRef | BitVecNumRef:
            if isinstance(other, BitVecNumRef) and isinstance(self, BitVecNumRef):
                if op == "add":
                    return BitVecNumRef(self._wrap(self.value + other.value), self.bits)
                if op == "sub":
                    return BitVecNumRef(self._wrap(self.value - other.value), self.bits)
                if op == "mul":
                    return BitVecNumRef(self._wrap(self.value * other.value), self.bits)
            return ExprRef(op, (self, other), bits=self.bits)

        def __add__(self, other: Any) -> ExprRef | BitVecNumRef:
            return self._binary("add", other)

        def __sub__(self, other: Any) -> ExprRef | BitVecNumRef:
            return self._binary("sub", other)

        def __mul__(self, other: Any) -> ExprRef | BitVecNumRef:
            return self._binary("mul", other)


    @dataclass(frozen=True)
    class BitVecNumRef(BitVecRef):
        """Concrete bit-vector value."""

        value: int

        def __init__(self, value: int, bits: int) -> None:
            object.__setattr__(self, "name", f"{value}:{bits}")
            object.__setattr__(self, "bits", bits)
            object.__setattr__(self, "value", value & ((1 << bits) - 1))


    def BitVec(name: str, bits: int) -> BitVecRef:
        return BitVecRef(name=name, bits=bits)


    def BitVecVal(value: int, bits: int) -> BitVecNumRef:
        return BitVecNumRef(value=value, bits=bits)


    def simplify(expr: Any) -> Any:
        return expr


    def is_bv_value(expr: Any) -> bool:
        return isinstance(expr, BitVecNumRef)
