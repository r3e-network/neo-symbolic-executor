from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isqrt


class Sort(StrEnum):
    INT = "int"
    BOOL = "bool"
    BYTES = "bytes"
    NULL = "null"
    BUFFER = "buffer"
    ARRAY = "array"
    STRUCT = "struct"
    MAP = "map"


@dataclass(frozen=True)
class IntConst:
    value: int

    @property
    def sort(self) -> Sort:
        return Sort.INT


@dataclass(frozen=True)
class BoolConst:
    value: bool

    @property
    def sort(self) -> Sort:
        return Sort.BOOL


@dataclass(frozen=True)
class BytesConst:
    value: bytes

    @property
    def sort(self) -> Sort:
        return Sort.BYTES


@dataclass(frozen=True)
class NullConst:
    @property
    def sort(self) -> Sort:
        return Sort.NULL


@dataclass(frozen=True)
class HeapRef:
    object_id: int
    ref_sort: Sort

    @property
    def sort(self) -> Sort:
        return self.ref_sort


@dataclass(frozen=True)
class Symbol:
    name: str
    symbol_sort: Sort

    @property
    def sort(self) -> Sort:
        return self.symbol_sort


@dataclass(frozen=True)
class UnaryExpr:
    op: str
    operand: Expression
    result_sort: Sort

    @property
    def sort(self) -> Sort:
        return self.result_sort


@dataclass(frozen=True)
class BinaryExpr:
    op: str
    left: Expression
    right: Expression
    result_sort: Sort

    @property
    def sort(self) -> Sort:
        return self.result_sort


Expression = IntConst | BoolConst | BytesConst | NullConst | HeapRef | Symbol | UnaryExpr | BinaryExpr

COMPARISON_OPS = {"==", "!=", "<", "<=", ">", ">="}
ARITHMETIC_OPS = {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"}
INVERSE_COMPARISON = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
}


def _int_to_signed_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    length = 1
    while True:
        try:
            return value.to_bytes(length, "little", signed=True)
        except OverflowError:
            length += 1


def _integer_byte_size(value: int) -> int:
    return len(_int_to_signed_bytes(value))


def _neo_divmod(left: int, right: int) -> tuple[int, int]:
    quotient = abs(left) // abs(right)
    if (left < 0) ^ (right < 0):
        quotient = -quotient
    remainder = left - quotient * right
    return quotient, remainder


def int_const(value: int) -> Expression:
    return IntConst(value)


def bool_const(value: bool) -> Expression:
    return BoolConst(value)


def bytes_const(value: bytes) -> Expression:
    return BytesConst(value)


def null_const() -> Expression:
    return NullConst()


def int_symbol(name: str) -> Expression:
    return Symbol(name=name, symbol_sort=Sort.INT)


def bool_symbol(name: str) -> Expression:
    return Symbol(name=name, symbol_sort=Sort.BOOL)


def bytes_symbol(name: str) -> Expression:
    return Symbol(name=name, symbol_sort=Sort.BYTES)


def is_int(expr: Expression) -> bool:
    return expr.sort == Sort.INT


def is_bool(expr: Expression) -> bool:
    return expr.sort == Sort.BOOL


def is_bytes(expr: Expression) -> bool:
    return expr.sort == Sort.BYTES


def is_null(expr: Expression) -> bool:
    return expr.sort == Sort.NULL


def is_buffer(expr: Expression) -> bool:
    return expr.sort == Sort.BUFFER


def is_array_like(expr: Expression) -> bool:
    return expr.sort in {Sort.ARRAY, Sort.STRUCT}


def is_map(expr: Expression) -> bool:
    return expr.sort == Sort.MAP


def truthy(expr: Expression) -> Expression:
    expr = simplify(expr)
    if is_bool(expr):
        return expr
    if isinstance(expr, IntConst):
        return BoolConst(expr.value != 0)
    if isinstance(expr, BytesConst):
        return BoolConst(any(byte != 0 for byte in expr.value))
    if isinstance(expr, NullConst):
        return BoolConst(False)
    if isinstance(expr, HeapRef):
        return BoolConst(True)
    return simplify(UnaryExpr("truthy", expr, Sort.BOOL))


def negate(expr: Expression) -> Expression:
    return simplify(UnaryExpr("not", expr, Sort.BOOL))


def make_unary(op: str, operand: Expression) -> Expression:
    if op == "not":
        return simplify(UnaryExpr(op, operand, Sort.BOOL))
    if op == "neg":
        return simplify(UnaryExpr(op, operand, Sort.INT))
    if op in {"abs", "sign", "sqrt"}:
        return simplify(UnaryExpr(op, operand, Sort.INT))
    if op in {"truthy", "nz"}:
        return simplify(UnaryExpr(op, operand, Sort.BOOL))
    if op == "invert":
        return simplify(UnaryExpr(op, operand, Sort.INT))
    if op in {"size", "to_int"}:
        return simplify(UnaryExpr(op, operand, Sort.INT))
    if op == "to_bytes":
        return simplify(UnaryExpr(op, operand, Sort.BYTES))
    raise ValueError(f"Unsupported unary op: {op}")


def make_binary(op: str, left: Expression, right: Expression) -> Expression:
    if op == "byte_at":
        return simplify(BinaryExpr(op, left, right, Sort.INT))
    if op == "pow":
        return simplify(BinaryExpr(op, left, right, Sort.INT))
    result_sort = Sort.BOOL if op in COMPARISON_OPS or op in {"and", "or"} else Sort.INT
    return simplify(BinaryExpr(op, left, right, result_sort))


def simplify(expr: Expression) -> Expression:
    if isinstance(expr, (IntConst, BoolConst, BytesConst, NullConst, HeapRef, Symbol)):
        return expr

    if isinstance(expr, UnaryExpr):
        operand = simplify(expr.operand)
        if expr.op == "neg":
            if not is_int(operand):
                raise TypeError("neg expects an integer operand")
            if isinstance(operand, IntConst):
                return IntConst(-operand.value)
            return UnaryExpr("neg", operand, Sort.INT)
        if expr.op == "abs":
            if not is_int(operand):
                raise TypeError("abs expects an integer operand")
            if isinstance(operand, IntConst):
                return IntConst(abs(operand.value))
            return UnaryExpr("abs", operand, Sort.INT)
        if expr.op == "sign":
            if not is_int(operand):
                raise TypeError("sign expects an integer operand")
            if isinstance(operand, IntConst):
                return IntConst(0 if operand.value == 0 else (1 if operand.value > 0 else -1))
            return UnaryExpr("sign", operand, Sort.INT)
        if expr.op == "sqrt":
            if not is_int(operand):
                raise TypeError("sqrt expects an integer operand")
            if isinstance(operand, IntConst):
                if operand.value < 0:
                    raise TypeError("sqrt expects a non-negative integer operand")
                return IntConst(isqrt(operand.value))
            return UnaryExpr("sqrt", operand, Sort.INT)
        if expr.op == "invert":
            if not is_int(operand):
                raise TypeError("invert expects an integer operand")
            if isinstance(operand, IntConst):
                return IntConst(~operand.value)
            return UnaryExpr("invert", operand, Sort.INT)
        if expr.op == "size":
            if isinstance(operand, BoolConst):
                return IntConst(1)
            if isinstance(operand, IntConst):
                return IntConst(_integer_byte_size(operand.value))
            if isinstance(operand, BytesConst):
                return IntConst(len(operand.value))
            if operand.sort not in {Sort.BOOL, Sort.INT, Sort.BYTES}:
                raise TypeError("size expects a primitive operand")
            if operand.sort == Sort.BOOL:
                return IntConst(1)
            return UnaryExpr("size", operand, Sort.INT)
        if expr.op == "to_int":
            if isinstance(operand, IntConst):
                return operand
            if isinstance(operand, BoolConst):
                return IntConst(1 if operand.value else 0)
            if isinstance(operand, BytesConst):
                return IntConst(int.from_bytes(operand.value, "little", signed=True))
            if operand.sort not in {Sort.BOOL, Sort.INT, Sort.BYTES}:
                raise TypeError("to_int expects a primitive operand")
            if operand.sort == Sort.INT:
                return operand
            return UnaryExpr("to_int", operand, Sort.INT)
        if expr.op == "to_bytes":
            if isinstance(operand, BytesConst):
                return operand
            if isinstance(operand, BoolConst):
                return BytesConst(b"\x01" if operand.value else b"\x00")
            if isinstance(operand, IntConst):
                return BytesConst(_int_to_signed_bytes(operand.value))
            if operand.sort not in {Sort.BOOL, Sort.INT, Sort.BYTES}:
                raise TypeError("to_bytes expects a primitive operand")
            if operand.sort == Sort.BYTES:
                return operand
            return UnaryExpr("to_bytes", operand, Sort.BYTES)
        if expr.op == "truthy" or expr.op == "nz":
            if isinstance(operand, BoolConst):
                return operand
            if isinstance(operand, IntConst):
                return BoolConst(operand.value != 0)
            if isinstance(operand, BytesConst):
                return BoolConst(any(byte != 0 for byte in operand.value))
            if isinstance(operand, NullConst):
                return BoolConst(False)
            if isinstance(operand, HeapRef):
                return BoolConst(True)
            return UnaryExpr("truthy", operand, Sort.BOOL)
        if expr.op == "not":
            if not is_bool(operand):
                raise TypeError("not expects a boolean operand")
            if isinstance(operand, BoolConst):
                return BoolConst(not operand.value)
            if isinstance(operand, UnaryExpr) and operand.op == "not":
                return operand.operand
            if isinstance(operand, BinaryExpr) and operand.op in INVERSE_COMPARISON:
                return simplify(
                    BinaryExpr(
                        INVERSE_COMPARISON[operand.op],
                        operand.left,
                        operand.right,
                        Sort.BOOL,
                    )
                )
            return UnaryExpr("not", operand, Sort.BOOL)
        raise ValueError(f"Unsupported unary op: {expr.op}")

    left = simplify(expr.left)
    right = simplify(expr.right)

    if expr.op == "byte_at":
        if left.sort not in {Sort.BOOL, Sort.INT, Sort.BYTES}:
            raise TypeError("byte_at expects a primitive operand")
        if not is_int(right):
            raise TypeError("byte_at expects an integer index")
        if isinstance(right, IntConst):
            if right.value < 0:
                raise TypeError("byte_at expects a non-negative index")
            if isinstance(left, BoolConst):
                if right.value == 0:
                    return IntConst(1 if left.value else 0)
                return BinaryExpr("byte_at", left, right, Sort.INT)
            if isinstance(left, IntConst):
                data = _int_to_signed_bytes(left.value)
                if right.value < len(data):
                    return IntConst(data[right.value])
                return BinaryExpr("byte_at", left, right, Sort.INT)
            if isinstance(left, BytesConst):
                if right.value < len(left.value):
                    return IntConst(left.value[right.value])
                return BinaryExpr("byte_at", left, right, Sort.INT)
            if left.sort == Sort.BOOL and right.value == 0:
                return simplify(UnaryExpr("to_int", left, Sort.INT))
        return BinaryExpr("byte_at", left, right, Sort.INT)

    if expr.op == "pow":
        if not is_int(left) or not is_int(right):
            raise TypeError("pow expects integer operands")
        if isinstance(left, IntConst) and isinstance(right, IntConst):
            if right.value < 0:
                raise TypeError("pow expects a non-negative exponent")
            return IntConst(pow(left.value, right.value))
        if isinstance(right, IntConst):
            if right.value < 0:
                raise TypeError("pow expects a non-negative exponent")
            if right.value == 0:
                return IntConst(1)
            if right.value == 1:
                return left
        if isinstance(left, IntConst):
            if left.value == 0:
                return IntConst(0)
            if left.value == 1:
                return IntConst(1)
        return BinaryExpr("pow", left, right, Sort.INT)

    if expr.op in ARITHMETIC_OPS:
        if not is_int(left) or not is_int(right):
            raise TypeError(f"{expr.op} expects integer operands")
        if isinstance(left, IntConst) and isinstance(right, IntConst):
            if expr.op == "+":
                return IntConst(left.value + right.value)
            if expr.op == "-":
                return IntConst(left.value - right.value)
            if expr.op == "*":
                return IntConst(left.value * right.value)
            if expr.op == "/":
                if right.value == 0:
                    return BinaryExpr("/", left, right, Sort.INT)
                quotient, _remainder = _neo_divmod(left.value, right.value)
                return IntConst(quotient)
            if expr.op == "%":
                if right.value == 0:
                    return BinaryExpr("%", left, right, Sort.INT)
                _quotient, remainder = _neo_divmod(left.value, right.value)
                return IntConst(remainder)
            if expr.op == "&":
                return IntConst(left.value & right.value)
            if expr.op == "|":
                return IntConst(left.value | right.value)
            if expr.op == "^":
                return IntConst(left.value ^ right.value)
            if expr.op == "<<":
                return IntConst(left.value << right.value)
            if expr.op == ">>":
                return IntConst(left.value >> right.value)
        if expr.op == "+":
            if isinstance(right, IntConst) and right.value == 0:
                return left
            if isinstance(left, IntConst) and left.value == 0:
                return right
        if expr.op == "-":
            if isinstance(right, IntConst) and right.value == 0:
                return left
            if isinstance(left, IntConst) and left.value == 0:
                return UnaryExpr("neg", right, Sort.INT)
            if left == right:
                return IntConst(0)
        if expr.op == "*":
            if isinstance(right, IntConst):
                if right.value == 0:
                    return IntConst(0)
                if right.value == 1:
                    return left
            if isinstance(left, IntConst):
                if left.value == 0:
                    return IntConst(0)
                if left.value == 1:
                    return right
        if expr.op == "/" and isinstance(right, IntConst) and right.value == 1:
            return left
        if expr.op in {"&", "|", "^"} and left == right:
            if expr.op == "&" or expr.op == "|":
                return left
            return IntConst(0)
        return BinaryExpr(expr.op, left, right, Sort.INT)

    if expr.op in COMPARISON_OPS:
        if expr.op not in {"==", "!="} and (not is_int(left) or not is_int(right)):
            raise TypeError(f"{expr.op} expects integer operands")
        if left == right:
            if expr.op in {"==", "<=", ">="}:
                return BoolConst(True)
            if expr.op in {"!=", "<", ">"}:
                return BoolConst(False)
        if left.sort != right.sort and expr.op in {"==", "!="}:
            return BoolConst(expr.op == "!=")
        if isinstance(left, HeapRef) and isinstance(right, HeapRef):
            if expr.op == "==":
                return BoolConst(left.object_id == right.object_id)
            if expr.op == "!=":
                return BoolConst(left.object_id != right.object_id)
        if isinstance(left, IntConst) and isinstance(right, IntConst):
            if expr.op == "==":
                return BoolConst(left.value == right.value)
            if expr.op == "!=":
                return BoolConst(left.value != right.value)
            if expr.op == "<":
                return BoolConst(left.value < right.value)
            if expr.op == "<=":
                return BoolConst(left.value <= right.value)
            if expr.op == ">":
                return BoolConst(left.value > right.value)
            if expr.op == ">=":
                return BoolConst(left.value >= right.value)
        if isinstance(left, BoolConst) and isinstance(right, BoolConst):
            if expr.op == "==":
                return BoolConst(left.value == right.value)
            if expr.op == "!=":
                return BoolConst(left.value != right.value)
        if isinstance(left, BytesConst) and isinstance(right, BytesConst):
            if expr.op == "==":
                return BoolConst(left.value == right.value)
            if expr.op == "!=":
                return BoolConst(left.value != right.value)
        if isinstance(left, NullConst) and isinstance(right, NullConst):
            return BoolConst(expr.op == "==")
        return BinaryExpr(expr.op, left, right, Sort.BOOL)

    if expr.op == "and":
        if not is_bool(left) or not is_bool(right):
            raise TypeError("and expects boolean operands")
        if isinstance(left, BoolConst):
            return right if left.value else BoolConst(False)
        if isinstance(right, BoolConst):
            return left if right.value else BoolConst(False)
        if left == right:
            return left
        return BinaryExpr("and", left, right, Sort.BOOL)

    if expr.op == "or":
        if not is_bool(left) or not is_bool(right):
            raise TypeError("or expects boolean operands")
        if isinstance(left, BoolConst):
            return BoolConst(True) if left.value else right
        if isinstance(right, BoolConst):
            return BoolConst(True) if right.value else left
        if left == right:
            return left
        return BinaryExpr("or", left, right, Sort.BOOL)

    raise ValueError(f"Unsupported binary op: {expr.op}")


def render_expr(expr: Expression) -> str:
    expr = simplify(expr)
    if isinstance(expr, IntConst):
        return str(expr.value)
    if isinstance(expr, BoolConst):
        return "true" if expr.value else "false"
    if isinstance(expr, BytesConst):
        return f"0x{expr.value.hex()}"
    if isinstance(expr, NullConst):
        return "null"
    if isinstance(expr, HeapRef):
        return f"{expr.sort.value}#{expr.object_id}"
    if isinstance(expr, Symbol):
        return expr.name
    if isinstance(expr, UnaryExpr):
        if expr.op == "size":
            return f"size({render_expr(expr.operand)})"
        if expr.op == "to_int":
            return f"int({render_expr(expr.operand)})"
        if expr.op == "to_bytes":
            return f"bytes({render_expr(expr.operand)})"
        return f"{expr.op}({render_expr(expr.operand)})"
    if expr.op == "byte_at":
        return f"{render_expr(expr.left)}[{render_expr(expr.right)}]"
    if expr.op == "pow":
        return f"pow({render_expr(expr.left)}, {render_expr(expr.right)})"
    return f"({render_expr(expr.left)} {expr.op} {render_expr(expr.right)})"
