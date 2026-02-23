"""NEF and manifest parsing package."""

from __future__ import annotations

from .manifest import (
    ContractEvent,
    ContractMethod,
    ContractPermission,
    Manifest,
    MethodParameter,
    parse_manifest,
)
from .opcodes import OpCode
from .parser import Instruction, MethodToken, NefFile, compute_nef_checksum, disassemble, parse_nef
from .syscalls import KNOWN_SYSCALLS, SYSCALLS_BY_ID, SYSCALLS_BY_NAME, SyscallInfo, compute_syscall_id

__all__ = [
    "KNOWN_SYSCALLS",
    "SYSCALLS_BY_ID",
    "SYSCALLS_BY_NAME",
    "ContractEvent",
    "ContractMethod",
    "ContractPermission",
    "Instruction",
    "Manifest",
    "MethodParameter",
    "MethodToken",
    "NefFile",
    "OpCode",
    "SyscallInfo",
    "compute_nef_checksum",
    "compute_syscall_id",
    "disassemble",
    "parse_manifest",
    "parse_nef",
]
