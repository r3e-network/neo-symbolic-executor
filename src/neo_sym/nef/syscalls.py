"""Neo N3 syscall registry metadata.

Generated from neo-project/neo commit 199b77c3ffb6cf9e1331519aee88afb8b8790ba2.
Syscall IDs use little-endian uint32 of SHA256(name) first 4 bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct


@dataclass(frozen=True, slots=True)
class SyscallInfo:
    name: str
    syscall_id: int
    fixed_price: int


def compute_syscall_id(name: str) -> int:
    digest = hashlib.sha256(name.encode("ascii")).digest()
    return struct.unpack("<I", digest[:4])[0]


KNOWN_SYSCALLS: tuple[SyscallInfo, ...] = (
    SyscallInfo(name="System.Contract.Call", syscall_id=0x525B7D62, fixed_price=32768),
    SyscallInfo(name="System.Contract.CallNative", syscall_id=0x677BF71A, fixed_price=0),
    SyscallInfo(name="System.Contract.CreateMultisigAccount", syscall_id=0x09E9336A, fixed_price=0),
    SyscallInfo(name="System.Contract.CreateStandardAccount", syscall_id=0x028799CF, fixed_price=0),
    SyscallInfo(name="System.Contract.GetCallFlags", syscall_id=0x813ADA95, fixed_price=1024),
    SyscallInfo(name="System.Contract.NativeOnPersist", syscall_id=0x93BCDB2E, fixed_price=0),
    SyscallInfo(name="System.Contract.NativePostPersist", syscall_id=0x165DA144, fixed_price=0),
    SyscallInfo(name="System.Crypto.CheckMultisig", syscall_id=0x3ADCD09E, fixed_price=0),
    SyscallInfo(name="System.Crypto.CheckSig", syscall_id=0x27B3E756, fixed_price=32768),
    SyscallInfo(name="System.Iterator.Next", syscall_id=0x9CED089C, fixed_price=32768),
    SyscallInfo(name="System.Iterator.Value", syscall_id=0x1DBF54F3, fixed_price=16),
    SyscallInfo(name="System.Runtime.BurnGas", syscall_id=0xBC8C5AC3, fixed_price=16),
    SyscallInfo(name="System.Runtime.CheckWitness", syscall_id=0x8CEC27F8, fixed_price=1024),
    SyscallInfo(name="System.Runtime.CurrentSigners", syscall_id=0x8B18F1AC, fixed_price=16),
    SyscallInfo(name="System.Runtime.GasLeft", syscall_id=0xCED88814, fixed_price=16),
    SyscallInfo(name="System.Runtime.GetAddressVersion", syscall_id=0xDC92494C, fixed_price=8),
    SyscallInfo(name="System.Runtime.GetCallingScriptHash", syscall_id=0x3C6E5339, fixed_price=16),
    SyscallInfo(name="System.Runtime.GetEntryScriptHash", syscall_id=0x38E2B4F9, fixed_price=16),
    SyscallInfo(name="System.Runtime.GetExecutingScriptHash", syscall_id=0x74A8FEDB, fixed_price=16),
    SyscallInfo(name="System.Runtime.GetInvocationCounter", syscall_id=0x43112784, fixed_price=16),
    SyscallInfo(name="System.Runtime.GetNetwork", syscall_id=0xE0A0FBC5, fixed_price=8),
    SyscallInfo(name="System.Runtime.GetNotifications", syscall_id=0xF1354327, fixed_price=4096),
    SyscallInfo(name="System.Runtime.GetRandom", syscall_id=0x28A9DE6B, fixed_price=0),
    SyscallInfo(name="System.Runtime.GetScriptContainer", syscall_id=0x3008512D, fixed_price=8),
    SyscallInfo(name="System.Runtime.GetTime", syscall_id=0x0388C3B7, fixed_price=8),
    SyscallInfo(name="System.Runtime.GetTrigger", syscall_id=0xA0387DE9, fixed_price=8),
    SyscallInfo(name="System.Runtime.LoadScript", syscall_id=0x8F800CB3, fixed_price=32768),
    SyscallInfo(name="System.Runtime.Log", syscall_id=0x9647E7CF, fixed_price=32768),
    SyscallInfo(name="System.Runtime.Notify", syscall_id=0x616F0195, fixed_price=32768),
    SyscallInfo(name="System.Runtime.Platform", syscall_id=0xF6FC79B2, fixed_price=8),
    SyscallInfo(name="System.Storage.AsReadOnly", syscall_id=0xE9BF4C76, fixed_price=16),
    SyscallInfo(name="System.Storage.Delete", syscall_id=0xEDC5582F, fixed_price=32768),
    SyscallInfo(name="System.Storage.Find", syscall_id=0x9AB830DF, fixed_price=32768),
    SyscallInfo(name="System.Storage.Get", syscall_id=0x31E85D92, fixed_price=32768),
    SyscallInfo(name="System.Storage.GetContext", syscall_id=0xCE67F69B, fixed_price=16),
    SyscallInfo(name="System.Storage.GetReadOnlyContext", syscall_id=0xE26BB4F6, fixed_price=16),
    SyscallInfo(name="System.Storage.Local.Delete", syscall_id=0x94F55475, fixed_price=32768),
    SyscallInfo(name="System.Storage.Local.Find", syscall_id=0xF3527607, fixed_price=32768),
    SyscallInfo(name="System.Storage.Local.Get", syscall_id=0xE85E8DD5, fixed_price=32768),
    SyscallInfo(name="System.Storage.Local.Put", syscall_id=0x0AE30C39, fixed_price=32768),
    SyscallInfo(name="System.Storage.Put", syscall_id=0x84183FE6, fixed_price=32768),
)


SYSCALLS_BY_ID: dict[int, SyscallInfo] = {entry.syscall_id: entry for entry in KNOWN_SYSCALLS}
SYSCALLS_BY_NAME: dict[str, SyscallInfo] = {entry.name: entry for entry in KNOWN_SYSCALLS}
