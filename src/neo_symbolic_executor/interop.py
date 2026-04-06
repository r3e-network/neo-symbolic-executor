from __future__ import annotations

import hashlib
from dataclasses import dataclass

TRIGGER_ON_PERSIST = 0x01
TRIGGER_POST_PERSIST = 0x02
TRIGGER_VERIFICATION = 0x20
TRIGGER_APPLICATION = 0x40
TRIGGER_SYSTEM = TRIGGER_ON_PERSIST | TRIGGER_POST_PERSIST
TRIGGER_ALL = TRIGGER_SYSTEM | TRIGGER_VERIFICATION | TRIGGER_APPLICATION

TRIGGER_NAME_TO_VALUE = {
    "onpersist": TRIGGER_ON_PERSIST,
    "postpersist": TRIGGER_POST_PERSIST,
    "verification": TRIGGER_VERIFICATION,
    "application": TRIGGER_APPLICATION,
    "system": TRIGGER_SYSTEM,
    "all": TRIGGER_ALL,
}

CALL_FLAGS_NONE = 0x00
CALL_FLAGS_READ_STATES = 0x01
CALL_FLAGS_WRITE_STATES = 0x02
CALL_FLAGS_ALLOW_CALL = 0x04
CALL_FLAGS_ALLOW_NOTIFY = 0x08
CALL_FLAGS_STATES = CALL_FLAGS_READ_STATES | CALL_FLAGS_WRITE_STATES
CALL_FLAGS_READ_ONLY = CALL_FLAGS_READ_STATES | CALL_FLAGS_ALLOW_CALL
CALL_FLAGS_ALL = CALL_FLAGS_STATES | CALL_FLAGS_ALLOW_CALL | CALL_FLAGS_ALLOW_NOTIFY

CALL_FLAG_NAME_TO_VALUE = {
    "none": CALL_FLAGS_NONE,
    "readstates": CALL_FLAGS_READ_STATES,
    "writestates": CALL_FLAGS_WRITE_STATES,
    "allowcall": CALL_FLAGS_ALLOW_CALL,
    "allownotify": CALL_FLAGS_ALLOW_NOTIFY,
    "states": CALL_FLAGS_STATES,
    "readonly": CALL_FLAGS_READ_ONLY,
    "all": CALL_FLAGS_ALL,
}

DEFAULT_NETWORK_MAGIC = 860_833_102
DEFAULT_ADDRESS_VERSION = 53


@dataclass(frozen=True)
class InteropDescriptorInfo:
    name: str
    required_call_flags: int = CALL_FLAGS_NONE


def interop_hash(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode("ascii")).digest()[:4], "little")


def _descriptor(name: str, required_call_flags: int = CALL_FLAGS_NONE) -> tuple[int, InteropDescriptorInfo]:
    return interop_hash(name), InteropDescriptorInfo(name=name, required_call_flags=required_call_flags)


INTEROP_BY_ID = dict(
    [
        _descriptor("System.Runtime.Platform"),
        _descriptor("System.Runtime.GetNetwork"),
        _descriptor("System.Runtime.GetAddressVersion"),
        _descriptor("System.Runtime.GetTrigger"),
        _descriptor("System.Runtime.GetTime"),
        _descriptor("System.Runtime.GetScriptContainer"),
        _descriptor("System.Runtime.GetExecutingScriptHash"),
        _descriptor("System.Runtime.GetCallingScriptHash"),
        _descriptor("System.Runtime.GetEntryScriptHash"),
        _descriptor("System.Runtime.LoadScript", CALL_FLAGS_ALLOW_CALL),
        _descriptor("System.Runtime.CheckWitness"),
        _descriptor("System.Runtime.GetInvocationCounter"),
        _descriptor("System.Runtime.GetRandom"),
        _descriptor("System.Runtime.Log", CALL_FLAGS_ALLOW_NOTIFY),
        _descriptor("System.Runtime.Notify", CALL_FLAGS_ALLOW_NOTIFY),
        _descriptor("System.Runtime.GetNotifications"),
        _descriptor("System.Runtime.GasLeft"),
        _descriptor("System.Runtime.BurnGas"),
        _descriptor("System.Runtime.CurrentSigners"),
        _descriptor("System.Contract.Call", CALL_FLAGS_READ_ONLY),
        _descriptor("System.Contract.CallNative"),
        _descriptor("System.Contract.GetCallFlags"),
        _descriptor("System.Contract.CreateStandardAccount"),
        _descriptor("System.Contract.CreateMultisigAccount"),
        _descriptor("System.Contract.NativeOnPersist", CALL_FLAGS_STATES),
        _descriptor("System.Contract.NativePostPersist", CALL_FLAGS_STATES),
        _descriptor("System.Storage.GetContext", CALL_FLAGS_READ_STATES),
        _descriptor("System.Storage.GetReadOnlyContext", CALL_FLAGS_READ_STATES),
        _descriptor("System.Storage.AsReadOnly", CALL_FLAGS_READ_STATES),
        _descriptor("System.Storage.Get", CALL_FLAGS_READ_STATES),
        _descriptor("System.Storage.Find", CALL_FLAGS_READ_STATES),
        _descriptor("System.Storage.Put", CALL_FLAGS_WRITE_STATES),
        _descriptor("System.Storage.Delete", CALL_FLAGS_WRITE_STATES),
        _descriptor("System.Iterator.Next"),
        _descriptor("System.Iterator.Value"),
        _descriptor("System.Crypto.CheckSig"),
        _descriptor("System.Crypto.CheckMultisig"),
    ]
)
