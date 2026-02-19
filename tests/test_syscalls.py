"""Tests for syscall registry and hashing."""
from __future__ import annotations

from neo_sym.nef.syscalls import SYSCALLS_BY_NAME, compute_syscall_id


def test_compute_syscall_id_matches_known_values():
    assert compute_syscall_id("System.Runtime.CheckWitness") == 0x8CEC27F8
    assert compute_syscall_id("System.Runtime.GetTime") == 0x0388C3B7
    assert compute_syscall_id("System.Storage.Get") == 0x31E85D92
    assert compute_syscall_id("System.Storage.Put") == 0x84183FE6
    assert compute_syscall_id("System.Contract.Call") == 0x525B7D62


def test_registry_contains_core_neo_n3_syscalls():
    for syscall_name in (
        "System.Runtime.CheckWitness",
        "System.Runtime.GetRandom",
        "System.Storage.Get",
        "System.Storage.Put",
        "System.Contract.Call",
    ):
        assert syscall_name in SYSCALLS_BY_NAME
