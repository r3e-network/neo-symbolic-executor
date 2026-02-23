"""Manifest parsing utilities."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ContractEvent", "ContractMethod", "ContractPermission", "Manifest", "MethodParameter", "parse_manifest"]


@dataclass(slots=True, frozen=True)
class MethodParameter:
    name: str
    type: str = "Any"


@dataclass(slots=True, frozen=True)
class ContractMethod:
    name: str
    offset: int = 0
    parameters: list[MethodParameter] = field(default_factory=list)
    return_type: str | None = None
    safe: bool = False


@dataclass(slots=True, frozen=True)
class ContractEvent:
    name: str
    parameters: list[MethodParameter] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class ContractPermission:
    contract: str = "*"
    methods: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Manifest:
    name: str = "unknown"
    supported_standards: list[str] = field(default_factory=list)
    abi_methods: list[ContractMethod] = field(default_factory=list)
    abi_events: list[ContractEvent] = field(default_factory=list)
    permissions: list[ContractPermission] = field(default_factory=list)
    trusts: list[str] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def method_by_name(self, method_name: str) -> ContractMethod | None:
        """Look up an ABI method by name, returning *None* if not found."""
        for method in self.abi_methods:
            if method.name == method_name:
                return method
        return None


def _parse_parameters(items: list[dict[str, Any]]) -> list[MethodParameter]:
    return [MethodParameter(name=str(item.get("name", "")), type=str(item.get("type", "Any"))) for item in items]


def parse_manifest(raw_json: str) -> Manifest:
    """Parse a contract manifest JSON string into typed structures."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid manifest JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Manifest root must be an object")

    raw_name = payload.get("name")
    raw_standards = payload.get("supportedstandards", [])
    raw_trusts = payload.get("trusts", [])
    raw_extra = payload.get("extra", {})
    manifest = Manifest(
        name=str(raw_name) if isinstance(raw_name, str) else "unknown",
        supported_standards=[str(s) for s in raw_standards] if isinstance(raw_standards, list) else [],
        trusts=[str(t) for t in raw_trusts] if isinstance(raw_trusts, list) else [],
        groups=list(payload.get("groups", [])),
        extra=raw_extra if isinstance(raw_extra, dict) else {},
    )

    abi = payload.get("abi", {})
    if isinstance(abi, dict):
        for method in abi.get("methods", []):
            if not isinstance(method, dict):
                continue
            raw_offset = method.get("offset", 0)
            manifest.abi_methods.append(
                ContractMethod(
                    name=str(method.get("name", "")),
                    offset=int(raw_offset) if isinstance(raw_offset, (int, float)) else 0,
                    parameters=_parse_parameters(list(method.get("parameters", []))),
                    return_type=str(method["returntype"]) if "returntype" in method else None,
                    safe=bool(method.get("safe", False)),
                )
            )
        for event in abi.get("events", []):
            if not isinstance(event, dict):
                continue
            manifest.abi_events.append(
                ContractEvent(
                    name=str(event.get("name", "")),
                    parameters=_parse_parameters(list(event.get("parameters", []))),
                )
            )

    permissions = payload.get("permissions", [])
    if isinstance(permissions, list):
        for perm in permissions:
            if not isinstance(perm, dict):
                continue
            methods = perm.get("methods", [])
            if methods == "*":
                parsed_methods = ["*"]
            elif isinstance(methods, list):
                parsed_methods = [str(m) for m in methods]
            else:
                parsed_methods = [str(methods)]
            manifest.permissions.append(
                ContractPermission(contract=str(perm.get("contract", "*")), methods=parsed_methods)
            )

    return manifest
