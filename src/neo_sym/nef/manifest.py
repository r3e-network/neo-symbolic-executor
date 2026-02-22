"""Manifest parsing utilities."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class MethodParameter:
    name: str
    type: str = "Any"


@dataclass(slots=True)
class ContractMethod:
    name: str
    offset: int = 0
    parameters: list[MethodParameter] = field(default_factory=list)
    return_type: str | None = None
    safe: bool = False


@dataclass(slots=True)
class ContractEvent:
    name: str
    parameters: list[MethodParameter] = field(default_factory=list)


@dataclass(slots=True)
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
        for method in self.abi_methods:
            if method.name == method_name:
                return method
        return None


def _parse_parameters(items: list[dict[str, Any]]) -> list[MethodParameter]:
    parameters: list[MethodParameter] = []
    for item in items:
        parameters.append(MethodParameter(name=str(item.get("name", "")), type=str(item.get("type", "Any"))))
    return parameters


def parse_manifest(raw_json: str) -> Manifest:
    """Parse a contract manifest JSON string into typed structures."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid manifest JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Manifest root must be an object")

    raw_name = payload.get("name")
    manifest = Manifest(
        name=str(raw_name) if isinstance(raw_name, str) else "unknown",
        supported_standards=[str(s) for s in payload.get("supportedstandards", [])]
        if isinstance(payload.get("supportedstandards", []), list)
        else [],
        trusts=[str(t) for t in payload.get("trusts", [])]
        if isinstance(payload.get("trusts", []), list)
        else [],
        groups=list(payload.get("groups", [])),
        extra=dict(payload.get("extra", {})) if isinstance(payload.get("extra", {}), dict) else {},
    )

    abi = payload.get("abi", {})
    if isinstance(abi, dict):
        for method in abi.get("methods", []):
            if not isinstance(method, dict):
                continue
            manifest.abi_methods.append(
                ContractMethod(
                    name=str(method.get("name", "")),
                    offset=int(method.get("offset", 0)) if isinstance(method.get("offset", 0), (int, float)) else 0,
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
