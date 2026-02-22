"""Tests for manifest parsing and validation."""
from __future__ import annotations

import json

import pytest
from neo_sym.nef.manifest import parse_manifest


def test_parse_manifest_with_abi_details():
    manifest_json = json.dumps(
        {
            "name": "SampleToken",
            "supportedstandards": ["NEP-17"],
            "abi": {
                "methods": [
                    {
                        "name": "transfer",
                        "offset": 32,
                        "parameters": [
                            {"name": "from", "type": "Hash160"},
                            {"name": "to", "type": "Hash160"},
                            {"name": "amount", "type": "Integer"},
                            {"name": "data", "type": "Any"},
                        ],
                        "safe": False,
                    }
                ],
                "events": [{"name": "Transfer", "parameters": []}],
            },
            "permissions": [{"contract": "*", "methods": ["onNEP17Payment"]}],
            "trusts": ["0x1234"],
        }
    )

    manifest = parse_manifest(manifest_json)
    assert manifest.name == "SampleToken"
    assert manifest.supported_standards == ["NEP-17"]
    assert len(manifest.abi_methods) == 1
    assert manifest.abi_methods[0].name == "transfer"
    assert len(manifest.abi_methods[0].parameters) == 4
    assert len(manifest.abi_events) == 1
    assert manifest.permissions[0].contract == "*"
    assert manifest.permissions[0].methods == ["onNEP17Payment"]


def test_parse_manifest_invalid_json():
    with pytest.raises(ValueError):
        parse_manifest("{invalid-json}")


def test_parse_manifest_null_name():
    m = parse_manifest(json.dumps({"name": None}))
    assert m.name == "unknown"


def test_parse_manifest_non_list_standards():
    m = parse_manifest(json.dumps({"supportedstandards": "NEP-17"}))
    assert m.supported_standards == []


def test_parse_manifest_non_integer_offset():
    m = parse_manifest(json.dumps({
        "abi": {"methods": [{"name": "foo", "offset": "bad"}]},
    }))
    assert m.abi_methods[0].offset == 0
