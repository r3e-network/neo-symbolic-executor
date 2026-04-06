from __future__ import annotations

import json
from pathlib import Path

from .assembly import parse_program, parse_script_items
from .bytecode import DecodeError, decode_hex_string, decode_script
from .model import Program
from .nef import parse_nef


def load_program_file(path: str, source_type: str = "auto") -> Program:
    file_path = Path(path)
    data = file_path.read_bytes()
    detected = _detect_source_type(file_path, data, source_type)

    if detected == "assembly":
        return _with_metadata(
            parse_program(data.decode("utf-8")),
            source_path=str(file_path),
            source_type="assembly",
        )
    if detected == "hex":
        return decode_hex_string(data.decode("utf-8"), metadata={"source_path": str(file_path), "source_type": "hex"})
    if detected == "binary":
        return decode_script(data, metadata={"source_path": str(file_path), "source_type": "binary"})
    if detected == "nef":
        nef = parse_nef(data)
        return decode_script(
            nef.script,
            metadata={
                "source_path": str(file_path),
                "source_type": "nef",
                "compiler": nef.compiler,
                "nef_source": nef.source,
                "method_tokens": [token.to_dict() for token in nef.method_tokens],
            },
        )
    if detected == "json":
        payload = json.loads(data.decode("utf-8"))
        if isinstance(payload, list) and all(isinstance(item, str) for item in payload):
            return _with_metadata(
                parse_script_items(payload),
                source_path=str(file_path),
                source_type="json",
            )
        if isinstance(payload, dict) and isinstance(payload.get("script"), list):
            return _with_metadata(
                parse_script_items(payload["script"]),
                source_path=str(file_path),
                source_type="json",
            )
        raise DecodeError("JSON input must be a script item array or an object with a 'script' array")
    raise DecodeError(f"Unsupported source type '{detected}'")


def _detect_source_type(path: Path, data: bytes, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower()
    if suffix == ".nef":
        return "nef"
    if suffix in {".neoasm", ".asm"}:
        return "assembly"
    if suffix == ".hex":
        return "hex"
    if suffix == ".json":
        return "json"
    if suffix == ".bin":
        return "binary"
    if data.startswith(b"NEF3"):
        return "nef"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    stripped = text.strip()
    if not stripped:
        return "assembly"
    if stripped.startswith("[") or stripped.startswith("{"):
        return "json"
    if _looks_like_hex_script(stripped):
        return "hex"
    return "assembly"


def _looks_like_hex_script(text: str) -> bool:
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    return bool(compact) and len(compact) % 2 == 0 and all(char in "0123456789abcdefABCDEF" for char in compact)


def _with_metadata(program: Program, **entries: object) -> Program:
    metadata = dict(program.metadata)
    metadata.update(entries)
    return Program(
        instructions=program.instructions,
        script=program.script,
        labels=program.labels,
        metadata=metadata,
    )
