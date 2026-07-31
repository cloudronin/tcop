"""Dependency-free structural check for the published v0.1 JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path


def validate_published_schema() -> None:
    root = Path(__file__).resolve().parents[2]
    location = root / "schemas" / "observation-v0.1.json"
    document = json.loads(location.read_text(encoding="utf-8"))
    if document.get("type") != "object":
        raise ValueError("observation schema root must be an object")
    required = set(document.get("required", []))
    expected = {"protocol_version", "observer", "subject", "signature", "expires_at", "tenant"}
    if not expected <= required:
        raise ValueError("observation schema omits v0.1 mandatory fields")
    if document.get("properties", {}).get("protocol_version", {}).get("const") != "0.1":
        raise ValueError("observation schema does not declare protocol version 0.1")


def main() -> None:
    validate_published_schema()
    print("TCX v0.1 schema: valid")


if __name__ == "__main__":
    main()
