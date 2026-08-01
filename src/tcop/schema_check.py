"""Dependency-free structural checks for versioned published TCX schemas."""

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


def validate_witness_schemas() -> None:
    root = Path(__file__).resolve().parents[2] / "schemas"
    observation = json.loads((root / "tcx-observation-v0.2.schema.json").read_text(encoding="utf-8"))
    if observation.get("properties", {}).get("protocol_version", {}).get("const") != "0.2":
        raise ValueError("witness observation schema does not declare protocol version 0.2")
    required = set(observation.get("required", []))
    expected = {"declared_evidence_class", "observer_control_group_id", "subject_control_group_id", "interaction_receipt_hash", "relay_chain"}
    if not expected <= required:
        raise ValueError("witness observation schema omits classification or provenance fields")
    for filename in ("interaction-receipt-v0.1.json", "patrol-authorization-v0.1.json", "witness-edge-v0.1.json"):
        document = json.loads((root / filename).read_text(encoding="utf-8"))
        if document.get("type") != "object" or not document.get("required"):
            raise ValueError(f"invalid witness schema: {filename}")


def main() -> None:
    validate_published_schema()
    validate_witness_schemas()
    print("TCX v0.1 and v0.2 schemas: valid")


if __name__ == "__main__":
    main()
