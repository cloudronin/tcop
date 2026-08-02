"""Deterministic native-STIX fixtures and auditable concept mapping.

The fixture validator is deliberately labelled structural.  It cannot satisfy
the future experiment's pinned external schema-validator gate, but it prevents
native-baseline TCOP extensions or custom properties from entering fixtures.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable, Mapping


MATRIX_ROWS = (
    "Authenticated source provenance", "Receiver-issued correlation handle", "Exact local subject binding",
    "Exact local resource binding", "Capability and scope binding", "Freshness and expiry check",
    "Replay handling", "Receiver-local action-time decision", "Remote enforcement prevented", "End-to-end transport behavior",
)
CONDITIONS = ("S1", "T2", "S2")
_STATUS = frozenset({"standard", "local-composition", "TCOP-profile", "absent", "not-applicable"})
_IDS = {
    "identity": "identity--11111111-1111-4111-8111-111111111111",
    "indicator": "indicator--22222222-2222-4222-8222-222222222222",
    "observed": "observed-data--33333333-3333-4333-8333-333333333333",
    "sighting": "sighting--44444444-4444-4444-8444-444444444444",
    "relationship": "relationship--55555555-5555-4555-8555-555555555555",
}


def native_objects() -> list[dict[str, Any]]:
    """Return a minimal standards-native S1 bundle without custom properties."""

    common = {"spec_version": "2.1", "created": "2026-08-01T00:00:00Z", "modified": "2026-08-01T00:00:00Z"}
    return [
        {"type": "identity", "id": _IDS["identity"], "name": "Domain A Detector", "identity_class": "system", **common},
        {"type": "indicator", "id": _IDS["indicator"], "name": "Suspicious prompt-injection artifact", "pattern": "[artifact:payload = 'prompt-injection']", "pattern_type": "stix", "valid_from": "2026-08-01T00:00:00Z", "confidence": 80, "created_by_ref": _IDS["identity"], **common},
        {"type": "observed-data", "id": _IDS["observed"], "first_observed": "2026-08-01T00:00:00Z", "last_observed": "2026-08-01T00:00:00Z", "number_observed": 1, "created_by_ref": _IDS["identity"], **common},
        {"type": "sighting", "id": _IDS["sighting"], "sighting_of_ref": _IDS["indicator"], "first_seen": "2026-08-01T00:00:00Z", "last_seen": "2026-08-01T00:00:00Z", "count": 1, "created_by_ref": _IDS["identity"], **common},
        {"type": "relationship", "id": _IDS["relationship"], "relationship_type": "based-on", "source_ref": _IDS["indicator"], "target_ref": _IDS["observed"], **common},
    ]


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield child, item
            yield from _walk(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


def audit_no_custom_properties(objects: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    findings = []
    for index, obj in enumerate(objects):
        for path, _value in _walk(obj):
            key = path.rsplit(".", 1)[-1]
            if key.startswith("x_") or key in {"extensions", "tcop_context", "receipt_ref", "action_binding", "remote_enforcement"}:
                findings.append({"object_index": index, "path": path, "reason": "custom_or_tcop_semantic_property"})
    return {"passed": not findings, "findings": findings, "audit": "native_baseline_custom_property_audit/v1"}


def structural_validate_native_objects(objects: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate required STIX 2.1 fixture shape, without claiming full schema validation."""

    required = {
        "identity": {"id", "type", "spec_version", "name", "identity_class", "created", "modified"},
        "indicator": {"id", "type", "spec_version", "name", "pattern", "pattern_type", "valid_from", "created", "modified"},
        "observed-data": {"id", "type", "spec_version", "first_observed", "last_observed", "number_observed", "created", "modified"},
        "sighting": {"id", "type", "spec_version", "sighting_of_ref", "first_seen", "last_seen", "count", "created", "modified"},
        "relationship": {"id", "type", "spec_version", "relationship_type", "source_ref", "target_ref", "created", "modified"},
    }
    failures = []
    copied = [deepcopy(dict(item)) for item in objects]
    for index, obj in enumerate(copied):
        kind = obj.get("type")
        if kind not in required or obj.get("spec_version") != "2.1" or not required.get(kind, set()).issubset(obj):
            failures.append({"object_index": index, "type": kind, "reason": "required_stix_2_1_fixture_fields_missing"})
    custom = audit_no_custom_properties(copied)
    return {"passed": not failures and custom["passed"], "validator": "tcop_structural_stix_2_1_fixture_validator", "external_pinned_schema_validator": "not_admitted", "failures": failures, "custom_property_audit": custom}


def semantic_capability_matrix() -> list[dict[str, str]]:
    entries = {
        "Authenticated source provenance": (("local-composition", "TAXII TLS/client authentication and B trust store"), ("TCOP-profile", "signed TCX issuer validation"), ("TCOP-profile", "signed TCX extension after TAXII delivery")),
        "Receiver-issued correlation handle": (("local-composition", "B-private state only; absent from exchanged STIX fields"), ("TCOP-profile", "receipt_ref and B-private binding"), ("TCOP-profile", "TCX extension receipt_ref and B-private binding")),
        "Exact local subject binding": (("absent", "no native STIX field carries B-local subject"), ("TCOP-profile", "accepted TCX subject compared at B"), ("TCOP-profile", "decoded TCX subject compared at B")),
        "Exact local resource binding": (("absent", "no native STIX field carries B-local resource namespace"), ("TCOP-profile", "accepted TCX resource namespace"), ("TCOP-profile", "decoded TCX resource namespace")),
        "Capability and scope binding": (("absent", "native warning is not B action-bound"), ("TCOP-profile", "accepted TCX capability and scope"), ("TCOP-profile", "decoded TCX capability and scope")),
        "Freshness and expiry check": (("standard", "valid_from, first_seen, last_seen, TAXII retrieval time"), ("TCOP-profile", "TCX issued/expires validation"), ("TCOP-profile", "TCX issued/expires validation")),
        "Replay handling": (("local-composition", "B-local TAXII object/delivery deduplication"), ("TCOP-profile", "receipt and observation replay state"), ("TCOP-profile", "receipt and observation replay state")),
        "Receiver-local action-time decision": (("local-composition", "B-local OPA decision"), ("local-composition", "B-local OPA decision after TCX acceptance"), ("local-composition", "B-local OPA decision after TCX acceptance")),
        "Remote enforcement prevented": (("local-composition", "OPA contract excludes remote enforcement"), ("local-composition", "OPA contract excludes remote enforcement"), ("local-composition", "OPA contract excludes remote enforcement")),
        "End-to-end transport behavior": (("standard", "TAXII 2.1 collection request/response"), ("TCOP-profile", "direct TCX transport"), ("standard", "TAXII 2.1 carrying declared TCX extension")),
    }
    result = []
    for capability in MATRIX_ROWS:
        row: dict[str, str] = {"Capability": capability}
        for condition, (status, evidence) in zip(CONDITIONS, entries[capability], strict=True):
            if status not in _STATUS:
                raise AssertionError("invalid capability status")
            row[condition] = status
            row[condition + "_evidence"] = evidence
        result.append(row)
    return result
