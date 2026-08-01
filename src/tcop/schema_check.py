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


def validate_reliability_schemas() -> None:
    """Check the v0.3 local-profile contracts without changing v0.1/v0.2."""

    root = Path(__file__).resolve().parents[2] / "schemas"
    expected = {
        "observer-reliability-v0.1.schema.json": "record_version",
        "reliability-input-event-v0.1.schema.json": "event_version",
        "reliability-transition-v0.1.schema.json": "transition_version",
        "compromise-window-v0.1.schema.json": "window_version",
        "weighted-resolution-v0.1.schema.json": "resolution_version",
        "observer-accusation-edge-v0.1.schema.json": "edge_version",
    }
    for filename, version_key in expected.items():
        document = json.loads((root / filename).read_text(encoding="utf-8"))
        if document.get("type") != "object" or version_key not in document.get("required", []):
            raise ValueError(f"invalid reliability schema: {filename}")


def validate_confirmation_schemas() -> None:
    root = Path(__file__).resolve().parents[2] / "schemas"
    expected = {
        "investigative-tip-v0.1.schema.json": "tip_version",
        "investigative-action-v0.1.schema.json": "action_version",
        "provisional-response-v0.1.schema.json": "response_version",
        "confirmation-requirement-v0.1.schema.json": "requirement_version",
        "confirmation-event-v0.1.schema.json": "confirmation_version",
        "evidence-campaign-v0.1.schema.json": "campaign_version",
        "response-severity-v0.1.schema.json": "response_version",
    }
    for filename, version_key in expected.items():
        document = json.loads((root / filename).read_text(encoding="utf-8"))
        if document.get("type") != "object" or version_key not in document.get("required", []):
            raise ValueError(f"invalid confirmation schema: {filename}")


def validate_minimality_schemas() -> None:
    root = Path(__file__).resolve().parents[2] / "schemas"
    expected = {
        "feature-manifest-v0.1.schema.json": "manifest_version",
        "composed-profile-v0.1.schema.json": "profile_version",
        "ablation-manifest-v0.1.schema.json": "ablation_version",
        "complexity-record-v0.1.schema.json": "complexity_version",
        "feature-contribution-v0.1.schema.json": "contribution_version",
        "pareto-record-v0.1.schema.json": "pareto_version",
        "deployment-profile-v0.1.schema.json": "deployment_profile_version",
        "profile-disposition-v0.1.schema.json": "disposition_version",
        "minimality-validation-frozen-profile-v0.1.schema.json": "frozen_profile_version",
    }
    for filename, version_key in expected.items():
        document = json.loads((root / filename).read_text(encoding="utf-8"))
        if document.get("type") != "object" or version_key not in document.get("required", []):
            raise ValueError(f"invalid minimality schema: {filename}")


def validate_federation_schema() -> None:
    """Validate the isolated v0.6 matrix contract without altering prior schemas."""

    root = Path(__file__).resolve().parents[2] / "schemas"
    document = json.loads((root / "federated-v0.6-matrix.schema.json").read_text(encoding="utf-8"))
    required = set(document.get("required", []))
    expected = {"cell_id", "topology_id", "scenario_id", "observer_id", "network_id", "architecture_id", "strategy_id", "seed", "classification"}
    if document.get("type") != "object" or not expected <= required or document.get("additionalProperties") is not False:
        raise ValueError("invalid federated v0.6 matrix schema")


def validate_agent_validation_schemas() -> None:
    """Validate study-only external-validation schemas separately from TCX."""

    root = Path(__file__).resolve().parents[2] / "schemas"
    expected = {
        "agent-trace-v0.1.schema.json": "canonical_action_digest",
        "agent-authorization-decision-v0.1.schema.json": "authority_domain",
        "agent-validation-artifact-v0.1.schema.json": "artifact_type",
    }
    for filename, field in expected.items():
        document = json.loads((root / filename).read_text(encoding="utf-8"))
        if document.get("type") != "object" or field not in document.get("required", []):
            raise ValueError(f"invalid agent-validation schema: {filename}")


def main() -> None:
    validate_published_schema()
    validate_witness_schemas()
    validate_reliability_schemas()
    validate_confirmation_schemas()
    validate_minimality_schemas()
    validate_federation_schema()
    validate_agent_validation_schemas()
    print("TCX v0.1 through v0.6 and agent-validation schemas: valid")


if __name__ == "__main__":
    main()
