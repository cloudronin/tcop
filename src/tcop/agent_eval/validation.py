"""Read-only verification for agent-validation artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .plan import SOURCE_EVIDENCE_DIGEST, SOURCE_FEDERATION_DIGEST
from .runner import ARTIFACT_TYPE, _root_digest


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def verify_agent_artifact(root: Path, *, require_complete: bool = False, require_replayable: bool = False) -> dict[str, Any]:
    """Validate source binding, replay equivalence, and local-authority rules."""

    manifest, status = _read(root / "manifest.json"), _read(root / "status.json")
    source = _read(root / "source-evidence-artifact.json")
    invariant = _read(root / "reports" / "invariant-report.json")
    authorization_audit = _read(root / "reports" / "authorization-audit.json")
    gateway_probe_path = root / "reports" / "gateway-integration-probe.json"
    gateway_probe = _read(gateway_probe_path) if gateway_probe_path.is_file() else None
    negative_controls = _read(root / "reports" / "negative-controls.json").get("controls", [])
    expected_root = _read(root / "artifact-root-digest.json").get("artifact_root_digest")
    actual_root = _root_digest(root)
    rows = [_read(path) for path in sorted((root / "runs").glob("*/*.json"))]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("cohort_trace_id") or row["scenario"]), []).append(row)
    replay_ok = bool(rows) and all(
        len({str(row["action_trace_digest"]) for row in group}) == 1
        and len({str(row["local_configuration"]["policy_digest"]) for row in group}) == 1
        for group in grouped.values()
    )
    local_authority = all(
        int(row["invariants"].get("remote_enforcement_successes", -1)) == 0
        and bool(row["invariants"].get("all_blocks_reference_local_policy"))
        and bool(row["invariants"].get("all_blocks_have_domain_b_authority"))
        and not bool(row["invariants"].get("remote_tcx_action_interpreted"))
        and row["local_configuration"].get("authorization_cache") == "disabled"
        for row in rows
    )
    live = str(manifest.get("manifest_version", "")).startswith("tcop.agent-validation-live/")
    live_reports = {
        "trace-generation-summary.json", "trace-eligibility-report.json", "paired-enforcement-results.json",
        "end-to-end-live-results.json", "containment-window-agent-results.json", "benign-workload-impact.json",
        "gateway-latency.json", "federation-latency.json", "correlation-success.json", "authorization-audit.json",
        "invariant-report.json", "agent-study-claim-readiness.json",
    }
    parent_ok = True
    if live:
        parent = _read(root / "source-scripted-artifact.json")
        parent_root = Path(str(parent.get("artifact_root", "")))
        parent_ok = parent_root.is_dir() and parent.get("artifact_root_digest") == _root_digest(parent_root)
    valid = (
        manifest.get("artifact_type") == ARTIFACT_TYPE
        and manifest.get("source_evidence_digest") == SOURCE_EVIDENCE_DIGEST
        and manifest.get("source_federation_digest") == SOURCE_FEDERATION_DIGEST
        and source.get("source_evidence_digest") == SOURCE_EVIDENCE_DIGEST
        and source.get("source_federation_digest") == SOURCE_FEDERATION_DIGEST
        and bool(status.get("passed"))
        and bool(invariant.get("passed"))
        and bool(authorization_audit.get("every_gateway_block_references_domain_b_policy_and_decision"))
        and (not manifest.get("gateway_integration_verified") or bool(gateway_probe and gateway_probe.get("passed")))
        and expected_root == actual_root
        and local_authority
        and parent_ok
        and (not live or live_reports <= {path.name for path in (root / "reports").glob("*.json")})
        and {"invalid_signature", "wrong_receipt", "expired_context", "replayed_context", "local_policy_monitor_only"}
        <= {str(item.get("control")) for item in negative_controls if isinstance(item, dict) and item.get("passed")}
    )
    if require_replayable:
        valid = valid and replay_ok and bool(manifest.get("replayable"))
    if require_complete:
        valid = valid and bool(manifest.get("complete"))
    return {
        "study": status.get("study"),
        "artifact_root": str(root),
        "artifact_root_digest": actual_root,
        "source_evidence_digest": manifest.get("source_evidence_digest"),
        "source_federation_digest": manifest.get("source_federation_digest"),
        "run_count": len(rows),
        "replay_equivalence": replay_ok,
        "local_authority_invariants": local_authority,
        "scripted_parent_unchanged": parent_ok,
        "complete": bool(manifest.get("complete")),
        "valid": valid,
    }
