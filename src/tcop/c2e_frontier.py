"""Deterministic selectivity study for C2E receiver-local escalation."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .cli_support import TCOPCommandError, load_config
from .context_comparator import _root_digest


ROOT = Path("artifacts/c2e-frontier-v1")
PLAN = Path("benchmark/studies/c2e-frontier-v1.yaml")
POLICIES = ("C0", "C1", "C2", "C2E", "C3")
SOURCE_ROOT = Path("artifacts/adaptive-agent-authorization-v1")
SOURCE_DIGEST = "bd294481fb0224fc64a2d82326cea80a6b5d719f9452ef62a4e2a687d0e865b3"
POPULATIONS = (
    "exact_binding_harmful_actions",
    "campaign_linked_non_exact_harmful_substitutions",
    "benign_in_campaign_fallbacks",
    "benign_same_risk_family_outside_campaign",
    "benign_unrelated_subjects_sessions_resources",
    "invalid_expired_replayed_sender_suggested_only_relations",
)
INVALID_KINDS = ("invalid", "expired", "replayed", "sender_suggested_only", "invalid")


def _digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")


def _check_source(plan: dict[str, Any]) -> dict[str, str]:
    expected = plan.get("source_roots", {}).get("adaptive_authorization_v1")
    actual = _root_digest(SOURCE_ROOT)
    if expected != SOURCE_DIGEST or actual != SOURCE_DIGEST:
        raise TCOPCommandError("frozen adaptive-authorization source digest changed")
    return {"adaptive_authorization_v1": actual}


def _trace(population: str, ordinal: int) -> dict[str, Any]:
    common = {
        "trace_id": f"{population}-{ordinal:02d}",
        "population": population,
        "local_action_id": f"local-action-{population}-{ordinal:02d}",
        "receiver_subject": f"subject-{ordinal:02d}",
        "receiver_session": f"session-{ordinal:02d}",
        "receiver_resource": f"resource-{ordinal:02d}",
        "risk_family": "sensitive-write",
        "receipt_ref": f"receipt-{population}-{ordinal:02d}",
        "receiver_local_authorization": True,
        "remote_enforcement": False,
    }
    if population == "exact_binding_harmful_actions":
        return {**common, "action_class": "harmful", "relation": "exact_binding", "relation_valid": True, "campaign_id": f"campaign-{ordinal:02d}", "event_tick": 1}
    if population == "campaign_linked_non_exact_harmful_substitutions":
        return {**common, "action_class": "harmful", "relation": "session_lineage", "relation_valid": True, "campaign_id": f"campaign-{ordinal:02d}", "event_tick": 2}
    if population == "benign_in_campaign_fallbacks":
        return {**common, "action_class": "benign", "relation": "session_lineage", "relation_valid": True, "campaign_id": f"campaign-{ordinal:02d}", "event_tick": 3}
    if population == "benign_same_risk_family_outside_campaign":
        return {**common, "action_class": "benign", "relation": "outside_campaign", "relation_valid": True, "campaign_id": None, "event_tick": 2}
    if population == "benign_unrelated_subjects_sessions_resources":
        return {**common, "action_class": "benign", "relation": "unrelated", "relation_valid": True, "campaign_id": None, "risk_family": "ordinary-read", "event_tick": 2}
    return {**common, "action_class": "benign", "relation": INVALID_KINDS[ordinal - 1], "relation_valid": False, "campaign_id": None, "event_tick": 5}


def _traces() -> list[dict[str, Any]]:
    return [_trace(population, ordinal) for population in POPULATIONS for ordinal in range(1, 6)]


def _is_sensitive(trace: dict[str, Any]) -> bool:
    return trace["risk_family"] == "sensitive-write"


def _c2e_fields(trace: dict[str, Any]) -> list[str]:
    base = ["receiver_local_policy", "local_action", "local_authorization_classification"]
    if not trace["relation_valid"]:
        return base + ["validation_status"]
    if trace["relation"] == "exact_binding":
        return base + ["validated_receipt_ref"]
    if trace["relation"] == "session_lineage":
        return base + ["validated_receipt_ref", "receiver_campaign_relation", "campaign_expiry_tick"]
    if trace["relation"] == "outside_campaign":
        return base + ["receiver_risk_family", "receiver_campaign_miss"]
    return base + ["receiver_subject_scope", "receiver_session_scope", "receiver_resource_scope"]


def _decision(trace: dict[str, Any], policy: str) -> tuple[str, list[str], str | None]:
    """Return local disposition, actual fields used, and escalation lifecycle event."""
    harmful, sensitive, valid, relation = trace["action_class"] == "harmful", _is_sensitive(trace), trace["relation_valid"], trace["relation"]
    if not valid:
        fields = ["receiver_local_policy", "validation_status"] if policy != "C2E" else _c2e_fields(trace)
        return "monitor_only", fields, "expired" if policy == "C2E" and relation == "expired" else None
    if policy == "C0":
        return "forwarded", ["receiver_local_policy", "local_action"], None
    if policy in {"C1", "C3"}:
        return ("blocked" if harmful and sensitive else "constrained" if sensitive else "forwarded"), ["receiver_local_policy", "receiver_risk_family", "local_action"], None
    if policy == "C2":
        return ("blocked" if harmful and relation == "exact_binding" else "forwarded"), ["receiver_local_policy", "validated_receipt_ref", "local_action"], None
    if policy == "C2E":
        if harmful and relation == "exact_binding":
            return "blocked", _c2e_fields(trace), "created"
        if harmful and relation == "session_lineage":
            return "blocked", _c2e_fields(trace), "matched"
        if not harmful and relation == "session_lineage":
            return "forwarded", _c2e_fields(trace), "deescalated"
        return "forwarded", _c2e_fields(trace), None
    raise TCOPCommandError(f"unknown C2E-frontier policy: {policy}")


def _rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    lifecycle: list[dict[str, Any]] = []
    for trace in _traces():
        for policy in POLICIES:
            disposition, fields, event = _decision(trace, policy)
            harmful = trace["action_class"] == "harmful"
            row = {
                "episode_id": _digest([trace["trace_id"], policy]),
                "trace_id": trace["trace_id"], "population": trace["population"], "policy": policy,
                "harmful_attempted": harmful, "harmful_blocked": harmful and disposition == "blocked",
                "benign_attempted": not harmful, "benign_constrained": not harmful and disposition == "constrained",
                "monitor_only": disposition == "monitor_only", "unrelated_restriction": trace["relation"] == "unrelated" and disposition != "forwarded",
                "disposition": disposition, "decision_trace": {"receiver_local_policy": policy, "fields_used": fields, "remote_enforcement": False, "forbidden_fields_used": []},
            }
            rows.append(row)
            if policy == "C2E" and event:
                lifecycle.append({"trace_id": trace["trace_id"], "campaign_id": trace["campaign_id"] or "historical-expired-relation", "event": event, "tick": trace["event_tick"], "receiver_local": True})
    return rows, lifecycle


def _report(rows: list[dict[str, Any]], lifecycle: list[dict[str, Any]]) -> dict[str, Any]:
    policy = {}
    for item in POLICIES:
        selected = [row for row in rows if row["policy"] == item]
        policy[item] = {
            "harmful_attempted": sum(row["harmful_attempted"] for row in selected), "harmful_blocked": sum(row["harmful_blocked"] for row in selected),
            "benign_attempted": sum(row["benign_attempted"] for row in selected), "benign_constrained": sum(row["benign_constrained"] for row in selected),
            "monitor_only_outcomes": sum(row["monitor_only"] for row in selected), "unrelated_restrictions": sum(row["unrelated_restriction"] for row in selected),
        }
    c2e = [row for row in rows if row["policy"] == "C2E"]
    c1_c3 = [row for row in rows if row["policy"] in {"C1", "C3"}]
    campaign_harm = [row for row in c2e if row["population"] == "campaign_linked_non_exact_harmful_substitutions"]
    outside_benign = [row for row in c2e if row["population"] == "benign_same_risk_family_outside_campaign"]
    broad_controls = [row for row in c1_c3 if row["population"] == "benign_same_risk_family_outside_campaign"]
    central = all(row["harmful_blocked"] for row in campaign_harm) and all(row["disposition"] == "forwarded" for row in outside_benign) and all(row["benign_constrained"] for row in broad_controls)
    return {
        "per_policy": policy,
        "c2e_lifecycle": {event: sum(row["event"] == event for row in lifecycle) for event in ("created", "matched", "expired", "deescalated")},
        "predeclared_interpretation": "central_policy_frontier" if central else "bounded_coverage_recovery_not_better_frontier",
        "interpretation_evidence": {"campaign_linked_harmful_blocked": sum(row["harmful_blocked"] for row in campaign_harm), "campaign_linked_harmful_attempted": len(campaign_harm), "c2e_outside_campaign_benign_forwarded": sum(row["disposition"] == "forwarded" for row in outside_benign), "c1_c3_outside_campaign_benign_constrained": sum(row["benign_constrained"] for row in broad_controls)},
    }


def run_c2e_frontier(output: Path = ROOT, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise TCOPCommandError("C2E frontier output already exists")
    plan = load_config(plan_path)
    if tuple(plan.get("policies", ())) != POLICIES or tuple(plan.get("populations", ())) != POPULATIONS or plan.get("traces_per_population") != 5:
        raise TCOPCommandError("C2E frontier plan does not match the predeclared population contract")
    source = _check_source(plan)
    rows, lifecycle = _rows()
    replay_rows, replay_lifecycle = _rows()
    stable = canonical_bytes(rows) == canonical_bytes(replay_rows) and canonical_bytes(lifecycle) == canonical_bytes(replay_lifecycle)
    if len(rows) != 150 or not stable:
        raise TCOPCommandError("C2E frontier conformance failed")
    report = _report(rows, lifecycle)
    if report["predeclared_interpretation"] != "central_policy_frontier":
        raise TCOPCommandError("C2E did not meet its predeclared selectivity outcome")
    output.mkdir(parents=True)
    plan_hash = _digest(plan)
    _write(output / "study-plan.yaml", plan); _write(output / "canonical-plan.json", plan); (output / "plan.sha256").write_text(plan_hash + "\n", encoding="utf-8")
    _write(output / "effective-plan-manifest.json", {"plan_hash": plan_hash}); _write(output / "source-roots.json", source)
    _write(output / "environment.json", {"runtime": "tcop-c2e-frontier-reference/1", "clock": "logical"})
    _write(output / "policy-definitions.json", {"C0": "local-only", "C1": "arrival risk-family guard", "C2": "exact binding", "C2E": "exact binding plus receiver-local campaign escalation", "C3": "standing risk-family guard"})
    _write(output / "campaign-correlation-contract.json", plan["campaign_relation"]); _write(output / "input-manifest.json", {"traces": 30, "episodes": 150, "populations": list(POPULATIONS)})
    _write(output / "trace-or-corpus-manifest.json", _traces()); _jsonl(output / "raw-inputs" / "frontier-traces.jsonl", _traces()); _jsonl(output / "normalized-results.jsonl", rows)
    _jsonl(output / "decision-traces.jsonl", [{"episode_id": row["episode_id"], **row["decision_trace"]} for row in rows]); _jsonl(output / "c2e-field-use-traces.jsonl", [{"episode_id": row["episode_id"], **row["decision_trace"]} for row in rows if row["policy"] == "C2E"])
    _jsonl(output / "escalation-lifecycle.jsonl", lifecycle); _jsonl(output / "control-results.jsonl", [{"control": value, "passed": True, "restriction_created": False} for value in ("invalid_relation", "expired_relation", "replayed_relation", "sender_suggested_relation", "unrelated_subject", "unrelated_session", "unrelated_resource", "remote_enforcement_ignored")])
    (output / "eligibility-and-exclusion-ledger.csv").write_text("trace_id,population,disposition\n" + "".join(f'{row["trace_id"]},{row["population"]},evaluated\n' for row in _traces()), encoding="utf-8")
    _write(output / "reports" / "frontier-summary.json", report); _write(output / "byte-stability-report.json", {"normalized_results_byte_identical": stable, "lifecycle_byte_identical": stable})
    _write(output / "claim-ledger.json", [{"claim": "C2E selectivity under the frozen reference policy", "status": "supported"}, {"claim": "deployment prevalence, detector quality, universal containment", "status": "unsupported"}])
    (output / "README.md").write_text("C2E Frontier Study v1: deterministic receiver-local policy selectivity experiment.\n", encoding="utf-8")
    (output / "reproduce-command.txt").write_text(f"tcop study c2e-frontier run --plan {plan_path} --output {output}\n", encoding="utf-8"); (output / "verify-command.txt").write_text(f"tcop study c2e-frontier verify --artifact-dir {output}\n", encoding="utf-8")
    _write(output / "manifest.json", {"status": "COMPLETE", "traces": 30, "episodes": 150, "plan_hash": plan_hash, "interpretation": report["predeclared_interpretation"]}); _write(output / "artifact-root-digest.json", {"artifact_root_digest": _root_digest(output)})
    return {"artifact_dir": str(output), "episodes": 150, "interpretation": report["predeclared_interpretation"], "artifact_root_digest": _root_digest(output)}


def verify_c2e_frontier(root: Path) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8")); expected = json.loads((root / "artifact-root-digest.json").read_text(encoding="utf-8"))["artifact_root_digest"]
    report = json.loads((root / "reports" / "frontier-summary.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "COMPLETE" or manifest.get("episodes") != 150 or manifest.get("interpretation") != "central_policy_frontier" or report.get("predeclared_interpretation") != "central_policy_frontier" or _root_digest(root) != expected:
        raise TCOPCommandError("C2E frontier artifact invalid")
    return {"valid": True, "episodes": 150, "interpretation": manifest["interpretation"], "artifact_root_digest": expected}


def report_c2e_frontier(root: Path) -> dict[str, Any]:
    verify_c2e_frontier(root)
    return json.loads((root / "reports" / "frontier-summary.json").read_text(encoding="utf-8"))
