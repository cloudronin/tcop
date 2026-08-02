"""Fail-closed preflight for the external-warning cross-host study.

This module intentionally refuses to fabricate an AgentDojo or Prompt Guard
result when the pinned external inputs or true two-host topology are absent.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .cli_support import EXIT_FROZEN_INPUT, TCOPCommandError, load_config
from .context_comparator import _root_digest
from .federation import artifact_root_digest
from .stix_taxii_comparator import run_deterministic_fixtures

ROOT = Path("artifacts/external-warning-adaptive-crosshost-v1")
PLAN = Path("benchmark/studies/external-warning-adaptive-crosshost-v1.yaml")
FEDERATED = "0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99"
VALIDATION_V2 = "da59b13917eac22bb329199886100861c1a9f91c33e69a7f6ad5db55ec3e731d"

def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
def _digest(value: Any) -> str: return sha256(canonical_bytes(value)).hexdigest()

def _source_roots() -> dict[str, Any]:
    observed = {"federated_evidence": artifact_root_digest(Path("artifacts/federated-domain-v0.6-evidence"))["artifact_root_digest"], "validation_value_v2": _root_digest(Path("artifacts/tcx-validation-value-v2"))}
    if observed != {"federated_evidence": FEDERATED, "validation_value_v2": VALIDATION_V2}:
        raise TCOPCommandError("frozen upstream root changed before external-study preflight", EXIT_FROZEN_INPUT)
    return observed

def _effective_plan_contract(plan: dict[str, Any]) -> dict[str, Any]:
    amendments = {str(item.get("id")): item for item in plan.get("amendments", []) if isinstance(item, dict)}
    branch_matrix = plan.get("adaptive_branch_matrix", {})
    timing = plan.get("timing_phase_diagram", {})
    adaptive_ok = isinstance(branch_matrix, dict) and set(branch_matrix) == {"A0", "A1", "A2", "A3", "A4"} and "adaptive_retry_ladder" not in plan
    broader = plan.get("valid_broader_risk", {})
    broader_ok = isinstance(broader, dict) and broader.get("candidate_census") == "required_before_held_out_execution" and broader.get("empty_population_disposition") == "incomplete_for_mismatch_escalation_claims"
    timing_ok = isinstance(timing, dict) and timing.get("network_delay_ms") == [10, 50, 100, 250] and timing.get("action_interval_ms") == [25, 100, 250, 500] and timing.get("impairment_implementation") == "isolated_two_host_network_interface_only" and timing.get("forbidden_implementation") == "application_level_sleep"
    return {"amendment_001": "001" in amendments, "amendment_002": "002" in amendments, "composition_conditions": {"S1", "T2", "S2"}.issubset(set(plan.get("conditions", []))), "adaptive_branch_matrix": adaptive_ok, "valid_broader_risk": broader_ok, "timing_phase_diagram": timing_ok, "amendments": amendments}

def _preflight(plan: dict[str, Any]) -> dict[str, Any]:
    host_a, host_b = os.environ.get("TCOP_EXTERNAL_HOST_A"), os.environ.get("TCOP_EXTERNAL_HOST_B")
    agentdojo = importlib.util.find_spec("agentdojo") is not None
    model_path = os.environ.get("TCOP_PROMPT_GUARD_MODEL_DIR")
    model_present = bool(model_path and Path(model_path).is_dir())
    topology = bool(host_a and host_b and host_a != host_b and host_a != socket.gethostname() and host_b != socket.gethostname())
    contract = _effective_plan_contract(plan)
    lock_environment = {
        "stix_schema": os.environ.get("TCOP_STIX_SCHEMA_LOCK"),
        "taxii": os.environ.get("TCOP_TAXII_LOCK"),
        "opa": os.environ.get("TCOP_OPA_LOCK"),
    }
    locks = {name: {"path": value, "present": bool(value and Path(value).is_file())} for name, value in lock_environment.items()}
    fixtures = run_deterministic_fixtures()
    blockers = []
    if not agentdojo: blockers.append("G1: pinned AgentDojo corpus is not installed or content-addressed locally")
    if not model_present: blockers.append("G1: pinned Prompt Guard 2 model revision is not locally available under TCOP_PROMPT_GUARD_MODEL_DIR")
    if not (contract["amendment_001"] and contract["composition_conditions"]): blockers.append("A8: Amendment 001 and S1/T2/S2 are not present in the effective plan")
    if not (contract["amendment_002"] and contract["adaptive_branch_matrix"] and contract["valid_broader_risk"] and contract["timing_phase_diagram"]): blockers.append("G12-G17: Amendment 002 adaptive, valid-broader-risk, and timing contracts are not complete in the effective plan")
    if not all(item["present"] for item in locks.values()): blockers.append("G2: pinned STIX schema validator, TAXII 2.1 client/server, and OPA lock files are required before evaluation")
    if not topology: blockers.append("G5: true two-host or two-VM topology is not configured; current execution host is " + socket.gethostname())
    return {"study": plan["study"], "status": "BLOCKED" if blockers else "READY", "external_sources": {"agentdojo": {"url": plan["external_sources"]["agentdojo"]["url"], "license_access": "externally documented MIT; local pinned LICENSE unavailable", "installed": agentdojo, "revision": None, "content_hash": None}, "llama_prompt_guard_2": {"url": plan["external_sources"]["llama_prompt_guard_2"]["url"], "license_access": "model-card license acceptance required; local pinned revision unavailable", "installed": model_present, "revision": None, "content_hash": None}}, "composition": {"amendment_integrated": contract["amendment_001"], "conditions_present": contract["composition_conditions"], "dependency_locks": locks, "deterministic_fixture": {"external_evaluation": fixtures["external_evaluation"], "gates": fixtures["gates"]}}, "amendment_002": {key: value for key, value in contract.items() if key != "amendments"}, "topology": {"required": plan["required_topology"], "host_a": host_a, "host_b": host_b, "current_host": socket.gethostname(), "satisfied": topology}, "timestamp": {"status": "not_obtained", "plan_term": "sealed pre-analysis plan", "reason": "external timestamp tool or verified proof unavailable before dependency admission"}, "blockers": blockers, "compatibility_finding": "No evaluation was run and no substitute corpus, detector, synthetic warning source, single-host topology, or fixture result was used as an external result."}

def run_external_adaptive(output: Path = ROOT, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()): raise TCOPCommandError(f"external-study output already exists and is non-empty: {output}")
    plan = load_config(plan_path); roots = _source_roots(); report = _preflight(plan)
    output.mkdir(parents=True, exist_ok=True)
    canonical = canonical_bytes(plan); plan_hash = sha256(canonical).hexdigest()
    amendments = _effective_plan_contract(plan)["amendments"]
    amendment_hashes: dict[str, str] = {}
    _write(output / "study-plan.yaml", plan); _write(output / "plan.canonical.json", json.loads(canonical)); (output / "plan.sha256").write_text(plan_hash + "\n", encoding="utf-8")
    (output / "amendments").mkdir(parents=True, exist_ok=True)
    targets = {"001": "001-stix-taxii-comparator.md", "002": "002-adaptive-mismatch-timing.md"}
    for amendment_id, target in targets.items():
        source = Path(str(amendments[amendment_id]["source"])); content_hash = sha256(source.read_bytes()).hexdigest(); amendment_hashes[amendment_id] = content_hash
        shutil.copyfile(source, output / "amendments" / target)
        _write(output / "amendments" / f"{amendment_id}.canonical.json", {"id": amendment_id, "path": str(source), "sha256": content_hash})
        (output / "amendments" / f"{amendment_id}.sha256").write_text(content_hash + "\n", encoding="utf-8")
    _write(output / "effective-plan-manifest.json", {"effective_plan_revision": plan.get("effective_plan_revision"), "plan_hash": plan_hash, "amendment_hashes": amendment_hashes, "external_timestamp_status": report["timestamp"]["status"]})
    _write(output / "preflight-report.json", report); _write(output / "external-input-lock.json", report["external_sources"]); _write(output / "detector-model-lock.json", report["external_sources"]["llama_prompt_guard_2"])
    _write(output / "source-roots.json", roots); _write(output / "exclusion-ledger.json", {"status": "INCOMPATIBLE_CORPUS_OR_ENVIRONMENT", "reason": report["blockers"], "evaluation_cases": 0, "substitution": "forbidden_by_study_plan"})
    _write(output / "expected-results.json", {"expected_status": "BLOCKED until G1 and G5 are satisfied", "evaluation_outputs": "absent by design"})
    _write(output / "claim-ledger.json", [{"claim": "External-warning cross-host efficacy was evaluated.", "status": "unsupported; preflight blocked before evaluation"}, {"claim": "The study plan is externally timestamped.", "status": "unsupported; sealed pre-analysis plan only"}])
    _write(output / "reproduce-command.txt", "PYTHONPATH=src python3 -m tcop.cli study external-adaptive run --output artifacts/external-warning-adaptive-crosshost-v1\n")
    _write(output / "verify-command.txt", "PYTHONPATH=src python3 -m tcop.cli study external-adaptive verify --artifact-dir artifacts/external-warning-adaptive-crosshost-v1\n")
    _write(output / "manifest.json", {"artifact_type": "external-warning-adaptive-crosshost", "version": "1.2", "status": report["status"], "complete": False, "evaluation_executed": False, "source_roots_unmodified": True, "plan_hash": plan_hash, "amendment_hashes": amendment_hashes, "blockers": report["blockers"]})
    _write(output / "artifact-root-digest.json", {"algorithm": "sha256-canonical-json", "artifact_root_digest": _root_digest(output)})
    return {"artifact_dir": str(output), "status": report["status"], "blockers": report["blockers"], "artifact_root_digest": _root_digest(output)}

def verify_external_adaptive(root: Path) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8")); expected = json.loads((root / "artifact-root-digest.json").read_text(encoding="utf-8"))["artifact_root_digest"]; actual = _root_digest(root)
    if manifest.get("status") != "BLOCKED" or manifest.get("evaluation_executed") or not manifest.get("blockers") or actual != expected: raise TCOPCommandError("external-study blocked artifact is invalid")
    if manifest.get("version") == "1.1":
        amendment = root / "amendments" / "001-stix-taxii-comparator.md"
        if not amendment.is_file() or sha256(amendment.read_bytes()).hexdigest() != manifest.get("amendment_hash"):
            raise TCOPCommandError("external-study amendment artifact is invalid")
    if manifest.get("version") == "1.2":
        targets = {"001": "001-stix-taxii-comparator.md", "002": "002-adaptive-mismatch-timing.md"}
        hashes = manifest.get("amendment_hashes", {})
        if not isinstance(hashes, dict): raise TCOPCommandError("external-study amendment hashes are invalid")
        for amendment_id, target in targets.items():
            amendment = root / "amendments" / target
            if not amendment.is_file() or sha256(amendment.read_bytes()).hexdigest() != hashes.get(amendment_id):
                raise TCOPCommandError("external-study amendment artifact is invalid")
    return {"valid": True, "status": "BLOCKED", "artifact_root_digest": actual, "blockers": manifest["blockers"]}

def report_external_adaptive(root: Path) -> dict[str, Any]:
    value = verify_external_adaptive(root); value["preflight"] = json.loads((root / "preflight-report.json").read_text(encoding="utf-8")); return value
