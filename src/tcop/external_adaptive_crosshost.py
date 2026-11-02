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
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .cli_support import EXIT_FROZEN_INPUT, TCOPCommandError, load_config
from .context_comparator import _root_digest
from .federation import artifact_root_digest
from .stix_taxii_comparator import run_deterministic_fixtures
from .external_enforcement_admission import PINS, verify_admission, base_admission
from .external_role_scripts import FAMILIES, verify_roles
from .external_expected_pattern import verify_expected_pattern
from .external_foundation_seals import read_json, require, ensure_unsealed_output
from .external_enforcement_validation import (AM004_SHA256, PROVISIONAL_INTERVALS,
    validate_plan_v14, validate_enforcement_records)

AMENDMENT_TARGETS = {
    "001": "001-stix-taxii-comparator.md",
    "002": "002-adaptive-mismatch-timing.md",
    "003": "003-enforcement-ladder.md",
    "004": "004-runtime-bindings.md",
}
LEGACY_CONDITIONS = ["E0", "E1", "E2", "E2M", "E2E", "E3", "S1", "T2", "S2"]
OWNER_BLOCKERS = [
    "AM003_OPEN_ISSUE_7: native scope revocation, freeze, and snapshot paths remain unresolved with owner",
    "AM003_OPEN_ISSUE_8: native E2a/E2b approval setting remains unresolved with owner",
    "AM003_OPEN_ISSUE_10: A4/E0 frontier anchor and accounting remain unresolved with owner",
]

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

def _ladder_contract(plan: dict[str, Any], amendments: dict[str, Any]) -> bool:
    """Legacy E0/E1/E2 stay base conditions; no ladder records enter those lists."""
    ladder = plan.get("enforcement_ladder")
    if not isinstance(ladder, dict) or not all(isinstance(plan.get(key), dict) for key in ("valid_broader_risk", "timing_phase_diagram")):
        return False
    arms, modes, families = (ladder.get(key) for key in ("arms", "e2_modes", "families"))
    text_values = lambda value, keys: isinstance(value, dict) and set(value) == keys and all(isinstance(v, str) and v.strip() for v in value.values())
    family_ok = isinstance(families, dict) and set(families) == set(FAMILIES) and all(
        isinstance(families[name], dict) and families[name].get("public_source_tag") == tag
        and isinstance(families[name].get("meaning"), str) and bool(families[name]["meaning"].strip())
        for name, tag in FAMILIES.items())
    policy = ladder.get("policy")
    amendment = amendments.get("003", {})
    return bool(
        str(plan.get("effective_plan_revision")) in {"1.3", "1.4"}
        and plan.get("plan_status") == ("amendments_001_002_003_004_integrated_pending_external_timestamp" if str(plan.get("effective_plan_revision")) == "1.4" else "amendments_001_002_003_integrated_pending_external_timestamp")
        and amendment.get("source") == "spec/external-warning-adaptive-crosshost-amendment-003.md"
        and amendment.get("status") == "incorporated_before_external_timestamp"
        and text_values(arms, {"E0", "E1", "E2"}) and text_values(modes, {"E2a", "E2b"})
        and ladder.get("pool_e2_modes") is False and family_ok and ladder.get("pins") == PINS
        and policy == {"tier": "required_at_admission", "presets": "required_at_admission",
                       "installed_effective_baseline_sha256": "required_at_admission"}
        and ladder.get("topology") == "three_distinct_physical_machines_runner_A_B"
        and ("open_owner_issues" not in ladder if str(plan.get("effective_plan_revision")) == "1.4" else ladder.get("open_owner_issues") == [7, 8, 10])
        and all(isinstance(ladder.get(key), str) and ladder[key].strip() for key in
                ("admission_record", "role_script_directory", "role_census", "expected_pattern", "expected_pattern_seal"))
        and plan.get("conditions") == LEGACY_CONDITIONS
        and plan.get("valid_broader_risk", {}).get("required_conditions") == LEGACY_CONDITIONS[1:]
        and plan.get("timing_phase_diagram", {}).get("required_conditions") == LEGACY_CONDITIONS)


def _effective_plan_contract(plan: dict[str, Any]) -> dict[str, Any]:
    raw_amendments = plan.get("amendments", [])
    amendments = {str(item.get("id")): item for item in raw_amendments if isinstance(item, dict)} if isinstance(raw_amendments, list) else {}
    unique_amendments = isinstance(raw_amendments, list) and len(raw_amendments) == len(amendments)
    conditions = plan.get("conditions")
    composition_ok = isinstance(conditions, list) and all(isinstance(item, str) for item in conditions) and {"S1", "T2", "S2"}.issubset(conditions)
    branch_matrix = plan.get("adaptive_branch_matrix", {})
    timing = plan.get("timing_phase_diagram", {})
    adaptive_ok = isinstance(branch_matrix, dict) and set(branch_matrix) == {"A0", "A1", "A2", "A3", "A4"} and "adaptive_retry_ladder" not in plan
    broader = plan.get("valid_broader_risk", {})
    broader_ok = isinstance(broader, dict) and broader.get("candidate_census") == "required_before_held_out_execution" and broader.get("empty_population_disposition") == "incomplete_for_mismatch_escalation_claims"
    timing_ok = isinstance(timing, dict) and timing.get("network_delay_ms") == [10, 50, 100, 250] and timing.get("action_interval_ms") == (PROVISIONAL_INTERVALS if str(plan.get("effective_plan_revision")) == "1.4" else [25, 100, 250, 500]) and timing.get("impairment_implementation") == "isolated_two_host_network_interface_only" and timing.get("forbidden_implementation") == "application_level_sleep"
    amendment_004 = False
    try:
        validate_plan_v14(plan)
        amendment_004 = unique_amendments and _ladder_contract(plan, amendments)
    except (TCOPCommandError, KeyError, TypeError, ValueError, IndexError, StopIteration):
        pass
    return {"amendment_004": amendment_004, "amendment_001": "001" in amendments, "amendment_002": "002" in amendments, "amendment_003": unique_amendments and _ladder_contract(plan, amendments), "composition_conditions": composition_ok, "adaptive_branch_matrix": adaptive_ok, "valid_broader_risk": broader_ok, "timing_phase_diagram": timing_ok, "amendments": amendments}

def _preflight(plan: dict[str, Any], *, admission: Path | None = None,
               census: Path | None = None, expected_pattern: Path | None = None) -> dict[str, Any]:
    host_a, host_b = os.environ.get("TCOP_EXTERNAL_HOST_A"), os.environ.get("TCOP_EXTERNAL_HOST_B")
    agentdojo = importlib.util.find_spec("agentdojo") is not None
    model_path = os.environ.get("TCOP_PROMPT_GUARD_MODEL_DIR")
    model_present = bool(model_path and Path(model_path).is_dir())
    topology = False  # Only a verified, environment-bound three-machine admission can satisfy this.
    contract = _effective_plan_contract(plan)
    lock_environment = {
        "stix_schema": os.environ.get("TCOP_STIX_SCHEMA_LOCK"),
        "taxii": os.environ.get("TCOP_TAXII_LOCK"),
        "opa": os.environ.get("TCOP_OPA_LOCK"),
    }
    locks = {name: {"path": value, "present": bool(value and Path(value).is_file())} for name, value in lock_environment.items()}
    fixtures = run_deterministic_fixtures()
    blockers = []
    ladder = plan.get("enforcement_ladder")
    ladder = ladder if isinstance(ladder, dict) else {}
    foundation_paths = {
        "admission": admission or os.environ.get("TCOP_EXTERNAL_ADMISSION_SEAL"),
        "role-census": census or os.environ.get("TCOP_EXTERNAL_ROLE_CENSUS_SEAL"),
        "expected-pattern": expected_pattern or os.environ.get("TCOP_EXTERNAL_EXPECTED_PATTERN_SEAL"),
    }
    foundations: dict[str, Any] = {}
    admission_hash = census_hash = None
    admission_value = census_value = prediction_value = None
    validation_summary = None
    try:
        require(bool(foundation_paths["admission"] and host_a and host_b), "verified admission seal and A/B environment identities required")
        value = verify_admission(Path(foundation_paths["admission"]), host_a=host_a, host_b=host_b, runner=socket.gethostname())
        require(value["record"].get("synthetic_fixture") is not True, "synthetic test admission cannot start a real run")
        topology = True
        admission_value = value
        admission_hash = value["base_record_sha256"]
        foundations["admission"] = {"path": str(foundation_paths["admission"]), "sha256": value["record_sha256"],
                                    "artifact_root_digest": value["artifact_root_digest"]}
    except TCOPCommandError as exc:
        blockers.append("AM003_ADMISSION: " + str(exc))
    try:
        require(bool(foundation_paths["role-census"]), "sealed role census required")
        value = verify_roles(Path(foundation_paths["role-census"]), non_smoke=True,
                             scripts_dir=Path(ladder.get("role_script_directory", "benchmark/role-scripts/amendment-003")))
        census_value = value
        census_hash = value["census_sha256"]
        foundations["role-census"] = {"path": str(foundation_paths["role-census"]), "sha256": census_hash,
                                      "artifact_root_digest": value["artifact_root_digest"]}
    except TCOPCommandError as exc:
        blockers.append("AM003_ROLE_CENSUS: " + str(exc))
    try:
        require(bool(foundation_paths["expected-pattern"]), "sealed expected-pattern record required")
        require(bool(admission_hash and census_hash), "prediction requires verified admission and role census bindings")
        value = verify_expected_pattern(Path(foundation_paths["expected-pattern"]), bindings={
            "plan_sha256": _digest(plan), "admission_sha256": admission_hash, "census_sha256": census_hash})
        prediction_value = value
        foundations["expected-pattern"] = {"path": str(foundation_paths["expected-pattern"]),
                                           "sha256": value["record_sha256"], "artifact_root_digest": value["artifact_root_digest"]}
    except TCOPCommandError as exc:
        blockers.append("AM003_EXPECTED_PATTERN: " + str(exc))
    if not contract["amendment_003"]:
        blockers.append("AM003_EFFECTIVE_PLAN: amendment 003 ladder contract is missing or malformed")
    if str(plan.get("effective_plan_revision")) == "1.4":
        if not contract["amendment_004"]:
            blockers.append("AM004_EFFECTIVE_PLAN: amendment 004 sealed binding/grid contract is missing or malformed")
        try:
            require(admission_value is not None and census_value is not None and prediction_value is not None,
                    "verified admission, census and prediction foundations required")
            records = admission_value["record"].get("validation_records")
            checked = validate_enforcement_records(records, purpose="admission")
            _bind_validation_foundations(records, plan, admission_value, census_value, prediction_value,
                                         Path(foundation_paths["role-census"]))
            validation_summary = {**checked, "sha256": _digest(records)}
        except TCOPCommandError as exc:
            blockers.append("AM004_VALIDATION_RECORDS: " + str(exc))
        blockers.append("AM004_RUNNER_NOT_IMPLEMENTED: Phase 2a validates records; live execution is not implemented")
    else:
        blockers.extend(OWNER_BLOCKERS)
    if not agentdojo: blockers.append("G1: pinned AgentDojo corpus is not installed or content-addressed locally")
    if not model_present: blockers.append("G1: pinned Prompt Guard 2 model revision is not locally available under TCOP_PROMPT_GUARD_MODEL_DIR")
    if not (contract["amendment_001"] and contract["composition_conditions"]): blockers.append("A8: Amendment 001 and S1/T2/S2 are not present in the effective plan")
    if not (contract["amendment_002"] and contract["adaptive_branch_matrix"] and contract["valid_broader_risk"] and contract["timing_phase_diagram"]): blockers.append("G12-G17: Amendment 002 adaptive, valid-broader-risk, and timing contracts are not complete in the effective plan")
    if not all(item["present"] for item in locks.values()): blockers.append("G2: pinned STIX schema validator, TAXII 2.1 client/server, and OPA lock files are required before evaluation")
    if not topology: blockers.append("G5: three distinct physical machines (runner/A/B) are not verified; current execution host is " + socket.gethostname())
    return {"study": plan["study"], "validation_records": validation_summary, "foundations": foundations, "status": "BLOCKED" if blockers else "READY", "external_sources": {"agentdojo": {"url": plan["external_sources"]["agentdojo"]["url"], "license_access": "externally documented MIT; local pinned LICENSE unavailable", "installed": agentdojo, "revision": None, "content_hash": None}, "llama_prompt_guard_2": {"url": plan["external_sources"]["llama_prompt_guard_2"]["url"], "license_access": "model-card license acceptance required; local pinned revision unavailable", "installed": model_present, "revision": None, "content_hash": None}}, "composition": {"amendment_integrated": contract["amendment_001"], "conditions_present": contract["composition_conditions"], "dependency_locks": locks, "deterministic_fixture": {"external_evaluation": fixtures["external_evaluation"], "gates": fixtures["gates"]}}, "amendment_002": {key: value for key, value in contract.items() if key != "amendments"}, "topology": {"required": "three_distinct_physical_machines_runner_A_B", "host_a": host_a, "host_b": host_b, "current_host": socket.gethostname(), "satisfied": topology}, "timestamp": {"status": "not_obtained", "plan_term": "sealed pre-analysis plan", "reason": "external timestamp tool or verified proof unavailable before dependency admission"}, "blockers": blockers, "compatibility_finding": "No evaluation was run and no substitute corpus, detector, synthetic warning source, single-host topology, or fixture result was used as an external result."}

def run_external_adaptive(output: Path = ROOT, plan_path: Path = PLAN, *, admission: Path | None = None,
                          census: Path | None = None, expected_pattern: Path | None = None) -> dict[str, Any]:
    ensure_unsealed_output(output)
    if output.exists() and any(output.iterdir()): raise TCOPCommandError(f"external-study output already exists and is non-empty: {output}")
    plan = load_config(plan_path); roots = _source_roots(); report = _preflight(plan, admission=admission, census=census, expected_pattern=expected_pattern)
    output.mkdir(parents=True, exist_ok=True)
    canonical = canonical_bytes(plan); plan_hash = sha256(canonical).hexdigest()
    amendments = _effective_plan_contract(plan)["amendments"]
    amendment_hashes: dict[str, str] = {}
    _write(output / "study-plan.yaml", plan); _write(output / "plan.canonical.json", json.loads(canonical)); (output / "plan.sha256").write_text(plan_hash + "\n", encoding="utf-8")
    (output / "amendments").mkdir(parents=True, exist_ok=True)
    version = "1.3" if str(plan.get("effective_plan_revision")) == "1.3" else "1.4"
    targets = {k:v for k,v in AMENDMENT_TARGETS.items() if version == "1.4" or k != "004"}
    for amendment_id, target in targets.items():
        source = Path(str(amendments.get(amendment_id, {}).get("source", f"spec/external-warning-adaptive-crosshost-amendment-{amendment_id}.md"))); content_hash = sha256(source.read_bytes()).hexdigest(); amendment_hashes[amendment_id] = content_hash
        shutil.copyfile(source, output / "amendments" / target)
        _write(output / "amendments" / f"{amendment_id}.canonical.json", {"id": amendment_id, "path": str(source), "sha256": content_hash})
        (output / "amendments" / f"{amendment_id}.sha256").write_text(content_hash + "\n", encoding="utf-8")
    foundation_hashes = {}
    for kind, source in report["foundations"].items():
        target = output / "foundations" / kind
        shutil.copytree(Path(source["path"]), target)
        require(_root_digest(target) == source["artifact_root_digest"], "foundation changed while copying")
        foundation_hashes[kind] = source["sha256"]
    validation_hash = None
    if report["validation_records"] is not None:
        records = read_json(output / "foundations/admission/record.json")["validation_records"]
        validation_hash = _digest(records)
        require(validation_hash == report["validation_records"]["sha256"], "validation records changed during admission closure")
        _write(output / "enforcement-validation.json", records)
    _write(output / "effective-plan-manifest.json", {"effective_plan_revision": plan.get("effective_plan_revision"), "plan_hash": plan_hash, "amendment_hashes": amendment_hashes, "foundation_hashes": foundation_hashes, "expected_pattern_sha256": foundation_hashes.get("expected-pattern"), "validation_records_sha256": validation_hash, "external_timestamp_status": report["timestamp"]["status"]})
    _write(output / "preflight-report.json", report); _write(output / "external-input-lock.json", report["external_sources"]); _write(output / "detector-model-lock.json", report["external_sources"]["llama_prompt_guard_2"])
    _write(output / "source-roots.json", roots); _write(output / "exclusion-ledger.json", {"status": "INCOMPATIBLE_CORPUS_OR_ENVIRONMENT", "reason": report["blockers"], "evaluation_cases": 0, "substitution": "forbidden_by_study_plan"})
    _write(output / "expected-results.json", {"expected_status": "BLOCKED until foundation, dependency, topology, validator, and execution gates are satisfied", "evaluation_outputs": "absent by design"})
    _write(output / "claim-ledger.json", [{"claim": "External-warning cross-host efficacy was evaluated.", "status": "unsupported; preflight blocked before evaluation"}, {"claim": "The study plan is externally timestamped.", "status": "unsupported; sealed pre-analysis plan only"}])
    _write(output / "reproduce-command.txt", "PYTHONPATH=src python3 -m tcop.cli study external-adaptive run --output artifacts/external-warning-adaptive-crosshost-v1\n")
    _write(output / "verify-command.txt", "PYTHONPATH=src python3 -m tcop.cli study external-adaptive verify --artifact-dir artifacts/external-warning-adaptive-crosshost-v1\n")
    _write(output / "manifest.json", {"artifact_type": "external-warning-adaptive-crosshost", "version": version, "valid_for_results": False, "validation_records_sha256": validation_hash, "status": report["status"], "complete": False, "evaluation_executed": False, "source_roots_unmodified": True, "plan_hash": plan_hash, "amendment_hashes": amendment_hashes, "foundation_hashes": foundation_hashes, "expected_pattern_sha256": foundation_hashes.get("expected-pattern"), "blockers": report["blockers"]})
    _write(output / "artifact-root-digest.json", {"algorithm": "sha256-canonical-json", "artifact_root_digest": _root_digest(output)})
    return {"artifact_dir": str(output), "status": report["status"], "blockers": report["blockers"], "artifact_root_digest": _root_digest(output)}

def _evidence_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _bind_validation_foundations(records: dict[str, Any], plan: dict[str, Any], admission: dict[str, Any],
                                 census: dict[str, Any], prediction: dict[str, Any], census_root: Path) -> None:
    require(records["admission"] == base_admission(admission["record"]), "gate bundle admission differs")
    require(records["foundation_bindings"] == {"plan_sha256": _digest(plan),
            "admission_sha256": admission["base_record_sha256"], "census_sha256": census["census_sha256"]},
            "gate bundle foundation hashes differ")
    require(records["expected_pattern"]["body"] == prediction["record"]
            and _evidence_time(records["expected_pattern"]["sealed_at"]) == _evidence_time(prediction["sealed_at"]), "prediction body or seal chronology differs")
    require(_evidence_time(records["census"]["sealed_at"]) == _evidence_time(read_json(census_root / "seal.json")["sealed_at"]), "census seal chronology differs")
    require(records["expected_pattern"]["body"]["seed"] == plan["seed"], "prediction seed differs from the pinned plan")
    for script in records["scripts"]:
        require(script["content"] == read_json(census_root / "scripts" / (script["script_id"] + ".json")),
                "gate bundle role script differs from sealed source bytes")


def _verify_13(root: Path, manifest: dict[str, Any], *, version: str = "1.3") -> None:
    is_14 = version == "1.4"
    blocked = manifest.get("status") == "BLOCKED"
    require(manifest.get("artifact_type") == "external-warning-adaptive-crosshost"
            and (manifest.get("complete") is False if blocked else is_14 and manifest.get("complete") is True),
            "external-study completion/status mismatch")
    plan = read_json(root / "plan.canonical.json")
    plan_hash = _digest(plan)
    require(plan_hash == manifest.get("plan_hash"), "external-study plan hash mismatch")
    require((root / "plan.sha256").read_text(encoding="utf-8").strip() == plan_hash, "external-study plan sidecar mismatch")
    require(read_json(root / "study-plan.yaml") == plan, "external-study plan copies differ")
    effective = read_json(root / "effective-plan-manifest.json")
    require(effective.get("plan_hash") == plan_hash and str(effective.get("effective_plan_revision")) == version,
            "external-study effective plan mismatch")
    require(effective.get("amendment_hashes") == manifest.get("amendment_hashes"), "effective amendment hashes differ")
    amendments = _effective_plan_contract(plan)["amendments"]
    for key in (AMENDMENT_TARGETS if is_14 else ("001", "002", "003")):
        metadata = read_json(root / "amendments" / f"{key}.canonical.json")
        expected = manifest["amendment_hashes"][key]
        require(metadata == {"id": key, "path": amendments.get(key, {}).get("source", f"spec/external-warning-adaptive-crosshost-amendment-{key}.md"), "sha256": expected}, "amendment canonical sidecar mismatch")
        require((root / "amendments" / f"{key}.sha256").read_text(encoding="utf-8").strip() == expected, "amendment hash sidecar mismatch")
    preflight = read_json(root / "preflight-report.json")
    require(preflight.get("status") == ("BLOCKED" if blocked else "READY") and preflight.get("blockers") == manifest.get("blockers"), "preflight/manifest mismatch")
    blockers = manifest["blockers"]
    if not is_14:
        require(all(item in blockers for item in OWNER_BLOCKERS), "open owner issue blockers required")
    if not _effective_plan_contract(plan)["amendment_003"]:
        require(any(item.startswith("AM003_EFFECTIVE_PLAN:") for item in blockers), "malformed ladder is missing its named blocker")
    hashes = manifest.get("foundation_hashes")
    require(isinstance(hashes, dict) and set(hashes) <= {"admission", "role-census", "expected-pattern"}, "invalid foundation hash inventory")
    require(effective.get("foundation_hashes") == hashes, "effective foundation hashes differ")
    require(manifest.get("expected_pattern_sha256") == hashes.get("expected-pattern")
            and effective.get("expected_pattern_sha256") == hashes.get("expected-pattern"), "expected-pattern manifest hash mismatch")
    gate_names = {"admission": "AM003_ADMISSION:", "role-census": "AM003_ROLE_CENSUS:", "expected-pattern": "AM003_EXPECTED_PATTERN:"}
    admitted = censused = predicted = None
    for kind, prefix in gate_names.items():
        target = root / "foundations" / kind
        if kind not in hashes:
            require(not target.exists() and any(item.startswith(prefix) for item in blockers), f"missing {kind} seal must have a named blocker")
            continue
        if kind == "admission":
            value = verify_admission(target)
            require(value["record"].get("synthetic_fixture") is not True, "synthetic admission in real preflight")
            topology = preflight.get("topology", {})
            verify_admission(target, host_a=topology.get("host_a"), host_b=topology.get("host_b"), runner=topology.get("current_host"))
            admitted = value
            actual = value["record_sha256"]
        elif kind == "role-census":
            censused = verify_roles(target, non_smoke=manifest.get("status") != "SMOKE_INVALID_FOR_RESULTS")
            actual = censused["census_sha256"]
        else:
            require("admission" in hashes and "role-census" in hashes, "prediction admission/census absent")
            predicted = verify_expected_pattern(target, bindings={"plan_sha256": plan_hash,
                "admission_sha256": admitted["base_record_sha256"] if is_14 else hashes["admission"], "census_sha256": hashes["role-census"]})
            actual = predicted["record_sha256"]
        require(actual == hashes[kind], f"{kind} manifest hash mismatch")
    if is_14:
        require(str(plan.get("effective_plan_revision")) == "1.4", "manifest/plan version mismatch")
        pin = amendments.get("004", {}).get("sha256")
        require(pin == AM004_SHA256 == manifest["amendment_hashes"]["004"], "amendment 004 differs from the plan's pinned seal hash")
        contract = _effective_plan_contract(plan)
        if not contract["amendment_004"]:
            require(blocked and any(b.startswith("AM004_EFFECTIVE_PLAN:") for b in blockers), "malformed 004 contract lacks its blocker")
        reference = manifest.get("validation_records_sha256")
        require(reference == effective.get("validation_records_sha256"), "validation record manifest references differ")
        path = root / "enforcement-validation.json"
        if reference is None:
            require(blocked and not path.exists() and any(b.startswith("AM004_VALIDATION_RECORDS:") for b in blockers), "missing gate records require a named blocker")
        else:
            records = read_json(path)
            require(_digest(records) == reference, "validation record content hash differs")
            validate_enforcement_records(records, purpose="verify")
            require(admitted is not None and censused is not None and predicted is not None, "gate records require all foundation seals")
            _bind_validation_foundations(records, plan, admitted, censused, predicted, root / "foundations/role-census")
            require(records["stage"] == ("admission" if blocked else "smoke" if manifest["status"] == "SMOKE_INVALID_FOR_RESULTS" else "results"), "gate-record stage/status mismatch")
            if not blocked:
                require(contract["amendment_004"], "results require the complete sealed 004 plan")
    require(read_json(root / "source-roots.json") == {"federated_evidence": FEDERATED, "validation_value_v2": VALIDATION_V2}, "upstream source root lock mismatch")


def verify_external_adaptive(root: Path) -> dict[str, Any]:
    try:
        manifest = read_json(root / "manifest.json")
        version = manifest.get("version")
        require(version in {"1.1", "1.2", "1.3", "1.4"}, "unknown external-study manifest version")
        expected = read_json(root / "artifact-root-digest.json")["artifact_root_digest"]
        actual = _root_digest(root)
        require(actual == expected, "external-study artifact root changed")
        if version == "1.4":
            status = manifest.get("status")
            require(status in {"BLOCKED", "COMPLETE", "SMOKE_INVALID_FOR_RESULTS"}, "unknown 1.4 status")
            if status == "BLOCKED":
                require(manifest.get("evaluation_executed") is False and manifest.get("valid_for_results") is False
                        and isinstance(manifest.get("blockers"), list) and bool(manifest["blockers"]), "blocked 1.4 artifact contract differs")
            else:
                require(manifest.get("evaluation_executed") is True and manifest.get("complete") is True
                        and manifest.get("blockers") == [] and manifest.get("valid_for_results") is (status == "COMPLETE"), "1.4 result/smoke status contract differs")
            require(all(isinstance(b,str) for b in manifest["blockers"]), "malformed blockers")
            require(not any(p.is_symlink() for p in root.rglob("*")), "1.4 artifact contains symlinks")
        else:
            require(manifest.get("status") == "BLOCKED" and manifest.get("evaluation_executed") is False
                    and isinstance(manifest.get("blockers"), list) and bool(manifest["blockers"])
                    and all(isinstance(b, str) for b in manifest["blockers"]),
                    "external-study blocked artifact is invalid")
        if version == "1.1":
            amendment = root / "amendments" / AMENDMENT_TARGETS["001"]
            require(amendment.is_file() and sha256(amendment.read_bytes()).hexdigest() == manifest.get("amendment_hash"), "external-study amendment artifact is invalid")
        else:
            targets = {k: AMENDMENT_TARGETS[k] for k in (("001", "002", "003", "004") if version == "1.4" else ("001", "002", "003") if version == "1.3" else ("001", "002"))}
            hashes = manifest.get("amendment_hashes")
            require(isinstance(hashes, dict) and set(hashes) == set(targets), "external-study amendment hashes are invalid")
            for key, target in targets.items():
                amendment = root / "amendments" / target
                require(amendment.is_file() and sha256(amendment.read_bytes()).hexdigest() == hashes[key], "external-study amendment artifact is invalid")
            if version in {"1.3", "1.4"}:
                _verify_13(root, manifest, version=version)
        return {"valid": True, "version": version, "status": manifest["status"], "valid_for_results": version == "1.4" and manifest.get("valid_for_results") is True, "artifact_root_digest": actual, "blockers": manifest["blockers"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TCOPCommandError("external-study artifact is malformed") from exc


def report_external_adaptive(root: Path) -> dict[str, Any]:
    value = verify_external_adaptive(root)
    if value.get("version") == "1.4":
        require(value.get("valid_for_results") is True and value["status"] == "COMPLETE", "result report refuses blocked or smoke artifacts")
        validate_enforcement_records(read_json(root / "enforcement-validation.json"), purpose="report")
    value["preflight"] = read_json(root / "preflight-report.json")
    return value
