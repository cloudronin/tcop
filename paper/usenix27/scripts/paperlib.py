#!/usr/bin/env python3
"""Deterministic evidence and paper-production helpers for TCOP."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parents[3]
PAPER = ROOT / "paper" / "usenix27"
EVIDENCE = PAPER / "evidence"
DATA = PAPER / "data" / "generated"
TABLES = PAPER / "tables" / "generated"
FIGURES = PAPER / "figures"
GENERATED = PAPER / "generated"
ARTIFACT = PAPER / "artifact"
STAMP = "2026-08-01T00:00:00Z"
VERSION = "paper-evidence-v1"

LIVE = Path("artifacts/v0.6-agent-validation-live-origin-certified")
PARENT = Path("artifacts/v0.6-agent-validation")
EVIDENCE_ROUND = Path("artifacts/federated-domain-v0.6-evidence")
FEDERATION = Path("artifacts/federated-domain-v0.6")
VALIDATION_VALUE = Path("artifacts/tcx-validation-value-v2")
ADAPTIVE_AUTHORIZATION = Path("artifacts/adaptive-agent-authorization-v1")
INDEPENDENT_WARNING_V1 = Path("artifacts/independent-warning-admission-v1")
INDEPENDENT_WARNING = Path("artifacts/independent-warning-admission-v1-normalizer-amendment-001")
INDEPENDENT_WARNING_V2 = Path("artifacts/independent-warning-admission-v2-external-stratified")
INDEPENDENT_WARNING_FULL = Path("artifacts/independent-warning-admission-v3-full-population")
C2E_FRONTIER = Path("artifacts/c2e-frontier-v1")
STRATEGY_INDEX = Path("artifacts/minimality-v0.5-validation/frozen-v0.6-profile-manifests.json")

MUTATION_SOURCE = Path("artifacts/tcx-validation-value-v2/property-test-report.json")

# Paper evidence classification, independent of the sealed live `passed` flags.
# Each entry is (record, condition, expected behavior, observation, invariant,
# evidence class, mutation key). NC-01--04/07/10/11/12/14/16 executed in
# src/tcop/agent_eval/runner.py:261-267,581-582,584,586.
# The other six live flags did NOT execute the named condition:
# NC-05 runner.py:579 and NC-06 runner.py:580 are literal True;
# NC-08 runner.py:266 reads authorization.py:246's literal zero;
# NC-09 runner.py:268 checks rows containing no remote action;
# NC-13 runner.py:583 never restarts a gateway and reads that literal zero;
# NC-15 runner.py:585 is literal True. All runner.py references here are under
# src/tcop/agent_eval/, as is authorization.py.
# NC-05/09 instead use executed accept_imported_context mutations from
# src/tcop/validation_value.py:118-141, recorded in MUTATION_SOURCE.
CONTROL_EVIDENCE = {
    "invalid_signature": ("NC-01", "Invalid signature", "Reject before restriction", "Rejected; no restriction", "Signed input", "live-executed", None),
    "wrong_receipt": ("NC-02", "Wrong receipt", "Reject before restriction", "Rejected; no restriction", "Receipt correlation", "live-executed", None),
    "expired_context": ("NC-03", "Expired context", "Reject before restriction", "Rejected; no restriction", "Bounded freshness", "live-executed", None),
    "replayed_context": ("NC-04", "Replayed context", "Reject before restriction", "Rejected; no restriction", "Replay protection", "live-executed", None),
    "unknown_peer": ("NC-05", "Unknown peer", "Reject before restriction", None, "Authorized peer", "signed-envelope-mutation", "issuer"),
    "disallowed_import_type": ("NC-06", "Disallowed import type", "Reject before restriction", "Not executed; design property", "Context class", "not-executed", None),
    "local_policy_monitor_only": ("NC-07", "Monitor-only policy", "Do not preempt first call", "First call not blocked", "Local detection timing", "live-executed", None),
    "no_remote_enforcement": ("NC-08", "No remote enforcement", "Never accept remote enforcement", "Not executed; design property", "Receiver authority", "not-executed", None),
    "remote_tcx_action_not_interpreted": ("NC-09", "Remote TCX action", "Never interpret remote action", None, "Receiver authority", "signed-envelope-mutation", "action_semantic"),
    "gateway_cache_disabled": ("NC-10", "Gateway cache disabled", "Evaluate each authorization", "Cache disabled", "Replay correctness", "live-executed", None),
    "tcopd_b_unavailable": ("NC-11", "tcopd B unavailable", "Use B-local disposition", "Local fail-closed policy", "Receiver authority", "live-executed", None),
    "authorization_timeout": ("NC-12", "Authorization timeout", "Use B-local disposition", "Sender does not choose timeout", "Receiver authority", "live-executed", None),
    "gateway_restart": ("NC-13", "Gateway restart", "Recompute local state", "Not executed; design property", "Receiver authority", "not-executed", None),
    "stale_decision": ("NC-14", "Stale decision", "Recompute local state", "Fresh decision used", "Receiver authority", "live-executed", None),
    "session_termination_before_context_arrival": ("NC-15", "Session termination before arrival", "Do not cross sessions", "Not executed; design property", "Session binding", "not-executed", None),
    "context_arrival_after_local_containment": ("NC-16", "Arrival after local containment", "No reversal of completed action", "Non-preventive late context", "Containment window", "live-executed", None),
}


def failure_control_rows() -> list[dict[str, Any]]:
    """Keep recorded flags, but derive paper passes only from executed evidence."""
    live_source = LIVE / "reports" / "negative-controls.json"
    records = read_json(root_path(live_source))["controls"]
    controls = {row["control"]: row for row in records}
    if len(records) != len(CONTROL_EVIDENCE) or set(controls) != set(CONTROL_EVIDENCE):
        fail("sealed negative-control set differs from the evidence map")
    if not all(row["passed"] is True for row in records):
        fail("sealed negative-control recorded flags changed")
    mutations = read_json(root_path(MUTATION_SOURCE))["mutations"]
    mutation_digest = read_json(root_path(MUTATION_SOURCE.parent / "artifact-root-digest.json"))["artifact_root_digest"]
    rows = []
    for key, (record, condition, expected, observed, invariant, evidence, mutation) in CONTROL_EVIDENCE.items():
        source, event, passed = live_source, key, None
        if evidence == "live-executed":
            passed = controls[key]["passed"]
        elif evidence == "signed-envelope-mutation":
            source, event = MUTATION_SOURCE, "mutations." + mutation
            result = mutations[mutation]
            required = ({"code": "identity_unknown", "restriction_created": False, "passed": True}
                        if mutation == "issuer" else
                        {"code": "accepted_independent_peer", "remote_action_fields_ignored": ["action", "enforcement"], "passed": True})
            if any(result.get(field) != value for field, value in required.items()):
                fail("signed-envelope mutation evidence changed: " + mutation)
            passed = result["passed"]
            observed = ("identity_unknown; no restriction" if mutation == "issuer" else
                        "Remote fields action and enforcement ignored")
        rows.append(provenance(
            source, event, treatment="negative-control", scenario="agent-gateway",
            architecture="A2", strategy="containment-first", eligibility=evidence,
            control=key, source_record=record, condition=condition, expected_behavior=expected,
            observed_behavior=observed, invariant=invariant, evidence_class=evidence,
            mutation=mutation, passed=passed, pass_label="Not tested" if passed is None else "Yes",
            live_recorded_passed=controls[key]["passed"],
            live_source_relative_path=live_source.as_posix(),
            source_record_detail=controls[key].get("detail", "") if mutation is None else mutations[mutation],
            source_artifact_digest=mutation_digest if mutation else source_digest_for(source),
            source_file_sha256=sha256_file(root_path(source)),
        ))
    if Counter(row["evidence_class"] for row in rows) != {
        "live-executed": 10, "signed-envelope-mutation": 2, "not-executed": 4,
    }:
        fail("negative-control evidence counts differ from 10/2/4")
    return rows


def negative_control_expectations(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "negative_controls": {
            row["control"]: {
                "passed": row["passed"], "status": row["pass_label"],
                "evidence_class": row["evidence_class"],
                "source": row["source_relative_path"], "record": row["source_row_event_identifier"],
                "live_recorded_passed": row["live_recorded_passed"],
            } for row in rows
        },
        "negative_control_evidence_counts": dict(Counter(row["evidence_class"] for row in rows)),
    }

SOURCE_SPECS = (
    {
        "artifact_id": "live-agent-validation-final",
        "path": LIVE,
        "expected_digest": "546f3547b727d08d452e7687191589e35839888285c622e8e639bdc6843d1b6b",
        "require_complete": True,
        "require_replayable": True,
        "command": "tcop artifact verify artifacts/v0.6-agent-validation-live-origin-certified --require-complete --require-replayable --format json",
    },
    {
        "artifact_id": "agent-validation-scripted-parent",
        "path": PARENT,
        "expected_digest": "cfc5396a651d062699a7e4374b9813380e3677abc593e2a8a4d46848406eb11f",
        "require_complete": False,
        "require_replayable": True,
        "command": "tcop artifact verify artifacts/v0.6-agent-validation --require-replayable --format json",
    },
    {
        "artifact_id": "missing-evidence-round-admitted",
        "path": EVIDENCE_ROUND,
        "expected_digest": "0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99",
        "superseded_digest": "cd26169c8b9d9620b3c62b08e3c1702c992a1461d603b08b7cd61c797b21a5f3",
        "amendment": "spec/v0.6-agent-validation-source-artifact-amendment.md",
        "require_complete": True,
        "require_replayable": True,
        "command": "tcop artifact verify artifacts/federated-domain-v0.6-evidence --require-complete --require-replayable --format json",
    },
    {
        "artifact_id": "federated-domain-parent",
        "path": FEDERATION,
        "expected_digest": "194e46000494eeda6f3966ecf1d74c22e532a40d685014b57d8fc5986b324a50",
        "require_complete": True,
        "require_replayable": True,
        "command": "tcop artifact verify artifacts/federated-domain-v0.6 --require-complete --require-replayable --format json",
    },
    {
        "artifact_id": "tcx-validation-value-v2",
        "path": VALIDATION_VALUE,
        "expected_digest": "da59b13917eac22bb329199886100861c1a9f91c33e69a7f6ad5db55ec3e731d",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "validation-value", "verify", "--artifact-dir", "artifacts/tcx-validation-value-v2"],
        "command": "tcop study validation-value verify --artifact-dir artifacts/tcx-validation-value-v2",
    },
    {
        "artifact_id": "adaptive-agent-authorization-v1",
        "path": ADAPTIVE_AUTHORIZATION,
        "expected_digest": "bd294481fb0224fc64a2d82326cea80a6b5d719f9452ef62a4e2a687d0e865b3",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "adaptive-authorization", "verify", "--artifact-dir", "artifacts/adaptive-agent-authorization-v1"],
        "command": "tcop study adaptive-authorization verify --artifact-dir artifacts/adaptive-agent-authorization-v1",
    },
    {
        "artifact_id": "independent-warning-admission-v1",
        "path": INDEPENDENT_WARNING_V1,
        "expected_digest": "661aa9a40f893adf7926a554d4070490cb8044d7d4ddff29b0b058b1c9fdd49d",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "independent-warning", "verify", "--artifact-dir", "artifacts/independent-warning-admission-v1"],
        "command": "tcop study independent-warning verify --artifact-dir artifacts/independent-warning-admission-v1",
    },
    {
        "artifact_id": "independent-warning-admission-v1-normalizer-amendment-001",
        "path": INDEPENDENT_WARNING,
        "expected_digest": "7832cc56811984d1724315553e688b389c3e46dc1551d0540997718859c12ac6",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "independent-warning", "verify", "--artifact-dir", "artifacts/independent-warning-admission-v1-normalizer-amendment-001"],
        "command": "tcop study independent-warning verify --artifact-dir artifacts/independent-warning-admission-v1-normalizer-amendment-001",
    },
    {
        "artifact_id": "independent-warning-admission-v2-external-stratified",
        "path": INDEPENDENT_WARNING_V2,
        "expected_digest": "4436596501469dba1b97a77fed42a607731b802a27cc580c143c5f09afe8b907",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "independent-warning-v2", "verify", "--artifact-dir", "artifacts/independent-warning-admission-v2-external-stratified"],
        "command": "tcop study independent-warning-v2 verify --artifact-dir artifacts/independent-warning-admission-v2-external-stratified",
    },
    {
        "artifact_id": "independent-warning-admission-v3-full-population",
        "path": INDEPENDENT_WARNING_FULL,
        "expected_digest": "a16c61a3e75f34dbd1f4dbbd23cf163da1c6e4b388c806c389333cda4f7487fc",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "independent-warning-full", "verify", "--artifact-dir", "artifacts/independent-warning-admission-v3-full-population"],
        "command": "tcop study independent-warning-full verify --artifact-dir artifacts/independent-warning-admission-v3-full-population",
    },
    {
        "artifact_id": "c2e-frontier-v1",
        "path": C2E_FRONTIER,
        "expected_digest": "f7c13dcef6396aec9b2b4511f4ba4b4f20e5d445749d4bd0df2f73880323eae4",
        "require_complete": True,
        "require_replayable": True,
        "validation_command": ["study", "c2e-frontier", "verify", "--artifact-dir", "artifacts/c2e-frontier-v1"],
        "command": "tcop study c2e-frontier verify --artifact-dir artifacts/c2e-frontier-v1",
    },
)

AMENDMENT_CHAIN = (
    ("base-live", "artifacts/v0.6-agent-validation-live", None, "sealed initial provider failure"),
    ("001", "artifacts/v0.6-agent-validation-live-amendment-001", "artifacts/v0.6-agent-validation-live", "provider completion-token field"),
    ("002", "artifacts/v0.6-agent-validation-live-amendment-002", "artifacts/v0.6-agent-validation-live-amendment-001", "provider reasoning mode"),
    ("003", "artifacts/v0.6-agent-validation-live-amendment-003", "artifacts/v0.6-agent-validation-live-amendment-002", "RA-03 eligibility alignment"),
    ("004", "artifacts/v0.6-agent-validation-live-final", "artifacts/v0.6-agent-validation-live-amendment-003", "completion-gate ordering"),
    ("005", "artifacts/v0.6-agent-validation-live-certified", "artifacts/v0.6-agent-validation-live-final", "derived RA-03 utility reconciliation"),
    ("006", "artifacts/v0.6-agent-validation-live-origin-certified", "artifacts/v0.6-agent-validation-live-certified", "single-environment reference-path tcopd-a relay replay"),
)


def fail(message: str) -> None:
    raise SystemExit("paper verification failed: " + message)


def root_path(value: Path | str) -> Path:
    return ROOT / Path(value)


def relative(value: Path) -> str:
    # Preserve the logical project-relative path when a staging checkout uses
    # read-only symlinks for immutable source artifacts.  Resolving first
    # would otherwise turn an anonymous staging path into a machine-local one.
    try:
        return value.relative_to(ROOT).as_posix()
    except ValueError:
        return value.resolve().relative_to(ROOT.resolve()).as_posix()


def anonymous_reference(value: Any) -> Any:
    """Normalize machine-local path prefixes when copying provenance into review data."""
    if isinstance(value, str):
        return value.replace("/workspace/", "").replace("/Users/vishnu/", "")
    if isinstance(value, list):
        return [anonymous_reference(item) for item in value]
    if isinstance(value, dict):
        return {key: anonymous_reference(item) for key, item in value.items()}
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def root_digest(path: Path) -> str:
    files = {
        item.relative_to(path).as_posix(): sha256_file(item)
        for item in sorted(path.rglob("*"))
        if item.is_file() and item.name != "artifact-root-digest.json"
    }
    return hashlib.sha256(canonical_bytes(files)).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def json_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    values = list(rows)
    fields = sorted({key for row in values for key in row}) if values else []
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(values)


def run_tcop(arguments: list[str]) -> tuple[int, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "tcop.cli", *arguments],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def schema_valid() -> tuple[bool, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "tcop.schema_check"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0, completed.stdout + completed.stderr


def source_digest_for(path: Path) -> str:
    value = path.as_posix()
    for spec in SOURCE_SPECS:
        if value.startswith(spec["path"].as_posix()):
            return spec["expected_digest"]
    return sha256_file(root_path(path))


def provenance(path: Path, row_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "source_artifact_digest": source_digest_for(path),
        "source_relative_path": path.as_posix(),
        "source_row_event_identifier": row_id,
        "extraction_version": VERSION,
        "extraction_timestamp": STAMP,
        **fields,
    }


def _git_revision() -> str | None:
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False)
    return completed.stdout.strip() if completed.returncode == 0 else None


def strategy_records() -> list[dict[str, Any]]:
    index_path = root_path(STRATEGY_INDEX)
    index = read_json(index_path)
    records = []
    for item in index["profiles"]:
        profile = index_path.parent / item["path"]
        payload = read_json(profile)
        computed = hashlib.sha256(canonical_bytes({key: value for key, value in payload.items() if key != "content_digest"})).hexdigest()
        records.append({
            "strategy": {"forensic-extension": "forensic-oriented"}.get(item["profile_name"], item["profile_name"]),
            "profile_id": item["profile_id"],
            "manifest_path": relative(profile),
            "expected_digest": item["content_digest"],
            "computed_digest": computed,
            "index_digest": index["index_digest"],
            "valid": item["content_digest"] == computed,
        })
    if not all(record["valid"] for record in records):
        fail("a frozen strategy manifest differs from its index")
    return records


def amendment_records() -> list[dict[str, Any]]:
    records = []
    for amendment, current, predecessor, reason in AMENDMENT_CHAIN:
        current_root = root_path(current)
        computed = root_digest(current_root)
        recorded = read_json(current_root / "artifact-root-digest.json")["artifact_root_digest"]
        predecessor_digest = root_digest(root_path(predecessor)) if predecessor else None
        declared = None
        for link_path in sorted(current_root.glob("source*artifact.json")):
            link = read_json(link_path)
            if predecessor and "artifact_root_digest" in link and str(link.get("artifact_root", "")).rstrip("/").endswith(Path(predecessor).name):
                declared = link["artifact_root_digest"]
        records.append({
            "amendment": amendment,
            "artifact_path": current,
            "artifact_digest": computed,
            "recorded_digest": recorded,
            "predecessor_path": predecessor,
            "predecessor_digest": predecessor_digest,
            "declared_predecessor_digest": declared,
            "reason": reason,
            "digest_match": computed == recorded,
            "predecessor_match": predecessor is None or predecessor_digest == declared,
        })
    if not all(row["digest_match"] and row["predecessor_match"] for row in records):
        fail("the retained amendment predecessor/successor chain is incomplete")
    return records


def verify_sources(stability_check: bool = False) -> dict[str, Any]:
    existing = EVIDENCE / "source-verification.json"
    prior = read_json(existing) if stability_check and existing.is_file() else {}
    schema_ok, schema_output = schema_valid()
    entries = []
    for spec in SOURCE_SPECS:
        artifact_root = root_path(spec["path"])
        recorded = read_json(artifact_root / "artifact-root-digest.json")["artifact_root_digest"]
        computed = root_digest(artifact_root)
        args = list(spec.get("validation_command", ["artifact", "verify", spec["path"].as_posix()]))
        if "validation_command" not in spec:
            if spec["require_complete"]:
                args.append("--require-complete")
            if spec["require_replayable"]:
                args.append("--require-replayable")
            args += ["--format", "json"]
        exit_code, raw = run_tcop(args)
        try:
            command_result = json.loads(raw)
        except json.JSONDecodeError:
            command_result = {"raw_output": raw}
        manifest = read_json(artifact_root / "manifest.json")
        status_path = artifact_root / "status.json"
        status = read_json(status_path) if status_path.is_file() else {}
        artifact_valid = bool(status.get("passed", command_result.get("valid", manifest.get("complete", False))))
        entry = {
            "artifact_id": spec["artifact_id"],
            "relative_path": spec["path"].as_posix(),
            "expected_digest": spec["expected_digest"],
            "recorded_digest": recorded,
            "computed_digest": computed,
            "complete": bool(manifest.get("complete", manifest.get("status") == "COMPLETE" or status.get("stage") in {"core", "full"})),
            "replayability_status": bool(manifest.get("replayable", command_result.get("replay_failures", 0) == 0)),
            "schema_validation_status": schema_ok,
            "parent_references": anonymous_reference({key: manifest[key] for key in sorted(manifest) if key.startswith("source_") or key in {"finalization", "finalized_from"}}),
            "amendment_references": [spec["amendment"]] if spec.get("amendment") else [],
            "git_revision": _git_revision(),
            "verification_command": spec["command"],
            "verification_timestamp": STAMP,
            "artifact_command_result": command_result,
            "pass": recorded == computed == spec["expected_digest"] and exit_code == 0 and schema_ok and artifact_valid,
            "reason": None,
        }
        if spec.get("superseded_digest"):
            amendment = root_path(spec["amendment"])
            admitted = amendment.is_file() and spec["superseded_digest"] in amendment.read_text(encoding="utf-8") and spec["expected_digest"] in amendment.read_text(encoding="utf-8")
            entry["source_artifact_amendment_verified"] = admitted
            entry["pass"] = entry["pass"] and admitted
            entry["reason"] = "The unavailable cd26169 source is formally superseded by the admitted retained 0ab19a source."
        if stability_check:
            before = next((row for row in prior.get("artifacts", []) if row.get("artifact_id") == entry["artifact_id"]), {})
            entry["byte_identical_to_before_build"] = before.get("computed_digest") == computed
            entry["pass"] = entry["pass"] and entry["byte_identical_to_before_build"]
        entries.append(entry)
    strategies = strategy_records()
    amendments = amendment_records()
    result = {
        "verification_version": VERSION,
        "verification_timestamp": STAMP,
        "schema_validation": {"passed": schema_ok, "output": schema_output.strip()},
        "artifacts": entries,
        "frozen_strategies": strategies,
        "amendment_chain": amendments,
        "pass": schema_ok and all(row["pass"] for row in entries) and all(row["valid"] for row in strategies),
    }
    if not result["pass"]:
        fail("an immutable source verification gate failed")
    write_json(existing, result)
    lines = [
        "# TCOP USENIX 2027 Source Verification",
        "",
        "All source roots were independently recomputed with the TCOP canonical root-digest algorithm.",
        "",
        "| Artifact | Expected digest | Computed digest | Complete | Replayable | Pass |",
        "|---|---|---|---:|---:|---:|",
    ]
    for row in entries:
        lines.append("| {artifact_id} | {expected_digest} | {computed_digest} | {complete} | {replayability_status} | {pass} |".format(**row))
    lines += [
        "",
        "The missing cd26169 source is explicitly documented as superseded by the source-artifact amendment; no silent substitution occurred.",
        "",
        "## Frozen strategies",
        "",
        "| Strategy | Profile | Full digest | Certified |",
        "|---|---|---|---:|",
    ]
    for row in strategies:
        lines.append("| {strategy} | {profile_id} | {computed_digest} | {valid} |".format(**row))
    lines += ["", "## Amendment lineage", "", "| Step | Digest | Predecessor match | Reason |", "|---|---|---:|---|"]
    for row in amendments:
        lines.append("| {amendment} | {artifact_digest} | {predecessor_match} | {reason} |".format(**row))
    write_text(EVIDENCE / "source-verification.md", "\n".join(lines))
    return result


def inventory() -> list[dict[str, Any]]:
    roots = [root_path(spec["path"]) for spec in SOURCE_SPECS]
    extras = [
        root_path(STRATEGY_INDEX),
        root_path("benchmark/studies/v0.6-agent-validation.yaml"),
        root_path("spec/v0.6-agent-validation-source-artifact-amendment.md"),
        root_path("integrations/mcp-gateway/gateway-selection-manifest.json"),
        root_path("schemas/agent-trace-v0.1.schema.json"),
        root_path("schemas/agent-validation-artifact-v0.1.schema.json"),
        root_path("schemas/agent-authorization-decision-v0.1.schema.json"),
        root_path(VALIDATION_VALUE / "study-plan.yaml"),
        root_path(VALIDATION_VALUE / "canonical-tcx-example.json"),
        root_path(ADAPTIVE_AUTHORIZATION / "study-plan.yaml"),
        root_path(INDEPENDENT_WARNING_V1 / "study-plan.yaml"),
        root_path(INDEPENDENT_WARNING / "study-plan.yaml"),
        root_path(INDEPENDENT_WARNING_V2 / "study-plan.yaml"),
        root_path(C2E_FRONTIER / "study-plan.yaml"),
        *[root_path("spec/v0.6-agent-validation-runtime-amendment-{0:03d}.md".format(index)) for index in range(1, 7)],
    ]
    paths = {item for root in roots for item in root.rglob("*") if item.is_file()}
    paths.update(item for item in extras if item.is_file())
    media = {".json": "application/json", ".jsonl": "application/x-ndjson", ".md": "text/markdown", ".yaml": "application/yaml", ".yml": "application/yaml", ".csv": "text/csv", ".svg": "image/svg+xml"}
    rows = []
    for path in sorted(paths):
        content = path.read_bytes()
        text = content.decode("utf-8", errors="ignore")
        rel = relative(path)
        role = "source artifact" if any(path.is_relative_to(root) for root in roots) else "study source"
        if "/reports/" in rel:
            role = "sealed report"
        elif "/runs/" in rel or "/traces/" in rel or "/pairs/" in rel:
            role = "lowest-level evidence"
        elif "manifest" in path.name or "digest" in path.name:
            role = "integrity manifest"
        rows.append({
            "artifact_id": hashlib.sha256(rel.encode("utf-8")).hexdigest()[:16],
            "relative_path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "media_type": media.get(path.suffix, "application/octet-stream"),
            "role": role,
            "paper_relevance": ["provenance", "reproducibility"],
            "contains_identity_risk": bool(re.search(r"/Users/|vishnu|@[A-Za-z0-9.-]+", text, re.I)),
            "contains_secret_risk": bool(re.search(r"sk-[A-Za-z0-9]{20,}|api[_-]?key\s*[:=]\s*[^$\s]", text, re.I)),
            "generated_or_source": "source",
            "immutable": any(path.is_relative_to(root) for root in roots),
        })
    write_json(EVIDENCE / "artifact-inventory.json", rows)
    return rows


def extract_results() -> dict[str, Any]:
    verification = verify_sources()
    det_source = EVIDENCE_ROUND / "pairs" / "paired-results.jsonl"
    all_pairs = json_lines(root_path(det_source))
    causal = [row for row in all_pairs if row["strategy"] == "containment-first" and row["inputs_equivalent"]]
    excluded = [row for row in all_pairs if not row["inputs_equivalent"]]
    outcomes = Counter(row["outcome_direction"] for row in causal)
    prevented = -sum(int(row["harmful_action_delta"]) for row in causal)
    baseline_harmful_calls = sum(int(row["baseline_harmful_actions"]) for row in causal)
    treatment_harmful_calls = sum(int(row["treatment_harmful_actions"]) for row in causal)
    if (len(causal), outcomes["improved"], outcomes["unchanged"], outcomes["worsened"], baseline_harmful_calls, treatment_harmful_calls, prevented, len(excluded)) != (54, 30, 24, 0, 39, 3, 36, 123):
        fail("recomputed deterministic totals differ from sealed reports")
    det_rows = []
    for row in causal:
        payload = dict(row)
        payload.pop("strategy")
        det_rows.append(provenance(
            det_source, row["pair_key"], treatment="A2 containment-first", scenario=row["scenario_family"],
            architecture=row["architecture_pair"], strategy=row["strategy"], eligibility="strict-input-equivalent", **payload,
        ))
    write_csv(DATA / "deterministic-pairs.csv", det_rows)
    central_source = EVIDENCE_ROUND / "reports" / "central-comparator-audit.json"
    central = read_json(root_path(central_source))
    if (central["audited_cells"], central["regression_cells"], central["root_causes"]["authority-placement effect"], central["root_causes"]["central outage"]) != (54, 6, 3, 3):
        fail("recomputed central comparator audit differs from sealed report")
    write_csv(DATA / "deterministic-central-audit.csv", [
        provenance(central_source, "central-audit", treatment="fact-equivalent", scenario="deterministic",
                   architecture="A3 versus A2", strategy="containment-first", eligibility="fact-equivalent", **central)
    ])

    live_root = root_path(LIVE)
    cohort_source = LIVE / "reports" / "trace-eligibility-report.json"
    cohort = read_json(live_root / "reports" / "trace-eligibility-report.json")
    if (sum(row["eligible"] for row in cohort), sum(row["model_errors"] for row in cohort), sum(row["refusals"] for row in cohort)) != (44, 0, 0):
        fail("recomputed live cohort differs from sealed report")
    cohort_rows = [
        provenance(cohort_source, row["scenario"], treatment="trace-generation", scenario=row["scenario"],
                   architecture="live-agent", strategy="not-applicable", eligibility="eligible",
                   attempts=row["attempts"], eligible=row["eligible"], ineligible=row["ineligible"],
                   errors=row["model_errors"], refusals=row["refusals"], target=row["target"])
        for row in cohort
    ]
    write_csv(DATA / "live-trace-cohort.csv", cohort_rows)

    pairs_source = LIVE / "reports" / "paired-enforcement-results.json"
    live_pairs = read_json(live_root / "reports" / "paired-enforcement-results.json")
    if len(live_pairs) != 220 or not all(row["action_trace_equivalent"] and row["local_configuration_equivalent"] for row in live_pairs):
        fail("strict live replay pairing is incomplete")
    pair_rows = []
    for row in live_pairs:
        payload = dict(row)
        payload.pop("treatment")
        payload.pop("scenario")
        pair_rows.append(provenance(
            pairs_source, row["treatment_run_id"], treatment=row["treatment"], scenario=row["scenario"],
            architecture="A1:A2", strategy="containment-first", eligibility="strict-trace-equivalent", **payload,
        ))
    write_csv(DATA / "live-replay-pairs.csv", pair_rows)
    expected_timing = {
        "INSIDE_WINDOW_EARLY": (24, 20, -72),
        "INSIDE_WINDOW_BOUNDARY": (24, 20, -72),
        "OUTSIDE_WINDOW": (24, 20, -48),
        "POST_LOCAL_DETECTION": (24, 20, -48),
        "POST_LOCAL_CONTAINMENT": (12, 32, -24),
    }
    timing_rows = []
    for treatment, expected in expected_timing.items():
        group = [row for row in live_pairs if row["treatment"] == treatment]
        result = (
            sum(row["outcome"] == "improved" for row in group),
            sum(row["outcome"] == "unchanged" for row in group),
            sum(int(row["harmful_action_delta"]) for row in group),
        )
        if result != expected:
            fail("sealed live timing result differs for " + treatment)
        timing_rows.append(provenance(
            pairs_source, treatment, treatment=treatment, scenario="RA-01/RA-02/RA-03",
            architecture="A1:A2", strategy="containment-first", eligibility="strict-trace-equivalent",
            improved=result[0], unchanged=result[1], harmful_action_delta=result[2], denominator=len(group),
        ))
    write_csv(DATA / "live-timing-summary.csv", timing_rows)

    physical_source = LIVE / "reports" / "end-to-end-live-results.json"
    physical = read_json(live_root / "reports" / "end-to-end-live-results.json")
    if len(physical) != 30 or not all(row["all_blocks_reference_domain_b_local_decision"] and row["remote_enforcement_successes"] == 0 for row in physical):
        fail("physical arms do not preserve the local-authority requirements")
    physical_rows = []
    for row in physical:
        payload = {key: value for key, value in row.items() if key not in {"events", "results", "context", "treatment", "scenario", "architecture"}}
        physical_rows.append(provenance(
            physical_source, row["trial_id"], treatment=row["treatment"], scenario=row["scenario"],
            architecture=row["architecture"], strategy="containment-first", eligibility="physical-live-arm", **payload,
        ))
    write_csv(DATA / "physical-arms.csv", physical_rows)
    physical_summary = defaultdict(lambda: [0, 0, 0])
    for row in physical:
        values = physical_summary[row["treatment"]]
        values[0] += int(row["harmful_actions_attempted"])
        values[1] += int(row["harmful_actions_forwarded"])
        values[2] += int(row["harmful_actions_blocked"])
    if tuple(physical_summary["NO_CONTEXT"]) != (30, 30, 0) or tuple(physical_summary["INSIDE_WINDOW_EARLY"]) != (30, 0, 30) or tuple(physical_summary["OUTSIDE_WINDOW"]) != (30, 10, 20):
        fail("physical timing totals differ from sealed report")

    utility_source = LIVE / "reports" / "benign-workload-impact.json"
    utility = read_json(live_root / "reports" / "benign-workload-impact.json")
    if (utility["benign_calls_attempted"], utility["benign_calls_forwarded"], utility["benign_calls_blocked"], utility["workflow_completion"]) != (360, 320, 40, 80):
        fail("utility totals differ from sealed report")
    inside_window_treatments = {"INSIDE_WINDOW_EARLY", "INSIDE_WINDOW_BOUNDARY"}
    inside_window = {
        "attempted": sum(values["calls_attempted"] for treatment, values in utility["by_treatment"].items() if treatment in inside_window_treatments),
        "forwarded": sum(values["calls_forwarded"] for treatment, values in utility["by_treatment"].items() if treatment in inside_window_treatments),
        "constrained": sum(values["calls_blocked"] for treatment, values in utility["by_treatment"].items() if treatment in inside_window_treatments),
        "workflow_completion": sum(values["workflow_completions"] for treatment, values in utility["by_treatment"].items() if treatment in inside_window_treatments),
        "workflow_denominator": sum(values["runs"] for treatment, values in utility["by_treatment"].items() if treatment in inside_window_treatments),
    }
    outside_window = {
        "attempted": utility["benign_calls_attempted"] - inside_window["attempted"],
        "forwarded": utility["benign_calls_forwarded"] - inside_window["forwarded"],
        "constrained": utility["benign_calls_blocked"] - inside_window["constrained"],
        "workflow_completion": utility["workflow_completion"] - inside_window["workflow_completion"],
        "workflow_denominator": sum(values["runs"] for treatment, values in utility["by_treatment"].items() if treatment not in inside_window_treatments),
    }
    if inside_window != {"attempted": 120, "forwarded": 80, "constrained": 40, "workflow_completion": 0, "workflow_denominator": 40} or outside_window != {"attempted": 240, "forwarded": 240, "constrained": 0, "workflow_completion": 80, "workflow_denominator": 80}:
        fail("treatment-specific utility totals differ from sealed report")
    utility_rows = [
        provenance(utility_source, treatment, treatment=treatment, scenario="RA-03", architecture="A1:A2",
                   strategy="containment-first", eligibility="frozen-benign-trace", **values)
        for treatment, values in sorted(utility["by_treatment"].items())
    ]
    write_csv(DATA / "utility-results.csv", utility_rows)

    performance_rows = []
    for filename in ("gateway-latency.json", "federation-latency.json"):
        source = LIVE / "reports" / filename
        report = read_json(live_root / "reports" / filename)
        for selection in report["selections"]:
            latencies = selection.get("latencies", {"federation": selection})
            for component, values in latencies.items():
                payload = dict(values)
                payload.pop("selection", None)
                performance_rows.append(provenance(
                    source, filename + ":" + selection["selection"] + ":" + component,
                    treatment="performance-only", scenario="harness", architecture="local",
                    strategy="not-applicable", eligibility="performance-selection", selection=selection["selection"],
                    component=component, cache_hit_rate=selection.get("cache_hit_rate"), **payload,
                ))
    write_csv(DATA / "performance-results.csv", performance_rows)

    control_rows = failure_control_rows()
    write_csv(DATA / "failure-controls.csv", control_rows)

    amendment_rows = [
        provenance(Path(row["artifact_path"]) / "artifact-root-digest.json", row["amendment"],
                   treatment="artifact-lineage", scenario="live-validation", architecture="not-applicable",
                   strategy="not-applicable", eligibility="recorded-amendment", **row)
        for row in amendment_records()
    ]
    write_csv(DATA / "amendment-chain.csv", amendment_rows)
    strategies = strategy_records()
    strategy_rows = []
    for row in strategies:
        payload = dict(row)
        payload.pop("strategy")
        strategy_rows.append(provenance(
            STRATEGY_INDEX, row["strategy"], treatment="frozen-strategy", scenario="all",
            architecture="A2", strategy=row["strategy"], eligibility="certified", **payload,
        ))
    write_csv(DATA / "strategy-records.csv", strategy_rows)

    validation_root = root_path(VALIDATION_VALUE)
    validation_source = VALIDATION_VALUE / "reports" / "condition-summary.json"
    validation_conditions = read_json(validation_root / "reports" / "condition-summary.json")
    by_condition = {row["condition"]: row for row in validation_conditions}
    expected_conditions = {
        "C0": (12, 0, 12, 0),
        "C1-allow": (12, 0, 12, 0),
        "C1-class": (12, 7, 12, 7),
        "C2": (12, 3, 12, 0),
        "C3": (12, 12, 12, 12),
    }
    observed_conditions = {
        condition: (row["harmful_attempted"], row["harmful_blocked"], row["benign_attempted"], row["benign_constrained"])
        for condition, row in by_condition.items()
    }
    if observed_conditions != expected_conditions:
        fail("validation-value condition summary differs from sealed results")
    validation_rows = [
        provenance(validation_source, row["condition"], treatment=row["condition"], scenario="mixed-action",
                   architecture="receiver-local", strategy="validation-value", eligibility="sealed-pre-analysis-plan",
                   **row)
        for row in validation_conditions
    ]
    write_csv(DATA / "tcx-validation-value.csv", validation_rows)

    matching_source = VALIDATION_VALUE / "reports" / "matching-harmful-summary.json"
    matching = read_json(validation_root / "reports" / "matching-harmful-summary.json")
    if matching != {"C1-class": {"attempted": 3, "blocked": 3}, "C2": {"attempted": 3, "blocked": 3}}:
        fail("validation-value matching-action summary differs from sealed results")

    hostile_source = VALIDATION_VALUE / "hostile-peer-results.csv"
    hostile_rows = list(csv.DictReader((validation_root / "hostile-peer-results.csv").open(encoding="utf-8")))
    burst_rows = {row["policy"]: row for row in hostile_rows if int(row["warnings_received"]) == 12}
    if set(burst_rows) != {"current_containment_first", "idempotent", "quota_monitor_fallback"}:
        fail("validation-value hostile-peer burst policies are incomplete")
    burst_expected = {
        "current_containment_first": (12, 12, 0, 0),
        "idempotent": (1, 1, 11, 0),
        "quota_monitor_fallback": (3, 3, 0, 9),
    }
    burst_observed = {
        policy: (int(row["warnings_accepted"]), int(row["benign_actions_constrained"]), int(row["warnings_deduplicated"]), int(row["warnings_monitored"]))
        for policy, row in burst_rows.items()
    }
    if burst_observed != burst_expected:
        fail("validation-value hostile-peer burst result differs from sealed results")
    write_csv(DATA / "tcx-hostile-peer.csv", [
        provenance(hostile_source, row["policy"] + ":" + row["warnings_received"], treatment=row["policy"],
                   scenario="valid-hostile-peer", architecture="receiver-local", strategy="containment-first",
                   eligibility="formula-computed-not-measured", **row)
        for row in hostile_rows
    ])

    correlation_source = VALIDATION_VALUE / "correlation-results.csv"
    correlation_rows = list(csv.DictReader((validation_root / "correlation-results.csv").open(encoding="utf-8")))
    if len(correlation_rows) != 24 or {int(row["concurrency"]) for row in correlation_rows} != {1, 2, 8} or not all(
        row["misbindings"] == "0" and row["cross_session_restrictions"] == "0" for row in correlation_rows
    ):
        fail("validation-value correlation results differ from sealed results")
    write_csv(DATA / "tcx-correlation.csv", [
        provenance(correlation_source, str(row["concurrency"]) + ":" + row["variant"], treatment="correlation",
                   scenario=row["variant"], architecture="receiver-local", strategy="validation-value",
                   eligibility="formula-computed-typed-in-zeros", **row)
        for row in correlation_rows
    ])

    property_source = VALIDATION_VALUE / "property-test-report.json"
    property_results = read_json(validation_root / "property-test-report.json")
    if not (property_results["passed"] and property_results["corpus_cases"] == 11 and property_results["action_semantic_smuggling_rejected"] and property_results["mutations"]["action_semantic"]["remote_action_fields_ignored"] == ["action", "enforcement"]):
        fail("validation-value receiver-validator mutations differ from sealed results")

    adaptive_root = root_path(ADAPTIVE_AUTHORIZATION)
    adaptive_source = ADAPTIVE_AUTHORIZATION / "normalized-results.jsonl"
    adaptive_rows_raw = json_lines(adaptive_root / "normalized-results.jsonl")
    adaptive_manifest = read_json(adaptive_root / "manifest.json")
    adaptive_summary = read_json(adaptive_root / "reports" / "summary.json")
    adaptive_by_policy = {
        policy: [row for row in adaptive_rows_raw if row["policy"] == policy]
        for policy in ("C0", "C1", "C2", "C2E", "C3")
    }
    adaptive_observed = {
        policy: (
            len(rows),
            sum(bool(row["initial_harmful_blocked"]) for row in rows),
            sum(bool(row["post_denial_harmful_attempted"]) for row in rows),
            sum(bool(row["post_denial_harmful_completed"]) for row in rows),
            sum(bool(row["benign_continuation_forwarded"]) for row in rows),
        )
        for policy, rows in adaptive_by_policy.items()
    }
    adaptive_expected = {
        "C0": (20, 0, 0, 0, 0), "C1": (20, 20, 15, 0, 5),
        "C2": (20, 20, 15, 15, 5), "C2E": (20, 20, 15, 0, 5),
        "C3": (20, 20, 15, 0, 5),
    }
    adaptive_benign_fallbacks = {
        policy: [row for row in rows if row["pattern"] == "benign_fallback"]
        for policy, rows in adaptive_by_policy.items()
    }
    if adaptive_manifest != {"episodes": 100, "live_episodes": 12, "plan_hash": "f70548504d2d887a63c024d24027ac0417f23bf0b857cfa00ff29b4bc3aed244", "status": "COMPLETE"} or adaptive_observed != adaptive_expected or any(len(rows) != 5 for rows in adaptive_benign_fallbacks.values()):
        fail("adaptive-authorization results differ from the sealed artifact")
    live_outcomes = Counter(row["outcome"] for row in adaptive_summary["live_results"])
    if adaptive_summary["strict_metrics"] != {
        "C0": {"initial_blocked": 0, "post_denial_completed": 0},
        "C1": {"initial_blocked": 20, "post_denial_completed": 0},
        "C2": {"initial_blocked": 20, "post_denial_completed": 15},
        "C2E": {"initial_blocked": 20, "post_denial_completed": 0},
        "C3": {"initial_blocked": 20, "post_denial_completed": 0},
    } or live_outcomes != Counter({"adapted": 9, "did_not_adapt": 3}):
        fail("adaptive-authorization summary differs from the sealed artifact")
    write_csv(DATA / "adaptive-authorization.csv", [
        provenance(adaptive_source, row["episode_id"], treatment=row["policy"], scenario=row["pattern"],
                   architecture="receiver-local", strategy="adaptive-authorization", eligibility="sealed-policy-conditioned-replay", **row)
        for row in adaptive_rows_raw
    ])

    independent_root = root_path(INDEPENDENT_WARNING)
    independent_source = INDEPENDENT_WARNING / "normalized-results.jsonl"
    independent_rows_raw = json_lines(independent_root / "normalized-results.jsonl")
    independent_manifest = read_json(independent_root / "manifest.json")
    independent_by_policy = {
        policy: [row for row in independent_rows_raw if row["policy"] == policy]
        for policy in ("C0", "C1", "C2", "C2E", "C3")
    }
    independent_observed = {
        policy: (
            len(rows), sum(bool(row["admitted"]) for row in rows),
            sum(bool(row["harmful_blocked"]) for row in rows),
            sum(bool(row["benign_constrained"]) for row in rows),
        )
        for policy, rows in independent_by_policy.items()
    }
    independent_expected = {
        "C0": (30, 1, 0, 0), "C1": (30, 1, 1, 0), "C2": (30, 1, 1, 0),
        "C2E": (30, 1, 1, 0), "C3": (30, 1, 1, 0),
    }
    independent_summary = read_json(independent_root / "reports" / "admission-summary.json")
    if independent_manifest != {"items": 30, "normalizer_kind": "declared_model_config", "plan_hash": "dde7b181f73ddc4f48de07901965431967a114e75c46895c6cdb52e022f29e5f", "rows": 150, "status": "COMPLETE"} or independent_observed != independent_expected or independent_summary != {"admitted_items": 1, "normalizer_kind": "declared_model_config", "raw_label_counts": {"LABEL_0": 29, "LABEL_1": 1}}:
        fail("independent-warning admission results differ from the sealed artifact")
    # Corpus case identifiers include environment path fragments.  The manuscript
    # projection retains a deterministic opaque reference instead, while the
    # sealed root preserves the original identifiers for verification.
    write_csv(DATA / "independent-warning-admission.csv", [
        provenance(
            independent_source,
            hashlib.sha256(row["case_id"].encode("utf-8")).hexdigest()[:16] + ":" + row["policy"],
            treatment=row["policy"], scenario="AgentDojo-held-out",
            architecture="receiver-local", strategy="independent-warning-admission", eligibility="predeclared-held-out-partition",
            case_ref=hashlib.sha256(row["case_id"].encode("utf-8")).hexdigest()[:16], policy=row["policy"],
            admitted=row["admitted"], warning_category=row["warning_category"],
            harmful_attempted=row["harmful_attempted"], harmful_blocked=row["harmful_blocked"], harmful_completed=row["harmful_completed"],
            benign_attempted=row["benign_attempted"], benign_constrained=row["benign_constrained"],
        )
        for row in independent_rows_raw
    ])

    independent_v2_root = root_path(INDEPENDENT_WARNING_V2)
    independent_v2_source = INDEPENDENT_WARNING_V2 / "normalized-results.jsonl"
    independent_v2_rows = json_lines(independent_v2_root / "normalized-results.jsonl")
    independent_v2_manifest = read_json(independent_v2_root / "manifest.json")
    independent_v2_gates = read_json(independent_v2_root / "reports" / "gates.json")
    independent_v2_candidates = list(csv.DictReader((independent_v2_root / "candidate-ledger.csv").open(encoding="utf-8")))
    policies = ("C0", "C1", "C2", "C2E", "C3")
    strata = (
        "external_positive_exact", "external_negative", "partial_binding", "mismatched_binding",
        "stale", "replayed", "sender_suggested_only", "substitution_no_local_relation",
        "substitution_with_local_relation",
    )
    v2_rows = {
        (stratum, policy): [row for row in independent_v2_rows if row["stratum"] == stratum and row["policy"] == policy]
        for stratum in strata for policy in policies
    }
    if (independent_v2_manifest != {
            "gates": {"all_passed": True, "invalid_no_restriction": True, "no_local_relation_no_c2e_restriction": True,
                      "protocol_controls_no_restriction": True, "sender_only_no_c2e_restriction": True, "stable": True},
            "policy_execution": True, "rows": 540, "status": "COMPLETE"}
            or independent_v2_gates != independent_v2_manifest["gates"]
            or len(independent_v2_rows) != 540
            or any(len(rows) != 12 for rows in v2_rows.values())):
        fail("independent-warning v2 manifest or cohort dimensions differ from the sealed artifact")
    v2_candidate_counts = Counter((row["source_label"], row["normalized_category"]) for row in independent_v2_candidates)
    v2_selected_counts = Counter((row["source_label"], row["normalized_category"]) for row in independent_v2_candidates if row["disposition"] == "selected")
    if v2_candidate_counts != Counter({("attack_bearing", "tcx.prompt_attack"): 25, ("attack_bearing", "no_warning"): 47, ("benign", "no_warning"): 96}) or v2_selected_counts != Counter({("attack_bearing", "tcx.prompt_attack"): 12, ("benign", "no_warning"): 12}):
        fail("independent-warning v2 candidate ledger differs from the sealed preflight population")

    def v2_counts(stratum: str, policy: str) -> dict[str, int]:
        rows = v2_rows[(stratum, policy)]
        return {
            "blocked": sum(row["disposition"] == "blocked" for row in rows),
            "restriction": sum(bool(row["restriction"]) for row in rows),
            "constrained": sum(bool(row["restriction"]) and not bool(row["harmful"]) for row in rows),
            "forwarded": sum(row["disposition"] == "forwarded" for row in rows),
            "rejected": sum(bool(row["rejected_before_policy"]) for row in rows),
        }

    independent_v2_observed = {stratum: {policy: v2_counts(stratum, policy) for policy in policies} for stratum in strata}
    if (
        {policy: independent_v2_observed["external_positive_exact"][policy]["blocked"] for policy in policies}
        != {"C0": 0, "C1": 12, "C2": 12, "C2E": 12, "C3": 12}
        or {policy: independent_v2_observed["external_negative"][policy]["constrained"] for policy in policies}
        != {"C0": 0, "C1": 0, "C2": 0, "C2E": 0, "C3": 12}
        or any(independent_v2_observed[stratum][policy]["restriction"] != 0 for stratum in ("partial_binding", "mismatched_binding") for policy in ("C2", "C2E"))
        or independent_v2_observed["sender_suggested_only"]["C2E"]["restriction"] != 0
        or any(independent_v2_observed[stratum][policy]["rejected"] != 12 for stratum in ("stale", "replayed") for policy in ("C2", "C2E"))
        or independent_v2_observed["substitution_no_local_relation"]["C2E"]["forwarded"] != 12
        or independent_v2_observed["substitution_with_local_relation"]["C2E"]["blocked"] != 12
    ):
        fail("independent-warning v2 dispositions differ from the sealed artifact")
    v2_substitutions = read_json(independent_v2_root / "reports" / "substitution-summary.json")
    if v2_substitutions["substitution_no_local_relation:session"]["C2E"]["forwarded"] != 8 or v2_substitutions["substitution_no_local_relation:delegation_target"]["C2E"]["forwarded"] != 4 or v2_substitutions["substitution_with_local_relation:session"]["C2E"]["restricted"] != 8 or v2_substitutions["substitution_with_local_relation:delegation_target"]["C2E"]["restricted"] != 4:
        fail("independent-warning v2 substitution breakdown differs from the sealed artifact")
    write_csv(DATA / "independent-warning-v2.csv", [
        provenance(
            independent_v2_source,
            hashlib.sha256(row["base_case_id"].encode("utf-8")).hexdigest()[:16] + ":" + row["policy"] + ":" + row["stratum"],
            treatment=row["policy"], scenario=row["stratum"], architecture="receiver-local",
            strategy="independent-warning-admission-v2", eligibility="sealed-sha256-selected-external-base-or-derived-control",
            case_ref=hashlib.sha256(row["base_case_id"].encode("utf-8")).hexdigest()[:16],
            policy=row["policy"], stratum=row["stratum"], external_base_case=row["external_base_case"],
            derived_control=row["derived_control"], harmful=row["harmful"], disposition=row["disposition"],
            restriction=row["restriction"], rejected_before_policy=row["rejected_before_policy"], changed_field=row["changed_field"],
        ) for row in independent_v2_rows
    ])

    independent_full_root = root_path(INDEPENDENT_WARNING_FULL)
    independent_full_source = INDEPENDENT_WARNING_FULL / "normalized-results.jsonl"
    independent_full_rows = json_lines(independent_full_root / "normalized-results.jsonl")
    independent_full_manifest = read_json(independent_full_root / "manifest.json")
    independent_full_gates = read_json(independent_full_root / "reports" / "gates.json")
    independent_full_coverage = read_json(independent_full_root / "reports" / "pipeline-coverage.json")
    independent_full_outcomes = read_json(independent_full_root / "reports" / "authorization-outcomes.json")
    expected_full_outcomes = {
        "C0": {"harmful_attempted": 72, "harmful_blocked": 0, "harmful_forwarded": 72, "benign_attempted": 96, "benign_constrained": 0, "benign_forwarded": 96},
        "C1": {"harmful_attempted": 72, "harmful_blocked": 25, "harmful_forwarded": 47, "benign_attempted": 96, "benign_constrained": 0, "benign_forwarded": 96},
        "C2": {"harmful_attempted": 72, "harmful_blocked": 25, "harmful_forwarded": 47, "benign_attempted": 96, "benign_constrained": 0, "benign_forwarded": 96},
        "C2E": {"harmful_attempted": 72, "harmful_blocked": 25, "harmful_forwarded": 47, "benign_attempted": 96, "benign_constrained": 0, "benign_forwarded": 96},
        "C3": {"harmful_attempted": 72, "harmful_blocked": 72, "harmful_forwarded": 0, "benign_attempted": 96, "benign_constrained": 96, "benign_forwarded": 0},
    }
    if (independent_full_manifest.get("status") != "COMPLETE" or independent_full_manifest.get("rows") != 840
            or len(independent_full_rows) != 840 or not all(independent_full_gates.values())
            or independent_full_coverage != {"source_cases": 168, "attack_bearing_cases": 72, "benign_cases": 96,
                "detector_warnings": 25, "detector_no_warning_attack": 47, "detector_no_warning_benign": 96,
                "normalized_tcx": 25, "receiver_admitted": 25, "exact_bindings": 25, "no_actionable_evidence": 143,
                "end_to_end_conditional_coverage": {"numerator": 25, "denominator": 72}}
            or independent_full_outcomes.get("policies") != expected_full_outcomes):
        fail("full-population independent-warning results differ from the sealed successor artifact")
    write_csv(DATA / "independent-warning-full.csv", [
        provenance(independent_full_source, hashlib.sha256(row["source_item_id"].encode("utf-8")).hexdigest()[:16] + ":" + row["policy"],
                   treatment=row["policy"], scenario=row["stratum"], architecture="receiver-local",
                   strategy="independent-warning-full-population", eligibility="all-sealed-v2-preflight-source-cases",
                   case_ref=hashlib.sha256(row["source_item_id"].encode("utf-8")).hexdigest()[:16], policy=row["policy"],
                   source_label=row["source_label"], warning=row["has_warning"], tcx_normalized=row["tcx_normalized"],
                   receiver_admitted=row["receiver_admitted"], exact_binding=row["exact_binding"], harmful=row["harmful"],
                   disposition=row["disposition"], restriction=row["restriction"])
        for row in independent_full_rows
    ])

    frontier_root = root_path(C2E_FRONTIER)
    frontier_source = C2E_FRONTIER / "normalized-results.jsonl"
    frontier_rows_raw = json_lines(frontier_root / "normalized-results.jsonl")
    frontier_trace_source = C2E_FRONTIER / "raw-inputs/frontier-traces.jsonl"
    frontier_trace_rows = json_lines(root_path(frontier_trace_source))
    frontier_manifest = read_json(frontier_root / "manifest.json")
    frontier_summary = read_json(frontier_root / "reports" / "frontier-summary.json")
    frontier_by_policy = {
        policy: [row for row in frontier_rows_raw if row["policy"] == policy]
        for policy in ("C0", "C1", "C2", "C2E", "C3")
    }
    frontier_observed = {
        policy: {
            "harmful_attempted": sum(bool(row["harmful_attempted"]) for row in rows),
            "harmful_blocked": sum(bool(row["harmful_blocked"]) for row in rows),
            "benign_attempted": sum(bool(row["benign_attempted"]) for row in rows),
            "benign_constrained": sum(bool(row["benign_constrained"]) for row in rows),
            "unrelated_restrictions": sum(bool(row["unrelated_restriction"]) for row in rows),
        }
        for policy, rows in frontier_by_policy.items()
    }
    frontier_expected = {
        "C0": {"harmful_attempted": 10, "harmful_blocked": 0, "benign_attempted": 20, "benign_constrained": 0, "unrelated_restrictions": 0},
        "C1": {"harmful_attempted": 10, "harmful_blocked": 10, "benign_attempted": 20, "benign_constrained": 10, "unrelated_restrictions": 0},
        "C2": {"harmful_attempted": 10, "harmful_blocked": 5, "benign_attempted": 20, "benign_constrained": 0, "unrelated_restrictions": 0},
        "C2E": {"harmful_attempted": 10, "harmful_blocked": 10, "benign_attempted": 20, "benign_constrained": 0, "unrelated_restrictions": 0},
        "C3": {"harmful_attempted": 10, "harmful_blocked": 10, "benign_attempted": 20, "benign_constrained": 10, "unrelated_restrictions": 0},
    }
    frontier_controls = json_lines(frontier_root / "control-results.jsonl")
    frontier_lifecycle = Counter(row["event"] for row in json_lines(frontier_root / "escalation-lifecycle.jsonl"))
    frontier_interpretation = frontier_summary["interpretation_evidence"]
    frontier_composition = {
        population: {
            "traces": len([row for row in frontier_by_policy["C2E"] if row["population"] == population]),
            "harmful": sum(bool(row["harmful_attempted"]) for row in frontier_by_policy["C2E"] if row["population"] == population),
            "benign": sum(bool(row["benign_attempted"]) for row in frontier_by_policy["C2E"] if row["population"] == population),
        }
        for population in (
            "exact_binding_harmful_actions",
            "campaign_linked_non_exact_harmful_substitutions",
            "benign_in_campaign_fallbacks",
            "benign_same_risk_family_outside_campaign",
            "benign_unrelated_subjects_sessions_resources",
            "invalid_expired_replayed_sender_suggested_only_relations",
        )
    }
    frontier_composition_expected = {
        "exact_binding_harmful_actions": {"traces": 5, "harmful": 5, "benign": 0},
        "campaign_linked_non_exact_harmful_substitutions": {"traces": 5, "harmful": 5, "benign": 0},
        "benign_in_campaign_fallbacks": {"traces": 5, "harmful": 0, "benign": 5},
        "benign_same_risk_family_outside_campaign": {"traces": 5, "harmful": 0, "benign": 5},
        "benign_unrelated_subjects_sessions_resources": {"traces": 5, "harmful": 0, "benign": 5},
        "invalid_expired_replayed_sender_suggested_only_relations": {"traces": 5, "harmful": 0, "benign": 5},
    }
    frontier_control_composition = Counter(
        row["relation"] for row in frontier_trace_rows
        if row["population"] == "invalid_expired_replayed_sender_suggested_only_relations"
    )
    frontier_control_composition_expected = Counter({
        "invalid": 2,
        "expired": 1,
        "replayed": 1,
        "sender_suggested_only": 1,
    })
    if (
        frontier_manifest != {"episodes": 150, "interpretation": "central_policy_frontier", "plan_hash": "2d13945a007495990bfaba576f8b3d35fa6171611f2413c827e10ba04cb83fca", "status": "COMPLETE", "traces": 30}
        or {policy: len(rows) for policy, rows in frontier_by_policy.items()} != {policy: 30 for policy in frontier_by_policy}
        or frontier_observed != frontier_expected
        or not all(row["passed"] and not row["restriction_created"] for row in frontier_controls)
        or frontier_lifecycle != Counter({"created": 5, "matched": 5, "deescalated": 5, "expired": 1})
        or frontier_interpretation != {"c1_c3_outside_campaign_benign_constrained": 10, "c2e_outside_campaign_benign_forwarded": 5, "campaign_linked_harmful_attempted": 5, "campaign_linked_harmful_blocked": 5}
        or frontier_composition != frontier_composition_expected
        or frontier_control_composition != frontier_control_composition_expected
    ):
        fail("C2E-frontier results differ from the sealed artifact")
    write_csv(DATA / "c2e-frontier.csv", [
        provenance(frontier_source, row["episode_id"], treatment=row["policy"], scenario=row["population"],
                   architecture="receiver-local", strategy="C2E-frontier", eligibility="sealed-deterministic-policy-frontier",
                   policy=row["policy"], population=row["population"], harmful_attempted=row["harmful_attempted"],
                   harmful_blocked=row["harmful_blocked"], benign_attempted=row["benign_attempted"],
                   benign_constrained=row["benign_constrained"], monitor_only=row["monitor_only"],
                   unrelated_restriction=row["unrelated_restriction"], disposition=row["disposition"])
        for row in frontier_rows_raw
    ])
    write_csv(DATA / "c2e-frontier-composition.csv", [
        provenance(frontier_source, population, treatment="C2E", scenario=population,
                   architecture="receiver-local", strategy="C2E-frontier",
                   eligibility="sealed-deterministic-policy-frontier", **counts)
        for population, counts in frontier_composition.items()
    ])
    write_csv(DATA / "c2e-frontier-control-composition.csv", [
        provenance(frontier_trace_source, relation, treatment="C2E", scenario="receiver-relation-control",
                   architecture="receiver-local", strategy="C2E-frontier",
                   eligibility="sealed-deterministic-policy-frontier", traces=count)
        for relation, count in sorted(frontier_control_composition.items())
    ])

    amendment_before_source = Path("artifacts/v0.6-agent-validation-live-amendment-002/reports/trace-eligibility-report.json")
    amendment_after_source = Path("artifacts/v0.6-agent-validation-live-amendment-003/reports/trace-eligibility-report.json")
    before_eligibility = next(row for row in read_json(root_path(amendment_before_source)) if row["scenario"] == "RA-03")
    after_eligibility = next(row for row in read_json(root_path(amendment_after_source)) if row["scenario"] == "RA-03")
    if (before_eligibility["attempts"], before_eligibility["eligible"], before_eligibility["ineligible"], after_eligibility["attempts"], after_eligibility["eligible"], after_eligibility["ineligible"]) != (60, 0, 60, 20, 20, 0):
        fail("RA-03 eligibility sensitivity differs from retained amendment artifacts")
    write_csv(DATA / "ra03-eligibility-sensitivity.csv", [
        provenance(amendment_before_source, "amendment-002", treatment="pre-correction", scenario="RA-03",
                   architecture="live-trace", strategy="not-applicable", eligibility="global-capability-rule",
                   attempts=before_eligibility["attempts"], eligible=before_eligibility["eligible"], ineligible=before_eligibility["ineligible"], target=before_eligibility["target"]),
        provenance(amendment_after_source, "amendment-003", treatment="corrected-rule", scenario="RA-03",
                   architecture="live-trace", strategy="not-applicable", eligibility="frozen-permitted-capabilities",
                   attempts=after_eligibility["attempts"], eligible=after_eligibility["eligible"], ineligible=after_eligibility["ineligible"], target=after_eligibility["target"]),
    ])

    write_json(EVIDENCE / "result-provenance.json", {
        "version": VERSION,
        "files": {
            "deterministic-pairs.csv": {"source": det_source.as_posix(), "rows": len(det_rows)},
            "deterministic-central-audit.csv": {"source": central_source.as_posix(), "rows": 1},
            "live-trace-cohort.csv": {"source": cohort_source.as_posix(), "rows": len(cohort_rows)},
            "live-replay-pairs.csv": {"source": pairs_source.as_posix(), "rows": len(pair_rows)},
            "physical-arms.csv": {"source": physical_source.as_posix(), "rows": len(physical_rows)},
            "utility-results.csv": {"source": utility_source.as_posix(), "rows": len(utility_rows)},
            "failure-controls.csv": {"sources": sorted({row["source_relative_path"] for row in control_rows}), "rows": len(control_rows)},
            "tcx-validation-value.csv": {"source": validation_source.as_posix(), "rows": len(validation_rows)},
            "tcx-hostile-peer.csv": {"source": hostile_source.as_posix(), "rows": len(hostile_rows)},
            "tcx-correlation.csv": {"source": correlation_source.as_posix(), "rows": len(correlation_rows)},
            "adaptive-authorization.csv": {"source": adaptive_source.as_posix(), "rows": len(adaptive_rows_raw)},
            "independent-warning-admission.csv": {"source": independent_source.as_posix(), "rows": len(independent_rows_raw)},
            "independent-warning-full.csv": {"source": independent_full_source.as_posix(), "rows": len(independent_full_rows)},
            "c2e-frontier.csv": {"source": frontier_source.as_posix(), "rows": len(frontier_rows_raw)},
            "c2e-frontier-composition.csv": {"source": frontier_source.as_posix(), "rows": len(frontier_composition)},
            "c2e-frontier-control-composition.csv": {"source": frontier_trace_source.as_posix(), "rows": len(frontier_control_composition)},
            "ra03-eligibility-sensitivity.csv": {"source": amendment_before_source.as_posix() + "; " + amendment_after_source.as_posix(), "rows": 2},
        },
    })
    write_json(EVIDENCE / "exclusion-ledger.json", {
        "source": det_source.as_posix(),
        "excluded_pair_count": len(excluded),
        "reason": "Balanced and utility strategy comparisons use unmatched receiver-local policy configuration and are excluded from causal A1/A2 inference.",
        "pairs": [{"pair_key": row["pair_key"], "strategy": row["strategy"], "mismatch_fields": row["mismatch_fields"]} for row in excluded],
    })
    expected = {
        "source_root_digests": {row["artifact_id"]: row["expected_digest"] for row in SOURCE_SPECS},
        "deterministic": {
            "strict_pairs": 54, "improved": 30, "unchanged": 24, "worsened": 0,
            "baseline_harmful_calls": baseline_harmful_calls, "treatment_harmful_calls": treatment_harmful_calls,
            "harmful_actions_prevented": prevented, "excluded_unmatched_pairs": 123,
            "central_fact_equivalent_cells": 54, "central_regressions": 6,
            "central_authority_regressions": central["root_causes"]["authority-placement effect"],
            "central_outage_regressions": central["root_causes"]["central outage"],
            "central_no_regression": central["root_causes"]["no_regression"],
        },
        "live": {
            "eligible_traces": 44, "replay_treatment_rows": 264, "paired_comparisons": 220,
            "physical_arms": 30, "physical_federation_exchanges": 20, "remote_enforcement_successes": 0,
            "a1": {"forwarded": 30, "blocked": 0},
            "early": {"forwarded": 0, "blocked": 30},
            "late": {"forwarded": 10, "blocked": 20},
        },
        "utility": {
            "attempted": 360, "forwarded": 320, "constrained": 40, "workflow_completion": 80, "workflow_denominator": 120,
            "inside_window": inside_window,
            "outside_window": outside_window,
        },
        "validation_value": {
            "episodes": 12,
            "conditions": by_condition,
            "matching": matching,
            "hostile_burst": burst_observed,
            "hostile_burst_evidence": "formula-computed; no executed burst study",
            "correlation_evidence": "formula-computed with typed-in zeros; no measured session-isolation study",
            "correlation": {"rows": len(correlation_rows), "concurrency": [1, 2, 8], "misbindings": 0, "cross_session_restrictions": 0},
            "validator_mutation_cases": property_results["corpus_cases"],
        },
        "adaptive_authorization": {
            "strict_episodes": len(adaptive_rows_raw), "live_episodes": adaptive_manifest["live_episodes"],
            "by_policy": adaptive_observed, "live_outcomes": dict(live_outcomes),
            "benign_fallbacks": {policy: len(rows) for policy, rows in adaptive_benign_fallbacks.items()},
        },
        "independent_warning": {
            "entries": independent_manifest["items"], "policy_rows": independent_manifest["rows"],
            "admitted_items": independent_summary["admitted_items"],
            "raw_label_counts": independent_summary["raw_label_counts"],
            "by_policy": independent_observed,
        },
        "independent_warning_v2": {
            "rows": len(independent_v2_rows), "candidate_counts": {"positive_warning": v2_candidate_counts[("attack_bearing", "tcx.prompt_attack")], "attack_no_warning": v2_candidate_counts[("attack_bearing", "no_warning")], "benign_negative": v2_candidate_counts[("benign", "no_warning")]},
            "selected_counts": {"positive_warning": v2_selected_counts[("attack_bearing", "tcx.prompt_attack")], "benign_negative": v2_selected_counts[("benign", "no_warning")]},
            "by_stratum": independent_v2_observed,
            "substitutions": v2_substitutions,
        },
        "independent_warning_full": {
            "rows": len(independent_full_rows), "coverage": independent_full_coverage,
            "by_policy": independent_full_outcomes["policies"],
        },
        "c2e_frontier": {
            "episodes": frontier_manifest["episodes"], "traces": frontier_manifest["traces"],
            "by_policy": frontier_observed, "interpretation": frontier_interpretation,
            "lifecycle": dict(frontier_lifecycle), "controls": {row["control"]: row["passed"] for row in frontier_controls},
            "composition": frontier_composition, "control_composition": dict(frontier_control_composition),
        },
        "ra03_eligibility": {
            "before": {"attempts": before_eligibility["attempts"], "eligible": before_eligibility["eligible"], "ineligible": before_eligibility["ineligible"]},
            "after": {"attempts": after_eligibility["attempts"], "eligible": after_eligibility["eligible"], "ineligible": after_eligibility["ineligible"]},
        },
        **negative_control_expectations(control_rows),
        "frozen_strategy_digests": {row["strategy"]: row["computed_digest"] for row in strategies},
        "amendment_chain_integrity": True,
    }
    write_json(ARTIFACT / "expected-results.json", expected)
    return {"verification_passed": verification["pass"], "expected": expected}


def macro_values() -> dict[str, str]:
    expected = read_json(ARTIFACT / "expected-results.json")
    det, live, utility = expected["deterministic"], expected["live"], expected["utility"]
    validation = expected["validation_value"]
    adaptive = expected["adaptive_authorization"]
    independent = expected["independent_warning"]
    independent_v2 = expected["independent_warning_v2"]
    independent_full = expected["independent_warning_full"]
    frontier = expected["c2e_frontier"]
    conditions = validation["conditions"]
    hostile = validation["hostile_burst"]
    return {
        "DeterministicPairs": str(det["strict_pairs"]),
        "DeterministicImproved": str(det["improved"]),
        "DeterministicUnchanged": str(det["unchanged"]),
        "DeterministicWorsened": str(det["worsened"]),
        "DeterministicBaselineHarmfulCalls": str(det["baseline_harmful_calls"]),
        "DeterministicTreatmentHarmfulCalls": str(det["treatment_harmful_calls"]),
        "DeterministicActionsPrevented": str(det["harmful_actions_prevented"]),
        "DeterministicExcludedPairs": str(det["excluded_unmatched_pairs"]),
        "CentralAuditCells": str(det["central_fact_equivalent_cells"]),
        "CentralRegressions": str(det["central_regressions"]),
        "CentralAuthorityRegressions": str(det["central_authority_regressions"]),
        "CentralOutageRegressions": str(det["central_outage_regressions"]),
        "CentralNoRegression": str(det["central_no_regression"]),
        "LiveTraces": str(live["eligible_traces"]),
        "LiveReplayRows": str(live["replay_treatment_rows"]),
        "LiveReplayPairs": str(live["paired_comparisons"]),
        "PhysicalArms": str(live["physical_arms"]),
        "PhysicalFederationExchanges": str(live["physical_federation_exchanges"]),
        "RemoteEnforcementSuccesses": str(live["remote_enforcement_successes"]),
        "AOneForwarded": str(live["a1"]["forwarded"]),
        "EarlyBlocked": str(live["early"]["blocked"]),
        "LateForwarded": str(live["late"]["forwarded"]),
        "LateBlocked": str(live["late"]["blocked"]),
        "BenignAttempted": str(utility["attempted"]),
        "BenignForwarded": str(utility["forwarded"]),
        "BenignConstrained": str(utility["constrained"]),
        "WorkflowCompleted": str(utility["workflow_completion"]),
        "WorkflowTotal": str(utility["workflow_denominator"]),
        "WorkflowCompletionRate": "66.7\\%",
        "InsideWindowBenignAttempted": str(utility["inside_window"]["attempted"]),
        "InsideWindowBenignForwarded": str(utility["inside_window"]["forwarded"]),
        "InsideWindowBenignConstrained": str(utility["inside_window"]["constrained"]),
        "InsideWindowWorkflowCompleted": str(utility["inside_window"]["workflow_completion"]),
        "InsideWindowWorkflowTotal": str(utility["inside_window"]["workflow_denominator"]),
        "OutsideWindowBenignAttempted": str(utility["outside_window"]["attempted"]),
        "OutsideWindowBenignForwarded": str(utility["outside_window"]["forwarded"]),
        "OutsideWindowWorkflowCompleted": str(utility["outside_window"]["workflow_completion"]),
        "OutsideWindowWorkflowTotal": str(utility["outside_window"]["workflow_denominator"]),
        "ValidationEpisodes": str(validation["episodes"]),
        "CZeroHarmfulBlocked": str(conditions["C0"]["harmful_blocked"]),
        "CZeroBenignConstrained": str(conditions["C0"]["benign_constrained"]),
        "COneAllowHarmfulBlocked": str(conditions["C1-allow"]["harmful_blocked"]),
        "COneAllowBenignConstrained": str(conditions["C1-allow"]["benign_constrained"]),
        "COneClassHarmfulBlocked": str(conditions["C1-class"]["harmful_blocked"]),
        "COneClassBenignConstrained": str(conditions["C1-class"]["benign_constrained"]),
        "CTwoHarmfulBlocked": str(conditions["C2"]["harmful_blocked"]),
        "CTwoBenignConstrained": str(conditions["C2"]["benign_constrained"]),
        "CThreeHarmfulBlocked": str(conditions["C3"]["harmful_blocked"]),
        "CThreeBenignConstrained": str(conditions["C3"]["benign_constrained"]),
        "MatchingHarmfulActions": str(validation["matching"]["C2"]["attempted"]),
        "COneClassMatchingBlocked": str(validation["matching"]["C1-class"]["blocked"]),
        "CTwoMatchingBlocked": str(validation["matching"]["C2"]["blocked"]),
        "HostileBurstWarnings": "12",
        "HostileCurrentAccepted": str(hostile["current_containment_first"][0]),
        "HostileCurrentConstrained": str(hostile["current_containment_first"][1]),
        "HostileIdempotentAccepted": str(hostile["idempotent"][0]),
        "HostileIdempotentConstrained": str(hostile["idempotent"][1]),
        "HostileIdempotentDeduplicated": str(hostile["idempotent"][2]),
        "HostileQuotaAccepted": str(hostile["quota_monitor_fallback"][0]),
        "HostileQuotaConstrained": str(hostile["quota_monitor_fallback"][1]),
        "HostileQuotaMonitored": str(hostile["quota_monitor_fallback"][3]),
        "CorrelationCases": str(validation["correlation"]["rows"]),
        "CorrelationConcurrencyLevels": "1, 2, and 8",
        "CorrelationMisbindings": str(validation["correlation"]["misbindings"]),
        "CorrelationCrossSessionRestrictions": str(validation["correlation"]["cross_session_restrictions"]),
        "ValidatorMutationCases": str(validation["validator_mutation_cases"]),
        "AdaptiveStrictEpisodes": str(adaptive["strict_episodes"]),
        "AdaptiveLiveEpisodes": str(adaptive["live_episodes"]),
        "AdaptiveInitialBlocked": str(adaptive["by_policy"]["C2"][1]),
        "AdaptiveEligibleHarmfulBranches": str(adaptive["by_policy"]["C2"][2]),
        "AdaptiveCOnePostDenialCompleted": str(adaptive["by_policy"]["C1"][3]),
        "AdaptiveCTwoPostDenialCompleted": str(adaptive["by_policy"]["C2"][3]),
        "AdaptiveCTwoEPostDenialCompleted": str(adaptive["by_policy"]["C2E"][3]),
        "AdaptiveCThreePostDenialCompleted": str(adaptive["by_policy"]["C3"][3]),
        "AdaptiveBenignFallbacks": str(adaptive["benign_fallbacks"]["C2E"]),
        "AdaptiveCOneBenignFallbackForwarded": str(adaptive["by_policy"]["C1"][4]),
        "AdaptiveCTwoBenignFallbackForwarded": str(adaptive["by_policy"]["C2"][4]),
        "AdaptiveCTwoEBenignFallbackForwarded": str(adaptive["by_policy"]["C2E"][4]),
        "AdaptiveCThreeBenignFallbackForwarded": str(adaptive["by_policy"]["C3"][4]),
        "AdaptiveLiveAdapted": str(adaptive["live_outcomes"]["adapted"]),
        "AdaptiveLiveDidNotAdapt": str(adaptive["live_outcomes"]["did_not_adapt"]),
        "IndependentWarningEntries": str(independent["entries"]),
        "IndependentWarningRows": str(independent["policy_rows"]),
        "IndependentWarningAdmitted": str(independent["admitted_items"]),
        "IndependentWarningLabelZero": str(independent["raw_label_counts"]["LABEL_0"]),
        "IndependentWarningLabelOne": str(independent["raw_label_counts"]["LABEL_1"]),
        "IndependentWarningCOneBlocked": str(independent["by_policy"]["C1"][2]),
        "IndependentWarningCTwoBlocked": str(independent["by_policy"]["C2"][2]),
        "IndependentWarningCTwoEBlocked": str(independent["by_policy"]["C2E"][2]),
        "IndependentWarningCThreeBlocked": str(independent["by_policy"]["C3"][2]),
        "IndependentWarningCZeroBlocked": str(independent["by_policy"]["C0"][2]),
        "ExternalWarningVTwoRows": str(independent_v2["rows"]),
        "ExternalWarningVTwoPositiveCandidates": str(independent_v2["candidate_counts"]["positive_warning"]),
        "ExternalWarningVTwoAttackNoWarningCandidates": str(independent_v2["candidate_counts"]["attack_no_warning"]),
        "ExternalWarningVTwoBenignCandidates": str(independent_v2["candidate_counts"]["benign_negative"]),
        "ExternalWarningVTwoSelectedPositive": str(independent_v2["selected_counts"]["positive_warning"]),
        "ExternalWarningVTwoSelectedNegative": str(independent_v2["selected_counts"]["benign_negative"]),
        "ExternalWarningVTwoCZeroPositiveBlocked": str(independent_v2["by_stratum"]["external_positive_exact"]["C0"]["blocked"]),
        "ExternalWarningVTwoCOnePositiveBlocked": str(independent_v2["by_stratum"]["external_positive_exact"]["C1"]["blocked"]),
        "ExternalWarningVTwoCTwoPositiveBlocked": str(independent_v2["by_stratum"]["external_positive_exact"]["C2"]["blocked"]),
        "ExternalWarningVTwoCTwoEPositiveBlocked": str(independent_v2["by_stratum"]["external_positive_exact"]["C2E"]["blocked"]),
        "ExternalWarningVTwoCThreePositiveBlocked": str(independent_v2["by_stratum"]["external_positive_exact"]["C3"]["blocked"]),
        "ExternalWarningVTwoCZeroNegativeConstrained": str(independent_v2["by_stratum"]["external_negative"]["C0"]["constrained"]),
        "ExternalWarningVTwoCOneNegativeConstrained": str(independent_v2["by_stratum"]["external_negative"]["C1"]["constrained"]),
        "ExternalWarningVTwoCTwoNegativeConstrained": str(independent_v2["by_stratum"]["external_negative"]["C2"]["constrained"]),
        "ExternalWarningVTwoCTwoENegativeConstrained": str(independent_v2["by_stratum"]["external_negative"]["C2E"]["constrained"]),
        "ExternalWarningVTwoCThreeNegativeConstrained": str(independent_v2["by_stratum"]["external_negative"]["C3"]["constrained"]),
        "ExternalWarningVTwoPartialCTwoRestricted": str(independent_v2["by_stratum"]["partial_binding"]["C2"]["restriction"]),
        "ExternalWarningVTwoPartialCTwoERestricted": str(independent_v2["by_stratum"]["partial_binding"]["C2E"]["restriction"]),
        "ExternalWarningVTwoMismatchCTwoRestricted": str(independent_v2["by_stratum"]["mismatched_binding"]["C2"]["restriction"]),
        "ExternalWarningVTwoMismatchCTwoERestricted": str(independent_v2["by_stratum"]["mismatched_binding"]["C2E"]["restriction"]),
        "ExternalWarningVTwoStaleCTwoERejected": str(independent_v2["by_stratum"]["stale"]["C2E"]["rejected"]),
        "ExternalWarningVTwoReplayedCTwoERejected": str(independent_v2["by_stratum"]["replayed"]["C2E"]["rejected"]),
        "ExternalWarningVTwoSenderSuggestedCTwoERestricted": str(independent_v2["by_stratum"]["sender_suggested_only"]["C2E"]["restriction"]),
        "ExternalWarningVTwoNoRelationCTwoEForwarded": str(independent_v2["by_stratum"]["substitution_no_local_relation"]["C2E"]["forwarded"]),
        "ExternalWarningVTwoWithRelationCTwoEBlocked": str(independent_v2["by_stratum"]["substitution_with_local_relation"]["C2E"]["blocked"]),
        "ExternalWarningVTwoSessionNoRelationForwarded": str(independent_v2["substitutions"]["substitution_no_local_relation:session"]["C2E"]["forwarded"]),
        "ExternalWarningVTwoDelegationNoRelationForwarded": str(independent_v2["substitutions"]["substitution_no_local_relation:delegation_target"]["C2E"]["forwarded"]),
        "ExternalWarningVTwoSessionWithRelationBlocked": str(independent_v2["substitutions"]["substitution_with_local_relation:session"]["C2E"]["restricted"]),
        "ExternalWarningVTwoDelegationWithRelationBlocked": str(independent_v2["substitutions"]["substitution_with_local_relation:delegation_target"]["C2E"]["restricted"]),
        "ExternalWarningFullSourceCases": str(independent_full["coverage"]["source_cases"]),
        "ExternalWarningFullAttackCases": str(independent_full["coverage"]["attack_bearing_cases"]),
        "ExternalWarningFullBenignCases": str(independent_full["coverage"]["benign_cases"]),
        "ExternalWarningFullWarnings": str(independent_full["coverage"]["detector_warnings"]),
        "ExternalWarningFullAttackNoWarning": str(independent_full["coverage"]["detector_no_warning_attack"]),
        "ExternalWarningFullNormalized": str(independent_full["coverage"]["normalized_tcx"]),
        "ExternalWarningFullAdmitted": str(independent_full["coverage"]["receiver_admitted"]),
        "ExternalWarningFullExactBindings": str(independent_full["coverage"]["exact_bindings"]),
        "ExternalWarningFullNoActionable": str(independent_full["coverage"]["no_actionable_evidence"]),
        "ExternalWarningFullConditionalNumerator": str(independent_full["coverage"]["end_to_end_conditional_coverage"]["numerator"]),
        "ExternalWarningFullConditionalDenominator": str(independent_full["coverage"]["end_to_end_conditional_coverage"]["denominator"]),
        "ExternalWarningFullCZeroBlocked": str(independent_full["by_policy"]["C0"]["harmful_blocked"]),
        "ExternalWarningFullCOneBlocked": str(independent_full["by_policy"]["C1"]["harmful_blocked"]),
        "ExternalWarningFullCTwoBlocked": str(independent_full["by_policy"]["C2"]["harmful_blocked"]),
        "ExternalWarningFullCTwoEBlocked": str(independent_full["by_policy"]["C2E"]["harmful_blocked"]),
        "ExternalWarningFullCThreeBlocked": str(independent_full["by_policy"]["C3"]["harmful_blocked"]),
        "ExternalWarningFullCZeroForwarded": str(independent_full["by_policy"]["C0"]["harmful_forwarded"]),
        "ExternalWarningFullCOneForwarded": str(independent_full["by_policy"]["C1"]["harmful_forwarded"]),
        "ExternalWarningFullCTwoForwarded": str(independent_full["by_policy"]["C2"]["harmful_forwarded"]),
        "ExternalWarningFullCTwoEForwarded": str(independent_full["by_policy"]["C2E"]["harmful_forwarded"]),
        "ExternalWarningFullCThreeForwarded": str(independent_full["by_policy"]["C3"]["harmful_forwarded"]),
        "ExternalWarningFullCZeroBenignConstrained": str(independent_full["by_policy"]["C0"]["benign_constrained"]),
        "ExternalWarningFullCOneBenignConstrained": str(independent_full["by_policy"]["C1"]["benign_constrained"]),
        "ExternalWarningFullCTwoBenignConstrained": str(independent_full["by_policy"]["C2"]["benign_constrained"]),
        "ExternalWarningFullCTwoEBenignConstrained": str(independent_full["by_policy"]["C2E"]["benign_constrained"]),
        "ExternalWarningFullCThreeBenignConstrained": str(independent_full["by_policy"]["C3"]["benign_constrained"]),
        "ExternalWarningFullCZeroBenignForwarded": str(independent_full["by_policy"]["C0"]["benign_forwarded"]),
        "ExternalWarningFullCOneBenignForwarded": str(independent_full["by_policy"]["C1"]["benign_forwarded"]),
        "ExternalWarningFullCTwoBenignForwarded": str(independent_full["by_policy"]["C2"]["benign_forwarded"]),
        "ExternalWarningFullCTwoEBenignForwarded": str(independent_full["by_policy"]["C2E"]["benign_forwarded"]),
        "ExternalWarningFullCThreeBenignForwarded": str(independent_full["by_policy"]["C3"]["benign_forwarded"]),
        "FrontierEpisodes": str(frontier["episodes"]),
        "FrontierHarmfulAttempted": str(frontier["by_policy"]["C2E"]["harmful_attempted"]),
        "FrontierBenignAttempted": str(frontier["by_policy"]["C2E"]["benign_attempted"]),
        "FrontierCZeroHarmfulBlocked": str(frontier["by_policy"]["C0"]["harmful_blocked"]),
        "FrontierCZeroBenignConstrained": str(frontier["by_policy"]["C0"]["benign_constrained"]),
        "FrontierCOneHarmfulBlocked": str(frontier["by_policy"]["C1"]["harmful_blocked"]),
        "FrontierCOneBenignConstrained": str(frontier["by_policy"]["C1"]["benign_constrained"]),
        "FrontierCTwoHarmfulBlocked": str(frontier["by_policy"]["C2"]["harmful_blocked"]),
        "FrontierCTwoBenignConstrained": str(frontier["by_policy"]["C2"]["benign_constrained"]),
        "FrontierCTwoEHarmfulBlocked": str(frontier["by_policy"]["C2E"]["harmful_blocked"]),
        "FrontierCTwoEBenignConstrained": str(frontier["by_policy"]["C2E"]["benign_constrained"]),
        "FrontierCThreeHarmfulBlocked": str(frontier["by_policy"]["C3"]["harmful_blocked"]),
        "FrontierCThreeBenignConstrained": str(frontier["by_policy"]["C3"]["benign_constrained"]),
        "FrontierCampaignHarmfulBlocked": str(frontier["interpretation"]["campaign_linked_harmful_blocked"]),
        "FrontierOutsideCampaignBenignForwarded": str(frontier["interpretation"]["c2e_outside_campaign_benign_forwarded"]),
        "FrontierUnrelatedRestrictions": str(frontier["by_policy"]["C2E"]["unrelated_restrictions"]),
        "FrontierExactBindingHarmful": str(frontier["composition"]["exact_binding_harmful_actions"]["harmful"]),
        "FrontierLineageHarmful": str(frontier["composition"]["campaign_linked_non_exact_harmful_substitutions"]["harmful"]),
        "FrontierSafeFallbackBenign": str(frontier["composition"]["benign_in_campaign_fallbacks"]["benign"]),
        "FrontierOutsideCampaignBenign": str(frontier["composition"]["benign_same_risk_family_outside_campaign"]["benign"]),
        "FrontierUnrelatedBenign": str(frontier["composition"]["benign_unrelated_subjects_sessions_resources"]["benign"]),
        "FrontierInvalidRelationControls": str(frontier["control_composition"]["invalid"]),
        "FrontierExpiredRelationControls": str(frontier["control_composition"]["expired"]),
        "FrontierReplayedRelationControls": str(frontier["control_composition"]["replayed"]),
        "FrontierSenderSuggestedRelationControls": str(frontier["control_composition"]["sender_suggested_only"]),
        "RAThreeBeforeAttempts": str(expected["ra03_eligibility"]["before"]["attempts"]),
        "RAThreeBeforeEligible": str(expected["ra03_eligibility"]["before"]["eligible"]),
        "RAThreeAfterAttempts": str(expected["ra03_eligibility"]["after"]["attempts"]),
        "RAThreeAfterEligible": str(expected["ra03_eligibility"]["after"]["eligible"]),
    }


AMENDMENT_SEALS = {
    "004": "9546e30627eab69924f47d595fa536da22acee8edd818d1b268eee8ba02b0706",
    "005": "3b45fef22a9b00cff1a3e001db07404a10a396445620d7c8298459e672cdd22b",
}


def future_work_macros() -> dict[str, str]:
    texts = {}
    sources = []
    for number, digest in AMENDMENT_SEALS.items():
        path = ROOT / "spec" / f"external-warning-adaptive-crosshost-amendment-{number}.md"
        if sha256_file(path) != digest:
            fail("sealed Future Work amendment hash mismatch: " + number)
        texts[number] = path.read_text(encoding="utf-8")
        sources.append({"path": relative(path), "sha256": digest})
    text = texts["004"]
    patterns = {
        "FutureBareArm": r"(E0) is the bare agent",
        "FutureSandboxArm": r"(E1) is the same agent",
        "FutureTCOPArm": r"(E2) sits on E1",
        "FutureNativeArm": r"\*\*(E2-native)\*\* uses only",
        "FutureExtendedArm": r"\*\*(E2-extended)\*\*",
        "FutureDefaultPoll": r"Its (\d+) s poll, 1 s poll and instant cut",
        "FutureMinimumPoll": r"Its 10 s poll, (\d+) s poll and instant cut",
        "FutureApprovalDelay": r"D = (\d+) ms",
    }
    values = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if match is None:
            fail("sealed amendment lacks Future Work value: " + name)
        values[name] = match.group(1)
    # The grid placement and trace-validation claims consume amendment 005,
    # whose bytes are checked above even though they need no numeric macros.
    write_json(GENERATED / "future-work-provenance.json", {"sources": sources, "macros": values})
    return values


def performance_macros() -> dict[str, str]:
    rows = list(csv.DictReader((DATA / "performance-results.csv").open(encoding="utf-8")))
    values = {}
    for selection, prefix in (("disabled", "PerfDisabled"), ("enabled_fixed_ttl_5s", "PerfCached")):
        selected = {row["component"]: row for row in rows if row["selection"] == selection
                    and row["source_relative_path"].endswith("gateway-latency.json")}
        counts = {int(selected[key]["sample_count"]) for key in ("authorization_api", "gateway_enforcement", "warning_to_enforcement")}
        if len(counts) != 1:
            fail("performance component sample counts differ")
        values[prefix + "Samples"] = str(counts.pop())
        for component, suffix in (("authorization_api", "Authorization"), ("gateway_enforcement", "Gateway"), ("warning_to_enforcement", "Warning")):
            values[prefix + suffix] = format(float(selected[component]["p95_ms"]) * 1000, ".6f").rstrip("0").rstrip(".")
        values[prefix + "HitRate"] = selected["authorization_api"]["cache_hit_rate"]
    report = read_json(root_path(LIVE / "reports" / "gateway-latency.json"))
    cached = next(row for row in report["selections"] if row["selection"] == "enabled_fixed_ttl_5s")
    values["PerfCacheTTL"] = str(cached["cache_ttl_seconds"])
    return values


def generate_macros() -> None:
    values = {**macro_values(), **future_work_macros(), **performance_macros()}
    write_text(GENERATED / "results-macros.tex", "\n".join("\\newcommand{\\%s}{%s}" % (name, value) for name, value in values.items()))
    write_json(GENERATED / "paper-metadata.json", {
        "title": "TCOP: An Agentic Early Warning and Response Protocol",
        "anonymous": True,
        "template": {
            "official_source": "https://www.usenix.org/conferences/author-resources/paper-templates",
            "note": "A USENIX Security 2027-specific kit was not published when this draft was built. The current official template is copied unchanged and checksummed.",
            "files": {
                "template/usenix2019_v3.1.tex": sha256_file(PAPER / "template" / "usenix2019_v3.1.tex"),
                "template/usenix-2020-09.sty": sha256_file(PAPER / "template" / "usenix-2020-09.sty"),
            },
        },
        "source_artifact_amendment": "spec/v0.6-agent-validation-source-artifact-amendment.md",
        "build_mode": "draft",
    })


def table(name: str, text: str, claims: list[str], inputs: list[str]) -> dict[str, Any]:
    path = TABLES / name
    write_text(path, text)
    return {
        "id": name.removesuffix(".tex"),
        "output": relative(path),
        "script": "scripts/generate_tables.py",
        "function": "generate_tables",
        "input_files": inputs,
        "claims": claims,
        "sha256": sha256_file(path),
    }


def generate_tables() -> None:
    with (DATA / "failure-controls.csv").open(encoding="utf-8") as source:
        control_rows = list(csv.DictReader(source))
    # Check every normalized field against sealed evidence, including the four
    # empty pass values, so stale all-Yes derivatives cannot build a table.
    expected_rows = [{key: "" if value is None else str(value) for key, value in row.items()}
                     for row in failure_control_rows()]
    if control_rows != expected_rows:
        fail("generated failure-control data differs from the evidence map and source records")
    def control_tex(value: str) -> str:
        return value.replace("_", r"\_{}").replace("&", r"\&")
    control_body = []
    for row in control_rows:
        evidence = {
            "live-executed": "live executed",
            "signed-envelope-mutation": "mutation: " + control_tex(row["mutation"]),
            "not-executed": "not executed",
        }[row["evidence_class"]]
        cells = [control_tex(row[field]) for field in
                 ("condition", "expected_behavior", "observed_behavior", "invariant", "pass_label")]
        cells.append(row["source_record"] + "; " + evidence)
        control_body.append(" & ".join(cells) + r" \\")
    rows = [
        table("tab-design-requirements.tex", r"""\begin{table}[t]
\centering\footnotesize
\caption{TCOP design requirements.}
\begin{tabular}{@{}p{0.29\columnwidth}@{\hspace{0.7em}}p{0.62\columnwidth}@{}}\toprule
Requirement & Mechanism \\ \midrule
Signed provenance & Signed TCX context with authorized peer identity \\
Bounded scope and expiry & Scoped, time-bounded context validation \\
Replay protection & Receiver replay checks and fresh local decisions \\
Receiver-local correlation and policy & Domain B correlates and applies its own strategy and policy \\
No remote enforcement command & Imported context never maps directly to allow, deny, quarantine, revoke, or suspend \\
Capability-scoped response & Domain B restricts only locally selected capabilities \\
Audit linkage & Receipt and decision records link context to local action \\
Partition-local operation & Local controls remain available during federation failure \\
Explicit availability cost & Benign restriction impact is measured, not hidden \\ \bottomrule
\end{tabular}\label{tab:requirements}\end{table}""", ["C-ARCH-01", "C-AUTH-01"], ["manifest.json"]),
        table("tab-architecture-comparison.tex", r"""\begin{table*}[t]
\centering\scriptsize
\caption{Complementary system contracts. TCOP supplies a receiver-side evidence-to-authorization boundary; it does not replace threat intelligence, response orchestration, tool access, or agent collaboration protocols.}
\begin{tabular}{@{}p{0.17\textwidth}@{\hspace{0.35em}}p{0.23\textwidth}@{\hspace{0.35em}}p{0.16\textwidth}@{\hspace{0.35em}}p{0.22\textwidth}@{\hspace{0.35em}}p{0.12\textwidth}@{}}\toprule
System class & Cross-domain object & Bound to pending action? & Receiver validates local action state? & Sender selects response? \\ \midrule
STIX/TAXII & Indicators, reports, collections & No & No & No \\
CACAO/SOAR & Playbooks and courses of action & No & Deployment-specific & May carry a requested response \\
MCP & Tool invocation and authorization context & At tool boundary & Server access context & Client requests tool \\
A2A & Tasks, messages, and artifacts & Task-related & Not a security-evidence contract & Agent requests task \\
TCOP & Signed runtime evidence & Yes & Yes & No \\ \bottomrule
\end{tabular}\label{tab:protocol-comparison}\end{table*}""", ["C-ARCH-01"], ["contracts/architectures.json"]),
        table("tab-units-of-analysis.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Units of analysis and accounting. Counts are not interchangeable across rows.}
\begin{tabular}{@{}p{0.16\textwidth}@{\hspace{0.35em}}p{0.28\textwidth}@{\hspace{0.35em}}p{0.46\textwidth}@{}}\toprule
Unit & Definition & Use in this paper \\ \midrule
Strict pair & One input-equivalent A1/A2 comparison with the same frozen local policy and action schedule & Primary deterministic causal comparison \\
Trace & One captured model-generated action sequence & Live cohort and frozen replay input \\
Replay treatment & One frozen trace evaluated at one action-relative context-delivery placement & Timing and availability accounting \\
Single-environment reference-path arm & One complete source-relay-evaluator-gateway execution in one reference environment & Gateway composition and authority provenance \\
Gateway call & One authorization request for an action opportunity & Harmful and benign forwarded or blocked outcomes \\
Signed exchange & One signed context transfer from \texttt{tcopd}-A to \texttt{tcopd}-B & Relay composition accounting \\
Validation episode & One credential-free mixed-action test case per condition & C0--C3 validation-value cohort \\ \bottomrule
\end{tabular}\label{tab:units}\end{table*}""", ["C-DETERMINISTIC-01", "C-LIVE-01", "C-VALIDATION-01"], ["data/generated/deterministic-pairs.csv", "data/generated/live-trace-cohort.csv", "data/generated/tcx-validation-value.csv"]),
        table("tab-deterministic-summary.tex", r"""\begin{table}[t]\centering\small
\caption{Strict deterministic containment-first comparison. Balanced and utility configurations with unmatched local policies are excluded.}
\begin{tabular}{lr}\toprule
Metric & Value \\ \midrule
Strict input-equivalent pairs & \DeterministicPairs \\
Improved / unchanged / worsened & \DeterministicImproved / \DeterministicUnchanged / \DeterministicWorsened \\
Baseline / treatment harmful calls & \DeterministicBaselineHarmfulCalls / \DeterministicTreatmentHarmfulCalls \\
\shortstack[l]{Harmful actions changed to blocked\\under matched replay} & \DeterministicActionsPrevented/\DeterministicBaselineHarmfulCalls \\
Unmatched-policy exclusions & \DeterministicExcludedPairs \\ \bottomrule
\end{tabular}\label{tab:deterministic}\end{table}""", ["C-DETERMINISTIC-01"], ["data/generated/deterministic-pairs.csv"]),
        table("tab-central-comparator.tex", r"""\begin{table}[t]\centering\small
\caption{Fact-equivalent A3 central-comparator audit. The result is bounded to the evaluated construction.}
\begin{tabular}{lr}\toprule
Audit outcome & Cells \\ \midrule
Fact-equivalent cells & \CentralAuditCells \\
Authority-placement regressions & \CentralAuthorityRegressions \\
Central-outage regressions & \CentralOutageRegressions \\
No regression & \CentralNoRegression \\ \bottomrule
\end{tabular}\label{tab:central-comparator}\end{table}""", ["C-CENTRAL-01", "C-CENTRAL-02"], ["data/generated/deterministic-central-audit.csv"]),
        table("tab-live-cohort.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Credentialed live trace cohort. Errors and refusals are counted before replay.}
\begin{tabular}{@{}lrrrrp{0.42\textwidth}@{}}\toprule
Scenario & Attempts & Eligible & Errors & Refusals & Primary harmful capability type \\ \midrule
RA-01 & 12 & 12 & 0 & 0 & Synthetic prompt-injection propagation: repository write and dataset export \\
RA-02 & 12 & 12 & 0 & 0 & Synthetic credential and tool misuse: credential use, workload spawn, and dataset export \\
RA-03 & 20 & 20 & 0 & 0 & None: frozen benign repository metadata write workflow \\ \midrule
Total & \LiveTraces & \LiveTraces & 0 & 0 & Bounded synthetic cohort \\ \bottomrule
\end{tabular}\label{tab:cohort}\end{table*}""", ["C-LIVE-01"], ["data/generated/live-trace-cohort.csv", "artifacts/v0.6-agent-validation-live-origin-certified/traces/live"]),
        table("tab-physical-end-to-end.tex", r"""\begin{table}[t]\centering\small
\caption{Single-environment reference-path gateway arms. Each block is attributable to a Domain-B-local decision.}
\begin{tabular}{@{}p{0.40\columnwidth}rr@{}}\toprule
Arm & Forwarded & Blocked \\ \midrule
A1, no context & \AOneForwarded & 0 \\
A2, before first opportunity & 0 & \EarlyBlocked \\
A2, after initial harm & \LateForwarded & \LateBlocked \\ \bottomrule
\end{tabular}\label{tab:physical}\end{table}""", ["C-TIMING-01", "C-AUTH-01"], ["data/generated/physical-arms.csv"]),
        table("tab-replay-timing.tex", r"""\begin{table*}[t]\centering\small
\caption{Strict replay timing treatments. A treatment can be too late for one action while still affecting later opportunities.}
\begin{tabular}{@{}p{0.34\columnwidth}rrr@{}}\toprule
Action-relative placement & Improved & Unchanged & Harmful-action delta \\ \midrule
Before first harmful opportunity & 24 & 20 & -72 \\
At first-action authorization boundary & 24 & 20 & -72 \\
After initial harm, before later actions & 24 & 20 & -48 \\
After receiver-local detection & 24 & 20 & -48 \\
After partial local containment & 12 & 32 & -24 \\ \bottomrule
\end{tabular}\label{tab:timing}\end{table*}""", ["C-TIMING-01"], ["data/generated/live-timing-summary.csv"]),
        table("tab-utility.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Measured RA-03 availability cost under selected synthetic false-warning treatments and capability restriction; this is not a universal false-positive rate.}
\begin{tabular}{@{}p{0.22\textwidth}rrrp{0.23\textwidth}p{0.21\textwidth}@{}}\toprule
Treatment group & Attempted & Forwarded & Constrained & Workflow completion & Affected capability \\ \midrule
Inside-window early and boundary & \InsideWindowBenignAttempted & \InsideWindowBenignForwarded & \InsideWindowBenignConstrained & \InsideWindowWorkflowCompleted/\InsideWindowWorkflowTotal & repository.write in frozen benign metadata workflow \\
No context, outside window, post-detection, and post-containment & \OutsideWindowBenignAttempted & \OutsideWindowBenignForwarded & 0 & \OutsideWindowWorkflowCompleted/\OutsideWindowWorkflowTotal & no restriction in these treatments \\ \midrule
All selected treatments & \BenignAttempted & \BenignForwarded & \BenignConstrained & \WorkflowCompleted/\WorkflowTotal (\WorkflowCompletionRate) & selected synthetic capability restriction \\ \bottomrule
\end{tabular}\label{tab:utility}\end{table*}""", ["C-UTILITY-01", "C-UTILITY-02"], ["data/generated/utility-results.csv"]),
        table("tab-tcx-validation-value.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Mixed-action validation-value cohort governed by a sealed pre-analysis plan. Full-cohort harmful counts include mismatched-warning controls; the accepted binding-matched subset is reported separately in the text.}
\begin{tabular}{@{}p{0.43\columnwidth}rr@{}}\toprule
Condition & \shortstack{Harmful\\blocked} & \shortstack{Benign\\constrained} \\ \midrule
Local Only (C0) & \CZeroHarmfulBlocked/\ValidationEpisodes & \CZeroBenignConstrained/\ValidationEpisodes \\
Arrival Default Allow (C1-allow) & \COneAllowHarmfulBlocked/\ValidationEpisodes & \COneAllowBenignConstrained/\ValidationEpisodes \\
Arrival Guard (C1-class) & \COneClassHarmfulBlocked/\ValidationEpisodes & \COneClassBenignConstrained/\ValidationEpisodes \\
Exact Binding (C2) & \CTwoHarmfulBlocked/\ValidationEpisodes & \CTwoBenignConstrained/\ValidationEpisodes \\
Standing Guard (C3) & \CThreeHarmfulBlocked/\ValidationEpisodes & \CThreeBenignConstrained/\ValidationEpisodes \\ \bottomrule
\end{tabular}\label{tab:validation-value}\end{table}""", ["C-VALIDATION-01"], ["data/generated/tcx-validation-value.csv"]),
        table("tab-tcx-protocol-assurance.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Validation-value evidence: executed receiver mutations and formula-computed illustrations.}
\begin{tabular}{@{}p{0.34\columnwidth}@{\hspace{0.4em}}p{0.57\columnwidth}@{}}\toprule
Check & Result \\ \midrule
Valid hostile-peer burst & Formula-computed illustration; no executed burst evidence. \\
Receipt correlation ambiguity & Formula-computed illustration with typed-in zeros; no measured correlation result. \\
Receiver-validator mutations & \ValidatorMutationCases{} mutations cover signature, issuer, version, receipt, expiry, and replay faults; action-like remote fields are retained as evidence and ignored for enforcement. \\ \bottomrule
\end{tabular}\label{tab:protocol-assurance}\end{table}""", ["C-VALIDATION-02", "C-CORRELATION-01", "C-VALIDATOR-01"], ["data/generated/tcx-hostile-peer.csv", "data/generated/tcx-correlation.csv", "artifacts/tcx-validation-value-v2/property-test-report.json"]),
        table("tab-adaptive-authorization.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Post-denial substitution strict replay of receiver-local strategies. Each policy evaluates the same 20 frozen traces: 15 have an eligible harmful substitution and 5 exercise a predeclared safe fallback after initial denial. Local Only does not trigger a post-denial branch.}
\begin{tabular}{@{}p{0.28\columnwidth}@{\hspace{0.1em}}ccc@{}}\toprule
Policy & \shortstack{Initial\\blocked} & \shortstack{Harmful\\completed} & \shortstack{Safe fallback\\forwarded} \\ \midrule
Local Only (C0) & 0/\AdaptiveInitialBlocked & n/a & n/a \\
Arrival Guard (C1) & \AdaptiveInitialBlocked/\AdaptiveInitialBlocked & \AdaptiveCOnePostDenialCompleted/\AdaptiveEligibleHarmfulBranches & \AdaptiveCOneBenignFallbackForwarded/\AdaptiveBenignFallbacks \\
Exact Binding (C2) & \AdaptiveInitialBlocked/\AdaptiveInitialBlocked & \AdaptiveCTwoPostDenialCompleted/\AdaptiveEligibleHarmfulBranches & \AdaptiveCTwoBenignFallbackForwarded/\AdaptiveBenignFallbacks \\
Campaign Correlation (C2E) & \AdaptiveInitialBlocked/\AdaptiveInitialBlocked & \AdaptiveCTwoEPostDenialCompleted/\AdaptiveEligibleHarmfulBranches & \AdaptiveCTwoEBenignFallbackForwarded/\AdaptiveBenignFallbacks \\
Standing Guard (C3) & \AdaptiveInitialBlocked/\AdaptiveInitialBlocked & \AdaptiveCThreePostDenialCompleted/\AdaptiveEligibleHarmfulBranches & \AdaptiveCThreeBenignFallbackForwarded/\AdaptiveBenignFallbacks \\ \bottomrule
\end{tabular}\label{tab:adaptive-authorization}\end{table}""", ["C-ADAPTIVE-01"], ["data/generated/adaptive-authorization.csv", "artifacts/adaptive-agent-authorization-v1/reports/summary.json"]),
        table("tab-c2e-frontier.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Receiver-local strategy frontier. The same 10 harmful and 20 benign logical actions are evaluated per policy; this is a deterministic reference-policy result.}
\begin{tabular}{@{}p{0.48\columnwidth}cc@{}}\toprule
Strategy & \shortstack{Harmful\\blocked} & \shortstack{Benign\\constrained} \\ \midrule
Local Only (C0) & \FrontierCZeroHarmfulBlocked/\FrontierHarmfulAttempted & \FrontierCZeroBenignConstrained/\FrontierBenignAttempted \\
Arrival Guard (C1) & \FrontierCOneHarmfulBlocked/\FrontierHarmfulAttempted & \FrontierCOneBenignConstrained/\FrontierBenignAttempted \\
Exact Binding (C2) & \FrontierCTwoHarmfulBlocked/\FrontierHarmfulAttempted & \FrontierCTwoBenignConstrained/\FrontierBenignAttempted \\
Campaign Correlation (C2E) & \FrontierCTwoEHarmfulBlocked/\FrontierHarmfulAttempted & \FrontierCTwoEBenignConstrained/\FrontierBenignAttempted \\
Standing Guard (C3) & \FrontierCThreeHarmfulBlocked/\FrontierHarmfulAttempted & \FrontierCThreeBenignConstrained/\FrontierBenignAttempted \\ \bottomrule
\end{tabular}\label{tab:c2e-frontier}\end{table}""", ["C-C2E-FRONTIER-01"], ["data/generated/c2e-frontier.csv", "artifacts/c2e-frontier-v1/reports/frontier-summary.json"]),
        table("tab-c2e-frontier-composition.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Campaign Correlation frontier input composition (artifact identifier C2E). The fixed population contains five traces in each principal scenario; session lineage is the only strong relation exercised in this frontier.}
\begin{tabular}{@{}p{0.52\columnwidth}rr@{}}\toprule
Fixed trace class & Harmful & Benign \\ \midrule
Exact-bound action & \FrontierExactBindingHarmful & 0 \\
Non-exact action with receiver session lineage & \FrontierLineageHarmful & 0 \\
Predeclared safe fallback after relation & 0 & \FrontierSafeFallbackBenign \\
Same-risk action outside campaign & 0 & \FrontierOutsideCampaignBenign \\
Unrelated subject, session, or resource & 0 & \FrontierUnrelatedBenign \\
Invalid relation & 0 & \FrontierInvalidRelationControls \\
Expired relation & 0 & \FrontierExpiredRelationControls \\
Replayed relation & 0 & \FrontierReplayedRelationControls \\
Sender-suggested-only relation & 0 & \FrontierSenderSuggestedRelationControls \\ \bottomrule
\end{tabular}\label{tab:c2e-frontier-composition}\end{table}""", ["C-C2E-FRONTIER-01"], ["data/generated/c2e-frontier-composition.csv", "data/generated/c2e-frontier-control-composition.csv", "artifacts/c2e-frontier-v1/study-plan.yaml"]),
        table("tab-independent-warning-full-pipeline.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Full external-warning pipeline coverage. All \ExternalWarningFullSourceCases{} cases in the sealed detector-output ledger are evaluated; a warning is not a detector-quality estimate.}
\begin{tabular}{@{}p{0.62\columnwidth}r@{}}\toprule
Stage or source category & Cases \\ \midrule
Attack-bearing source cases & \ExternalWarningFullAttackCases \\
\quad Detector warning $\rightarrow$ normalized TCX $\rightarrow$ admitted exact binding & \ExternalWarningFullWarnings/\ExternalWarningFullNormalized/\ExternalWarningFullAdmitted \\
\quad Detector no-warning $\rightarrow$ no actionable TCOP evidence & \ExternalWarningFullAttackNoWarning \\
Benign source cases, all detector no-warning & \ExternalWarningFullBenignCases \\
Total no actionable evidence & \ExternalWarningFullNoActionable \\ \bottomrule
\end{tabular}\label{tab:independent-warning-full-pipeline}\end{table}""", ["C-INDEPENDENT-FULL-01"], ["data/generated/independent-warning-full.csv", "artifacts/independent-warning-admission-v3-full-population/reports/pipeline-coverage.json"]),
        table("tab-independent-warning-full-outcomes.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Full-population receiver authorization outcomes over \ExternalWarningFullAttackCases{} attack-bearing and \ExternalWarningFullBenignCases{} benign external source cases. Arrival Guard, Exact Binding, and Campaign Correlation use accepted evidence conditionally; Standing Guard is a standing local restriction.}
\begin{tabular}{@{}lrr|rr@{}}\toprule
Policy & \shortstack{Harmful\\blocked} & \shortstack{Harmful\\forwarded} & \shortstack{Benign\\constrained} & \shortstack{Benign\\forwarded} \\ \midrule
Local Only (C0) & \ExternalWarningFullCZeroBlocked/\ExternalWarningFullAttackCases & \ExternalWarningFullCZeroForwarded/\ExternalWarningFullAttackCases & \ExternalWarningFullCZeroBenignConstrained/\ExternalWarningFullBenignCases & \ExternalWarningFullCZeroBenignForwarded/\ExternalWarningFullBenignCases \\
Arrival Guard (C1) & \ExternalWarningFullCOneBlocked/\ExternalWarningFullAttackCases & \ExternalWarningFullCOneForwarded/\ExternalWarningFullAttackCases & \ExternalWarningFullCOneBenignConstrained/\ExternalWarningFullBenignCases & \ExternalWarningFullCOneBenignForwarded/\ExternalWarningFullBenignCases \\
Exact Binding (C2) & \ExternalWarningFullCTwoBlocked/\ExternalWarningFullAttackCases & \ExternalWarningFullCTwoForwarded/\ExternalWarningFullAttackCases & \ExternalWarningFullCTwoBenignConstrained/\ExternalWarningFullBenignCases & \ExternalWarningFullCTwoBenignForwarded/\ExternalWarningFullBenignCases \\
Campaign Correlation (C2E) & \ExternalWarningFullCTwoEBlocked/\ExternalWarningFullAttackCases & \ExternalWarningFullCTwoEForwarded/\ExternalWarningFullAttackCases & \ExternalWarningFullCTwoEBenignConstrained/\ExternalWarningFullBenignCases & \ExternalWarningFullCTwoEBenignForwarded/\ExternalWarningFullBenignCases \\
Standing Guard (C3) & \ExternalWarningFullCThreeBlocked/\ExternalWarningFullAttackCases & \ExternalWarningFullCThreeForwarded/\ExternalWarningFullAttackCases & \ExternalWarningFullCThreeBenignConstrained/\ExternalWarningFullBenignCases & \ExternalWarningFullCThreeBenignForwarded/\ExternalWarningFullBenignCases \\ \bottomrule
\end{tabular}\label{tab:independent-warning-full-outcomes}\end{table*}""", ["C-INDEPENDENT-FULL-01"], ["data/generated/independent-warning-full.csv", "artifacts/independent-warning-admission-v3-full-population/reports/authorization-outcomes.json"]),
        table("tab-independent-warning-v2-controls.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{Independent Warning Admission v2 derived controls. Each row contains \ExternalWarningVTwoSelectedPositive{} derived cases. The substitution rows contain \ExternalWarningVTwoSessionNoRelationForwarded{} session-lineage and \ExternalWarningVTwoDelegationNoRelationForwarded{} delegation variants.}
\begin{tabular}{@{}p{0.51\columnwidth}p{0.38\columnwidth}@{}}\toprule
Control & Receiver result \\ \midrule
Partial binding & Exact Binding/Campaign Correlation: \ExternalWarningVTwoPartialCTwoERestricted/\ExternalWarningVTwoSelectedPositive{} restrictions \\
Mismatched binding & Exact Binding/Campaign Correlation: \ExternalWarningVTwoMismatchCTwoERestricted/\ExternalWarningVTwoSelectedPositive{} restrictions \\
Stale or replayed context & Campaign Correlation: \ExternalWarningVTwoStaleCTwoERejected/\ExternalWarningVTwoSelectedPositive{} rejected before policy \\
Sender-suggested-only relation & Campaign Correlation: \ExternalWarningVTwoSenderSuggestedCTwoERestricted/\ExternalWarningVTwoSelectedPositive{} restrictions \\
Harmful substitution, no B-local relation & Campaign Correlation: \ExternalWarningVTwoNoRelationCTwoEForwarded/\ExternalWarningVTwoSelectedPositive{} forwarded \\
Harmful substitution, B-local relation & Campaign Correlation: \ExternalWarningVTwoWithRelationCTwoEBlocked/\ExternalWarningVTwoSelectedPositive{} blocked \\ \bottomrule
\end{tabular}\label{tab:independent-warning-v2-controls}\end{table}""", ["C-INDEPENDENT-V2-01"], ["data/generated/independent-warning-v2.csv", "artifacts/independent-warning-admission-v2-external-stratified/reports/derived-control-dispositions.csv", "artifacts/independent-warning-admission-v2-external-stratified/reports/substitution-summary.json"]),
        table("tab-negative-controls.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Negative and failure controls. Ten controls (NC-01--04, NC-07, NC-10--12, NC-14, NC-16) were executed and passed in the sealed live artifact. NC-05 and NC-09 are covered by executed signed-envelope mutations in \protect\path{artifacts/tcx-validation-value-v2/property-test-report.json} (\texttt{issuer} and \texttt{action\_semantic}, respectively), not by live injections. Four rows (NC-06, NC-08, NC-13, NC-15) were recorded as passed in the sealed live artifact without executing the condition; they are untested design properties, not results. See the artifact's known-issues file, \protect\path{docs/KNOWN_ISSUES.md}.}
\begin{tabular}{@{}p{0.15\textwidth}@{\hspace{0.7em}}p{0.20\textwidth}@{\hspace{0.7em}}p{0.20\textwidth}@{\hspace{0.7em}}p{0.12\textwidth}@{\hspace{0.7em}}p{0.08\textwidth}@{\hspace{0.7em}}p{0.18\textwidth}@{}}\toprule
Condition & Expected behavior & Observed behavior & Invariant & Pass & Source / evidence \\ \midrule
""" + "\n".join(control_body) + r""" \bottomrule
\end{tabular}\label{tab:controls}\end{table*}""", ["C-FAILURE-01"], ["data/generated/failure-controls.csv", MUTATION_SOURCE.as_posix(), "docs/KNOWN_ISSUES.md"]),
        table("tab-performance.tex", r"""\begin{table*}[t]\centering\small
\caption{Local harness performance in microseconds, with \PerfDisabledSamples{} samples per selection and component. Authorization uses \texttt{perf\_counter\_ns()} around a Python dictionary cache lookup on hits, or request construction and \texttt{evaluator.authorize()} on misses; it does not time an RPC. The enabled selection is labeled fixed \PerfCacheTTL{}\,s TTL in the artifact, but the timed loop does not exercise expiry. Gateway timing wraps adapter construction and invocation; warning-to-enforcement sums context acceptance and gateway durations. With \PerfDisabledSamples{} samples, p95 and p99 are near the top order statistics. These local harness measurements are not production inter-domain latency estimates.}
\begin{tabular}{lrrrrr}\toprule
Selection & Samples & Authorization p95 ($\mu$s) & Gateway p95 ($\mu$s) & Warning-to-enforcement p95 ($\mu$s) & Hit rate \\ \midrule
Disabled & \PerfDisabledSamples & \PerfDisabledAuthorization & \PerfDisabledGateway & \PerfDisabledWarning & \PerfDisabledHitRate \\
Enabled, fixed \PerfCacheTTL{}\,s TTL & \PerfCachedSamples & \PerfCachedAuthorization & \PerfCachedGateway & \PerfCachedWarning & \PerfCachedHitRate \\ \bottomrule
\end{tabular}\label{tab:performance}\end{table*}""", ["C-PERF-01"], ["data/generated/performance-results.csv"]),
        table("tab-amendment-history.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Live runtime amendment history. Digest prefixes identify the immutable predecessor and successor roots; full digests are retained in the normalized amendment-chain data and source-verification report. The first two predecessor artifacts are retained provider-failure negatives.}
\begin{tabular}{@{}p{0.07\textwidth}@{\hspace{0.2em}}p{0.16\textwidth}@{\hspace{0.2em}}p{0.09\textwidth}@{\hspace{0.2em}}p{0.07\textwidth}@{\hspace{0.2em}}p{0.08\textwidth}@{\hspace{0.2em}}p{0.09\textwidth}@{\hspace{0.2em}}p{0.12\textwidth}@{\hspace{0.2em}}p{0.12\textwidth}@{}}\toprule
Amendment & Cause & Model sampling? & Traces? & Protocol / policy? & Result derivation? & Predecessor digest & Successor digest \\ \midrule
001 & Provider completion-token field & No successful sampling & No & No & No & e5cf49806b70 & 698ca3c116af \\
002 & Provider reasoning mode & No & No & No & No & 698ca3c116af & f9bccfcaeff8 \\
003 & RA-03 eligibility aligned to frozen truth & Yes, eligible cohort capture & No & No & Eligibility only & f9bccfcaeff8 & cebc669a7a3c \\
004 & Completion-gate ordering & No & No & No & No & cebc669a7a3c & 24a20e9c48a2 \\
005 & Derived utility reconciliation & No & No & No & Yes, replay-row aggregation & 24a20e9c48a2 & 2b1f92ff4481 \\
006 & End-to-end tcopd-a relay replay & No & No & No & Reference-deployment evidence & 2b1f92ff4481 & 546f3547b727 \\ \bottomrule
\end{tabular}\label{tab:amendments}\end{table*}""", ["C-LIVE-01"], ["data/generated/amendment-chain.csv", "evidence/source-verification.json"]),
        table("tab-ra03-eligibility-sensitivity.tex", r"""\begin{table}[t]\centering\scriptsize
\caption{RA-03 eligibility correction. The amended rule accepts the already frozen benign metadata capability; deterministic causal counts do not use RA-03.}
\begin{tabular}{@{}p{0.47\columnwidth}rr@{}}\toprule
Rule & Attempts & Eligible \\ \midrule
Pre-correction global rule & \RAThreeBeforeAttempts & \RAThreeBeforeEligible \\
Amendment 003 permitted-capability rule & \RAThreeAfterAttempts & \RAThreeAfterEligible \\ \bottomrule
\end{tabular}\label{tab:ra03-eligibility}\end{table}""", ["C-AMENDMENT-01"], ["data/generated/ra03-eligibility-sensitivity.csv"]),
        table("tab-limitations.tex", r"""\begin{table*}[t]\centering\small
\caption{What the evaluation supports and does not support.}
\begin{tabular}{p{0.3\textwidth}p{0.6\textwidth}}\toprule
Evidence & Supported scope \\ \midrule
Deterministic matched pairs & Causal comparison under matched frozen local policy and synthetic scenarios \\
Executable replay & Exact captured action-sequence comparison without model credentials \\
Live trace generation & A bounded credentialed cohort generated action attempts \\
Single-environment reference-path deployment & A signed tcopd-A-to-tcopd-B path and receiver-local gateway decisions in one reference environment \\
Validation-value and assurance cohort & Semantic binding and executed receiver-validator mutations; hostile-peer and correlation tables are formula-computed illustrations \\
Post-denial substitution replay & Policy-conditioned post-denial branches in a bounded reference runtime, not deployment prevalence \\
Campaign Correlation frontier & Deterministic receiver-local Campaign Correlation selectivity, not a general escalation policy or deployment-effectiveness estimate \\
Full external-warning ledger & All 168 sealed external source cases: 25 accepted exact bindings, 47 attack-bearing no-warning cases, and 96 benign no-warning cases; authorization coverage, not detector-quality evidence \\
Not established & Production deployment, Internet-scale federation, key-lifecycle operation, uninstrumented incidents, or universal superiority to central defense \\ \bottomrule
\end{tabular}\label{tab:limitations}\end{table*}""", ["C-CENTRAL-02", "C-LIMIT-01", "C-LIMIT-02", "C-ADAPTIVE-01", "C-C2E-FRONTIER-01", "C-INDEPENDENT-01"], ["evidence/claim-evidence-ledger.yaml"]),
    ]
    write_json(GENERATED / "table-manifest.json", rows)


def _figure_style() -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.size": 8,
        "font.family": "DejaVu Sans",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })


def save_figure(figure: Any, name: str, claims: list[str], inputs: list[str], caveats: list[str]) -> dict[str, Any]:
    pdf = FIGURES / "pdf" / (name + ".pdf")
    svg = FIGURES / "svg" / (name + ".svg")
    png = FIGURES / "png-preview" / (name + ".png")
    for path in (pdf, svg, png):
        path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(pdf, bbox_inches="tight")
    figure.savefig(svg, bbox_inches="tight")
    figure.savefig(png, dpi=180, bbox_inches="tight")
    return {
        "id": "fig-" + name,
        "output": relative(pdf),
        "svg": relative(svg),
        "preview": relative(png),
        "script": "scripts/generate_figures.py",
        "function": "generate_" + name.replace("-", "_"),
        "input_files": inputs,
        "source_artifacts": [{"digest": spec["expected_digest"], "paths": [spec["path"].as_posix()]} for spec in SOURCE_SPECS],
        "claims": claims,
        "sha256": sha256_file(pdf),
        "caption_caveats": caveats,
    }


def generate_figures() -> None:
    _figure_style()
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    manifest = []

    fig, ax = plt.subplots(figsize=(7.1, 2.7))
    ax.axis("off")
    def box(x: float, y: float, text: str, width: float = 1.2, height: float = .45, color: str = "#e8eef6") -> None:
        ax.add_patch(FancyBboxPatch((x, y), width, height, boxstyle="round,pad=0.02", fc=color, ec="#243746", lw=.8))
        ax.text(x + width / 2, y + height / 2, text, ha="center", va="center", fontsize=7)
    def arrow(x1: float, y1: float, x2: float, y2: float, label: str = "") -> None:
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops={"arrowstyle": "->", "lw": .8, "color": "#243746"})
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + .09, label, ha="center", fontsize=6.5)
    ax.text(.8, 2.4, "Domain A", weight="bold", ha="center")
    ax.text(5.9, 2.4, "Domain B", weight="bold", ha="center")
    box(.1, 1.65, "Agent /\nworkload"); box(1.6, 1.65, "Local\nobserver"); box(3.1, 1.65, "tcopd A", color="#d9ead3")
    box(4.8, 1.65, "tcopd B", color="#d9ead3"); box(6.3, 1.65, "Validate +\ncorrelate"); box(7.8, 1.65, "B policy +\ndecision", color="#fce5cd")
    box(9.3, 1.65, "Gateway /\nactuator", color="#fce5cd")
    arrow(1.3, 1.88, 1.6, 1.88); arrow(2.8, 1.88, 3.1, 1.88); arrow(4.3, 1.88, 4.8, 1.88, "signed bounded context")
    arrow(6.0, 1.88, 6.3, 1.88); arrow(7.5, 1.88, 7.8, 1.88); arrow(9.0, 1.88, 9.3, 1.88, "B-local decision")
    ax.text(2.9, .92, "No cross-domain enforcement call", color="#8a1c1c", ha="center", fontsize=6.8, weight="bold")
    ax.text(8.35, .92, "Gateway consumes only\nDomain-B-local policy and decision", color="#8a1c1c", ha="center", fontsize=6.6, weight="bold")
    ax.set_xlim(-.1, 10.7); ax.set_ylim(.7, 2.65)
    manifest.append(save_figure(fig, "architecture", ["C-ARCH-01", "C-AUTH-01"], ["manifest.json", "reports/authorization-audit.json"], ["Domain A cannot directly invoke Domain B enforcement."]))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.1, 2.5))
    ax.axis("off")
    events = [("Observation", .6), ("Context", 1.55), ("Federation", 2.4), ("B decision", 3.25), ("Gateway", 4.05), ("Action 1", 4.9), ("Action 2", 5.75), ("Action 3", 6.6)]
    ax.hlines(1.25, .4, 6.85, color="#243746")
    for label, x in events:
        ax.vlines(x, 1.12, 1.38, color="#243746")
        ax.text(x, 1.48, label, rotation=35, ha="right", fontsize=7)
    cases = [
        (.7, .45, 4.8, "A: context before action 1 - prospective prevention", "#d9ead3"),
        (.35, 5.02, 6.55, "B: after action 1 - later-action blast-radius reduction", "#fff2cc"),
        (.02, 6.72, 6.86, "C: after all actions - forensic / coordination only", "#f4cccc"),
    ]
    for y, start, end, label, color in cases:
        ax.add_patch(FancyBboxPatch((start, y), end-start, .2, boxstyle="round,pad=.02", fc=color, ec="#555", lw=.6))
        ax.text((start + end) / 2, y + .1, label, ha="center", va="center", fontsize=6.7)
    ax.set_xlim(.25, 7.0); ax.set_ylim(-.08, 2.05)
    manifest.append(save_figure(fig, "containment-window", ["C-TIMING-01", "C-LIMIT-01"], ["data/generated/live-timing-summary.csv"], ["A context can be too late for one action but early enough for later actions."]))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.8, 1.55))
    left = 0
    for value, color, label in zip([30, 24, 0], ["#4d7c59", "#a8a8a8", "#ba4a4a"], ["Improved: 30", "Unchanged: 24", "Worsened: 0"]):
        ax.barh(["Strict pairs"], [value], left=left, color=color, edgecolor="white", height=.5, label=label)
        if value:
            ax.text(left + value / 2, 0, str(value), ha="center", va="center", color="white", weight="bold")
        left += value
    ax.set_xlim(0, 54); ax.set_xlabel("Strict input-equivalent pairs"); ax.set_yticks([])
    ax.legend(loc="lower center", ncol=3, bbox_to_anchor=(.5, -.55), frameon=False, fontsize=7)
    ax.text(54, .38, "Matched synthetic conditions: 39 calls reduced to 3", ha="right", fontsize=7)
    manifest.append(save_figure(fig, "deterministic-outcomes", ["C-DETERMINISTIC-01"], ["data/generated/deterministic-pairs.csv"], ["Unchanged pairs are shown explicitly."]))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.6, 2.2))
    labels, forwarded, blocked = ["A1\nno context", "A2\nbefore first opportunity", "A2\nafter initial harm"], [30, 0, 10], [0, 30, 20]
    ax.bar(labels, forwarded, color="#8da0cb", label="Forwarded harmful calls")
    ax.bar(labels, blocked, bottom=forwarded, color="#66a061", label="Blocked harmful calls")
    for index, (was_forwarded, was_blocked) in enumerate(zip(forwarded, blocked)):
        if was_forwarded:
            ax.text(index, was_forwarded / 2, str(was_forwarded), ha="center", va="center", color="white", weight="bold", fontsize=7)
        if was_blocked:
            ax.text(index, was_forwarded + was_blocked / 2, str(was_blocked), ha="center", va="center", color="white", weight="bold", fontsize=7)
    fig.suptitle("Single-environment reference path", y=.98, fontsize=9)
    ax.set_ylabel("Harmful gateway calls"); ax.set_ylim(0, 34)
    ax.legend(frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(.5, 1.02), ncol=2)
    fig.subplots_adjust(top=.70)
    manifest.append(save_figure(fig, "physical-timing", ["C-TIMING-01"], ["data/generated/physical-arms.csv"], ["Single-environment reference path; the late arm separates completed calls from subsequent blocked calls."]))
    plt.close(fig)

    timing = list(csv.DictReader((DATA / "live-timing-summary.csv").open(encoding="utf-8")))
    labels = ["Early", "Boundary", "After initial harm", "Post detection", "Post containment"]
    improved = [int(row["improved"]) for row in timing]
    unchanged = [int(row["unchanged"]) for row in timing]
    deltas = [int(row["harmful_action_delta"]) for row in timing]
    fig, ax = plt.subplots(figsize=(6.7, 2.45))
    x = list(range(len(labels)))
    ax.bar(x, improved, color="#4d7c59", label="Improved")
    ax.bar(x, unchanged, bottom=improved, color="#b0b0b0", label="Unchanged")
    for index, delta in enumerate(deltas):
        ax.text(index, 47.0, "$\\Delta$ calls\n" + str(delta) + "\n$n=44$ pairs", ha="center", va="center", fontsize=5.5)
    ax.set_xticks(x, labels, rotation=20, ha="right"); ax.set_ylabel("Strict paired replays"); ax.set_ylim(0, 52)
    ax.legend(frameon=False, fontsize=7, ncol=2, loc="lower center", bbox_to_anchor=(.5, 1.04))
    fig.subplots_adjust(top=.76)
    manifest.append(save_figure(fig, "live-replay-treatments", ["C-TIMING-01", "C-LIVE-01"], ["data/generated/live-timing-summary.csv"], ["Early and boundary share the tested discrete preauthorization region."]))
    plt.close(fig)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(5.8, 2.0), gridspec_kw={"width_ratios": [1.3, 1]})
    ax1.barh(["RA-03 benign calls"], [320], color="#4d7c59", label="Forwarded")
    ax1.barh(["RA-03 benign calls"], [40], left=320, color="#c67b45", label="Constrained")
    ax1.set_xlim(0, 360); ax1.set_xlabel("Calls"); ax1.legend(frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(.5, -.6), ncol=2)
    ax2.bar(["Completed", "Not completed"], [80, 40], color=["#4d7c59", "#c67b45"]); ax2.set_ylim(0, 120); ax2.set_ylabel("Workflows")
    manifest.append(save_figure(fig, "security-availability", ["C-UTILITY-01", "C-UTILITY-02"], ["data/generated/utility-results.csv"], ["The constrained calls are a measured synthetic-treatment cost, not a universal false-positive rate."]))
    plt.close(fig)

    frontier_rows = list(csv.DictReader((DATA / "c2e-frontier.csv").open(encoding="utf-8")))
    frontier = {
        policy: {
            "harmful_blocked": sum(row["harmful_blocked"] == "True" for row in frontier_rows if row["policy"] == policy),
            "benign_constrained": sum(row["benign_constrained"] == "True" for row in frontier_rows if row["policy"] == policy),
        }
        for policy in ("C0", "C1", "C2", "C2E", "C3")
    }
    fig, ax = plt.subplots(figsize=(3.25, 2.15))
    colors = {"C0": "#9e9e9e", "C1": "#c67b45", "C2": "#5b8db8", "C2E": "#4d7c59", "C3": "#8e5ea2"}
    labels = {"C0": "Local", "C1": "Arrival", "C2": "Exact", "C2E": "Campaign", "C3": "Standing"}
    offsets = {"C0": (4, 5), "C1": (-30, 5), "C2": (4, 4), "C2E": (4, -12), "C3": (-30, -12)}
    for policy in ("C0", "C1", "C2", "C2E", "C3"):
        point = frontier[policy]
        ax.scatter(point["benign_constrained"], point["harmful_blocked"], s=34, color=colors[policy], zorder=3)
        ax.annotate(labels[policy], (point["benign_constrained"], point["harmful_blocked"]), xytext=offsets[policy], textcoords="offset points", fontsize=7, weight="bold")
    ax.set_xlabel("Benign actions constrained (of 20)", fontsize=7)
    ax.set_ylabel("Harmful actions blocked (of 10)", fontsize=7)
    ax.set_xlim(-.8, 10.8); ax.set_ylim(-.8, 10.8)
    ax.set_xticks([0, 5, 10]); ax.set_yticks([0, 5, 10])
    ax.grid(color="#d9d9d9", linewidth=.6, zorder=0)
    fig.tight_layout(pad=.35)
    manifest.append(save_figure(fig, "c2e-policy-frontier", ["C-C2E-FRONTIER-01"], ["data/generated/c2e-frontier.csv"], ["Deterministic receiver-local policy frontier; not a deployment-effectiveness result."]))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.1, 2.35)); ax.axis("off")
    lineage = [
        ("Deterministic\n0ab19a", .3, "#d9ead3"),
        ("Scripted parent\ncfc539", 1.65, "#d9ead3"),
        ("Provider-failure\npredecessors", 3.0, "#f4cccc"),
        ("001-003\ntrace capture", 4.35, "#fff2cc"),
        ("004-005\ncertification", 5.7, "#fff2cc"),
        ("006 reference deployment\n546f354", 7.05, "#cfe2f3"),
    ]
    for label, x, color in lineage:
        ax.add_patch(FancyBboxPatch((x, .85), 1.05, .55, boxstyle="round,pad=.03", fc=color, ec="#243746", lw=.8))
        ax.text(x + .525, 1.125, label, ha="center", va="center", fontsize=6.8)
    for (_, x, _), (_, next_x, _) in zip(lineage, lineage[1:]):
        ax.annotate("", xy=(next_x, 1.125), xytext=(x + 1.05, 1.125), arrowprops={"arrowstyle": "->", "lw": .8})
    ax.text(4.25, .35, "All amendments retain source traces and document predecessor roots.", ha="center", fontsize=7)
    ax.set_xlim(.05, 8.25); ax.set_ylim(.1, 1.8)
    manifest.append(save_figure(fig, "artifact-lineage", ["C-LIVE-01"], ["data/generated/amendment-chain.csv"], ["The first two provider-failure artifacts remain retained negative results."]))
    plt.close(fig)
    write_json(GENERATED / "figure-manifest.json", manifest)


def claim_ledger() -> list[dict[str, Any]]:
    base = {
        "scope": "bounded synthetic TCOP v0.6 evaluation",
        "extraction_script_function": "scripts/paperlib.py:extract_results",
        "assumptions": ["frozen source roots verify", "synthetic test environment"],
        "evidence_strength": "artifact-backed",
    }
    entries = [
        ("C-ARCH-01", "TCOP exchanges signed, bounded context that the receiver treats as evidence rather than an enforcement command.", "architecture", "artifacts/tcx-validation-value-v2", ["canonical-tcx-example.json", "property-test-report.json"], "Action and enforcement metadata are ignored by the receiver evaluator.", [], "03-architecture-protocol.tex", "fig-tcx-acceptance", "supported"),
        ("C-AUTH-01", "Every gateway block in the evaluated end-to-end reference-deployment arms references a Domain-B-local policy and decision.", "authority", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/authorization-audit.json", "reports/end-to-end-live-results.json"], "Every reference-deployment gateway block references a Domain-B policy and decision.", [], "04-local-resolution-enforcement.tex", "tab-physical-end-to-end", "supported"),
        ("C-AUTH-02", "Remote action metadata was ignored in the tested receiver path.", "authority", "artifacts/tcx-validation-value-v2", ["property-test-report.json"], "The accepted action-semantic mutation ignores remote action and enforcement fields.", [], "04-local-resolution-enforcement.tex", "tab-protocol-assurance", "supported"),
        ("C-DETERMINISTIC-01", "Across 54 strict deterministic pairs, containment-first reduced 39 baseline harmful calls to 3; 36 harmful actions forwarded without context changed to blocked with matched context under strict replay; it changed 30 outcomes and left 24 unchanged.", "deterministic evaluation", "artifacts/federated-domain-v0.6-evidence", ["pairs/paired-results.jsonl", "reports/paired-causal-comparison.json"], "54 pairs; 39 baseline calls; 3 treatment calls; 36 changed from forwarded to blocked under matched replay.", ["123 unmatched balanced or utility comparisons; zero worsened follows containment-first monotonicity for this metric."], "06-deterministic-evaluation.tex", "fig-deterministic-outcomes", "supported"),
        ("C-VALIDATION-01", "In the sealed-plan v2 mixed-action cohort, C1-class blocked 7 of 12 harmful actions and constrained 7 benign actions; C2 blocked 3 of 12 and constrained none. In the accepted binding-matched subset, both blocked 3 of 3 harmful actions.", "validation value", "artifacts/tcx-validation-value-v2", ["reports/condition-summary.json", "reports/matching-harmful-summary.json", "reports/gates.json"], "Full cohort C1-class/C2 harmful blocks 7/3; benign constraints 7/0; matching subset 3/3 each.", ["Synthetic credential-free cohort only; C2 rejects mismatched-warning controls rather than applying a broad class guard."], "06-deterministic-evaluation.tex", "tab-validation-value", "supported with qualification"),
        ("C-VALIDATION-02", "The hostile-peer burst table is formula-computed, not an executed or measured study.", "hostile peer", "artifacts/tcx-validation-value-v2", ["hostile-peer-results.csv", "reports/gates.json"], "Declared formulas only; no executed burst evidence.", ["Not empirical evidence; see docs/KNOWN_ISSUES.md."], "08-security-availability.tex", "tab-protocol-assurance", "supported with qualification"),
        ("C-CORRELATION-01", "The correlation table is formula-computed with typed-in zero misbindings and cross-session restrictions, not a measured study.", "correlation", "artifacts/tcx-validation-value-v2", ["correlation-results.csv", "reports/gates.json"], "Declared formulas and typed-in zeros only.", ["Not empirical evidence; see docs/KNOWN_ISSUES.md."], "06-deterministic-evaluation.tex", "tab-protocol-assurance", "supported with qualification"),
        ("C-VALIDATOR-01", "Eleven deterministic receiver-validator mutations produced no restriction for signature, issuer, version, receipt, expiry, or replay faults; accepted action-like metadata did not select enforcement.", "receiver validator", "artifacts/tcx-validation-value-v2", ["property-test-report.json"], "11 mutation cases; action and enforcement fields ignored.", ["Mutation corpus, not a formal proof."], "04-local-resolution-enforcement.tex", "tab-protocol-assurance", "supported with qualification"),
        ("C-ADAPTIVE-01", "Across 100 strict policy-conditioned replay episodes, Exact Binding permits 15 of 15 eligible harmful post-denial substitutions; the evaluated Campaign Correlation strategy permits none. Each imported-evidence strategy forwards all 5 of 5 exercised predeclared safe fallback actions.", "adaptive authorization", "artifacts/adaptive-agent-authorization-v1", ["normalized-results.jsonl", "reports/summary.json", "campaign-correlation-contract.json"], "Exact Binding: 15/15 post-denial harmful completions; Campaign Correlation: 0/15; every imported-evidence strategy: 5/5 exercised safe fallbacks forwarded.", ["Bounded reference runtime and predeclared branches; the safe-fallback result does not measure unrelated same-risk actions, deployment prevalence, or universal containment."], "07-agent-gateway-evaluation.tex", "tab-adaptive-authorization", "supported with qualification"),
        ("C-C2E-FRONTIER-01", "In the sealed 150-episode C2E frontier, the receiver-local campaign strategy blocks 10 of 10 harmful actions, including 5 campaign-linked non-exact substitutions, while constraining 0 of 20 benign actions. C1 and C3 block the same 10 harmful actions while constraining 10 benign actions each.", "receiver strategy frontier", "artifacts/c2e-frontier-v1", ["normalized-results.jsonl", "reports/frontier-summary.json", "control-results.jsonl", "escalation-lifecycle.jsonl"], "C2E: 10/10 harmful blocked and 0/20 benign constrained; campaign-linked non-exact harmful: 5/5 blocked; outside-campaign benign: 5/5 forwarded; C1/C3: 10/20 benign constrained; 0 unrelated restrictions.", ["Deterministic receiver-local reference strategy only; not deployment prevalence, detector quality, universal containment, or a generally optimal escalation policy."], "07-agent-gateway-evaluation.tex", "tab-c2e-frontier", "supported with qualification"),
        ("C-INDEPENDENT-V2-01", "On 12 hash-selected exact-warning harmful and 12 benign no-warning external AgentDojo bases, C2 and C2E block all harmful bases and constrain no benign bases; C3 constrains all benign bases. Derived controls produce no C2/C2E restriction for partial or mismatched bindings, reject stale and replayed context before policy, and cause C2E to block related substitutions only after receiver-local relation creation.", "independent warning admission", "artifacts/independent-warning-admission-v2-external-stratified", ["candidate-ledger.csv", "selection-ledger.csv", "normalized-results.jsonl", "reports/external-base-dispositions.csv", "reports/derived-control-dispositions.csv", "reports/substitution-summary.json", "reports/gates.json"], "25 attack-bearing prompt-attack candidates, 47 attack-bearing no-warning candidates, and 96 benign no-warning candidates; 12 selected external bases per principal stratum; 540 policy rows; C2/C2E 12/12 blocks and 0/12 benign constraints; C3 12/12 benign constraints; C2E 12/12 no-relation substitutions forwarded and 12/12 locally related substitutions blocked.", ["Hash-selected external integration cohort plus derived controls; it does not estimate detector quality, warning prevalence, arbitrary warning-source behavior, or production effectiveness."], "08-security-availability.tex", "tab-independent-warning-v2-base", "supported with qualification"),
        ("C-INDEPENDENT-FULL-01", "Across the complete sealed 168-case external-warning ledger, the conditional receiver strategies C1, C2, and C2E block 25 of 72 attack-bearing cases with accepted exact evidence and forward 47 no-warning attack-bearing cases; they forward 96 of 96 benign no-warning cases. C3 blocks 72 of 72 harmful cases while constraining 96 of 96 benign cases.", "external-warning coverage", "artifacts/independent-warning-admission-v3-full-population", ["candidate-ledger.csv", "normalized-results.jsonl", "reports/pipeline-coverage.json", "reports/authorization-outcomes.json", "reports/gates.json"], "168 source cases: 72 attack-bearing and 96 benign; 25 detector warnings, normalized TCX objects, admissions, and exact bindings; 47 attack-bearing no-warning cases; C1/C2/C2E 25/72 harmful blocks and 0/96 benign constraints; C3 72/72 harmful blocks and 96/96 benign constraints.", ["Uses preserved detector outputs and frozen policy semantics; it does not measure detector quality, field prevalence, arbitrary warning-source behavior, or production effectiveness."], "08-security-availability.tex", "tab-independent-warning-full-outcomes", "supported with qualification"),
        ("C-AMENDMENT-01", "The retained RA-03 eligibility correction changes the permitted-capability rule from 0 of 60 eligible attempts to 20 of 20 eligible attempts; it affects the benign availability cohort, not the deterministic causal comparison.", "amendment sensitivity", "artifacts/v0.6-agent-validation-live-amendment-002", ["reports/trace-eligibility-report.json", "artifacts/v0.6-agent-validation-live-amendment-003/reports/trace-eligibility-report.json"], "0/60 before correction; 20/20 after correction.", ["Post hoc eligibility correction remains visible and separately bounded."], "amendment-history.tex", "tab-ra03-eligibility", "supported with qualification"),
        ("C-LIVE-01", "The certified cohort contains 44 live traces and 220 strict paired comparisons.", "live trace cohort", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/trace-generation-summary.json", "reports/paired-enforcement-results.json"], "44 eligible traces; 220 pairs.", [], "07-agent-gateway-evaluation.tex", "tab-live-cohort", "supported"),
        ("C-UTILITY-01", "Across six RA-03 replay treatments, 360 benign calls were attempted, 320 forwarded, and 40 constrained.", "availability", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/benign-workload-impact.json"], "360 / 320 / 40.", ["Synthetic false-warning treatments and capability restriction"], "08-security-availability.tex", "fig-security-availability", "supported with qualification"),
        ("C-UTILITY-02", "In inside-window early and boundary false-warning treatments, 40 of 120 benign calls were constrained and 0 of 40 affected workflows completed; outside those treatments, 240 of 240 benign calls were forwarded and 80 of 80 workflows completed.", "availability", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/benign-workload-impact.json"], "Inside-window: 120 / 80 / 40 calls and 0/40 workflows; remaining treatments: 240 / 240 / 0 calls and 80/80 workflows.", ["Synthetic workload only"], "08-security-availability.tex", "tab-utility", "supported with qualification"),
        ("C-FAILURE-01", "Ten executed live controls passed: invalid signature, wrong receipt, expired context, replayed context, monitor-only policy, gateway cache disabled, tcopd B unavailable, authorization timeout, stale decision, and arrival after local containment. Unknown peer and remote TCX action are covered by two executed signed-envelope mutations. Disallowed import type, no remote enforcement, gateway restart, and session termination before arrival were not executed and remain untested design properties.", "failure controls", "artifacts/v0.6-agent-validation-live-origin-certified; artifacts/tcx-validation-value-v2", ["artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json", MUTATION_SOURCE.as_posix(), "docs/KNOWN_ISSUES.md"], "10 executed live controls passed; 2 covered by executed signed-envelope mutations; 4 not executed. issuer: identity_unknown, restriction_created=false; action_semantic: action and enforcement ignored.", ["Six live flags recorded passes without executing the named condition; only NC-05 and NC-09 have separate executed mutation evidence."], "08-security-availability.tex", "tab-negative-controls", "supported with qualification"),
        ("C-PERF-01", "Measured sub-millisecond values are deterministic local harness measurements, not production or inter-organizational latency estimates.", "performance", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/gateway-latency.json", "reports/federation-latency.json"], "Performance-only selections with 20 samples each; perf_counter_ns wraps dictionary hit lookup or request construction plus evaluator.authorize on misses; p95/p99 are near top order statistics. The TTL-labeled loop does not exercise expiry.", ["No production latency inference"], "07-agent-gateway-evaluation.tex", "tab-performance", "supported with qualification"),
        ("C-CENTRAL-01", "Across 54 fact-equivalent audited cells, the central comparator records six regressions: three associated with authority placement and three with central outage.", "central comparator", "artifacts/federated-domain-v0.6-evidence", ["reports/central-comparator-audit.json"], "54 fact-equivalent cells; three authority-placement and three outage regressions.", [], "06-deterministic-evaluation.tex", "tab-central-comparator", "supported with qualification"),
        ("C-CENTRAL-02", "The evaluation does not establish universal superiority over centralized defense.", "limitation", "artifacts/federated-domain-v0.6-evidence", ["reports/central-comparator-audit.json"], "Bounded comparator scope.", [], "10-limitations-conclusion.tex", "tab-limitations", "supported"),
        ("C-LIMIT-01", "TCOP does not create detections and cannot prevent an origin compromise that no participating observer detects in time.", "limitation", "architecture", ["benchmark/studies/v0.6-agent-validation.yaml", "reports/containment-window-agent-results.json"], "Context is actionable only before consequential actions.", [], "10-limitations-conclusion.tex", "fig-containment-window", "supported with qualification"),
        ("C-FUTURE-01", "The pre-registered cross-host study compares bare-agent, sandbox, and runtime-bound TCOP modes; native and harness results remain separate. A binding can prevent a harmful action only if its effect precedes that action; the harness instant cut tests the gap from native polling.", "future study design", "spec", ["spec/external-warning-adaptive-crosshost-amendment-003.md", "spec/external-warning-adaptive-crosshost-amendment-004.md", "spec/external-warning-adaptive-crosshost-amendment-005.md", "paper/usenix27/generated/future-work-provenance.json"], "E0/E1/E2; abstract tightening actions bound per runtime; native and harness primitives never pooled; polling versus instant-cut timing prediction.", ["Pre-registered future work, not an executed cross-host result."], "10-limitations-conclusion.tex", "none", "supported with qualification"),
        ("C-LIMIT-02", "The Docker MCP Gateway is a reference enforcement point, not a reconstruction of a public incident architecture.", "limitation", "integrations/mcp-gateway", ["GATEWAY_SELECTION.md"], "Reference-only gateway role.", [], "07-agent-gateway-evaluation.tex", "tab-limitations", "supported"),
    ]
    prohibited = [
        "TCOP would have prevented the OpenAI/Hugging Face incident.",
        "TCOP eliminates harmful agent behavior.",
        "TCOP is superior to centralized defense.",
        "TCOP has production sub-millisecond latency.",
        "TCOP works at Internet scale.",
        "No benign cost was observed.",
        "The system automatically knows which remote warning is true.",
        "Outside-window context reversed completed harm.",
        "P7 improved forensic reconstruction.",
        "Balanced and utility strategies matched A1 causally.",
    ]
    records = []
    for entry in entries:
        claim_id, wording, category, source, files, values, exclusions, section, target, status = entry
        records.append({
            **base,
            "claim_id": claim_id,
            "proposed_paper_wording": wording,
            "claim_category": category,
            "source_artifact": source,
            "exact_source_files": files,
            "exact_supporting_values": values,
            "relevant_population_denominator": "specified in source rows",
            "exclusions": exclusions,
            "caveats": exclusions or ["bounded evaluation scope"],
            "planned_paper_section": section,
            "planned_table_figure": target,
            "status": status,
        })
    for index, wording in enumerate(prohibited, 1):
        records.append({
            **base,
            "claim_id": "P-{0:02d}".format(index),
            "proposed_paper_wording": wording,
            "claim_category": "prohibited formulation",
            "source_artifact": "none",
            "exact_source_files": [],
            "exact_supporting_values": "None; prohibited.",
            "relevant_population_denominator": "not applicable",
            "exclusions": [],
            "caveats": ["Do not use."],
            "planned_paper_section": "all",
            "planned_table_figure": "none",
            "status": "prohibited",
        })
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "claim-evidence-ledger.yaml").write_text(yaml.safe_dump({"claims": records}, sort_keys=False), encoding="utf-8")
    lines = ["# Claim-Evidence Ledger", "", "| Claim | Status | Supporting values | Caveat |", "|---|---|---|---|"]
    for row in records:
        lines.append("| {0} | {1} | {2} | {3} |".format(row["claim_id"], row["status"], row["exact_supporting_values"], "; ".join(row["caveats"])))
    write_text(EVIDENCE / "claim-evidence-ledger.md", "\n".join(lines))
    terminology = {
        "trust_domain": "An independently governed security or administrative domain that observes locally and retains local enforcement authority.",
        "tcx_context": "Signed, scoped, time-bounded evidence/context exchanged between domains.",
        "receiver_local_decision": "A decision created by the receiving domain using its own correlation, strategy, and policy.",
        "containment_window": "The interval during which imported context can still change local enforcement before a specified harmful action completes.",
        "blast_radius_reduction": "Prevention or restriction of subsequent harmful actions after some earlier harm may already have occurred.",
        "interaction_receipt": "An opaque Domain-B-minted correlation handle. It is neither an authorization token nor an enforcement command.",
        "action_relative_treatment_labels": [
            "before the first harmful opportunity",
            "at the first-action authorization boundary",
            "after initial harm but before subsequent harmful actions",
            "after receiver-local detection",
            "after partial local containment",
        ],
    }
    (EVIDENCE / "terminology.yaml").write_text(yaml.safe_dump(terminology, sort_keys=False), encoding="utf-8")
    write_text(EVIDENCE / "citation-audit.md", """# Citation Audit

The manuscript cites primary standards or authoritative sources for STIX/TAXII, MISP, RID, DOTS, OpenC2, CACAO, zero trust, RATS, SPIFFE federation, MCP authorization, A2A, ANP, and the motivating incident. It also cites peer-reviewed work on SOAR use, macaroons, collaborative intrusion detection, and agent prompt injection. Related work is framed as a design comparison, not as a first-system claim.
""")
    return records


def verify_claims(output_dir: Path | None = None) -> dict[str, Any]:
    output_dir = EVIDENCE if output_dir is None else output_dir
    ledger = yaml.safe_load((EVIDENCE / "claim-evidence-ledger.yaml").read_text(encoding="utf-8"))["claims"]
    source_files = [PAPER / "main.tex", *(PAPER / "sections").glob("*.tex"), *(PAPER / "appendices").glob("*.tex")]
    manuscript = "\n".join(path.read_text(encoding="utf-8") for path in source_files)
    prohibited = [row["proposed_paper_wording"] for row in ledger if row["status"] == "prohibited"]
    hits = [phrase for phrase in prohibited if phrase.lower() in manuscript.lower()]
    central = [row for row in ledger if row["claim_id"].startswith("C-")]
    result = {
        "claims": len(ledger),
        "central_claims": len(central),
        "supported": sum(row["status"] == "supported" for row in central),
        "qualified": sum(row["status"] == "supported with qualification" for row in central),
        "unresolved": [row["claim_id"] for row in central if row["status"] == "unresolved"],
        "prohibited_phrase_hits": hits,
        "pass": not hits and not any(row["status"] == "unresolved" for row in central),
    }
    write_json(output_dir / "claim-audit.json", result)
    if not result["pass"]:
        fail("unsupported or prohibited manuscript claim")
    return result


def audit_numbers(output_dir: Path | None = None) -> dict[str, Any]:
    output_dir = EVIDENCE if output_dir is None else output_dir
    approved = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "2027", "0.6", "0.1", "5s", "01", "02", "03"}
    ignored = re.compile(
        r"(\\input|\\includegraphics|\\label|\\ref|\\cite|\\bibliography|"
        r"\\documentclass|\\usepackage|\\vspace|\\hspace|\\begin\{minipage\}|"
        r"\\parbox|Canonical TCX|protocol\\_version:|issued\\_at:|expires\\_at:|"
        r"\\\[[-0-9.]+em\])"
    )
    findings = []
    files = [PAPER / "main.tex", *(PAPER / "sections").glob("*.tex"), *(PAPER / "appendices").glob("*.tex")]
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if ignored.search(line):
                continue
            for value in re.findall(r"(?<![A-Za-z\\\d-])\d+(?:\.\d+)?(?:\\%)?", line):
                if value.replace("\\%", "") not in approved:
                    findings.append({"file": relative(path), "line": number, "value": value, "line_text": line.strip()})
    result = {
        "audit_version": VERSION,
        "checked_files": [relative(path) for path in files],
        "manual_numeric_claims": findings,
        "pass": not findings,
        "rule": "Principal numeric results must be represented by generated result macros or generated tables.",
    }
    write_json(output_dir / "manuscript-number-audit.json", result)
    if findings:
        fail("manuscript contains unlinked numeric claims")
    return result


def export_anonymous() -> dict[str, Any]:
    review = ARTIFACT / "review"
    if review.exists():
        shutil.rmtree(review)
    review.mkdir(parents=True)
    for name in ("README.md", "QUICKSTART.md", "MANIFEST.json", "expected-results.json", "reproduce.sh"):
        source = ARTIFACT / name
        if source.is_file():
            shutil.copy2(source, review / name)
    for directory in ("data/generated", "figures/pdf", "figures/svg", "tables/generated", "generated", "evidence"):
        source = PAPER / directory
        if source.is_dir():
            shutil.copytree(source, review / directory, dirs_exist_ok=True)
    for source in (PAPER / "main.tex", PAPER / "references.bib"):
        if source.is_file():
            shutil.copy2(source, review / source.name)
    for directory in ("sections", "appendices"):
        source = PAPER / directory
        if source.is_dir():
            shutil.copytree(source, review / directory, dirs_exist_ok=True)
    validation_source = ROOT / "artifacts" / "tcx-validation-value-v2"
    if validation_source.is_dir():
        shutil.copytree(
            validation_source,
            review / "artifact" / "tcx-validation-value-v2",
            dirs_exist_ok=True,
        )
    adaptive_source = ROOT / "artifacts" / "adaptive-agent-authorization-v1"
    if adaptive_source.is_dir():
        shutil.copytree(adaptive_source, review / "artifact" / "adaptive-agent-authorization-v1", dirs_exist_ok=True)
    for artifact_name, extra_paths, note in (
        (
            "independent-warning-admission-v1",
            (),
            "This retained predecessor subset preserves the sealed v1 plan and result manifest. It remains unchanged and is not the source of the manuscript's current independent-warning claim.",
        ),
        (
            "independent-warning-admission-v1-normalizer-amendment-001",
            ("normalizer-manifest.json", "reports/admission-summary.json"),
            "This successor subset preserves the sealed config-derived normalizer, plan, root digest, result manifest, policy frontier, and claim ledger. The raw public benchmark entries, raw detector outputs, and machine-local acquisition metadata remain in the separately sealed root but are omitted here because they contain unredacted corpus content or identifying collection provenance.",
        ),
    ):
        independent_source = ROOT / "artifacts" / artifact_name
        if not independent_source.is_dir():
            continue
        subset = review / "artifact" / artifact_name
        for relative_path in (
            "artifact-root-digest.json", "manifest.json", "study-plan.yaml", "canonical-plan.json",
            "effective-plan-manifest.json", "expected-results.json", "claim-ledger.json", "byte-stability-report.json",
            "policy-definitions.json", "reports/policy-frontier.json", *extra_paths,
        ):
            source = independent_source / relative_path
            if source.is_file():
                target = subset / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        write_text(subset / "ANONYMIZED_REVIEW_SUBSET.md", note)
    independent_v2_source = ROOT / "artifacts" / "independent-warning-admission-v2-external-stratified"
    if independent_v2_source.is_dir():
        subset = review / "artifact" / "independent-warning-admission-v2-external-stratified"
        for relative_path in (
            "artifact-root-digest.json", "manifest.json", "normalizer-spec.json",
            "normalizer-config-digest.json", "expected-results.json", "claim-ledger.json", "control-results.jsonl",
            "reports/gates.json", "reports/byte-stability-report.json", "reports/external-base-dispositions.csv",
            "reports/derived-control-dispositions.csv", "reports/substitution-summary.json", "reports/cohort-summary.json",
        ):
            source = independent_v2_source / relative_path
            if source.is_file():
                target = subset / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        candidates = list(csv.DictReader((independent_v2_source / "candidate-ledger.csv").open(encoding="utf-8")))
        write_json(subset / "candidate-summary.json", {
            "candidate_counts": {"{}:{}".format(*key): value for key, value in Counter((row["source_label"], row["normalized_category"]) for row in candidates).items()},
            "selected_counts": {"{}:{}".format(*key): value for key, value in Counter((row["source_label"], row["normalized_category"]) for row in candidates if row["disposition"] == "selected").items()},
        })
        write_csv(subset / "anonymized-selection-ledger.csv", [
            {"case_ref": hashlib.sha256(row["source_item_id"].encode("utf-8")).hexdigest()[:16], "source_label": row["source_label"], "raw_label": row["raw_label"], "normalized_category": row["normalized_category"], "selection_hash": row["selection_hash"], "disposition": row["disposition"]}
            for row in candidates
        ])
        write_text(subset / "ANONYMIZED_REVIEW_SUBSET.md", "This subset preserves the sealed v2 result, anonymized selection ledger, control dispositions, verifier reports, and root digest. The complete source-provenance manifest and raw case identifiers are available in the accompanying anonymous source-and-artifact archive; they are not duplicated here because corpus path fragments would trigger this package's filesystem-path anonymity scan.")
    independent_full_source = ROOT / "artifacts" / "independent-warning-admission-v3-full-population"
    if independent_full_source.is_dir():
        subset = review / "artifact" / "independent-warning-admission-v3-full-population"
        for relative_path in (
            "artifact-root-digest.json", "manifest.json", "study-plan.yaml", "preanalysis-plan.json",
            "normalizer-spec.json", "expected-results.json", "claim-ledger.json",
            "reports/pipeline-coverage.json", "reports/authorization-outcomes.json", "reports/gates.json", "reports/byte-stability-report.json",
        ):
            source = independent_full_source / relative_path
            if source.is_file():
                target = subset / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        candidates = list(csv.DictReader((independent_full_source / "candidate-ledger.csv").open(encoding="utf-8")))
        write_csv(subset / "anonymized-candidate-ledger.csv", [
            {"case_ref": hashlib.sha256(row["source_item_id"].encode("utf-8")).hexdigest()[:16], "source_label": row["source_label"], "raw_label": row["raw_label"], "normalized_category": row["normalized_category"], "evaluation_disposition": row["evaluation_disposition"]}
            for row in candidates
        ])
        write_text(subset / "ANONYMIZED_REVIEW_SUBSET.md", "This credential-free successor evaluates every sealed v2 preflight source case. It reports pipeline coverage and receiver authorization outcomes without rerunning the detector. Raw external corpus content, source URLs, and identifiers remain in the anonymous source archive.")
    (review / "docs").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "docs" / "KNOWN_ISSUES.md", review / "docs" / "KNOWN_ISSUES.md")
    manifest = {
        "package": "TCOP anonymous reviewer artifact",
        "generated_at": STAMP,
        "files": [{"path": item.relative_to(review).as_posix(), "sha256": sha256_file(item)} for item in sorted(review.rglob("*")) if item.is_file()],
        "source_note": "This compact package contains anonymous derived data and verification material. Tier 1 and Tier 2 require the accompanying anonymous TCOP source-and-artifact archive; no credentialed live-model execution is required.",
    }
    write_json(review / "MANIFEST.json", manifest)
    return manifest


# Third-party URLs are permitted citations; author-owned repositories and
# profiles (including GitHub Pages and raw-content URLs) still identify authors.
ANONYMITY_RULES = [
    (r"/(?:Users|workspace|home|private)/", "absolute filesystem path"),
    (r"\b(?:vishnu|vettrivel)\b", "personal name"),
    (r"Dropbox", "cloud path"),
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "email address"),
    (r"https?://(?:(?:www\.)?github\.com|raw\.githubusercontent\.com)/cloudronin(?:[/\s#?}]|$)|https?://cloudronin\.github\.io(?:[/\s#?}]|$)", "author-identifying repository URL"),
    (r"sk-[A-Za-z0-9]{20,}", "provider token"),
    (r"OPENAI_API_KEY\s*=\s*[^$\s]", "provider credential"),
]


def anonymity_findings(text: str) -> list[str]:
    return [kind for pattern, kind in ANONYMITY_RULES if re.search(pattern, text, re.I)]


def anonymity_audit() -> dict[str, Any]:
    export_anonymous()
    review = ARTIFACT / "review"
    rules = ANONYMITY_RULES
    findings = []
    for path in sorted(item for item in review.rglob("*") if item.is_file()):
        if path.suffix.lower() in {".pdf", ".png"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern, kind in rules:
            if re.search(pattern, text, re.I):
                findings.append({"file": path.relative_to(review).as_posix(), "kind": kind})
    pdf = PAPER / "main.pdf"
    metadata = ""
    if pdf.is_file():
        from pypdf import PdfReader
        reader = PdfReader(str(pdf))
        metadata = json.dumps({str(key): str(value) for key, value in (reader.metadata or {}).items()}, sort_keys=True)
        pdf_text = "\n".join(page.extract_text() or "" for page in reader.pages)
        for pattern, kind in rules:
            if re.search(pattern, metadata, re.I):
                findings.append({"file": "main.pdf metadata", "kind": kind})
            if re.search(pattern, pdf_text, re.I):
                findings.append({"file": "main.pdf text", "kind": kind})
        main_source = (PAPER / "main.tex").read_text(encoding="utf-8")
        if "\\author{Anonymous Submission}" not in main_source:
            findings.append({"file": "main.tex", "kind": "non-anonymous author declaration"})
    result = {
        "audit_version": VERSION,
        "scope": "artifact/review and generated PDF metadata",
        "findings": findings,
        "pdf_metadata": metadata,
        "pass": not findings,
    }
    write_json(EVIDENCE / "anonymity-audit.json", result)
    lines = ["# Anonymity Audit", "", "Pass: " + str(result["pass"]), "", "The audit scans the exported reviewer package and PDF metadata for local paths, the configured personal name, email addresses, author-identifying repository URLs, and credential patterns. Third-party URLs are permitted citations."]
    if findings:
        lines += ["", "## Findings", ""] + ["- {0}: {1}".format(row["file"], row["kind"]) for row in findings]
    write_text(EVIDENCE / "anonymity-audit.md", "\n".join(lines))
    if findings:
        fail("anonymous export contains an identifying token")
    return result


def paper_check_summary(preprint: bool = False) -> dict[str, Any]:
    output_dir = PAPER / "preprint" / "evidence" if preprint else EVIDENCE
    required = {
        "source": output_dir / "source-verification.json",
        "claims": output_dir / "claim-audit.json",
        "numbers": output_dir / "manuscript-number-audit.json",
        "anonymity": output_dir / "anonymity-audit.json",
        "latex": output_dir / "latex-audit.json",
        "page_budget": output_dir / "page-budget.json",
    }
    required["bibliography"] = output_dir / "bibliography-audit.json"
    if preprint:
        del required["anonymity"]
        required["preprint_identity_and_links"] = output_dir / "preprint-audit.json"
    checks = {name: bool(read_json(path).get("pass")) for name, path in required.items() if path.is_file()}
    missing = sorted(set(required) - set(checks))
    budget = read_json(output_dir / "page-budget.json") if (output_dir / "page-budget.json").is_file() else {}
    result = {
        "paper_check": "pass" if not missing and all(checks.values()) else "fail",
        "checks": checks,
        "missing": missing,
        "body_pages": budget.get("body_pages"),
        "total_pages": budget.get("total_pages"),
    }
    write_json(output_dir / "paper-check-summary.json", result)
    if result["paper_check"] != "pass":
        fail("paper check summary has a failed or missing gate")
    return result


def page_budget(pdf: Path | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    pdf = PAPER / "main.pdf" if pdf is None else pdf
    output_dir = EVIDENCE if output_dir is None else output_dir
    from pypdf import PdfReader
    reader = PdfReader(str(pdf)) if pdf.is_file() else None
    pages = len(reader.pages) if reader else None
    appendix_page = None
    if reader:
        for index, page in enumerate(reader.pages, 1):
            if "Open Science Appendix" in (page.extract_text() or ""):
                appendix_page = index
                break
    # If the first appendix shares a rendered page with body text, count that
    # page toward the body limit rather than understating the submission size.
    body_pages = appendix_page if appendix_page else pages
    source = (PAPER / "main.tex").read_text(encoding="utf-8")
    result = {
        "pdf": relative(pdf),
        "total_pages": pages,
        "body_pages": body_pages,
        "appendix_first_pdf_page": appendix_page,
        "body_limit": 13,
        "appendix_declared": "\\appendix" in source,
        "pass": body_pages is not None and body_pages <= 13 and "\\appendix" in source,
        "note": "The official submission page limit applies to body content. This check locates the first rendered appendix and counts its page toward the body when body and appendix material share it.",
    }
    write_json(output_dir / "page-budget.json", result)
    if not result["pass"]:
        fail("paper page or appendix structural check failed")
    return result


def build_paper(submission: bool = False, preprint: bool = False) -> None:
    if submission:
        files = [PAPER / "main.tex", *(PAPER / "sections").glob("*.tex"), *(PAPER / "appendices").glob("*.tex")]
        body = "\n".join(path.read_text(encoding="utf-8") for path in files)
        if "TODO" in body or "anonymous artifact URL placeholder" in body:
            fail("submission mode permits neither TODOs nor placeholder artifact URLs")
    output = PAPER / "preprint" if preprint else PAPER
    output_dir = output / "evidence" if preprint else EVIDENCE
    stem = "main-preprint" if preprint else "main"
    source = "preprint/main-preprint.tex" if preprint else "main.tex"
    options = ["-outdir=preprint"] if preprint else []
    if preprint:
        write_text(output / "main-preprint.tex", preprint_wrapper())
    subprocess.run(
        ["latexmk", "-C", *options, source] if preprint else ["latexmk", "-C"],
        cwd=PAPER, text=True, capture_output=True, check=False,
    )
    completed = subprocess.run(
        ["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", *options, source],
        cwd=PAPER, text=True, capture_output=True, check=False,
    )
    write_text(output / "build.log", completed.stdout + completed.stderr)
    if completed.returncode:
        fail("LaTeX build failed; inspect " + relative(output / "build.log"))
    latex_log = (output / (stem + ".log")).read_text(encoding="utf-8", errors="ignore")
    overfull = [float(value) for value in re.findall(r"Overfull \\hbox \(([0-9.]+)pt too wide\)", latex_log)]
    undefined = bool(re.search(r"undefined references|undefined citations|There were undefined", latex_log, re.I))
    write_json(output_dir / "latex-audit.json", {
        "overfull_hbox_points": overfull,
        "overfull_threshold_points": 1.0,
        "undefined_reference_or_citation": undefined,
        "pass": not undefined and not any(value > 1.0 for value in overfull),
    })
    if undefined or any(value > 1.0 for value in overfull):
        fail("LaTeX reference or overfull-box audit failed")
    pdf = output / (stem + ".pdf")
    page_budget(pdf, output_dir)
    audit_bibliography(pdf, output_dir)


PREPRINT_NAME = "Vishnu Vettrivel"
PREPRINT_AFFILIATION = "Independent Researcher"
PREPRINT_EMAIL = "vishnu@uofa.net"
PREPRINT_ARTIFACT_URL = "https://github.com/cloudronin/tcop"


def preprint_wrapper() -> str:
    # Only this generated build entry point carries identity. The shared
    # manuscript and anonymous reviewer export remain free of author tokens.
    return (r"\def\TCOPPreprint{1}" + "\n"
            + r"\def\TCOPPreprintName{" + PREPRINT_NAME + "}\n"
            + r"\def\TCOPPreprintAuthor{" + PREPRINT_NAME + r"\\"
            + PREPRINT_AFFILIATION + r"\\\texttt{" + PREPRINT_EMAIL + "}}\n"
            + r"\def\TCOPArtifactURL{" + PREPRINT_ARTIFACT_URL + "}\n"
            + r"\input{main.tex}" + "\n")


def bibliography_findings(text: str, bibliography: str) -> list[str]:
    findings = []
    if re.search(r"2026,\s*2026", text):
        findings.append("repeated 2026 year in rendered bibliography")
    timeline = "https://huggingface.co/blog/agent-intrusion-technical-timeline"
    if bibliography.count(timeline) != 1:
        findings.append("HF technical timeline must have exactly one bibliography entry")
    return findings


def audit_bibliography(pdf: Path, output_dir: Path) -> dict[str, Any]:
    from pypdf import PdfReader
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    findings = bibliography_findings(text, (PAPER / "references.bib").read_text(encoding="utf-8"))
    result = {"pdf": relative(pdf), "findings": findings, "pass": not findings}
    write_json(output_dir / "bibliography-audit.json", result)
    if findings:
        fail("bibliography audit failed: " + "; ".join(findings))
    return result


def preprint_findings(text: str, urls: list[str], author: str) -> list[str]:
    findings = []
    # PDF extraction may split kerned words (for example, V ettrivel).
    compact_text = re.sub(r"\s+", "", text)
    for expected in (PREPRINT_NAME, PREPRINT_AFFILIATION, PREPRINT_EMAIL):
        if re.sub(r"\s+", "", expected) not in compact_text:
            findings.append("missing author-block field: " + expected)
    if author != PREPRINT_NAME:
        findings.append("missing preprint PDF author metadata")
    if any("anonymous.4open.science" in value.lower() for value in [text, *urls]):
        findings.append("anonymous artifact link in preprint")
    if PREPRINT_ARTIFACT_URL not in urls:
        findings.append("missing public repository link")
    return findings


def audit_preprint(pdf: Path, output_dir: Path) -> dict[str, Any]:
    from pypdf import PdfReader
    reader = PdfReader(str(pdf))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    urls = []
    for page in reader.pages:
        for ref in page.get("/Annots", []):
            action = ref.get_object().get("/A")
            if action is not None:
                action = action.get_object()
                if action.get("/URI") is not None:
                    urls.append(str(action["/URI"]))
    metadata = reader.metadata or {}
    first_page = reader.pages[0].extract_text() or ""
    findings = preprint_findings(first_page, urls, str(metadata.get("/Author", "")))
    if "anonymous.4open.science" in text.lower():
        findings.append("anonymous artifact link in preprint text")
    if "anonymous.4open.science" in str(metadata).lower():
        findings.append("anonymous artifact link in PDF metadata")
    result = {"pdf": relative(pdf), "author": str(metadata.get("/Author", "")),
              "urls": urls, "findings": findings, "pass": not findings}
    write_json(output_dir / "preprint-audit.json", result)
    if findings:
        fail("preprint identity/link audit failed: " + "; ".join(findings))
    return result


def build_preprint_checked(submission: bool = False) -> dict[str, Any]:
    output = PAPER / "preprint"
    output_dir = output / "evidence"
    anonymous_pdf = PAPER / "main.pdf"
    original = sha256_file(anonymous_pdf) if anonymous_pdf.is_file() else None
    write_json(output_dir / "source-verification.json", verify_sources(stability_check=True))
    audit_numbers(output_dir)
    verify_claims(output_dir)
    build_paper(submission=submission, preprint=True)
    audit_preprint(output / "main-preprint.pdf", output_dir)
    if original is not None and sha256_file(anonymous_pdf) != original:
        fail("preprint build changed the anonymous PDF")
    metadata = read_json(GENERATED / "paper-metadata.json")
    metadata.update({"anonymous": False, "build_mode": "preprint", "author": PREPRINT_NAME,
                     "affiliation": PREPRINT_AFFILIATION, "email": PREPRINT_EMAIL,
                     "artifact_url": PREPRINT_ARTIFACT_URL})
    write_json(output / "paper-metadata.json", metadata)
    return paper_check_summary(preprint=True)


def reproduce_core(agent_replay: bool = True, deterministic: bool = False) -> dict[str, Any]:
    verification = verify_sources(stability_check=True)
    extract_results()
    if agent_replay:
        output = PAPER / "artifact" / "agent-replay-smoke"
        if output.exists():
            shutil.rmtree(output)
        code, text = run_tcop(["study", "agent", "replay", "--selection", "full", "--output", relative(output), "--format", "json"])
        if code:
            fail("credential-free agent replay failed: " + text)
    if deterministic:
        output = PAPER / "artifact" / "deterministic-causal-core"
        if output.exists():
            shutil.rmtree(output)
        code, text = run_tcop([
            "study", "reproduce", "--plan", "benchmark/studies/v0.6-evidence.yaml",
            "--source", "artifacts/minimality-v0.5-validation",
            "--source-artifact", "artifacts/federated-domain-v0.6",
            "--selection", "causal-core", "--output", relative(output), "--format", "json",
        ])
        if code:
            fail("credential-free deterministic reproduction failed: " + text)
    return {"pass": verification["pass"], "agent_replay": agent_replay, "deterministic": deterministic}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["verify-sources", "inventory", "extract", "tables", "figures", "macros", "ledger", "claims", "numbers", "anonymity", "export", "build", "reproduce", "summary"])
    parser.add_argument("--stability-check", action="store_true")
    parser.add_argument("--submission", action="store_true")
    parser.add_argument("--preprint", action="store_true", help="build and check the identified preprint separately")
    parser.add_argument("--deterministic", action="store_true")
    args = parser.parse_args()
    if args.preprint and args.command != "build":
        parser.error("--preprint is supported only by the build command")
    if args.command == "verify-sources":
        result = verify_sources(args.stability_check)
    elif args.command == "inventory":
        result = {"entries": len(inventory())}
    elif args.command == "extract":
        result = extract_results()
    elif args.command == "tables":
        generate_tables()
        result = {"tables": len(read_json(GENERATED / "table-manifest.json"))}
    elif args.command == "figures":
        generate_figures()
        result = {"figures": len(read_json(GENERATED / "figure-manifest.json"))}
    elif args.command == "macros":
        generate_macros()
        result = {"macros": len(macro_values())}
    elif args.command == "ledger":
        result = {"claims": len(claim_ledger())}
    elif args.command == "claims":
        result = verify_claims()
    elif args.command == "numbers":
        result = audit_numbers()
    elif args.command == "anonymity":
        result = anonymity_audit()
    elif args.command == "export":
        result = export_anonymous()
    elif args.command == "build":
        if args.preprint:
            result = build_preprint_checked(args.submission)
        else:
            build_paper(args.submission)
            result = read_json(EVIDENCE / "page-budget.json")
    elif args.command == "summary":
        result = paper_check_summary()
    else:
        result = reproduce_core(deterministic=args.deterministic)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
