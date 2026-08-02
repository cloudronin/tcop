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
STRATEGY_INDEX = Path("artifacts/minimality-v0.5-validation/frozen-v0.6-profile-manifests.json")

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
)

AMENDMENT_CHAIN = (
    ("base-live", "artifacts/v0.6-agent-validation-live", None, "sealed initial provider failure"),
    ("001", "artifacts/v0.6-agent-validation-live-amendment-001", "artifacts/v0.6-agent-validation-live", "provider completion-token field"),
    ("002", "artifacts/v0.6-agent-validation-live-amendment-002", "artifacts/v0.6-agent-validation-live-amendment-001", "provider reasoning mode"),
    ("003", "artifacts/v0.6-agent-validation-live-amendment-003", "artifacts/v0.6-agent-validation-live-amendment-002", "RA-03 eligibility alignment"),
    ("004", "artifacts/v0.6-agent-validation-live-final", "artifacts/v0.6-agent-validation-live-amendment-003", "completion-gate ordering"),
    ("005", "artifacts/v0.6-agent-validation-live-certified", "artifacts/v0.6-agent-validation-live-final", "derived RA-03 utility reconciliation"),
    ("006", "artifacts/v0.6-agent-validation-live-origin-certified", "artifacts/v0.6-agent-validation-live-certified", "physical tcopd-a relay replay"),
)


def fail(message: str) -> None:
    raise SystemExit("paper verification failed: " + message)


def root_path(value: Path | str) -> Path:
    return ROOT / Path(value)


def relative(value: Path) -> str:
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
        args = ["artifact", "verify", spec["path"].as_posix()]
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
        status = read_json(artifact_root / "status.json")
        entry = {
            "artifact_id": spec["artifact_id"],
            "relative_path": spec["path"].as_posix(),
            "expected_digest": spec["expected_digest"],
            "recorded_digest": recorded,
            "computed_digest": computed,
            "complete": bool(manifest.get("complete", status.get("stage") in {"core", "full"})),
            "replayability_status": bool(manifest.get("replayable", command_result.get("replay_failures", 1) == 0)),
            "schema_validation_status": schema_ok,
            "parent_references": anonymous_reference({key: manifest[key] for key in sorted(manifest) if key.startswith("source_") or key in {"finalization", "finalized_from"}}),
            "amendment_references": [spec["amendment"]] if spec.get("amendment") else [],
            "git_revision": _git_revision(),
            "verification_command": spec["command"],
            "verification_timestamp": STAMP,
            "artifact_command_result": command_result,
            "pass": recorded == computed == spec["expected_digest"] and exit_code == 0 and schema_ok and bool(status.get("passed")),
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
    if (len(causal), outcomes["improved"], outcomes["unchanged"], outcomes["worsened"], prevented, len(excluded)) != (54, 30, 24, 0, 36, 123):
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

    control_source = LIVE / "reports" / "negative-controls.json"
    controls = read_json(live_root / "reports" / "negative-controls.json")["controls"]
    if not controls or not all(row["passed"] for row in controls):
        fail("a negative or failure control did not pass")
    control_rows = [
        provenance(
            control_source, row["control"], treatment="negative-control", scenario="agent-gateway",
            architecture="A2", strategy="containment-first", eligibility="control",
            injected_condition=row["control"], expected_behavior=row.get("detail", "reject or preserve local authority"),
            observed_behavior=row.get("detail", "passed"), invariant="receiver-local authority", passed=row["passed"],
        )
        for row in controls
    ]
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

    write_json(EVIDENCE / "result-provenance.json", {
        "version": VERSION,
        "files": {
            "deterministic-pairs.csv": {"source": det_source.as_posix(), "rows": len(det_rows)},
            "deterministic-central-audit.csv": {"source": central_source.as_posix(), "rows": 1},
            "live-trace-cohort.csv": {"source": cohort_source.as_posix(), "rows": len(cohort_rows)},
            "live-replay-pairs.csv": {"source": pairs_source.as_posix(), "rows": len(pair_rows)},
            "physical-arms.csv": {"source": physical_source.as_posix(), "rows": len(physical_rows)},
            "utility-results.csv": {"source": utility_source.as_posix(), "rows": len(utility_rows)},
            "failure-controls.csv": {"source": control_source.as_posix(), "rows": len(control_rows)},
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
            "harmful_actions_prevented": 36, "excluded_unmatched_pairs": 123,
            "central_fact_equivalent_cells": 54, "central_regressions": 6,
        },
        "live": {
            "eligible_traces": 44, "replay_treatment_rows": 264, "paired_comparisons": 220,
            "physical_arms": 30, "physical_federation_exchanges": 20, "remote_enforcement_successes": 0,
            "a1": {"forwarded": 30, "blocked": 0},
            "early": {"forwarded": 0, "blocked": 30},
            "late": {"forwarded": 10, "blocked": 20},
        },
        "utility": {"attempted": 360, "forwarded": 320, "constrained": 40, "workflow_completion": 80, "workflow_denominator": 120},
        "negative_controls": {row["control"]: row["passed"] for row in controls},
        "frozen_strategy_digests": {row["strategy"]: row["computed_digest"] for row in strategies},
        "amendment_chain_integrity": True,
    }
    write_json(ARTIFACT / "expected-results.json", expected)
    return {"verification_passed": verification["pass"], "expected": expected}


def macro_values() -> dict[str, str]:
    expected = read_json(ARTIFACT / "expected-results.json")
    det, live, utility = expected["deterministic"], expected["live"], expected["utility"]
    return {
        "DeterministicPairs": str(det["strict_pairs"]),
        "DeterministicImproved": str(det["improved"]),
        "DeterministicUnchanged": str(det["unchanged"]),
        "DeterministicWorsened": str(det["worsened"]),
        "DeterministicActionsPrevented": str(det["harmful_actions_prevented"]),
        "DeterministicExcludedPairs": str(det["excluded_unmatched_pairs"]),
        "CentralAuditCells": str(det["central_fact_equivalent_cells"]),
        "CentralRegressions": str(det["central_regressions"]),
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
    }


def generate_macros() -> None:
    values = macro_values()
    write_text(GENERATED / "results-macros.tex", "\n".join("\\newcommand{\\%s}{%s}" % (name, value) for name, value in values.items()))
    write_json(GENERATED / "paper-metadata.json", {
        "title": "Receiver-Sovereign Federated Early Warning for Cross-Domain Agent Tool Use",
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
    control_rows = {row["injected_condition"]: row for row in csv.DictReader((DATA / "failure-controls.csv").open(encoding="utf-8"))}
    required_controls = {
        "invalid_signature", "wrong_receipt", "expired_context", "replayed_context", "local_policy_monitor_only",
        "no_remote_enforcement", "gateway_cache_disabled", "remote_tcx_action_not_interpreted", "unknown_peer",
        "disallowed_import_type", "tcopd_b_unavailable", "authorization_timeout", "gateway_restart", "stale_decision",
        "session_termination_before_context_arrival", "context_arrival_after_local_containment",
    }
    if set(control_rows) != required_controls or not all(row["passed"] == "True" for row in control_rows.values()):
        fail("generated failure-control table is not backed by the complete passing control set")
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
\caption{Evaluative architecture roles. A2 is the receiver-sovereign TCOP configuration; the other rows are baselines, comparators, or upper bounds.}
\begin{tabular}{@{}p{0.07\textwidth}@{\hspace{0.35em}}p{0.13\textwidth}@{\hspace{0.35em}}p{0.13\textwidth}@{\hspace{0.35em}}p{0.13\textwidth}@{\hspace{0.35em}}p{0.13\textwidth}@{\hspace{0.35em}}p{0.17\textwidth}@{}}\toprule
Architecture & Visibility & Authority & Outage dependence & Privacy exposure & Evaluative role \\ \midrule
A0 & None & None & N/A & None & No coordinated defense baseline \\
A1 & Receiver-local & Domain B & Local only & Local only & Isolated capable observers \\
A2 & Bounded exported facts & Domain B & Federation degrades to local operation & Bounded context & TCOP \\
A3 & Equivalent exportable facts & Central service & Central decision path & Exported facts to central & Fact-equivalent central comparator \\
A4 & Full telemetry & Central service & Central decision path & Full telemetry to central & Central upper bound \\
A5 & Oracle & Oracle & Assumed & Oracle visibility & Oracle upper bound \\ \bottomrule
\end{tabular}\label{tab:architectures}\end{table*}""", ["C-CENTRAL-01", "C-CENTRAL-02"], ["contracts/architectures.json"]),
        table("tab-deterministic-summary.tex", r"""\begin{table}[t]\centering\small
\caption{Strict deterministic containment-first comparison. Balanced and utility configurations with unmatched local policies are excluded.}
\begin{tabular}{lr}\toprule
Metric & Value \\ \midrule
Strict input-equivalent pairs & \DeterministicPairs \\
Improved / unchanged / worsened & \DeterministicImproved / \DeterministicUnchanged / \DeterministicWorsened \\
Harmful actions prevented & \DeterministicActionsPrevented \\
Unmatched-policy exclusions & \DeterministicExcludedPairs \\ \bottomrule
\end{tabular}\label{tab:deterministic}\end{table}""", ["C-DETERMINISTIC-01"], ["data/generated/deterministic-pairs.csv"]),
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
\caption{Physical end-to-end gateway arms. Each block is attributable to a Domain-B-local decision.}
\begin{tabular}{lrr}\toprule
Arm & Forwarded & Blocked \\ \midrule
A1, no context & \AOneForwarded & 0 \\
A2, before first opportunity & 0 & \EarlyBlocked \\
A2, after initial harm & \LateForwarded & \LateBlocked \\ \bottomrule
\end{tabular}\label{tab:physical}\end{table}""", ["C-TIMING-01", "C-AUTH-01"], ["data/generated/physical-arms.csv"]),
        table("tab-replay-timing.tex", r"""\begin{table*}[t]\centering\small
\caption{Strict replay timing treatments. A treatment can be too late for one action while still affecting later opportunities.}
\begin{tabular}{lrrr}\toprule
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
Inside-window early and boundary & 120 & 80 & 40 & 0/40 & repository.write in frozen benign metadata workflow \\
No context, outside window, post-detection, and post-containment & 240 & 240 & 0 & 80/80 & no restriction in these treatments \\ \midrule
All selected treatments & \BenignAttempted & \BenignForwarded & \BenignConstrained & \WorkflowCompleted/\WorkflowTotal (\WorkflowCompletionRate) & selected synthetic capability restriction \\ \bottomrule
\end{tabular}\label{tab:utility}\end{table*}""", ["C-UTILITY-01", "C-UTILITY-02"], ["data/generated/utility-results.csv"]),
        table("tab-negative-controls.tex", r"""\begin{table*}[t]\centering\scriptsize
\caption{Negative and failure controls. All listed conditions passed in the sealed live artifact.}
\begin{tabular}{@{}p{0.15\textwidth}@{\hspace{0.2em}}p{0.23\textwidth}@{\hspace{0.2em}}p{0.20\textwidth}@{\hspace{0.2em}}p{0.14\textwidth}@{\hspace{0.2em}}c@{\hspace{0.2em}}p{0.08\textwidth}@{}}\toprule
Injected condition & Expected behavior & Observed behavior & Invariant & Pass & Source record \\ \midrule
Invalid signature & Reject before restriction & Rejected; no restriction & Signed input & Yes & NC-01 \\
Wrong receipt & Reject before restriction & Rejected; no restriction & Receipt correlation & Yes & NC-02 \\
Expired context & Reject before restriction & Rejected; no restriction & Bounded freshness & Yes & NC-03 \\
Replayed context & Reject before restriction & Rejected; no restriction & Replay protection & Yes & NC-04 \\
Unknown peer & Reject before restriction & Rejected; no restriction & Authorized peer & Yes & NC-05 \\
Disallowed import type & Reject before restriction & Rejected; no restriction & Context class & Yes & NC-06 \\
Monitor-only policy & Do not preempt first call & First call not blocked & Local detection timing & Yes & NC-07 \\
No remote enforcement & Never accept remote enforcement & No remote action used & Receiver authority & Yes & NC-08 \\
Remote TCX action & Never interpret remote action & No remote action used & Receiver authority & Yes & NC-09 \\
Gateway cache disabled & Evaluate each authorization & Cache disabled & Replay correctness & Yes & NC-10 \\
tcopd B unavailable & Use B-local disposition & Local fail-closed policy & Receiver authority & Yes & NC-11 \\
Authorization timeout & Use B-local disposition & Sender does not choose timeout & Receiver authority & Yes & NC-12 \\
Gateway restart & Recompute local state & Fresh decision used & Receiver authority & Yes & NC-13 \\
Stale decision & Recompute local state & Fresh decision used & Receiver authority & Yes & NC-14 \\
Session termination before arrival & Do not cross sessions & Context has no new session effect & Session binding & Yes & NC-15 \\
Arrival after local containment & No reversal of completed action & Non-preventive late context & Containment window & Yes & NC-16 \\ \bottomrule
\end{tabular}\label{tab:controls}\end{table*}""", ["C-FAILURE-01"], ["data/generated/failure-controls.csv"]),
        table("tab-performance.tex", r"""\begin{table*}[t]\centering\small
\caption{Local harness performance. These deterministic local measurements characterize implementation overhead in the test harness and are not production inter-domain latency estimates.}
\begin{tabular}{lrrrr}\toprule
Selection & Authorization p95 (ms) & Gateway p95 (ms) & Warning-to-enforcement p95 (ms) & Cache hit rate \\ \midrule
Disabled & 0.019750 & 0.024584 & 0.331624 & 0.00 \\
Enabled, fixed 5s TTL & 0.000667 & 0.027250 & 0.328208 & 0.95 \\ \bottomrule
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
006 & Physical tcopd-a relay replay & No & No & No & Physical-path evidence & 2b1f92ff4481 & 546f3547b727 \\ \bottomrule
\end{tabular}\label{tab:amendments}\end{table*}""", ["C-LIVE-01"], ["data/generated/amendment-chain.csv", "evidence/source-verification.json"]),
        table("tab-limitations.tex", r"""\begin{table*}[t]\centering\small
\caption{What the evaluation supports and does not support.}
\begin{tabular}{p{0.3\textwidth}p{0.6\textwidth}}\toprule
Evidence & Supported scope \\ \midrule
Deterministic matched pairs & Causal comparison under matched frozen local policy and synthetic scenarios \\
Executable replay & Exact captured action-sequence comparison without model credentials \\
Live trace generation & A bounded credentialed cohort generated action attempts \\
Physical federation and reference gateway & A signed tcopd-A-to-tcopd-B path and receiver-local gateway decisions \\
Not established & Production deployment, Internet-scale federation, uninstrumented incidents, or universal superiority to central defense \\ \bottomrule
\end{tabular}\label{tab:limitations}\end{table*}""", ["C-CENTRAL-02", "C-LIMIT-01", "C-LIMIT-02"], ["evidence/claim-evidence-ledger.yaml"]),
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
    ax.text(54, .38, "36 harmful actions prevented", ha="right", fontsize=7)
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
    ax.set_ylabel("Harmful calls"); ax.set_ylim(0, 34)
    ax.legend(frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(.5, 1.02), ncol=2)
    fig.subplots_adjust(top=.78)
    manifest.append(save_figure(fig, "physical-timing", ["C-TIMING-01"], ["data/generated/physical-arms.csv"], ["The late arm separates completed calls from subsequently prevented calls."]))
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
        ax.text(index, 46.0, "Delta harm " + str(delta), ha="center", fontsize=6.4)
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

    fig, ax = plt.subplots(figsize=(7.1, 2.35)); ax.axis("off")
    lineage = [
        ("Deterministic\n0ab19a", .3, "#d9ead3"),
        ("Scripted parent\ncfc539", 1.65, "#d9ead3"),
        ("Provider-failure\npredecessors", 3.0, "#f4cccc"),
        ("001-003\ntrace capture", 4.35, "#fff2cc"),
        ("004-005\ncertification", 5.7, "#fff2cc"),
        ("006 physical path\n546f354", 7.05, "#cfe2f3"),
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
        ("C-ARCH-01", "TCOP exchanges signed, bounded context rather than enforcement commands.", "architecture", "artifacts/v0.6-agent-validation-live-origin-certified", ["manifest.json", "reports/invariant-report.json"], "Remote TCX action is not interpreted; remote enforcement successes are zero.", [], "03-architecture-protocol.tex", "fig-architecture", "supported"),
        ("C-AUTH-01", "Every evaluated gateway block references a Domain-B-local policy and decision.", "authority", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/authorization-audit.json", "reports/end-to-end-live-results.json"], "Every gateway block references a Domain-B policy and decision.", [], "04-local-resolution-enforcement.tex", "tab-physical-end-to-end", "supported"),
        ("C-AUTH-02", "Remote enforcement successes were zero in every evaluated arm.", "authority", "artifacts/v0.6-agent-validation-live-origin-certified", ["manifest.json", "reports/origin-federation-audit.json"], "remote_enforcement_successes equals zero.", [], "04-local-resolution-enforcement.tex", "tab-physical-end-to-end", "supported"),
        ("C-DETERMINISTIC-01", "Across 54 strict deterministic pairs, containment-first improved 30 outcomes, left 24 unchanged, worsened none, and prevented 36 harmful actions.", "deterministic evaluation", "artifacts/federated-domain-v0.6-evidence", ["pairs/paired-results.jsonl", "reports/paired-causal-comparison.json"], "54 / 30 / 24 / 0 / 36.", ["123 unmatched balanced or utility comparisons"], "06-deterministic-evaluation.tex", "fig-deterministic-outcomes", "supported"),
        ("C-VALIDATION-01", "In the preregistered v2 mixed-action cohort, C2 blocked the same three accepted matching harmful actions as C1-class while constraining no benign action; C1-class constrained seven benign actions and C3 constrained twelve.", "validation value", "artifacts/tcx-validation-value-v2", ["reports/condition-summary.json", "reports/matching-harmful-summary.json", "reports/gates.json"], "C1-class/C2 matching block 3/3; benign constraints 7/0; C3 12.", ["Synthetic credential-free cohort only; mismatched-warning controls are separate."], "06-deterministic-evaluation.tex", "none", "supported with qualification"),
        ("C-TIMING-01", "In 30 physical gateway arms, A1 forwarded 30 harmful calls; A2 before the first harmful opportunity blocked 30; after initial harm it forwarded 10 completed calls and blocked 20 later calls.", "timing", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/end-to-end-live-results.json"], "30 / 30 / 10 / 20.", [], "07-agent-gateway-evaluation.tex", "fig-physical-timing", "supported"),
        ("C-LIVE-01", "The certified cohort contains 44 live traces and 220 strict paired comparisons.", "live trace cohort", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/trace-generation-summary.json", "reports/paired-enforcement-results.json"], "44 eligible traces; 220 pairs.", [], "07-agent-gateway-evaluation.tex", "tab-live-cohort", "supported"),
        ("C-UTILITY-01", "Across six RA-03 replay treatments, 360 benign calls were attempted, 320 forwarded, and 40 constrained.", "availability", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/benign-workload-impact.json"], "360 / 320 / 40.", ["Synthetic false-warning treatments and capability restriction"], "08-security-availability.tex", "fig-security-availability", "supported with qualification"),
        ("C-UTILITY-02", "Selected RA-03 workflow completion was 80 of 120 (66.7 percent).", "availability", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/benign-workload-impact.json"], "80 / 120 / 66.7 percent.", ["Synthetic workload only"], "08-security-availability.tex", "tab-utility", "supported with qualification"),
        ("C-FAILURE-01", "Invalid, expired, replayed, unknown-peer, wrong-receipt, stale-decision, restart, timeout, and late-context controls passed.", "failure controls", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/negative-controls.json"], "16 passed controls.", [], "08-security-availability.tex", "tab-negative-controls", "supported"),
        ("C-PERF-01", "Measured sub-millisecond values are deterministic local harness measurements, not production or inter-organizational latency estimates.", "performance", "artifacts/v0.6-agent-validation-live-origin-certified", ["reports/gateway-latency.json", "reports/federation-latency.json"], "Performance-only selections with 20 samples each.", ["No production latency inference"], "07-agent-gateway-evaluation.tex", "tab-performance", "supported with qualification"),
        ("C-CENTRAL-01", "Under fact equivalence, receiver-local enforcement avoided six failures associated with central outage or authority placement in evaluated cells.", "central comparator", "artifacts/federated-domain-v0.6-evidence", ["reports/central-comparator-audit.json"], "54 fact-equivalent cells; three authority-placement and three outage regressions.", [], "06-deterministic-evaluation.tex", "tab-architecture-comparison", "supported with qualification"),
        ("C-CENTRAL-02", "The evaluation does not establish universal superiority over centralized defense.", "limitation", "artifacts/federated-domain-v0.6-evidence", ["reports/central-comparator-audit.json"], "Bounded comparator scope.", [], "10-limitations-conclusion.tex", "tab-limitations", "supported"),
        ("C-LIMIT-01", "TCOP does not create detections and cannot prevent an origin compromise that no participating observer detects in time.", "limitation", "architecture", ["benchmark/studies/v0.6-agent-validation.yaml", "reports/containment-window-agent-results.json"], "Context is actionable only before consequential actions.", [], "10-limitations-conclusion.tex", "fig-containment-window", "supported with qualification"),
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
        "physical_treatment_labels": [
            "before the first harmful opportunity",
            "at the first-action authorization boundary",
            "after initial harm but before subsequent harmful actions",
            "after receiver-local detection",
            "after partial local containment",
        ],
    }
    (EVIDENCE / "terminology.yaml").write_text(yaml.safe_dump(terminology, sort_keys=False), encoding="utf-8")
    write_text(EVIDENCE / "citation-audit.md", """# Citation Audit

Draft status: related-work categories are mapped, but verified bibliographic citations remain TODOs. The draft makes no novelty-priority claim and uses no unverified factual literature assertion. Before submission, add and verify citations for STIX/TAXII, MISP, zero trust, RATS, SPIFFE/SPIRE, distributed and cooperative intrusion response, policy decision/enforcement, agent prompt-injection defenses, and MCP gateway authorization.
""")
    return records


def verify_claims() -> dict[str, Any]:
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
    write_json(EVIDENCE / "claim-audit.json", result)
    if not result["pass"]:
        fail("unsupported or prohibited manuscript claim")
    return result


def audit_numbers() -> dict[str, Any]:
    approved = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "2027", "0.6", "0.1", "5s", "01", "02", "03"}
    ignored = re.compile(r"(\\input|\\includegraphics|\\label|\\ref|\\cite|\\bibliography|\\documentclass|\\usepackage)")
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
    write_json(EVIDENCE / "manuscript-number-audit.json", result)
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
    manifest = {
        "package": "TCOP anonymous reviewer artifact",
        "generated_at": STAMP,
        "files": [{"path": item.relative_to(review).as_posix(), "sha256": sha256_file(item)} for item in sorted(review.rglob("*")) if item.is_file()],
        "source_note": "This compact package contains anonymous derived data and verification material. Tier 1 and Tier 2 require the accompanying anonymous TCOP source-and-artifact archive; no credentialed live-model execution is required.",
    }
    write_json(review / "MANIFEST.json", manifest)
    return manifest


def anonymity_audit() -> dict[str, Any]:
    export_anonymous()
    review = ARTIFACT / "review"
    rules = [
        (r"/(?:Users|workspace|home|private)/", "absolute filesystem path"),
        (r"\bvishnu\b", "personal name"),
        (r"Dropbox", "cloud path"),
        (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "email address"),
        (r"https?://github\.com/", "repository URL"),
        (r"sk-[A-Za-z0-9]{20,}", "provider token"),
        (r"OPENAI_API_KEY\s*=\s*[^$\s]", "provider credential"),
    ]
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
    lines = ["# Anonymity Audit", "", "Pass: " + str(result["pass"]), "", "The audit scans the exported reviewer package and PDF metadata for local paths, the configured personal name, email addresses, repository URLs, and credential patterns."]
    if findings:
        lines += ["", "## Findings", ""] + ["- {0}: {1}".format(row["file"], row["kind"]) for row in findings]
    write_text(EVIDENCE / "anonymity-audit.md", "\n".join(lines))
    if findings:
        fail("anonymous export contains an identifying token")
    return result


def paper_check_summary() -> dict[str, Any]:
    required = {
        "source": EVIDENCE / "source-verification.json",
        "claims": EVIDENCE / "claim-audit.json",
        "numbers": EVIDENCE / "manuscript-number-audit.json",
        "anonymity": EVIDENCE / "anonymity-audit.json",
        "latex": EVIDENCE / "latex-audit.json",
        "page_budget": EVIDENCE / "page-budget.json",
    }
    checks = {name: bool(read_json(path).get("pass")) for name, path in required.items() if path.is_file()}
    missing = sorted(set(required) - set(checks))
    budget = read_json(EVIDENCE / "page-budget.json") if (EVIDENCE / "page-budget.json").is_file() else {}
    result = {
        "paper_check": "pass" if not missing and all(checks.values()) else "fail",
        "checks": checks,
        "missing": missing,
        "body_pages": budget.get("body_pages"),
        "total_pages": budget.get("total_pages"),
    }
    write_json(EVIDENCE / "paper-check-summary.json", result)
    if result["paper_check"] != "pass":
        fail("paper check summary has a failed or missing gate")
    return result


def page_budget() -> dict[str, Any]:
    pdf = PAPER / "main.pdf"
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
    write_json(EVIDENCE / "page-budget.json", result)
    if not result["pass"]:
        fail("paper page or appendix structural check failed")
    return result


def build_paper(submission: bool = False) -> None:
    if submission:
        files = [PAPER / "main.tex", *(PAPER / "sections").glob("*.tex"), *(PAPER / "appendices").glob("*.tex")]
        body = "\n".join(path.read_text(encoding="utf-8") for path in files)
        if "TODO" in body or "anonymous artifact URL placeholder" in body:
            fail("submission mode permits neither TODOs nor placeholder artifact URLs")
    subprocess.run(
        ["latexmk", "-C"],
        cwd=PAPER,
        text=True,
        capture_output=True,
        check=False,
    )
    completed = subprocess.run(
        ["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
        cwd=PAPER,
        text=True,
        capture_output=True,
        check=False,
    )
    write_text(PAPER / "build.log", completed.stdout + completed.stderr)
    if completed.returncode:
        fail("LaTeX build failed; inspect paper/usenix27/build.log")
    latex_log = (PAPER / "main.log").read_text(encoding="utf-8", errors="ignore")
    overfull = [float(value) for value in re.findall(r"Overfull \\hbox \(([0-9.]+)pt too wide\)", latex_log)]
    undefined = bool(re.search(r"undefined references|undefined citations|There were undefined", latex_log, re.I))
    write_json(EVIDENCE / "latex-audit.json", {
        "overfull_hbox_points": overfull,
        "overfull_threshold_points": 1.0,
        "undefined_reference_or_citation": undefined,
        "pass": not undefined and not any(value > 1.0 for value in overfull),
    })
    if undefined or any(value > 1.0 for value in overfull):
        fail("LaTeX reference or overfull-box audit failed")
    page_budget()


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
    parser.add_argument("--deterministic", action="store_true")
    args = parser.parse_args()
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
        build_paper(args.submission)
        result = read_json(EVIDENCE / "page-budget.json")
    elif args.command == "summary":
        result = paper_check_summary()
    else:
        result = reproduce_core(deterministic=args.deterministic)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
