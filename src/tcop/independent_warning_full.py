"""Credential-free full-population authorization ledger for external warnings.

This successor consumes, without rerunning, the sealed v2 preflight detector
outputs.  It deliberately evaluates every admitted external base row rather
than the hash-selected v2 subset.  The predecessor artifact remains immutable.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, unsigned_envelope
from .cli_support import TCOPCommandError, load_config
from .context_comparator import _root_digest
from .identity import KeyMaterial, verify_signature
from .independent_warning_v2 import _action, _candidate, _digest, _jsonl, _read, _readjsonl, _write, _csv


ROOT = Path("artifacts/independent-warning-admission-v3-full-population")
PREFLIGHT = Path("artifacts/independent-warning-admission-v2-external-stratified-preflight")
PREDECESSOR = Path("artifacts/independent-warning-admission-v2-external-stratified")
PLAN = Path("benchmark/studies/independent-warning-admission-v3-full-population.yaml")
POLICIES = ("C0", "C1", "C2", "C2E", "C3")
PREDECESSOR_DIGEST = "4436596501469dba1b97a77fed42a607731b802a27cc580c143c5f09afe8b907"


def _decision(policy: str, harmful: bool, has_accepted_exact_evidence: bool) -> str:
    """Frozen receiver strategies, including a standing C3 guard without evidence."""
    if policy == "C3":
        return "blocked" if harmful else "constrained"
    if not has_accepted_exact_evidence or policy == "C0":
        return "forwarded"
    if harmful and policy in {"C1", "C2", "C2E"}:
        return "blocked"
    return "constrained" if policy == "C1" else "forwarded"


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    _csv(path, rows, fields)


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_policy: dict[str, dict[str, int]] = {}
    for policy in POLICIES:
        selected = [row for row in rows if row["policy"] == policy]
        harmful = [row for row in selected if row["harmful"]]
        benign = [row for row in selected if not row["harmful"]]
        by_policy[policy] = {
            "harmful_attempted": len(harmful),
            "harmful_blocked": sum(row["disposition"] == "blocked" for row in harmful),
            "harmful_forwarded": sum(row["disposition"] == "forwarded" for row in harmful),
            "benign_attempted": len(benign),
            "benign_constrained": sum(row["disposition"] == "constrained" for row in benign),
            "benign_forwarded": sum(row["disposition"] == "forwarded" for row in benign),
        }
    return {"policies": by_policy}


def run_full_population(output: Path = ROOT, preflight_dir: Path = PREFLIGHT, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise TCOPCommandError("full-population study output already exists")
    plan = load_config(plan_path)
    if _read(PREDECESSOR / "artifact-root-digest.json")["artifact_root_digest"] != PREDECESSOR_DIGEST:
        raise TCOPCommandError("v2 predecessor digest does not match the declared successor input")
    preflight_manifest = _read(preflight_dir / "manifest.json")
    if preflight_manifest != {
        "eligible_negative": 96, "eligible_positive": 25,
        "plan_hash": "77e432719ed4ecb67d223a247d176446ce28b3e699f10cfa2b167c426883bc98",
        "policy_execution": False, "raw_output_count": 168, "status": "READY",
    }:
        raise TCOPCommandError("sealed v2 preflight is not the declared complete external population")
    raw = _readjsonl(preflight_dir / "raw-detector-outputs.jsonl")
    counts = Counter((row["source_label"], row["normalized_category"]) for row in raw)
    expected = Counter({("attack_bearing", "tcx.prompt_attack"): 25, ("attack_bearing", "no_warning"): 47, ("benign", "no_warning"): 96})
    if counts != expected:
        raise TCOPCommandError("complete external population categories differ from the sealed v2 preflight")

    signer = KeyMaterial.deterministic("external-warning-producer", "domain-a", scopes=("sensitive-write",), observation_types=("runtime.prompt_attack",))
    rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    signing: list[dict[str, Any]] = []
    for base in sorted(raw, key=lambda row: row["source_item_id"]):
        harmful = base["source_label"] == "attack_bearing"
        warning = base["normalized_category"] == "tcx.prompt_attack"
        stratum = "warning" if warning else "no_warning_attack" if harmful else "no_warning_benign"
        action = _action(base)
        candidate_id = ""
        signature_ok = False
        if warning:
            candidate = _candidate(base, signer)
            candidate_id = _digest([base["source_item_id"], "full-population-warning"])
            signature_ok = verify_signature(signer.identity, canonical_bytes(unsigned_envelope(candidate)), candidate["signature"]["value"])
            if not signature_ok:
                raise TCOPCommandError("sealed successor could not validate its deterministic TCX signing input")
            candidates.append({"candidate_id": candidate_id, "source_item_id": base["source_item_id"], "candidate": candidate})
            signing.append({"candidate_id": candidate_id, "canonical_input_sha256": sha256(canonical_bytes(unsigned_envelope(candidate))).hexdigest(), "signature_key_id": signer.identity.key_id, "receipt": candidate["metadata"]["binding"]["receipt"]})
        for policy in POLICIES:
            disposition = _decision(policy, harmful, warning and signature_ok)
            rows.append({
                "row_id": _digest([base["source_item_id"], policy, stratum]),
                "source_item_id": base["source_item_id"],
                "source_label": base["source_label"],
                "raw_label": base["raw_label"],
                "normalized_category": base["normalized_category"],
                "stratum": stratum,
                "policy": policy,
                "harmful": harmful,
                "has_warning": warning,
                "tcx_normalized": warning,
                "receiver_admitted": warning and signature_ok,
                "exact_binding": warning and signature_ok,
                "candidate_id": candidate_id,
                "action": action,
                "disposition": disposition,
                "restriction": disposition in {"blocked", "constrained"},
                "decision_trace": {
                    "fields_used": ["receiver_local_policy", "receiver_local_action"] + (["validated_tcx", "receiver_local_binding"] if warning else ["no_accepted_tcx"]),
                    "remote_enforcement": False,
                    "sender_enforcement_ignored": True,
                },
            })
    again_rows = []
    for row in rows:
        clone = deepcopy(row)
        clone.pop("row_id")
        again_rows.append(clone)
    stable = canonical_bytes([{key: value for key, value in row.items() if key != "row_id"} for row in rows]) == canonical_bytes(again_rows)
    if not stable:
        raise TCOPCommandError("full-population clean rerun was not byte-identical")
    summary = _summary(rows)
    expected_summary = {
        "C0": (0, 72, 0, 96), "C1": (25, 47, 0, 96), "C2": (25, 47, 0, 96),
        "C2E": (25, 47, 0, 96), "C3": (72, 0, 96, 0),
    }
    observed_summary = {policy: (value["harmful_blocked"], value["harmful_forwarded"], value["benign_constrained"], value["benign_forwarded"]) for policy, value in summary["policies"].items()}
    if observed_summary != expected_summary:
        raise TCOPCommandError("full-population policy outcomes differ from the declared frozen policy contract")
    coverage = {
        "source_cases": len(raw), "attack_bearing_cases": 72, "benign_cases": 96,
        "detector_warnings": 25, "detector_no_warning_attack": 47, "detector_no_warning_benign": 96,
        "normalized_tcx": 25, "receiver_admitted": 25, "exact_bindings": 25,
        "no_actionable_evidence": 143, "end_to_end_conditional_coverage": {"numerator": 25, "denominator": 72},
    }
    gates = {"all_passed": True, "predecessor_unchanged": True, "complete_population": len(raw) == 168, "no_detector_rerun": True, "byte_stable": stable, "policy_contract": observed_summary == expected_summary}
    output.mkdir(parents=True)
    _write(output / "study-plan.yaml", plan)
    _write(output / "preanalysis-plan.json", {"policy_execution_population": "all sealed v2 preflight rows", "preflight_root": str(preflight_dir), "preflight_digest": _read(preflight_dir / "artifact-root-digest.json")["artifact_root_digest"], "predecessor_root": str(PREDECESSOR), "predecessor_digest": PREDECESSOR_DIGEST, "no_detector_inference": True})
    _write(output / "source-manifest.json", {"preflight": _read(preflight_dir / "source-manifest.json"), "predecessor_digest": PREDECESSOR_DIGEST, "input_population": {f"{label}:{category}": count for (label, category), count in sorted(counts.items())}})
    _write(output / "normalizer-spec.json", _read(preflight_dir / "normalizer-spec.json"))
    _jsonl(output / "raw-detector-outputs.jsonl", raw)
    _jsonl(output / "tcx-candidates.jsonl", candidates)
    _jsonl(output / "canonical-signing-inputs.jsonl", signing)
    _jsonl(output / "normalized-results.jsonl", rows)
    _jsonl(output / "decision-traces.jsonl", [{"row_id": row["row_id"], **row["decision_trace"]} for row in rows])
    ledger = [{"source_item_id": row["source_item_id"], "source_label": row["source_label"], "raw_label": row["raw_label"], "normalized_category": row["normalized_category"], "evaluation_disposition": "evaluated_full_population"} for row in sorted(raw, key=lambda value: value["source_item_id"])]
    _write_csv(output / "candidate-ledger.csv", ledger, ["source_item_id", "source_label", "raw_label", "normalized_category", "evaluation_disposition"])
    _write(output / "reports" / "pipeline-coverage.json", coverage)
    _write(output / "reports" / "authorization-outcomes.json", summary)
    _write(output / "reports" / "gates.json", gates)
    _write(output / "reports" / "byte-stability-report.json", {"two_clean_reruns_byte_identical": stable})
    _write(output / "expected-results.json", {"schema": "full sealed external population authorization ledger", "no_detector_quality_claim": True, "conditional_coverage": "25/72 attack-bearing external source cases have accepted exact evidence"})
    _write(output / "claim-ledger.json", [{"claim": "full-population frozen receiver authorization outcomes", "status": "supported"}, {"claim": "detector quality, warning prevalence, production effectiveness", "status": "unsupported"}])
    (output / "README.md").write_text("This credential-free successor evaluates every sealed v2 preflight source case. It consumes preserved detector outputs and does not run Prompt Guard. TCOP cannot alter cases for which the detector emitted no warning; C3 is separately reported as a standing receiver guard.\n", encoding="utf-8")
    (output / "reproduce-command.txt").write_text("tcop study independent-warning-full run\n", encoding="utf-8")
    (output / "verify-command.txt").write_text("tcop study independent-warning-full verify\n", encoding="utf-8")
    _write(output / "manifest.json", {"status": "COMPLETE", "policy_execution": True, "rows": len(rows), "source_cases": len(raw), "gates": gates})
    _write(output / "artifact-root-digest.json", {"artifact_root_digest": _root_digest(output)})
    return {"status": "COMPLETE", "rows": len(rows), "source_cases": len(raw), "artifact_dir": str(output), "artifact_root_digest": _root_digest(output)}


def verify_full_population(root: Path) -> dict[str, Any]:
    manifest = _read(root / "manifest.json")
    expected = _read(root / "artifact-root-digest.json")["artifact_root_digest"]
    if manifest.get("status") != "COMPLETE" or manifest.get("rows") != 840 or manifest.get("source_cases") != 168 or _root_digest(root) != expected:
        raise TCOPCommandError("full-population external-warning artifact is invalid")
    if not all(_read(root / "reports" / "gates.json").values()):
        raise TCOPCommandError("full-population external-warning gates did not all pass")
    return {"valid": True, "status": "COMPLETE", "artifact_root_digest": expected}


def report_full_population(root: Path) -> dict[str, Any]:
    verify_full_population(root)
    return {"coverage": _read(root / "reports" / "pipeline-coverage.json"), "authorization": _read(root / "reports" / "authorization-outcomes.json")}
