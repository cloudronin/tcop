"""Read-only TCOP research artifact inspection and equivalence operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cli_support import EXIT_ARTIFACT, TCOPCommandError
from .evidence_round import verify_evidence_artifact
from .federation import MatrixCell, artifact_root_digest, verify_artifacts


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TCOPCommandError(f"invalid artifact data at {path}: {exc}", EXIT_ARTIFACT) from exc


def _matrix(root: Path, stage: str) -> list[MatrixCell]:
    path = root / "matrix" / f"{stage}-matrix.json"
    values = _json(path)
    if not isinstance(values, list):
        raise TCOPCommandError("artifact matrix must be a list", EXIT_ARTIFACT)
    try:
        return [MatrixCell(**item) for item in values]
    except (TypeError, ValueError) as exc:
        raise TCOPCommandError(f"artifact matrix is invalid: {exc}", EXIT_ARTIFACT) from exc


def inspect_artifact(root: Path) -> dict[str, Any]:
    status, manifest = _json(root / "status.json"), _json(root / "manifest.json")
    digest_path = root / "artifact-root-digest.json"
    digest = _json(digest_path) if digest_path.is_file() else None
    return {
        "artifact_root": str(root),
        "status": status,
        "manifest": manifest,
        "artifact_root_digest": digest,
        "report_files": sorted(str(path.relative_to(root)) for path in (root / "reports").glob("*") if path.is_file()) if (root / "reports").is_dir() else [],
    }


def verify_artifact(root: Path, *, require_complete: bool = False, require_replayable: bool = False) -> dict[str, Any]:
    status, manifest = _json(root / "status.json"), _json(root / "manifest.json")
    if manifest.get("artifact_type") == "evidence-round":
        result = verify_evidence_artifact(root, require_complete=require_complete, require_replayable=require_replayable)
        if not result["valid"]:
            raise TCOPCommandError(json.dumps(result, sort_keys=True), EXIT_ARTIFACT)
        return result
    stage = str(manifest.get("stage", ""))
    cells = _matrix(root, stage)
    verification: dict[str, Any]
    if stage in {"core", "full"}:
        try:
            verification = verify_artifacts(root, cells, matrix_name=f"{stage}-matrix.json")
        except AssertionError as exc:
            raise TCOPCommandError(str(exc), EXIT_ARTIFACT) from exc
    else:
        verification = {"passed": bool(cells), "scope": stage}
    conformance = _json(root / "harness-conformance.json")
    replay = _json(root / "smoke-replay.json")
    digest_record = _json(root / "artifact-root-digest.json") if (root / "artifact-root-digest.json").is_file() else None
    actual_digest = artifact_root_digest(root)
    digest_match = digest_record is not None and digest_record.get("artifact_root_digest") == actual_digest["artifact_root_digest"]
    valid = bool(status.get("passed")) and bool(verification.get("passed")) and bool(conformance.get("passed")) and bool(replay.get("passed")) and (digest_match or digest_record is None)
    if require_complete:
        valid = valid and stage in {"core", "full"}
    if require_replayable:
        valid = valid and bool(replay.get("passed"))
    result = {
        "study": status.get("study"), "artifact_root": str(root), "artifact_root_digest": actual_digest["artifact_root_digest"],
        "frozen_inputs_verified": bool(_json(root / "frozen-inputs.json").get("passed")),
        "strategies_certified": len(_json(root / "strategy-certifications.json")),
        "included_cells": len(cells), "completed_cells": verification.get("expected_run_count", len(cells)),
        "missing_runs": len(verification.get("missing", [])), "invariant_failures": int(not conformance.get("passed")),
        "replay_failures": int(not replay.get("passed")), "digest_match": digest_match,
        "valid": valid,
    }
    if not valid:
        raise TCOPCommandError(json.dumps(result, sort_keys=True), EXIT_ARTIFACT)
    return result


def compare_artifacts(left: Path, right: Path) -> dict[str, Any]:
    left_info, right_info = inspect_artifact(left), inspect_artifact(right)
    left_digest = (left_info.get("artifact_root_digest") or {}).get("artifact_root_digest")
    right_digest = (right_info.get("artifact_root_digest") or {}).get("artifact_root_digest")
    left_manifest, right_manifest = left_info["manifest"], right_info["manifest"]
    if left_digest and left_digest == right_digest:
        classification = "exact_byte_equivalence"
    elif left_manifest.get("result_digest") == right_manifest.get("result_digest"):
        classification = "exact_runtime_equivalence"
    elif left_manifest.get("artifact_type") == "evidence-round" or right_manifest.get("artifact_type") == "evidence-round":
        left_readiness = _json(left / "reports" / "paper-claim-readiness.json")
        right_readiness = _json(right / "reports" / "paper-claim-readiness.json")
        left_pairs = _json(left / "reports" / "paired-causal-comparison.json")
        right_pairs = _json(right / "reports" / "paired-causal-comparison.json")
        classification = "evidence_claim_equivalence" if left_readiness == right_readiness and left_pairs == right_pairs else "not_equivalent"
    else:
        left_metrics = _json(left / "summaries" / "per-cell-metrics.json")
        right_metrics = _json(right / "summaries" / "per-cell-metrics.json")
        left_decisions = [
            _json(path).get("result") for path in sorted((left / "runs").glob("*/summary.json"))
        ]
        right_decisions = [
            _json(path).get("result") for path in sorted((right / "runs").glob("*/summary.json"))
        ]
        if left_decisions == right_decisions:
            classification = "final_decision_equivalence"
        elif left_metrics == right_metrics:
            classification = "aggregate_metric_equivalence"
        elif isinstance(left_metrics, list) and isinstance(right_metrics, list) and [item.get("attack_success") for item in left_metrics] == [item.get("attack_success") for item in right_metrics]:
            classification = "outcome_equivalence"
        else:
            classification = "not_equivalent"
    return {"left": str(left), "right": str(right), "classification": classification, "left_digest": left_digest, "right_digest": right_digest, "left_result_digest": left_manifest.get("result_digest"), "right_result_digest": right_manifest.get("result_digest")}
