"""Fail-closed source-artifact admission for the agent-validation study."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..cli_support import EXIT_FROZEN_INPUT, TCOPCommandError, load_config
from ..federation import FROZEN_ROOT, FrozenStrategyAdapter, artifact_root_digest


AGENT_STUDY_KIND = "agent_validation"
STUDY_PLAN = Path("benchmark/studies/v0.6-agent-validation.yaml")
SOURCE_EVIDENCE_DIGEST = "0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99"
SOURCE_FEDERATION_DIGEST = "194e46000494eeda6f3966ecf1d74c22e532a40d685014b57d8fc5986b324a50"
SUPERSEDED_SOURCE_DIGEST = "cd26169c8b9d9620b3c62b08e3c1702c992a1461d603b08b7cd61c797b21a5f3"
SOURCE_EVIDENCE_ROOT = Path("artifacts/federated-domain-v0.6-evidence")
SOURCE_FEDERATION_ROOT = Path("artifacts/federated-domain-v0.6")
FROZEN_STRATEGY_DIGESTS = {
    "containment-first": "60a4c97851d19c6bcf09d24a063b480e9a29a49dca7e0665ead9013eaf8d2691",
    "balanced": "4b2dfb385d71ee4ef3e8c598cf7cac4da80fdb62ed8d22d7ad241918c9e69890",
    "utility-preserving": "7cf402995d0b4c0e6473aaad4cca7b420abcccf35b7844b65935d07ee9db8940",
    "forensic-oriented": "e30ded1303d08c6067a5030d9e1741183bf30af96d218c2143bc1e21db237d96",
}


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TCOPCommandError(f"agent study source is unreadable: {path}: {exc}", EXIT_FROZEN_INPUT) from exc
    if not isinstance(value, dict):
        raise TCOPCommandError(f"agent study source must be an object: {path}", EXIT_FROZEN_INPUT)
    return value


def load_agent_plan(path: Path = STUDY_PLAN) -> dict[str, Any]:
    """Load the external-validation plan without accepting alternate source IDs."""

    plan = load_config(path)
    required = {
        "study", "study_kind", "source_artifact_amendment", "source_evidence", "source_federation",
        "frozen_strategy_digests", "timing", "architectures", "scenarios", "authorization", "gateway", "artifact_root",
    }
    missing = required - set(plan)
    if missing or plan.get("study_kind") != AGENT_STUDY_KIND:
        detail = ", ".join(sorted(missing)) or "incorrect study_kind"
        raise TCOPCommandError(f"agent study plan is incomplete: {detail}", EXIT_FROZEN_INPUT)
    if plan.get("source_evidence", {}).get("artifact_root_digest") != SOURCE_EVIDENCE_DIGEST:
        raise TCOPCommandError("agent study plan source evidence digest is not the formally admitted digest", EXIT_FROZEN_INPUT)
    if plan.get("source_federation", {}).get("artifact_root_digest") != SOURCE_FEDERATION_DIGEST:
        raise TCOPCommandError("agent study plan source federation digest is not the formally admitted digest", EXIT_FROZEN_INPUT)
    if plan.get("frozen_strategy_digests") != FROZEN_STRATEGY_DIGESTS:
        raise TCOPCommandError("agent study plan frozen strategy digests differ from admitted inputs", EXIT_FROZEN_INPUT)
    if plan.get("authorization", {}).get("cache_correctness") != "disabled" or plan.get("gateway", {}).get("authorization_cache") != "disabled":
        raise TCOPCommandError("agent study plan must disable authorization caching for correctness runs", EXIT_FROZEN_INPUT)
    if plan.get("gateway", {}).get("selection_manifest") != "integrations/mcp-gateway/gateway-selection-manifest.json":
        raise TCOPCommandError("agent study plan gateway selection manifest differs from the admitted integration", EXIT_FROZEN_INPUT)
    return plan


def verify_agent_source(
    *,
    evidence_root: Path = SOURCE_EVIDENCE_ROOT,
    federation_root: Path = SOURCE_FEDERATION_ROOT,
    frozen_root: Path = FROZEN_ROOT,
) -> dict[str, Any]:
    """Verify the source artifacts and frozen strategies before any study work.

    This intentionally does not reproduce or rewrite either source artifact:
    a missing or changed input is an error, not an instruction to regenerate it.
    """

    evidence_manifest = _read(evidence_root / "manifest.json")
    federation_manifest = _read(federation_root / "manifest.json")
    evidence_digest = artifact_root_digest(evidence_root)["artifact_root_digest"]
    federation_digest = artifact_root_digest(federation_root)["artifact_root_digest"]
    if evidence_digest != SOURCE_EVIDENCE_DIGEST:
        raise TCOPCommandError(
            f"agent study source evidence digest mismatch: expected {SOURCE_EVIDENCE_DIGEST}, got {evidence_digest}",
            EXIT_FROZEN_INPUT,
        )
    if federation_digest != SOURCE_FEDERATION_DIGEST:
        raise TCOPCommandError(
            f"agent study source federation digest mismatch: expected {SOURCE_FEDERATION_DIGEST}, got {federation_digest}",
            EXIT_FROZEN_INPUT,
        )
    if not evidence_manifest.get("passed") or evidence_manifest.get("remote_enforcement_successes") != 0:
        raise TCOPCommandError("agent study evidence source did not pass its local-authority invariants", EXIT_FROZEN_INPUT)
    if not federation_manifest.get("passed") or not federation_manifest.get("no_remote_enforcement_for_a2"):
        raise TCOPCommandError("agent study federation source did not pass its local-enforcement invariants", EXIT_FROZEN_INPUT)
    thresholds = evidence_root / "reports" / "strategy-timing-thresholds.json"
    if not thresholds.is_file():
        raise TCOPCommandError("agent study source omits pre-registered timing thresholds", EXIT_FROZEN_INPUT)
    certifications = FrozenStrategyAdapter(frozen_root).certify_all()
    received = {key: value.get("manifest_digest") for key, value in certifications.items()}
    if received != FROZEN_STRATEGY_DIGESTS:
        raise TCOPCommandError("agent study frozen strategy certification mismatch", EXIT_FROZEN_INPUT)
    return {
        "source_artifact_amendment": "spec/v0.6-agent-validation-source-artifact-amendment.md",
        "superseded_source_digest": SUPERSEDED_SOURCE_DIGEST,
        "source_evidence_root": str(evidence_root),
        "source_evidence_digest": evidence_digest,
        "source_federation_root": str(federation_root),
        "source_federation_digest": federation_digest,
        "timing_thresholds": str(thresholds),
        "frozen_strategy_digests": received,
        "passed": True,
    }
