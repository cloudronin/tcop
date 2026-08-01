"""Frozen v0.5 strategy operations exposed through the single TCOP CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cli_support import EXIT_STRATEGY, TCOPCommandError
from .federation import FROZEN_ROOT, FrozenStrategyAdapter


def _certifications(source: Path) -> dict[str, dict[str, Any]]:
    try:
        return FrozenStrategyAdapter(source).certify_all()
    except (AssertionError, OSError, ValueError) as exc:
        raise TCOPCommandError(f"strategy certification failed: {exc}", EXIT_STRATEGY) from exc


def list_strategies(source: Path = FROZEN_ROOT) -> list[dict[str, Any]]:
    records = _certifications(source)
    return [
        {
            "strategy_id": key,
            "canonical_manifest": value["canonical_manifest"],
            "manifest_digest": value["manifest_digest"],
            "resolver_entrypoint": value["resolver_entrypoint"],
            "certified": True,
        }
        for key, value in sorted(records.items())
    ]


def inspect_strategy(strategy_id: str, source: Path = FROZEN_ROOT) -> dict[str, Any]:
    records = _certifications(source)
    if strategy_id not in records:
        raise TCOPCommandError(f"unknown strategy: {strategy_id}", EXIT_STRATEGY)
    return records[strategy_id]


def verify_strategy(strategy_id: str, *, source: Path = FROZEN_ROOT, manifest: Path | None = None) -> dict[str, Any]:
    record = inspect_strategy(strategy_id, source)
    manifest_match = True
    supplied_digest: str | None = None
    if manifest is not None:
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TCOPCommandError(f"invalid strategy manifest: {exc}", EXIT_STRATEGY) from exc
        supplied_digest = str(payload.get("content_digest", ""))
        manifest_match = supplied_digest == record["manifest_digest"] and payload.get("profile_id") == record["canonical_manifest"]
        if not manifest_match:
            raise TCOPCommandError("supplied manifest differs from its frozen canonical strategy", EXIT_STRATEGY)
    return {
        "strategy_id": strategy_id,
        "canonical_manifest": record["canonical_manifest"],
        "manifest_digest": record["manifest_digest"],
        "validator_entrypoint": record["validator_entrypoint"],
        "resolver_entrypoint": record["resolver_entrypoint"],
        "fixture_count": record["fixture_record_count"],
        "decision_digest_match": True,
        "outcome_digest_match": True,
        "supplied_manifest_digest": supplied_digest,
        "manifest_match": manifest_match,
        "certified": True,
    }


def certify_strategies(*, source: Path = FROZEN_ROOT, strategy_id: str | None = None, manifest: Path | None = None) -> dict[str, Any] | list[dict[str, Any]]:
    if strategy_id:
        return verify_strategy(strategy_id, source=source, manifest=manifest)
    if manifest is not None:
        raise TCOPCommandError("--manifest requires a named strategy", EXIT_STRATEGY)
    return [verify_strategy(identifier, source=source) for identifier in sorted(_certifications(source))]
