"""Versioned preservation check for the completed deterministic v0.1 suite."""

from __future__ import annotations

import json
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from typing import Any

from .benchmark import BASELINES, SCENARIOS, BenchmarkRunner
from .witness_benchmark import run_witness_suite
from .reliability_benchmark import run_reliability_suite
from .confirmation_benchmark import run_confirmation_suite


FIXTURE = files("tcop").joinpath("data/v0.1-regression.json")
WITNESS_FIXTURE = files("tcop").joinpath("data/v0.2-regression.json")
RELIABILITY_FIXTURE = files("tcop").joinpath("data/v0.3-regression.json")
CONFIRMATION_EXPECTED_DIGEST = "16849be9aca4405849f2a87e9e1ab2d5f726125e6a72e5440265f82ab424a127"


def run_v01_regression(output: Path, *, seed: int = 42) -> dict[str, Any]:
    """Re-run the frozen v0.1 corpus without sharing its artifact directory.

    The corpus digest covers every per-run deterministic digest, sorted by
    scenario and baseline. It detects a semantic regression without requiring
    generated artifacts to be committed to the repository.
    """

    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    runner = BenchmarkRunner()
    rows = [
        runner.run(scenario.scenario_id, baseline=baseline, seed=seed, output=output)
        for scenario in SCENARIOS
        for baseline in BASELINES
    ]
    material = [
        {
            "scenario_id": row["scenario_id"],
            "baseline": row["baseline"],
            "deterministic_digest": row["deterministic_digest"],
        }
        for row in sorted(rows, key=lambda row: (row["scenario_id"], row["baseline"]))
    ]
    suite_digest = sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    result = {
        "version": "v0.1",
        "seed": seed,
        "scenarios": len(SCENARIOS),
        "baselines": len(BASELINES),
        "suite_digest": suite_digest,
        "expected_suite_digest": expected["suite_digest"],
        "passed": suite_digest == expected["suite_digest"],
    }
    (output / "regression-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise AssertionError("v0.1 deterministic regression digest changed")
    return result


def run_v02_regression(output: Path, *, seed: int = 42) -> dict[str, Any]:
    """Freeze-check the completed v0.2 witness corpus without changing it."""

    expected = json.loads(WITNESS_FIXTURE.read_text(encoding="utf-8"))
    suite = run_witness_suite(output, seed=seed)
    result = {
        "version": "v0.2",
        "seed": seed,
        "suite_digest": suite["same_seed_digest"],
        "expected_suite_digest": expected["suite_digest"],
        "passed": suite["same_seed_digest"] == expected["suite_digest"],
    }
    (output / "regression-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise AssertionError("v0.2 deterministic witness regression digest changed")
    return result


def run_v03_regression(output: Path, *, seed: int = 42) -> dict[str, Any]:
    """Freeze-check the completed v0.3 reliability corpus without mutation."""

    expected = json.loads(RELIABILITY_FIXTURE.read_text(encoding="utf-8"))
    suite = run_reliability_suite(output, seed=seed)
    result = {
        "version": "v0.3",
        "seed": seed,
        "suite_digest": suite["same_seed_digest"],
        "expected_suite_digest": expected["suite_digest"],
        "passed": suite["same_seed_digest"] == expected["suite_digest"],
    }
    (output / "regression-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise AssertionError("v0.3 deterministic reliability regression digest changed")
    return result


def run_v04_regression(output: Path, *, seed: int = 42) -> dict[str, Any]:
    """Freeze-check the v0.4 confirmation corpus without changing it."""

    suite = run_confirmation_suite(output, seed=seed)
    result = {
        "version": "v0.4",
        "seed": seed,
        "suite_digest": suite["same_seed_digest"],
        "expected_suite_digest": CONFIRMATION_EXPECTED_DIGEST,
        "passed": suite["same_seed_digest"] == CONFIRMATION_EXPECTED_DIGEST,
    }
    (output / "regression-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise AssertionError("v0.4 deterministic confirmation digest changed")
    return result
