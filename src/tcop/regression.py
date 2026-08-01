"""Versioned preservation check for the completed deterministic v0.1 suite."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from .benchmark import BASELINES, SCENARIOS, BenchmarkRunner


FIXTURE = Path(__file__).parents[2] / "tests" / "fixtures" / "v0.1-regression.json"


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
