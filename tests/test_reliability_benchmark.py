"""Regression tests for the isolated v0.3 reliability benchmark."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.regression import run_v01_regression, run_v02_regression
from tcop.reliability_benchmark import (
    RELIABILITY_BASELINES,
    RELIABILITY_SCENARIOS,
    ReliabilityBenchmarkRunner,
    run_reliability_suite,
)
from tcop.schema_check import validate_reliability_schemas


class ReliabilityBenchmarkTests(unittest.TestCase):
    def test_catalogue_and_schemas_are_complete(self) -> None:
        self.assertEqual([f"B-{number:03d}" for number in range(31, 51)], [item.scenario_id for item in RELIABILITY_SCENARIOS])
        self.assertEqual(10, len(RELIABILITY_BASELINES))
        catalogue = json.loads(Path("benchmark/scenarios/v0.3-reliability-catalog.json").read_text(encoding="utf-8"))
        self.assertEqual([item.scenario_id for item in RELIABILITY_SCENARIOS], [item["id"] for item in catalogue["scenarios"]])
        validate_reliability_schemas()

    def test_probation_and_group_cap_reduce_false_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = ReliabilityBenchmarkRunner()
            probation = runner.run("B-032", baseline="weighted_full_v0_3", output=root)
            count_based = runner.run("B-033", baseline="v0_2_unweighted_two_domain", output=root)
            collusion = runner.run("B-033", baseline="weighted_full_v0_3", output=root)
            self.assertTrue(all(state != "quarantined" for state in probation["metrics"]["final_envelopes"].values()))
            self.assertTrue(all(state != "quarantined" for state in collusion["metrics"]["final_envelopes"].values()))
            self.assertTrue(all(state == "quarantined" for state in count_based["metrics"]["final_envelopes"].values()))

    def test_central_and_distributed_use_identical_raw_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = ReliabilityBenchmarkRunner()
            runner.run("B-050", baseline="central_weighted_equal", output=root)
            runner.run("B-050", baseline="weighted_full_v0_3", output=root)
            central = json.loads(next(root.glob("b-050-central_weighted_equal-*/manifest.json")).read_text(encoding="utf-8"))
            local = json.loads(next(root.glob("b-050-weighted_full_v0_3-*/manifest.json")).read_text(encoding="utf-8"))
            self.assertEqual(central["input_fact_digests"], local["input_fact_digests"])
            self.assertEqual("central", central["decision_architecture"])
            self.assertEqual("distributed_local", local["decision_architecture"])

    def test_suite_is_reproducible_and_emits_required_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_reliability_suite(root)
            self.assertTrue(result["same_seed_reproducible"])
            artifact = root / "b-041-weighted_full_v0_3-seed-42"
            for name in (
                "observer-reliability.jsonl",
                "reliability-transitions.jsonl",
                "weighted-resolution.jsonl",
                "observer-accusation-graph.json",
                "compromise-windows.jsonl",
                "probation-events.jsonl",
                "stability-metrics.json",
                "decision-explanations.md",
            ):
                self.assertTrue((artifact / name).exists(), name)

    def test_upstream_profile_digests_remain_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(run_v01_regression(root / "v0.1")["passed"])
            self.assertTrue(run_v02_regression(root / "v0.2")["passed"])
