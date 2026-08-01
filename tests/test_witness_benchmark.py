"""Regression checks for the versioned deterministic witness benchmark."""

from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from tcop.regression import run_v01_regression
from tcop.schema_check import validate_witness_schemas
from tcop.witness_benchmark import WITNESS_BASELINES, WITNESS_SCENARIOS, WitnessBenchmarkRunner, run_witness_suite


class WitnessBenchmarkTests(unittest.TestCase):
    def test_v01_regression_digest_remains_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertTrue(run_v01_regression(Path(temporary))["passed"])

    def test_v02_catalogue_and_schemas_are_complete(self) -> None:
        self.assertEqual([f"B-{number:03d}" for number in range(11, 31)], [scenario.scenario_id for scenario in WITNESS_SCENARIOS])
        self.assertEqual(10, len(WITNESS_BASELINES))
        catalogue = json.loads(Path("benchmark/scenarios/v0.2-witness-catalog.json").read_text(encoding="utf-8"))
        self.assertEqual([scenario.scenario_id for scenario in WITNESS_SCENARIOS], [item["id"] for item in catalogue["scenarios"]])
        validate_witness_schemas()

    def test_partition_heals_by_relay_without_creating_a_new_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = WitnessBenchmarkRunner().run("B-013", baseline="tcx_passive_plus_patrol", output=Path(temporary))
            self.assertEqual(1, summary["metrics"]["synchronization_after_heal"])
            self.assertEqual("constrained", summary["metrics"]["final_envelopes"]["node-1"])

    def test_patrol_unavailable_and_fabricated_receipt_are_measured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = WitnessBenchmarkRunner()
            unavailable = runner.run("B-014", baseline="tcx_passive_only", output=Path(temporary))
            fabricated = runner.run("B-019", baseline="tcx_passive_plus_patrol", output=Path(temporary))
            self.assertEqual(1, unavailable["metrics"]["patrol_unavailable"])
            self.assertEqual(1.0, fabricated["metrics"]["scenario_objective_success"])

    def test_clean_patrol_recovery_and_faultable_central_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = WitnessBenchmarkRunner()
            recovery = runner.run("B-025", baseline="tcx_passive_plus_patrol", output=Path(temporary))
            no_evidence = runner.run("B-027", baseline="tcx_passive_plus_patrol", output=Path(temporary))
            central = runner.run("B-029", baseline="central_faultable", output=Path(temporary))
            self.assertTrue(all(state == "healthy" for state in recovery["metrics"]["final_envelopes"].values()))
            self.assertEqual(5, no_evidence["metrics"]["no_evidence_nodes"])
            self.assertEqual(1.0, central["metrics"]["scenario_objective_success"])

    def test_central_and_tcx_share_the_same_signed_input_fact_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = WitnessBenchmarkRunner()
            runner.run("B-029", baseline="central_equal", output=root)
            runner.run("B-029", baseline="tcx_passive_plus_patrol", output=root)
            central = json.loads(next(root.glob("b-029-central_equal-*/manifest.json")).read_text(encoding="utf-8"))
            tcx = json.loads(next(root.glob("b-029-tcx_passive_plus_patrol-*/manifest.json")).read_text(encoding="utf-8"))
            self.assertEqual(central["input_fact_digests"], tcx["input_fact_digests"])

    def test_witness_suite_reproduces_and_writes_required_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_witness_suite(root)
            artifact = root / "b-020-tcx_passive_plus_patrol-seed-42"
            self.assertTrue(result["same_seed_reproducible"])
            for name in ("witness-graph.json", "interaction-receipts.jsonl", "patrol-events.jsonl", "control-group-registry.json", "observer-classification.jsonl", "conflicting-evidence.jsonl"):
                self.assertTrue((artifact / name).exists(), name)
