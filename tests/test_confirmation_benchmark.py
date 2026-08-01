"""Regression tests for the isolated deterministic v0.4 benchmark."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.confirmation_benchmark import CONFIRMATION_BASELINES, CONFIRMATION_SCENARIOS, ConfirmationBenchmarkRunner, run_confirmation_suite
from tcop.regression import run_v01_regression, run_v02_regression, run_v03_regression
from tcop.schema_check import validate_confirmation_schemas


class ConfirmationBenchmarkTests(unittest.TestCase):
    def test_catalogue_and_schemas_are_complete(self) -> None:
        self.assertEqual([f"B-{number:03d}" for number in range(51, 71)], [item.scenario_id for item in CONFIRMATION_SCENARIOS])
        self.assertEqual(10, len(CONFIRMATION_BASELINES))
        catalogue = json.loads(Path("benchmark/scenarios/v0.4-confirmation-catalog.json").read_text())
        self.assertEqual([item.scenario_id for item in CONFIRMATION_SCENARIOS], [item["id"] for item in catalogue["scenarios"]])
        validate_confirmation_schemas()

    def test_staging_avoids_first_batch_false_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = ConfirmationBenchmarkRunner()
            immediate = runner.run("B-056", baseline="v0_3_weighted_full", output=root)
            staged = runner.run("B-056", baseline="full_v0_4", output=root)
            self.assertIn("quarantined", immediate["metrics"]["final_envelopes"].values())
            self.assertNotIn("confirmed_quarantine", staged["metrics"]["final_envelopes"].values())
            self.assertGreater(staged["metrics"]["provisional_containment_count"], 0)

    def test_suite_reproduces_and_writes_confirmation_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_confirmation_suite(root)
            self.assertTrue(result["same_seed_reproducible"])
            artifact = root / "b-059-full_v0_4-seed-42"
            for name in (
                "investigative-tips.jsonl", "investigative-actions.jsonl", "provisional-responses.jsonl",
                "confirmation-requirements.jsonl", "confirmation-events.jsonl", "evidence-campaigns.jsonl",
                "response-severity.jsonl", "confirmation-explanations.txt",
            ):
                self.assertTrue((artifact / name).exists(), name)

    def test_prior_profile_digests_remain_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(run_v01_regression(root / "v0.1")["passed"])
            self.assertTrue(run_v02_regression(root / "v0.2")["passed"])
            self.assertTrue(run_v03_regression(root / "v0.3")["passed"])
