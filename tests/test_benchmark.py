"""Artifact and isolation checks for the deterministic benchmark harness."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.analysis import write_analysis
from tcop.benchmark import BASELINES, SCENARIOS, BenchmarkRunner


class BenchmarkTests(unittest.TestCase):
    def test_catalogue_contains_b_001_through_b_010(self) -> None:
        self.assertEqual([f"B-{number:03d}" for number in range(1, 11)], [scenario.scenario_id for scenario in SCENARIOS])

    def test_published_catalogue_matches_executable_scenarios(self) -> None:
        catalogue = json.loads(Path("benchmark/scenarios/v0.1-catalog.json").read_text(encoding="utf-8"))
        published = [(item["id"], item["attack"], item["propagates"]) for item in catalogue["scenarios"]]
        executable = [(item.scenario_id, item.attack, item.propagates) for item in SCENARIOS]
        self.assertEqual(published, executable)

    def test_false_accusation_is_bounded_not_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = BenchmarkRunner().run("B-004", output=Path(temporary))
            self.assertEqual(1.0, summary["metrics"]["attack_success_rate"])
            self.assertEqual(1.0, summary["metrics"]["false_containment_success"])
            self.assertEqual(1.0, summary["metrics"]["false_containment_rate"])

    def test_delayed_critical_evidence_records_attack_window_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = BenchmarkRunner().run("B-007", output=Path(temporary))
            self.assertEqual(1.0, summary["metrics"]["attack_success_rate"])
            self.assertEqual(10, summary["metrics"]["context_dissemination_latency"])

    def test_sybil_restriction_is_counted_as_availability_disruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = BenchmarkRunner().run("B-010", output=Path(temporary))
            self.assertEqual(1.0, summary["metrics"]["availability_disruption_success"])
            self.assertEqual(1.0, summary["metrics"]["protocol_poisoning_success"])

    def test_artifacts_separate_truth_from_protocol_and_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            BenchmarkRunner().run("B-002", output=root)
            run = next(root.iterdir())
            expected = {
                "manifest.json", "config.json", "environment.json", "protocol-events.jsonl",
                "resolution-events.jsonl", "benchmark-truth.jsonl", "evidence.jsonl",
                "evidence.sqlite3", "propagation-graph.json", "metrics.json", "summary.json", "report.md",
            }
            self.assertTrue(expected <= {path.name for path in run.iterdir()})
            truth = (run / "benchmark-truth.jsonl").read_text(encoding="utf-8")
            protocol = (run / "protocol-events.jsonl").read_text(encoding="utf-8")
            self.assertIn("attack_started", truth)
            self.assertNotIn("attack_started", protocol)

    def test_analysis_writes_a_complete_baseline_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = BenchmarkRunner()
            summaries = [runner.run("B-002", baseline=baseline, output=root) for baseline in BASELINES]
            analysis = write_analysis(root, summaries)
            self.assertEqual(len(BASELINES), analysis["runs"])
            report = (root / "benchmark-report.md").read_text(encoding="utf-8")
            self.assertIn("TCX", report)
            self.assertIn("B-002", report)
