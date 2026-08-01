"""Focused deterministic conformance tests for the v0.6 outer harness."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.federation import ARCHITECTURES, PHASES, SCENARIOS, FrozenStrategyAdapter, generate_matrix, run_federated_study


class FederatedHarnessTests(unittest.TestCase):
    def test_frozen_strategy_certification_binds_all_admitted_profiles(self) -> None:
        certifications = FrozenStrategyAdapter().certify_all()
        self.assertEqual(set(certifications), {"containment-first", "balanced", "utility-preserving", "forensic-oriented"})
        self.assertEqual(certifications["balanced"]["canonical_manifest"], "V05_CONSOLIDATION_REDUCED")
        self.assertIn("INTERACTION_RECEIPTS", certifications["balanced"]["required_feature_closure"])
        self.assertEqual(certifications["forensic-oriented"]["fixed_runtime_compatibility_configuration"]["configuration_kind"], "runtime_distinct_not_overlay")

    def test_matrix_is_explicit_and_uses_all_registered_scenarios(self) -> None:
        cells = generate_matrix("full")
        self.assertTrue(cells)
        self.assertEqual(set(SCENARIOS), {f"S{index:02d}" for index in range(1, 19)})
        self.assertEqual({cell.scenario_id for cell in cells}, set(SCENARIOS))
        self.assertEqual(set(PHASES.values()), set(range(10)))
        self.assertTrue(all(cell.architecture_id in ARCHITECTURES for cell in cells))
        self.assertTrue(all(cell.strategy_id != "none" for cell in cells if cell.architecture_id == "A2"))

    def test_smoke_enforces_information_and_replay_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "federated"
            result = run_federated_study(root, stage="smoke")
            self.assertTrue(result["conformance"]["passed"])
            self.assertTrue(result["verification"]["passed"])
            replay = json.loads((root / "smoke-replay.json").read_text(encoding="utf-8"))
            self.assertTrue(replay["passed"])
            self.assertTrue((root / "reports" / "federated-domain-report.md").is_file())


if __name__ == "__main__":
    unittest.main()
