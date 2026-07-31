"""Regression checks for the deterministic second-iteration experiments."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcop.experiments import run_deterministic_experiments


class DeterministicExperimentTests(unittest.TestCase):
    def test_experiments_locate_containment_window_and_failure_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_deterministic_experiments(Path(temporary))
            self.assertEqual(108, result["summary"]["timing_points"])
            self.assertEqual(48, result["summary"]["topology_points"])
            self.assertTrue(any(not point["full_containment"] for point in result["timing_sweep"]))
            self.assertTrue(
                all(
                    (point["containment_window"] is not None and point["containment_window"] >= 0)
                    == point["full_containment"]
                    for point in result["timing_sweep"]
                )
            )
            self.assertTrue(any(not point["full_containment"] for point in result["topology_sweep"]))
            self.assertTrue(any(point["full_containment"] for point in result["topology_sweep"]))
            postures = {row["posture"]: row for row in result["partition_postures"]}
            self.assertEqual(1.1, postures["fail_open"]["weighted_security_loss"])
            self.assertEqual(0.0, postures["fail_closed"]["weighted_security_loss"])
            self.assertEqual(0.0, postures["fail_open"]["weighted_utility_loss"])
            self.assertEqual(1.1, postures["fail_closed"]["weighted_utility_loss"])
            self.assertTrue(result["false_containment"]["withdrawal_restored_operation"])
            self.assertEqual(1.0, result["false_containment"]["severity_weighted_utility_loss"])
            self.assertEqual(0, result["architecture_controls"]["tcx"]["cross_domain_blast_radius"])
            self.assertEqual(2, result["architecture_controls"]["central_unavailable"]["cross_domain_blast_radius"])
            self.assertEqual("scope_violation", result["ablations"]["observer_scope"]["enforced"])
            self.assertEqual("accepted", result["ablations"]["observer_scope"]["disabled"])
            self.assertEqual("expired", result["ablations"]["expiration"]["enforced"])
            self.assertEqual("accepted", result["ablations"]["expiration"]["disabled"])
            self.assertEqual("constrained", result["ablations"]["trust_domain_diversity"]["enforced_state"])
            self.assertEqual("quarantined", result["ablations"]["trust_domain_diversity"]["disabled_state"])
