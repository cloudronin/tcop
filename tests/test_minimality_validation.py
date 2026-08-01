"""Focused conformance checks for the v0.5 validation-only analysis layer."""

from __future__ import annotations

import unittest

from tcop.minimality_validation import consolidation_profile
from tcop.pareto_analysis import dominates, pareto_records
from tcop.profile_composer import PROFILE_BY_ID, valid_advanced_combinations


class MinimalityValidationTests(unittest.TestCase):
    def test_duplicate_pareto_points_are_equivalent_not_dominators(self) -> None:
        records = [
            {"profile_id": "P2", "security_loss": 86, "utility_loss": 343},
            {"profile_id": "F-00000000", "security_loss": 86, "utility_loss": 343},
        ]
        frontier, dominated = pareto_records(records, dimensions=("security_loss", "utility_loss"))
        self.assertEqual([], dominated)
        self.assertTrue(all(item["pareto_status"] == "equivalent" for item in frontier))
        self.assertFalse(dominates(records[0], records[1], ("security_loss", "utility_loss")))

    def test_joint_consolidation_is_dependency_valid_existing_composition(self) -> None:
        profile = consolidation_profile()
        profile.validate()
        self.assertEqual("P7", profile.parent_profile_id)
        self.assertTrue(set(profile.enabled_features) < set(PROFILE_BY_ID["P7"].enabled_features))
        self.assertNotIn("ACTIVE_PATROL", profile.enabled_features)

    def test_p2_and_zero_advanced_feature_profile_share_enabled_features(self) -> None:
        zero = next(profile for profile in valid_advanced_combinations() if profile.profile_id == "F-00000000")
        self.assertEqual(PROFILE_BY_ID["P2"].enabled_features, zero.enabled_features)

