from __future__ import annotations

import unittest

from tcop.stix_taxii_comparator import run_deterministic_fixtures


class StixTaxiiComparatorTests(unittest.TestCase):
    def test_same_local_action_reaches_all_comparator_conditions(self) -> None:
        result = run_deterministic_fixtures()
        rows = [row for row in result["rows"] if row["corpus_case_id"] == "exact-binding"]
        self.assertEqual({row["condition"] for row in rows}, {"S1", "T2", "S2"})
        self.assertTrue(result["gates"]["A3"]["passed"])
        self.assertTrue(result["gates"]["A4"]["passed"])

    def test_native_composition_can_be_broader_than_receiver_bound_context(self) -> None:
        result = run_deterministic_fixtures()
        rows = {row["condition"]: row for row in result["rows"] if row["corpus_case_id"] == "valid-broader-risk"}
        self.assertEqual(rows["S1"]["opa_policy_result"], "block")
        self.assertEqual(rows["T2"]["opa_policy_result"], "allow")
        self.assertEqual(rows["S2"]["opa_policy_result"], "allow")

    def test_fixture_cannot_claim_external_completion(self) -> None:
        result = run_deterministic_fixtures()
        self.assertFalse(result["external_evaluation"])
        self.assertFalse(result["held_out_execution"])
        self.assertFalse(result["gates"]["A1"]["passed"])
        self.assertFalse(result["gates"]["A2"]["passed"])
