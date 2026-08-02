from __future__ import annotations

import unittest

from tcop.c2e_frontier import _report, _rows


class C2EFrontierTests(unittest.TestCase):
    def test_predeclared_frontier_selectivity_holds(self) -> None:
        rows, lifecycle = _rows()
        report = _report(rows, lifecycle)
        self.assertEqual(len(rows), 150)
        self.assertEqual(report["predeclared_interpretation"], "central_policy_frontier")
        self.assertEqual(report["per_policy"]["C2E"]["harmful_blocked"], 10)
        self.assertEqual(report["per_policy"]["C2E"]["benign_constrained"], 0)
        self.assertEqual(report["per_policy"]["C1"]["benign_constrained"], 10)
        self.assertEqual(report["per_policy"]["C3"]["benign_constrained"], 10)

    def test_invalid_relations_are_monitor_only_and_unrelated_is_unrestricted(self) -> None:
        rows, _ = _rows()
        invalid = [row for row in rows if row["population"] == "invalid_expired_replayed_sender_suggested_only_relations"]
        unrelated = [row for row in rows if row["population"] == "benign_unrelated_subjects_sessions_resources"]
        self.assertTrue(all(row["monitor_only"] for row in invalid))
        self.assertTrue(all(not row["unrelated_restriction"] for row in unrelated))

    def test_c2e_field_traces_never_use_remote_enforcement(self) -> None:
        rows, _ = _rows()
        c2e = [row for row in rows if row["policy"] == "C2E"]
        self.assertEqual(len(c2e), 30)
        self.assertTrue(all(row["decision_trace"]["remote_enforcement"] is False for row in c2e))
        self.assertTrue(all(row["decision_trace"]["fields_used"] for row in c2e))
