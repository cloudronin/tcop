from __future__ import annotations

import unittest

from tcop.adaptive_coverage import AdaptiveContractError, BRANCHES, validate_adaptation_view, validate_coverage_ledger, validate_valid_broader_risk, valid_broader_risk_summary


def _ledger() -> list[dict[str, object]]:
    rows = []
    for branch in BRANCHES:
        row: dict[str, object] = {"corpus_case_id": "case-1", "condition": "E2E", "branch_id": branch, "disposition": "not_triggered"}
        if branch == "A3": row.update({"disposition": "executed", "subject_relation": "new_subject_or_workload", "campaign_relation": "declared_shared_campaign", "harmful_action": True})
        if branch == "A4": row.update({"disposition": "executed", "harmful_action": False})
        rows.append(row)
    return rows


class AdaptiveCoverageTests(unittest.TestCase):
    def test_every_branch_needs_one_disposition(self) -> None:
        self.assertTrue(validate_coverage_ledger(_ledger(), ["case-1"], ["E2E"])["passed"])
        with self.assertRaises(AdaptiveContractError):
            validate_coverage_ledger(_ledger()[:-1], ["case-1"], ["E2E"])

    def test_a3_and_a4_contracts_fail_closed(self) -> None:
        rows = _ledger(); rows[4]["harmful_action"] = True
        with self.assertRaises(AdaptiveContractError):
            validate_coverage_ledger(rows, ["case-1"], ["E2E"])
        rows = _ledger(); rows[3]["subject_relation"] = "same_subject"
        with self.assertRaises(AdaptiveContractError):
            validate_coverage_ledger(rows, ["case-1"], ["E2E"])

    def test_adaptation_cannot_receive_tcx_or_receiver_state(self) -> None:
        self.assertEqual(validate_adaptation_view({"gateway_result": "denied"})["gateway_result"], "denied")
        with self.assertRaises(AdaptiveContractError):
            validate_adaptation_view({"gateway_result": "denied", "tcx_contents": "forbidden"})

    def test_valid_broader_risk_is_evaluator_only_and_requires_mismatch(self) -> None:
        row = {"detector_independent": True, "protocol_valid_at_receiver": True, "evaluator_ground_truth_harmful": True, "receiver_relevant_relation": True, "mismatch_dimensions": ["subject"], "runtime_inputs": {"warning": "signed"}}
        self.assertTrue(validate_valid_broader_risk(row)["passed"])
        row["mismatch_dimensions"] = []
        with self.assertRaises(AdaptiveContractError):
            validate_valid_broader_risk(row)
        self.assertEqual(valid_broader_risk_summary(2, 0)["mismatch_escalation_status"], "incomplete_for_mismatch_escalation_claims")
