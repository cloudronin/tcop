"""CT-065 through CT-090 for the deterministic v0.4 confirmation profile."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.confirmation import ConfirmationProfile, ConfirmationResolver, EvidenceCampaignManager, VersionedConfirmationValidator
from tcop.confirmation_benchmark import ConfirmationBenchmarkRunner


class ConfirmationConformanceTests(unittest.TestCase):
    def run_case(self, scenario: str, baseline: str = "full_v0_4") -> tuple[dict, Path, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        summary = ConfirmationBenchmarkRunner().run(scenario, baseline=baseline, output=root)
        run_dir = next(root.glob(f"{scenario.lower()}-{baseline}-*"))
        return summary, run_dir, temporary

    def test_ct_065_quarantined_issuer_has_tip_but_zero_credit(self) -> None:
        _, directory, temporary = self.run_case("B-051")
        try:
            tip = json.loads((directory / "investigative-tips.jsonl").read_text().splitlines()[0])
            self.assertTrue(tip["eligible"])
            self.assertEqual(0, tip["corroborative_influence_milli"])
        finally:
            temporary.cleanup()

    def test_ct_066_invalid_artifact_dispatch_is_rejected(self) -> None:
        self.assertEqual((False, "unsupported_confirmation_version"), VersionedConfirmationValidator().validate({"signature": "forged"}))

    def test_ct_067_tip_cannot_quarantine_directly(self) -> None:
        summary, _, temporary = self.run_case("B-052")
        try:
            self.assertTrue(all(state != "confirmed_quarantine" for state in summary["metrics"]["final_envelopes"].values()))
        finally:
            temporary.cleanup()

    def test_ct_068_tip_is_scope_limited(self) -> None:
        _, directory, temporary = self.run_case("B-052")
        try:
            response = json.loads((directory / "provisional-responses.jsonl").read_text().splitlines()[0])
            self.assertEqual("tool:data.export", response["scope"])
        finally:
            temporary.cleanup()

    def test_ct_069_repeated_tips_are_budgeted_and_deduplicated(self) -> None:
        summary, _, temporary = self.run_case("B-067")
        try:
            self.assertGreater(summary["metrics"]["tip_flood_work_prevented"], 0)
            self.assertLessEqual(summary["metrics"]["investigation_cost_milli"], 2400)
        finally:
            temporary.cleanup()

    def test_ct_070_unavailable_patrol_is_not_clean(self) -> None:
        summary, _, temporary = self.run_case("B-055")
        try:
            self.assertEqual(1, summary["metrics"]["patrol_unavailable"])
            self.assertNotEqual("healthy", next(iter(summary["metrics"]["final_envelopes"].values())))
        finally:
            temporary.cleanup()

    def test_ct_071_remote_first_batch_is_provisional(self) -> None:
        summary, _, temporary = self.run_case("B-056")
        try:
            self.assertEqual(0, summary["metrics"]["false_quarantine_success"])
            self.assertGreater(summary["metrics"]["provisional_containment_count"], 0)
        finally:
            temporary.cleanup()

    def test_ct_072_authorized_direct_local_evidence_can_quarantine(self) -> None:
        summary, directory, temporary = self.run_case("B-060")
        try:
            self.assertIn("confirmed_quarantine", summary["metrics"]["final_envelopes"].values())
            self.assertIn("audit-B-060-3", (directory / "confirmation-explanations.txt").read_text())
        finally:
            temporary.cleanup()

    def test_ct_073_and_ct_074_provisional_has_deadline_and_never_escalates_from_time(self) -> None:
        summary, directory, temporary = self.run_case("B-062")
        try:
            response = json.loads((directory / "provisional-responses.jsonl").read_text().splitlines()[0])
            self.assertGreater(response["confirmation_deadline"], response["activated_at"])
            self.assertTrue(all(state == "monitored" for state in summary["metrics"]["final_envelopes"].values()))
        finally:
            temporary.cleanup()

    def test_ct_075_repeat_does_not_confirm(self) -> None:
        summary, _, temporary = self.run_case("B-057")
        try:
            self.assertGreater(summary["metrics"]["repeated_source_confirmation_attempts_rejected"], 0)
        finally:
            temporary.cleanup()

    def test_ct_076_relay_equivalent_is_one_campaign(self) -> None:
        manager = EvidenceCampaignManager("domain-a", ConfirmationProfile())
        observation = {"observation_id": "obs-1", "subject": {"id": "subject"}, "scope": ["memory.write"], "observation_type": "tool.prohibited_export", "observer_control_group_id": "group-a", "interaction_id": "interaction-1"}
        first = manager.ingest(observation, 1)
        relayed = {**observation, "relay_chain": ["relay-a"]}
        second = manager.ingest(relayed, 2)
        self.assertEqual(first.campaign_id, second.campaign_id)
        self.assertEqual(1, len(second.observation_ids))

    def test_ct_077_same_source_new_interaction_is_not_novel_by_default(self) -> None:
        summary, _, temporary = self.run_case("B-058")
        try:
            self.assertTrue(all(state != "confirmed_quarantine" for state in summary["metrics"]["final_envelopes"].values()))
        finally:
            temporary.cleanup()

    def test_ct_078_new_group_can_confirm(self) -> None:
        summary, _, temporary = self.run_case("B-059")
        try:
            self.assertIn("confirmed_quarantine", summary["metrics"]["final_envelopes"].values())
        finally:
            temporary.cleanup()

    def test_ct_079_failed_patrol_can_confirm(self) -> None:
        summary, _, temporary = self.run_case("B-061")
        try:
            self.assertIn("confirmed_quarantine", summary["metrics"]["final_envelopes"].values())
        finally:
            temporary.cleanup()

    def test_ct_080_direct_local_can_confirm(self) -> None:
        summary, _, temporary = self.run_case("B-060")
        try:
            self.assertGreater(summary["metrics"]["provisional_to_quarantine_count"], 0)
        finally:
            temporary.cleanup()

    def test_ct_081_clean_patrol_deescalates(self) -> None:
        summary, _, temporary = self.run_case("B-054")
        try:
            self.assertTrue(all(state == "monitored" for state in summary["metrics"]["final_envelopes"].values()))
        finally:
            temporary.cleanup()

    def test_ct_082_staggered_evidence_is_grouped(self) -> None:
        _, directory, temporary = self.run_case("B-064")
        try:
            campaigns = [json.loads(line) for line in (directory / "evidence-campaigns.jsonl").read_text().splitlines()]
            self.assertEqual(1, len([item for item in campaigns if item["local_domain_id"] == "domain-node-1"]))
        finally:
            temporary.cleanup()

    def test_ct_083_slow_evidence_splits_under_explicit_window(self) -> None:
        _, directory, temporary = self.run_case("B-065")
        try:
            campaigns = [json.loads(line) for line in (directory / "evidence-campaigns.jsonl").read_text().splitlines()]
            self.assertGreaterEqual(len(campaigns), 2)
        finally:
            temporary.cleanup()

    def test_ct_084_expiry_is_deterministic(self) -> None:
        first, _, first_tmp = self.run_case("B-062")
        second, _, second_tmp = self.run_case("B-062")
        try:
            self.assertEqual(first["deterministic_digest"], second["deterministic_digest"])
        finally:
            first_tmp.cleanup()
            second_tmp.cleanup()

    def test_ct_085_high_risk_tip_reserves_capacity(self) -> None:
        _, directory, temporary = self.run_case("B-067")
        try:
            actions = [json.loads(line) for line in (directory / "investigative-actions.jsonl").read_text().splitlines()]
            scheduled = [item for item in actions if item["result"] == "scheduled"]
            self.assertTrue(any(item["scope"] == "financial.transfer" for item in scheduled))
            self.assertTrue(all(sum(item["result"] == "scheduled" and item["local_domain_id"] == domain for item in actions) <= 3 for domain in {item["local_domain_id"] for item in actions}))
        finally:
            temporary.cleanup()

    def test_ct_086_tip_does_not_restore_reliability(self) -> None:
        _, directory, temporary = self.run_case("B-051")
        try:
            tips = [json.loads(line) for line in (directory / "investigative-tips.jsonl").read_text().splitlines()]
            self.assertTrue(all(item["corroborative_influence_milli"] == 0 for item in tips if item["eligible"]))
        finally:
            temporary.cleanup()

    def test_ct_087_severity_is_integer_and_deterministic(self) -> None:
        summary, directory, temporary = self.run_case("B-066")
        try:
            entries = [json.loads(line) for line in (directory / "response-severity.jsonl").read_text().splitlines()]
            self.assertTrue(all(isinstance(item["severity_milli"], int) for item in entries))
            self.assertIn("severity_weighted_false_containment_milli", summary["metrics"])
        finally:
            temporary.cleanup()

    def test_ct_088_central_and_tcx_share_inputs(self) -> None:
        _, local_dir, local_tmp = self.run_case("B-070", "full_v0_4")
        _, central_dir, central_tmp = self.run_case("B-070", "central_weighted_staged_equal")
        try:
            local = json.loads((local_dir / "manifest.json").read_text())
            central = json.loads((central_dir / "manifest.json").read_text())
            self.assertEqual(local["input_fact_digests"], central["input_fact_digests"])
            self.assertEqual(local["receipt_digests"], central["receipt_digests"])
            self.assertEqual(local["fault_schedule"], central["fault_schedule"])
        finally:
            local_tmp.cleanup()
            central_tmp.cleanup()

    def test_ct_089_same_time_confirmation_uses_snapshot(self) -> None:
        summary, _, temporary = self.run_case("B-056")
        try:
            self.assertTrue(summary["metrics"]["same_time_confirmation_snapshot"])
        finally:
            temporary.cleanup()

    def test_ct_090_confirmation_code_has_no_benchmark_truth_import(self) -> None:
        import tcop.confirmation as confirmation

        self.assertNotIn("benchmark", confirmation.__dict__)
