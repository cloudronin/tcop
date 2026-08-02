from __future__ import annotations

import unittest

from tcop.independent_warning_v2 import _evaluate


class IndependentWarningV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = {
            "source_item_id": "agentdojo/run-1", "source_item_content_hash": "a" * 64,
            "source_label": "attack_bearing", "raw_label": "LABEL_1", "normalized_category": "tcx.prompt_attack",
        }

    def test_exact_and_receiver_relation_controls_have_declared_boundaries(self) -> None:
        rows, candidates, signing, lifecycle = _evaluate({"selected_external_positive_exact": [self.base], "selected_external_negative": []}, {})
        self.assertTrue(candidates); self.assertTrue(signing); self.assertTrue(lifecycle)
        by = {(row["stratum"], row["policy"]): row for row in rows}
        self.assertTrue(by[("external_positive_exact", "C2")]["restriction"])
        self.assertFalse(by[("partial_binding", "C2E")]["restriction"])
        self.assertFalse(by[("mismatched_binding", "C2E")]["restriction"])
        self.assertFalse(by[("sender_suggested_only", "C2E")]["restriction"])
        self.assertFalse(by[("substitution_no_local_relation", "C2E")]["restriction"])
        self.assertTrue(by[("substitution_with_local_relation", "C2E")]["restriction"])

    def test_stale_and_replayed_controls_cannot_restrict(self) -> None:
        rows, _, _, _ = _evaluate({"selected_external_positive_exact": [self.base], "selected_external_negative": []}, {})
        for row in rows:
            if row["stratum"] in {"stale", "replayed"}:
                self.assertFalse(row["restriction"])
                self.assertTrue(row["rejected_before_policy"])
