"""Regression gates for the separately rooted context-value comparator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.context_comparator import ArrivalToken, _decision, run_context_comparator, verify_context_comparator


class ContextComparatorTests(unittest.TestCase):
    def test_arrival_only_token_cannot_expose_context_fields(self) -> None:
        token = ArrivalToken(True, 2, 60)
        with self.assertRaises(AssertionError):
            _ = token.subject

    def test_context_mismatch_is_selective_but_arrival_only_is_not(self) -> None:
        action = {"capability": "repository.write", "subject": "agent-account-19", "resource": "synthetic-benign-metadata", "ordinal": 3}
        token = ArrivalToken(True, 2, 60)
        forwarded, reason, _ = _decision("C1", action, token=token, context=None, baseline_forwarded=True)
        self.assertFalse(forwarded); self.assertEqual(reason, "arrival_only_blanket")

    def test_complete_run_is_sealed_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "comparator"
            result = run_context_comparator(root)
            self.assertEqual(result["rows"], 3824)
            self.assertTrue(result["summary"]["primary_result"]["containment_preserved_C2_vs_C1"])
            self.assertTrue(verify_context_comparator(root)["valid"])
            rows = (root / "normalized" / "comparator-results.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertTrue(all(json.loads(row)["pair_key"].endswith(":comparator-v1") for row in rows))
