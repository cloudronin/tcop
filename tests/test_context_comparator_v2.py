"""Regression gates for comparator v2, whose controls are executed rather than asserted."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.cli_support import TCOPCommandError
from tcop.context_comparator_v2 import (
    ACCEPTED_CONTROL,
    ENVIRONMENT_SIDECAR,
    REJECTION_CONTROLS,
    IntakeControl,
    _controls,
    _execute,
    _fixture,
    _observed_pass,
    _unknown_receipt,
    run_context_comparator_v2,
    verify_context_comparator_v2,
)


class ContextComparatorV2Tests(unittest.TestCase):
    def test_every_control_is_executed_and_passes_on_its_observation(self) -> None:
        rows = _controls()
        self.assertEqual(len(rows), 24)
        for row in rows:
            self.assertTrue(row["executed"])
            self.assertTrue(row["passed"])
            self.assertEqual(row["passed"], _observed_pass(row["expected"], row["observed"]))
        expected = {control.name: control.expected_code for control in REJECTION_CONTROLS}
        for row in rows:
            if row["control"] in expected:
                self.assertEqual(row["observed"]["code"], expected[row["control"]])
                self.assertFalse(row["intake"]["accepted"])
                self.assertFalse(row["observed"]["restriction_created"])

    def test_accepted_context_reaches_only_context_reading_policies(self) -> None:
        rows, token, validated = _execute(ACCEPTED_CONTROL, _fixture())
        self.assertIsNotNone(token); self.assertIsNotNone(validated)
        restricted = {row["condition"]: row["observed"]["policy_restriction_created"] for row in rows}
        self.assertEqual(restricted, {"C0": False, "C1": True, "C2": True, "C3": False})

    def test_control_that_is_not_rejected_is_reported_failed(self) -> None:
        # Same expectation as the invalid-signature control, but the context
        # is left untouched, so the receiver accepts it.
        untampered = IntakeControl("invalid_signature", "signature_invalid")
        rows, token, _ = _execute(untampered, _fixture())
        self.assertIsNotNone(token)
        for row in rows:
            self.assertEqual(row["observed"]["code"], "accepted_independent_peer")
            self.assertTrue(row["observed"]["restriction_created"])
            self.assertFalse(row["passed"])

    def test_rejection_with_the_wrong_code_is_reported_failed(self) -> None:
        mislabeled = IntakeControl("invalid_signature", "signature_invalid", _unknown_receipt)
        rows, _, _ = _execute(mislabeled, _fixture())
        self.assertTrue(all(row["observed"]["code"] == "receipt_unknown" and not row["passed"] for row in rows))

    def test_missing_observation_cannot_pass(self) -> None:
        with self.assertRaises(TCOPCommandError):
            _observed_pass({"code": "signature_invalid", "restriction_created": False}, {"code": "signature_invalid"})

    def test_complete_run_keeps_v1_rows_and_replays_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "comparator-v2"
            result = run_context_comparator_v2(root)
            self.assertEqual(result["rows"], 3824)
            self.assertTrue(result["controls_passed"])
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["result_digest"], manifest["supersedes"]["result_digest"])
            self.assertTrue(manifest["controls_executed"])
            verified = verify_context_comparator_v2(root)
            self.assertTrue(verified["valid"]); self.assertEqual(verified["controls_replayed"], 24)

    def test_root_digest_does_not_depend_on_python_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "comparator-v2"
            digest = run_context_comparator_v2(root)["artifact_root_digest"]
            self.assertFalse((root / "environment.json").exists())
            sidecar = root / ENVIRONMENT_SIDECAR
            sidecar.write_text(json.dumps({**json.loads(sidecar.read_text(encoding="utf-8")), "python": "0.0.0"}), encoding="utf-8")
            self.assertEqual(verify_context_comparator_v2(root)["artifact_root_digest"], digest)
