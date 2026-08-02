"""Executable gates for the separately rooted TCX validation-value study."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcop.validation_value import run_validation_value, verify_validation_value


class ValidationValueTests(unittest.TestCase):
    def test_v2_study_seals_all_preregistered_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_validation_value(Path(temporary) / "v2")
            self.assertEqual(result["rows"], 120)
            self.assertTrue(all(result["gates"].values()))
            self.assertTrue(result["byte_stability"]["normalized_results_byte_identical"])
            self.assertTrue(verify_validation_value(Path(temporary) / "v2")["valid"])
