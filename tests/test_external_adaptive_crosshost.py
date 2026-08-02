from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from tcop.external_adaptive_crosshost import run_external_adaptive, verify_external_adaptive

class ExternalAdaptivePreflightTests(unittest.TestCase):
    def test_missing_pinned_dependencies_or_second_host_seals_blocked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_external_adaptive(Path(temporary) / "external")
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(verify_external_adaptive(Path(temporary) / "external")["valid"])
