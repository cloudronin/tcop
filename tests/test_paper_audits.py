"""Regression checks for paper evidence boundaries and anonymity rules."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "paperlib", Path(__file__).resolve().parents[1] / "paper/usenix27/scripts/paperlib.py"
)
paperlib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paperlib)


class PaperAnonymityTests(unittest.TestCase):
    def test_third_party_urls_pass(self):
        for url in (
            "https://github.com/NVIDIA/NemoClaw",
            "https://github.com/abiosoft/colima/blob/main/docs/FAQ.md",
            "https://huggingface.co/blog/agent-intrusion-technical-timeline",
        ):
            with self.subTest(url=url):
                self.assertEqual([], paperlib.anonymity_findings(url))

    def test_author_identifiers_fail(self):
        for text in (
            "https://github.com/cloudronin/tcop",
            "https://github.com/cloudronin",
            "https://raw.githubusercontent.com/cloudronin/tcop/main/README.md",
            "https://cloudronin.github.io/tcop/",
            "Vishnu Vettrivel",
            "author@example.org",
            "/Users/alice/project/main.tex",
            "/home/alice/project/main.tex",
        ):
            with self.subTest(text=text):
                self.assertTrue(paperlib.anonymity_findings(text))


class PaperEvidenceTests(unittest.TestCase):
    def test_controls_preserve_unexecuted_and_mutation_evidence(self):
        rows = paperlib.failure_control_rows()
        self.assertEqual(16, len(rows))
        self.assertEqual(10, sum(r["evidence_class"] == "live-executed" for r in rows))
        self.assertEqual(2, sum(r["evidence_class"] == "signed-envelope-mutation" for r in rows))
        untested = {r["control"] for r in rows if r["passed"] is None}
        self.assertEqual({"disallowed_import_type", "no_remote_enforcement", "gateway_restart",
                          "session_termination_before_context_arrival"}, untested)
        self.assertTrue(all(r["pass_label"] == "Not tested" for r in rows if r["passed"] is None))


if __name__ == "__main__":
    unittest.main()
