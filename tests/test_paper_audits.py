"""Regression checks for paper evidence boundaries and anonymity rules."""
import importlib.util
import copy
import json
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


class PaperBuildModeTests(unittest.TestCase):
    def test_preprint_requires_identity_and_public_link(self):
        text = "Vishnu Vettrivel Independent Researcher vishnu@uofa.net"
        urls = [paperlib.PREPRINT_ARTIFACT_URL]
        self.assertEqual([], paperlib.preprint_findings(text, urls, "Vishnu Vettrivel"))
        self.assertEqual([], paperlib.preprint_findings(
            text.replace("Vettrivel", "V ettrivel"), urls, "Vishnu Vettrivel"))
        self.assertTrue(paperlib.preprint_findings("Anonymous Submission", urls, ""))
        self.assertTrue(paperlib.preprint_findings(text, [], "Vishnu Vettrivel"))

    def test_preprint_rejects_anonymous_links_even_with_author(self):
        text = "Vishnu Vettrivel Independent Researcher vishnu@uofa.net"
        urls = [paperlib.PREPRINT_ARTIFACT_URL,
                "https://anonymous.4open.science/r/tcop-B5A5/"]
        self.assertIn("anonymous artifact link in preprint",
                      paperlib.preprint_findings(text, urls, "Vishnu Vettrivel"))

    def test_bibliography_rejects_duplicate_source_and_year(self):
        url = "https://huggingface.co/blog/agent-intrusion-technical-timeline"
        self.assertEqual([], paperlib.bibliography_findings("July 27, 2026.", url))
        self.assertTrue(paperlib.bibliography_findings("2026,\n2026", url))
        self.assertTrue(paperlib.bibliography_findings("2026", url + "\n" + url))


class PreprintRepositoryLinkTests(unittest.TestCase):
    def test_file_and_directory_links_use_the_tag(self):
        for path, kind in (("docs/KNOWN_ISSUES.md", "blob"), ("docs", "tree"), ("", "tree")):
            with self.subTest(path=path):
                url = paperlib.preprint_repository_url(path)
                row = paperlib.repository_link_row(url)
                self.assertTrue(row["tracked_at_head"])
                self.assertTrue(row["valid"])
                self.assertEqual(paperlib.PREPRINT_TAG, row["ref"])
                self.assertIn("/" + kind + "/", url)

    def test_untracked_path_and_wrong_refs_fail(self):
        path = "docs/KNOWN_ISSUES.md"
        url = paperlib.preprint_repository_url(path)
        for invalid in (url.replace("/" + paperlib.PREPRINT_TAG + "/", "/main/"),
                        paperlib.preprint_repository_url("docs/nonexistent-link-fixture.md"),
                        paperlib.PREPRINT_REPOSITORY,
                        url.replace("/blob/", "/tree/")):
            with self.subTest(url=invalid):
                self.assertFalse(paperlib.repository_link_row(invalid)["valid"])

    def test_external_urls_have_no_git_tracking_claim(self):
        row = paperlib.repository_link_row("https://openid.net/specs/example.html")
        self.assertTrue(row["valid"])
        self.assertFalse(row["repository"])
        self.assertIsNone(row["tracked_at_head"])


class CaseMotivationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((paperlib.PAPER / "data/case-motivation.json").read_text())
        self.bibliography = (paperlib.PAPER / "references.bib").read_text()

    def test_sourced_values_and_calendar_day_difference(self):
        values = paperlib.case_motivation_values(self.data, self.bibliography)
        self.assertEqual("July 9", values["CaseHFActivityStart"])
        self.assertEqual("September 10", values["CaseAustraliaNotice"])
        self.assertEqual("84", values["CaseAustraliaNoticeDays"])
        self.assertEqual("mid-August", values["CaseAustraliaDiscovery"])

    def test_unsourced_value_and_wrong_interval_fail(self):
        for name, field, value in (("CaseYear", "source_keys", []),
                                   ("CaseAustraliaNoticeDays", "value", 85)):
            data = copy.deepcopy(self.data)
            data["values"][name][field] = value
            with self.subTest(name=name), self.assertRaises(SystemExit):
                paperlib.case_motivation_values(data, self.bibliography)

    def test_primary_bibtex_records_must_stay_exact(self):
        changed = self.bibliography.replace("Press conference - New York", "Changed title")
        with self.assertRaises(SystemExit):
            paperlib.case_motivation_values(self.data, changed)


if __name__ == "__main__":
    unittest.main()
