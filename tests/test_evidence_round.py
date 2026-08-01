"""Deterministic contract tests for the v0.6 missing-evidence round."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.evidence_round import run_evidence_study, verify_evidence_artifact
from tcop.federation import artifact_root_digest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "artifacts" / "federated-domain-v0.6"


class EvidenceRoundTests(unittest.TestCase):
    def test_smoke_audits_pairs_and_replays_diagnostics_without_mutating_source(self) -> None:
        if not (SOURCE / "status.json").is_file():
            self.skipTest("requires the generated v0.6 federation source artifact")
        source_before = artifact_root_digest(SOURCE)["artifact_root_digest"]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            result = run_evidence_study(output, selection="smoke", source_artifact=SOURCE)
            self.assertTrue(result["replay"]["passed"])
            self.assertEqual(result["pair_count"], 177)
            pair_report = json.loads((output / "pairs" / "input-equivalence-report.json").read_text(encoding="utf-8"))
            self.assertEqual(pair_report["eligible_pair_count"], 54)
            self.assertEqual(pair_report["mismatch_fields"], {"local_policy_configuration": 123})
            verification = verify_evidence_artifact(output, require_replayable=True)
            self.assertTrue(verification["valid"])
            recorded = json.loads((output / "artifact-root-digest.json").read_text(encoding="utf-8"))
            self.assertEqual(recorded["artifact_root_digest"], artifact_root_digest(output)["artifact_root_digest"])
        self.assertEqual(source_before, artifact_root_digest(SOURCE)["artifact_root_digest"])


if __name__ == "__main__":
    unittest.main()
