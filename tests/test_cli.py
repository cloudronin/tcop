"""Contract tests for the installed, single TCOP command surface."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from time import time

from tcop.cli import build_parser, dispatch
from tcop.cli_context import create_context, verify_context, verify_receipt
from tcop.cli_support import EXIT_PROTOCOL, EXIT_SERVICE, TCOPCommandError
from tcop.federation import FROZEN_INDEX, FROZEN_ROOT
from tcop.identity import KeyMaterial
from tcop.runtime_services import LocalServiceState


class TCOPCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def _dispatch(self, *arguments: str):
        return dispatch(self.parser.parse_args(list(arguments)))

    def test_documented_top_level_groups_are_available(self) -> None:
        command_action = next(action for action in self.parser._actions if action.dest == "command")
        self.assertTrue({"strategy", "context", "service", "study", "artifact", "admin"} <= set(command_action.choices))

    def test_strategy_verification_is_backed_by_frozen_certification(self) -> None:
        if not (FROZEN_ROOT / FROZEN_INDEX).is_file():
            self.skipTest("requires the generated frozen v0.5 validation artifact")
        value, output = self._dispatch("strategy", "verify", "balanced", "--format", "json")
        self.assertEqual(output, "json")
        self.assertTrue(value["certified"])
        self.assertEqual(value["canonical_manifest"], "V05_CONSOLIDATION_REDUCED")
        self.assertTrue(value["decision_digest_match"])

    def test_context_receipt_round_trip_uses_shared_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context_path, receipt_path = root / "warning.json", root / "receipt.json"
            created = create_context(
                version="0.2", observer_id="observer-1", trust_domain="partner.example",
                subject_id="agent-1", scope="tool:data.export", observation_type="tool.prohibited_export",
                now=2_200_000_000, ttl=60, severity="high", write=context_path, receipt_write=receipt_path,
            )
            self.assertEqual(created["receipt_written_to"], str(receipt_path))
            self.assertTrue(verify_context(context_path, receipt=receipt_path)["accepted"])
            self.assertTrue(verify_receipt(receipt_path, context=context_path)["accepted"])
            tampered = json.loads(context_path.read_text(encoding="utf-8"))
            tampered["severity"] = "low"
            context_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(TCOPCommandError) as raised:
                verify_context(context_path, receipt=receipt_path)
            self.assertEqual(raised.exception.code, EXIT_PROTOCOL)

    def test_context_validation_accepts_an_explicit_public_trust_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context_path, receipt_path, trust_path = root / "warning.json", root / "receipt.json", root / "trust.json"
            create_context(
                version="0.2", observer_id="observer-1", trust_domain="partner.example",
                subject_id="agent-1", scope="tool:data.export", observation_type="tool.prohibited_export",
                now=2_200_000_000, ttl=60, severity="high", write=context_path, receipt_write=receipt_path,
            )
            observer = KeyMaterial.deterministic("observer-1", "partner.example")
            subject = KeyMaterial.deterministic("agent-1", "subject-local")
            trust_path.write_text(json.dumps({
                "trust_store_version": "tcop.trust-store/0.1",
                "identities": [
                    {"id": "observer-1", "trust_domain": "partner.example", "key_id": "v1", "public_key": observer.identity.public_key.hex()},
                    {"id": "agent-1", "trust_domain": "subject-local", "key_id": "v1", "public_key": subject.identity.public_key.hex()},
                ],
                "control_groups": [
                    {"id": "observer-1", "admin_domain_id": "partner.example", "control_group_id": "control::observer-1", "role": "peer"},
                    {"id": "agent-1", "admin_domain_id": "subject-local", "control_group_id": "control::agent-1", "role": "subject"},
                ],
            }), encoding="utf-8")
            result = verify_context(context_path, receipt=receipt_path, trust_store=trust_path)
            self.assertTrue(result["accepted"])
            self.assertEqual(result["trust_store"], str(trust_path))

    def test_study_matrix_accepts_primary_alias_and_writes_core_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            matrix = Path(temporary) / "matrix.json"
            value, _ = self._dispatch("study", "matrix", "--selection", "primary", "--output", str(matrix))
            self.assertEqual(value["selection"], "primary")
            cells = json.loads(matrix.read_text(encoding="utf-8"))
            self.assertEqual(value["cell_count"], len(cells))
            self.assertTrue(cells)
            self.assertTrue(all(cell["architecture_id"] in {"A0", "A1", "A2", "A3"} for cell in cells))

    def test_service_rejects_remote_enforcement_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "unsafe.json"
            config.write_text(json.dumps({
                "apiVersion": "tcop.io/v0.6", "kind": "Domain", "metadata": {"domainId": "example"},
                "spec": {"remoteEnforcement": {"enabled": True}},
            }), encoding="utf-8")
            with self.assertRaises(TCOPCommandError) as raised:
                self._dispatch("service", "domain", "--config", str(config), "--dry-run")
            self.assertEqual(raised.exception.code, EXIT_SERVICE)

    def test_local_runtime_validates_then_records_only_a_local_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = int(time())
            created = create_context(
                version="0.1", observer_id="observer-1", trust_domain="partner.example",
                subject_id="agent-1", scope="tool:data.export", observation_type="tool.prohibited_export",
                now=now, ttl=60, severity="high",
            )
            state = LocalServiceState("enterprise-us", "domain", root / "state")
            accepted, record = state.validate_and_store(created["context"])
            self.assertTrue(accepted)
            self.assertIn("local_resolution", record)
            self.assertIn("local_enforcement", record)
            self.assertNotIn("remote_enforcement", record)


if __name__ == "__main__":
    unittest.main()
