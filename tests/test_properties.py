"""Focused generative-style invariants without exposing benchmark ground truth."""

from __future__ import annotations

import unittest
import json
from pathlib import Path

from tcop.canonical import canonical_bytes, unsigned_envelope
from tcop.identity import AuthorityRegistry, KeyMaterial
from tcop.protocol import make_observation
from tcop.schema_check import validate_published_schema
from tcop.time import parse_rfc3339
from tcop.simulation import Cluster


class ProtocolInvariantTests(unittest.TestCase):
    def test_canonicalization_is_invariant_to_insertion_order(self) -> None:
        original = {"z": [3, 2, 1], "a": {"y": True, "x": "value"}}
        reordered = {"a": {"x": "value", "y": True}, "z": [3, 2, 1]}
        self.assertEqual(canonical_bytes(original), canonical_bytes(reordered))

    def test_authority_cycle_is_invalid(self) -> None:
        registry = AuthorityRegistry()
        left = KeyMaterial.deterministic("left", "domain-left")
        right = KeyMaterial.deterministic("right", "domain-right")
        registry.register(left.identity, delegated_by="right")
        registry.register(right.identity, delegated_by="left")
        self.assertFalse(registry.validate_authority_chain("left"))

    def test_tampering_any_signed_field_breaks_signature(self) -> None:
        cluster = Cluster()
        try:
            observation = cluster.observe("runtime", "agent-1", "runtime.lifecycle", "runtime:default")
            observation["confidence"] = 0.1
            result = cluster.disseminate("node-1", observation, destinations=["node-1"])[0]
            self.assertEqual("signature_invalid", result.code)
        finally:
            cluster.close()

    def test_core_packages_do_not_import_benchmark_oracle(self) -> None:
        import tcop.protocol as protocol
        import tcop.responses as responses
        import tcop.trust as trust

        for module in (protocol, responses, trust):
            self.assertNotIn("benchmark", module.__dict__)

    def test_published_schema_is_valid_for_the_reference_profile(self) -> None:
        validate_published_schema()

    def test_golden_observation_fixture_verifies_without_reencoding_drift(self) -> None:
        fixture = Path("tests/fixtures/valid-observation-v0.1.json")
        observation = json.loads(fixture.read_text(encoding="utf-8"))
        cluster = Cluster(now=parse_rfc3339(observation["issued_at"]))
        try:
            result = cluster.disseminate("node-1", observation, destinations=["node-1"])[0]
            self.assertTrue(result.accepted)
        finally:
            cluster.close()
