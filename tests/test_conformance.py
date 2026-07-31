"""Executable TCOP Appendix B conformance tests CT-001 through CT-020."""

from __future__ import annotations

import copy
import unittest

from tcop.canonical import canonical_bytes, unsigned_envelope
from tcop.identity import KeyMaterial
from tcop.protocol import make_observation
from tcop.simulation import Cluster


class ConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster = Cluster()
        self.subject = "agent-1"

    def tearDown(self) -> None:
        self.cluster.close()

    def _send(self, observation, destination="node-1"):
        return self.cluster.disseminate("node-1", observation, destinations=[destination])[0]

    def test_ct_001_valid_signed_observation_is_accepted_and_stored(self) -> None:
        result = self._send(self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default", severity="low"))
        self.assertTrue(result.accepted)
        self.assertEqual(1, self.cluster.nodes["node-1"].store.count_observations())

    def test_ct_002_invalid_signature_is_rejected(self) -> None:
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default")
        observation["metadata"]["altered"] = True
        result = self._send(observation)
        self.assertEqual("signature_invalid", result.code)

    def test_ct_003_observer_outside_scope_is_rejected(self) -> None:
        observation = self.cluster.observe("tool", self.subject, "tool.prohibited_export", "runtime:default")
        result = self._send(observation)
        self.assertEqual("scope_violation", result.code)

    def test_ct_004_expired_observation_is_rejected(self) -> None:
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default", ttl=-1)
        result = self._send(observation)
        self.assertEqual("expired", result.code)

    def test_ct_005_duplicate_does_not_create_duplicate_transition(self) -> None:
        observation = self.cluster.observe("tool", self.subject, "tool.prohibited_export", "tool:data.export")
        self._send(observation)
        result = self._send(observation)
        self.assertEqual("replay_detected", result.code)
        self.assertEqual(1, self.cluster.nodes["node-1"].store.count_observations())

    def test_ct_006_older_sequence_cannot_overwrite_newer_sequence(self) -> None:
        newer = self.cluster.observe("runtime", self.subject, "runtime.behavior_deviation", "runtime:default", sequence_number=2)
        older = self.cluster.observe("runtime", self.subject, "runtime.behavior_deviation", "runtime:default", sequence_number=1)
        self.assertTrue(self._send(newer).accepted)
        self.assertEqual("replay_detected", self._send(older).code)

    def test_ct_007_replayed_signed_observation_is_detected(self) -> None:
        observation = self.cluster.observe("memory", self.subject, "memory.contamination", "memory:shared")
        self.assertTrue(self._send(observation).accepted)
        self.assertEqual("replay_detected", self._send(copy.deepcopy(observation)).code)

    def test_ct_008_unknown_optional_extension_is_safe(self) -> None:
        observation = make_observation(
            self.cluster.observers["runtime"],
            subject_id=self.subject,
            observation_type="runtime.lifecycle",
            scope=("runtime:default",),
            now=self.cluster.clock.now,
            extensions=[{"id": "future.optional", "mandatory": False}],
        )
        self.assertTrue(self._send(observation).accepted)

    def test_ct_009_unknown_mandatory_extension_fails_closed(self) -> None:
        observation = make_observation(
            self.cluster.observers["runtime"],
            subject_id=self.subject,
            observation_type="runtime.lifecycle",
            scope=("runtime:default",),
            now=self.cluster.clock.now,
            extensions=[{"id": "future.required", "mandatory": True}],
        )
        self.assertEqual("mandatory_extension_unknown", self._send(observation).code)

    def test_ct_010_partitioned_node_continues_bounded_local_operation(self) -> None:
        self.cluster.transport.partition("node-1", "node-2")
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default")
        self.cluster.disseminate("node-1", observation, destinations=["node-2"])
        envelope = self.cluster.nodes["node-2"].heartbeat_missing(self.subject)
        self.assertEqual("unknown", envelope.state)

    def test_ct_011_sync_after_partition_does_not_resurrect_expired_state(self) -> None:
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default", ttl=1)
        self.cluster.advance(2)
        result = self._send(observation, "node-2")
        self.assertEqual("expired", result.code)

    def test_ct_012_missing_heartbeat_is_unknown_not_healthy(self) -> None:
        envelope = self.cluster.nodes["node-1"].heartbeat_missing(self.subject)
        self.assertEqual("unknown", envelope.state)

    def test_ct_013_single_malicious_observer_cannot_force_quarantine(self) -> None:
        observation = self.cluster.observe("tool", self.subject, "tool.prohibited_export", "tool:data.export", severity="critical")
        self._send(observation)
        self.assertEqual("constrained", self.cluster.nodes["node-1"].responses.envelopes[self.subject].state)

    def test_ct_014_same_trust_domain_is_not_independent_corroboration(self) -> None:
        for index in (1, 2):
            signer = KeyMaterial.deterministic(
                f"same-domain-{index}", "same-domain", scopes=("tool:*",), observation_types=("tool.*",)
            )
            self.cluster.registry.register(signer.identity)
            observation = make_observation(
                signer,
                subject_id=self.subject,
                observation_type="tool.prohibited_export",
                scope=("tool:data.export",),
                now=self.cluster.clock.now,
                sequence_number=index,
                severity="critical",
            )
            self.assertTrue(self._send(observation).accepted)
        self.assertEqual("constrained", self.cluster.nodes["node-1"].responses.envelopes[self.subject].state)

    def test_ct_015_recovery_requires_new_evidence(self) -> None:
        risk = self.cluster.observe("tool", self.subject, "tool.prohibited_export", "tool:data.export", ttl=1)
        self.assertTrue(self._send(risk).accepted)
        self.cluster.advance(2)
        recovery = self.cluster.observe(
            "recovery", self.subject, "recovery.clean_checkpoint", "recovery:checkpoint", sequence_number=2, severity="low"
        )
        self.assertTrue(self._send(recovery).accepted)
        self.assertEqual("recovered", self.cluster.nodes["node-1"].responses.envelopes[self.subject].state)

    def test_ct_016_transport_preserves_signed_canonical_payload(self) -> None:
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default")
        before = canonical_bytes(unsigned_envelope(observation))
        transported = {key: observation[key] for key in reversed(list(observation))}
        self.assertEqual(before, canonical_bytes(unsigned_envelope(transported)))
        self.assertTrue(self._send(transported).accepted)

    def test_ct_017_cross_tenant_observation_is_rejected(self) -> None:
        self.cluster.nodes["node-1"].validator.accepted_tenants = {"isolated"}
        observation = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default")
        self.assertEqual("tenant_violation", self._send(observation).code)

    def test_ct_018_rate_limit_prevents_unbounded_flood(self) -> None:
        node = self.cluster.nodes["node-1"]
        node.validator.max_rate_per_tick = 1
        first = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default", sequence_number=1)
        second = self.cluster.observe("runtime", self.subject, "runtime.lifecycle", "runtime:default", sequence_number=2)
        self.assertTrue(self._send(first).accepted)
        self.assertEqual("rate_limited", self._send(second).code)

    def test_ct_019_challenge_nonce_cannot_be_reused(self) -> None:
        replay = self.cluster.nodes["node-1"].validator.replay
        self.assertTrue(replay.use_challenge_nonce("challenge-1"))
        self.assertFalse(replay.use_challenge_nonce("challenge-1"))

    def test_ct_020_rotation_accepts_new_and_rejects_revoked_key(self) -> None:
        old = self.cluster.observers["runtime"]
        replacement = KeyMaterial.deterministic(
            "runtime", "domain-runtime", key_id="v2", scopes=("runtime:*",), observation_types=("runtime.*",)
        )
        self.cluster.registry.rotate("runtime", "v1", replacement.identity)
        old_observation = make_observation(
            old, subject_id=self.subject, observation_type="runtime.lifecycle", scope=("runtime:default",), now=self.cluster.clock.now
        )
        new_observation = make_observation(
            replacement, subject_id=self.subject, observation_type="runtime.lifecycle", scope=("runtime:default",), now=self.cluster.clock.now, sequence_number=2
        )
        self.assertEqual("identity_unknown", self._send(old_observation).code)
        self.assertTrue(self._send(new_observation).accepted)

