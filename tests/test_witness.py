"""CT-021 through CT-040 for the deterministic TCX v0.2 witness profile."""

from __future__ import annotations

import unittest

from tcop.canonical import canonical_bytes
from tcop.witness import (
    VersionedObservationValidator,
    WitnessCluster,
    make_interaction_receipt,
    make_relay,
    make_v02_observation,
    receipt_hash,
    verify_interaction_receipt,
)
from tcop.simulation import Cluster


class WitnessConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster = WitnessCluster()
        self.subject = "agent-external-1"

    def _fact(
        self,
        observer: str = "node-2",
        *,
        observation_type: str = "tool.prohibited_export",
        severity: str = "critical",
        receipt_refused: bool = False,
    ) -> dict:
        signer = self.cluster.keys[observer]
        subject_key = None if receipt_refused else self.cluster.keys[self.subject]
        receipt = make_interaction_receipt(
            signer, subject_key, self.cluster.control_groups, subject_id=self.subject,
            interaction_id=f"test-{observer}-{self.cluster.next_sequence(observer, self.subject)}", capability="tool:data.export",
            now=self.cluster.clock.now, receipt_mode="unilateral_transport" if receipt_refused else "bilateral",
        )
        digest = receipt_hash(receipt)
        self.cluster.receipts[digest] = receipt
        return make_v02_observation(
            signer, self.cluster.control_groups, subject_id=self.subject, observation_type=observation_type,
            scope=("tool:data.export",), now=self.cluster.clock.now, sequence_number=self.cluster.next_sequence(observer, self.subject),
            severity=severity, interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest, receipt_mode=receipt["receipt_mode"],
        )

    def test_ct_021_self_assertion_never_counts_as_independent(self) -> None:
        _, result = self.cluster.self_assert(self.subject)
        self.assertTrue(result.accepted)
        self.assertEqual("self_assertion", result.effective_evidence_class)

    def test_ct_022_same_control_group_is_reclassified(self) -> None:
        observation = self._fact("agent-same-control")
        result = self.cluster.nodes["node-1"].receive(observation)
        self.assertEqual("first_party", result.effective_evidence_class)
        self.assertEqual("same_control_group_reclassified", result.code)

    def test_ct_023_witness_farm_counts_once(self) -> None:
        for number in range(10):
            observer = f"farm-{number}"
            self.cluster._register_principal(observer, f"domain-{number}", "control-external", "peer")
            self.cluster.nodes["node-1"].receive(self._fact(observer, severity="low", observation_type="attestation.result"))
        latest = self.cluster.nodes["node-1"].resolver.events[-1]
        self.assertEqual([], latest["independence_set"])

    def test_ct_024_relay_preserves_original_provenance(self) -> None:
        original = self._fact()
        relay = make_relay(original, self.cluster.keys["node-3"], now=self.cluster.clock.now)
        self.assertEqual(original["observation_id"], relay["original_observation_id"])
        self.assertEqual(original["observer"], relay["original_observation"]["observer"])

    def test_ct_025_repeated_relays_do_not_add_witnesses(self) -> None:
        observation = self._fact()
        self.cluster.nodes["node-1"].receive(observation)
        for relay_id, destination in (("node-3", "node-2"), ("node-4", "node-3")):
            self.cluster.relay("node-1", destination, observation, relay_id)
        groups = self.cluster.nodes["node-1"].resolver.events[-1]["independence_set"]
        self.assertEqual(1, len(groups))

    def test_ct_026_direct_peer_receipt_is_accepted(self) -> None:
        result = self.cluster.nodes["node-1"].receive(self._fact())
        self.assertTrue(result.accepted)
        self.assertTrue(result.receipt_verified)

    def test_ct_027_forged_receipt_is_rejected(self) -> None:
        observation = self._fact()
        self.cluster.receipts[observation["interaction_receipt_hash"]]["response_hash"] = "tampered"
        self.assertEqual("receipt_invalid", self.cluster.nodes["node-1"].receive(observation).code)

    def test_ct_028_acknowledgement_proves_occurrence_only(self) -> None:
        observation = self._fact(observation_type="attestation.result", severity="low")
        receipt = self.cluster.receipts[observation["interaction_receipt_hash"]]
        self.assertEqual((True, "receipt_verified"), verify_interaction_receipt(receipt, self.cluster.identities))
        self.cluster.nodes["node-1"].receive(observation)
        self.assertNotEqual("quarantined", self.cluster.nodes["node-1"].responses.envelopes[self.subject].state)

    def test_ct_029_receipt_refusal_retains_unilateral_evidence(self) -> None:
        result = self.cluster.nodes["node-1"].receive(self._fact(receipt_refused=True))
        self.assertTrue(result.accepted)
        self.assertTrue(result.receipt_verified)
        self.assertEqual("receipt_subject_refused", result.code)

    def test_ct_030_unauthorized_patrol_is_rejected(self) -> None:
        _, code = self.cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=self.subject, target_node="node-1", authorization_id="missing", outcome="failure")
        self.assertEqual("patrol_not_authorized", code)

    def test_ct_031_out_of_scope_patrol_is_rejected(self) -> None:
        self.cluster.authorize_patrol("auth", "patrol-neutral", capabilities=("tool:data.export",))
        observation = self._fact("patrol-neutral")
        observation.update({
            "observation_mode": "active_patrol", "declared_evidence_class": "neutral_third_party", "scope": ["financial.transfer"],
            "patrol_authorization_ref": "auth", "challenge_profile_id": "safe-canary-v1", "challenge_profile_version": "v1", "synthetic_data_only": True,
        })
        observation["signature"] = {
            "algorithm": "ed25519",
            "value": self.cluster.keys["patrol-neutral"].sign(canonical_bytes({k: v for k, v in observation.items() if k != "signature"})),
        }
        self.assertEqual("patrol_scope_violation", self.cluster.nodes["node-1"].receive(observation).code)

    def test_ct_032_expired_patrol_authorization_is_rejected(self) -> None:
        self.cluster.authorize_patrol("expired", "patrol-neutral", ttl=-1)
        _, code = self.cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=self.subject, target_node="node-1", authorization_id="expired", outcome="failure")
        self.assertEqual("patrol_not_authorized", code)

    def test_ct_033_patrol_budget_is_enforced(self) -> None:
        self.cluster.authorize_patrol("one", "patrol-neutral", query_budget=1)
        self.assertTrue(self.cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=self.subject, target_node="node-1", authorization_id="one", outcome="clean")[0])
        self.assertEqual("patrol_budget_exceeded", self.cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=self.subject, target_node="node-1", authorization_id="one", outcome="clean")[1])

    def test_ct_034_local_patrol_is_first_party(self) -> None:
        self.cluster.authorize_patrol("local", "patrol-local")
        _, code = self.cluster.patrols.challenge(patrol_id="patrol-local", subject_id=self.subject, target_node="node-1", authorization_id="local", outcome="failure")
        self.assertEqual("same_control_group_reclassified", code)

    def test_ct_035_neutral_patrol_counts_once_per_control_group(self) -> None:
        self.cluster.authorize_patrol("neutral", "patrol-neutral", query_budget=2)
        for _ in range(2):
            self.cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=self.subject, target_node="node-1", authorization_id="neutral", outcome="failure")
        self.assertEqual(["control-neutral-audit"], self.cluster.nodes["node-1"].resolver.events[-1]["independence_set"])

    def test_ct_036_conflicting_observations_are_preserved(self) -> None:
        self.cluster.nodes["node-1"].receive(self._fact("node-2"))
        self.cluster.nodes["node-1"].receive(self._fact("node-3", observation_type="patrol.clean_result", severity="low"))
        self.assertEqual(2, len(self.cluster.nodes["node-1"].observations))
        self.assertTrue(self.cluster.nodes["node-1"].resolver.events[-1]["conflicting_evidence"])

    def test_ct_037_withdrawal_changes_resolution_without_erasure(self) -> None:
        risk = self._fact()
        self.cluster.nodes["node-1"].receive(risk)
        withdrawal = make_v02_observation(
            self.cluster.keys["node-2"], self.cluster.control_groups, subject_id=self.subject, observation_type="recovery.withdrawal",
            scope=("recovery:withdrawal",), now=self.cluster.clock.now, sequence_number=self.cluster.next_sequence("node-2", self.subject),
            severity="low", metadata={"withdraws": risk["observation_id"]},
        )
        self.cluster.nodes["node-1"].receive(withdrawal)
        self.assertEqual(2, len(self.cluster.nodes["node-1"].observations))
        self.assertEqual("approval_gated", self.cluster.nodes["node-1"].responses.envelopes[self.subject].state)

    def test_ct_038_relay_loops_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_relay(self._fact(), self.cluster.keys["node-3"], now=self.cluster.clock.now, relay_chain=("node-3",))

    def test_ct_039_hidden_common_control_does_not_count_as_independent(self) -> None:
        result = self.cluster.nodes["node-1"].receive(self._fact("agent-hidden-control"))
        self.assertEqual("first_party", result.effective_evidence_class)

    def test_ct_040_witness_packages_do_not_import_benchmark_truth(self) -> None:
        import tcop.faultable_central as central
        import tcop.witness as witness

        self.assertNotIn("benchmark", witness.__dict__)
        self.assertNotIn("benchmark", central.__dict__)

    def test_versioned_validator_dispatches_without_changing_v01(self) -> None:
        legacy = Cluster()
        try:
            dispatcher = VersionedObservationValidator(legacy.nodes["node-1"].validator, self.cluster.nodes["node-1"].validator)
            v01 = legacy.observe("runtime", "agent-v01", "runtime.lifecycle", "runtime:default")
            self.assertTrue(dispatcher.validate(v01, legacy.clock.now).accepted)
            self.assertTrue(dispatcher.validate(self._fact(), self.cluster.clock.now).accepted)
        finally:
            legacy.close()
