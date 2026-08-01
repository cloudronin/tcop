"""CT-041 through CT-064 for the isolated deterministic v0.3 profile."""

from __future__ import annotations

import unittest

from tcop.reliability import (
    CompromiseWindow,
    ReliabilityInput,
    ReliabilityLedger,
    ReliabilityProfile,
    VersionedReliabilityValidator,
    WeightedResolver,
    accusation_graph,
    explanation_markdown,
    multiply_milli,
)
from tcop.witness import WitnessCluster, make_interaction_receipt, make_v02_observation, receipt_hash


class ReliabilityConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = ReliabilityProfile()
        self.ledger = ReliabilityLedger("domain-a", self.profile)

    def event(self, kind: str, at: int, *, group: str = "group-b", scope: str = "payment.transaction", **kwargs: object) -> ReliabilityInput:
        return ReliabilityInput(f"event-{kind}-{at}-{group}", "domain-a", group, scope, kind, at, **kwargs)

    def observation(self, *, group: str = "group-b", scope: str = "payment.transaction", at: int = 1) -> dict:
        cluster = WitnessCluster(now=2_100_000_000)
        cluster._register_principal("test-observer", "domain-test", group, "peer")
        signer = cluster.keys["test-observer"]
        subject = cluster.keys["agent-external-1"]
        receipt = make_interaction_receipt(signer, subject, cluster.control_groups, interaction_id="test-interaction", capability=scope, now=cluster.clock.now)
        digest = receipt_hash(receipt)
        cluster.receipts[digest] = receipt
        observation = make_v02_observation(signer, cluster.control_groups, subject_id="agent-external-1", observation_type="tool.prohibited_export", scope=(scope,), now=cluster.clock.now, interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest, receipt_mode=receipt["receipt_mode"])
        result = cluster.nodes["node-1"].validator.validate(observation, cluster.clock.now)
        self.assertTrue(result.accepted)
        stored = dict(observation)
        stored.update({"effective_evidence_class": result.effective_evidence_class, "receipt_verified": result.receipt_verified, "direct_local": False})
        stored["scope"] = [scope]
        # This test helper changes only a receiver-local copy.  Issued times
        # are already canonical and remain suitable for v0.3 evaluation.
        return stored

    def test_ct_041_reliability_is_local_to_receiver(self) -> None:
        other = ReliabilityLedger("domain-b", self.profile)
        self.ledger.apply_batch([self.event("severe_compromise", 1)])
        self.assertEqual("quarantined", self.ledger.get("group-b", "payment.transaction", 1).issuer_state)
        self.assertEqual("unknown", other.get("group-b", "payment.transaction", 1).issuer_state)

    def test_ct_042_reliability_is_scope_specific(self) -> None:
        self.ledger.apply_batch([self.event("severe_compromise", 1, scope="memory.integrity")])
        self.assertEqual("quarantined", self.ledger.get("group-b", "memory.integrity", 1).issuer_state)
        self.assertEqual("unknown", self.ledger.get("group-b", "payment.transaction", 1).issuer_state)

    def test_ct_043_subject_risk_and_issuer_reliability_are_separate(self) -> None:
        item = self.observation()
        resolver = WeightedResolver("domain-a", self.ledger)
        resolver.resolve("agent-external-1", [item], 2_100_000_000)
        self.ledger.apply_batch([self.event("negative", 2_100_000_001)])
        self.assertNotIn("issuer_state", item)
        self.assertIn("state", resolver.events[-1])

    def test_ct_044_quarantined_observer_contributes_zero(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="quarantined", now=0)
        value = WeightedResolver("domain-a", self.ledger).evaluate(self.observation(), 2_100_000_000)
        self.assertEqual(0, value.effective_influence_milli)

    def test_ct_045_suspicious_and_restricted_reduce_influence(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="suspicious", now=0)
        suspicious = WeightedResolver("domain-a", self.ledger).evaluate(self.observation(), 2_100_000_000)
        self.ledger.seed("group-b", "payment.transaction", state="restricted", now=0)
        restricted = WeightedResolver("domain-a", self.ledger).evaluate(self.observation(), 2_100_000_000)
        self.assertGreater(suspicious.effective_influence_milli, restricted.effective_influence_milli)

    def test_ct_046_recovery_enters_probation(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="quarantined", now=0)
        self.ledger.apply_batch([self.event("recovery", 6)])
        self.assertEqual("probation", self.ledger.get("group-b", "payment.transaction", 6).issuer_state)

    def test_ct_047_probation_ramp_is_deterministic(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="probation", now=0)
        record = self.ledger.get("group-b", "payment.transaction", 3)
        self.assertEqual(400, self.profile.state_factor("probation", 3, record))
        self.assertEqual(400, self.profile.state_factor("probation", 3, record))

    def test_ct_048_minimum_dwell_blocks_immediate_recovery(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="quarantined", now=0)
        self.ledger.apply_batch([self.event("recovery", 1)])
        self.assertEqual("quarantined", self.ledger.get("group-b", "payment.transaction", 1).issuer_state)

    def test_ct_049_entry_and_recovery_thresholds_differ(self) -> None:
        self.assertNotEqual(self.profile.restricted_threshold, self.profile.normal_threshold)
        self.assertGreater(self.profile.minimum_dwell, 0)

    def test_ct_050_confidence_decays_toward_unknown(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        self.ledger.advance(60)
        self.assertEqual("unknown", self.ledger.get("group-b", "payment.transaction", 60).issuer_state)

    def test_ct_051_silence_and_unavailability_are_not_positive_evidence(self) -> None:
        before = self.ledger.get("group-b", "payment.transaction", 0)
        self.ledger.apply_batch([self.event("unavailable", 1, patrol_outcome="unavailable")])
        after = self.ledger.get("group-b", "payment.transaction", 1)
        self.assertEqual(before.positive_evidence_accumulator, after.positive_evidence_accumulator)

    def test_ct_052_group_cap_blocks_report_volume(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        items = [self.observation() for _ in range(4)]
        for index, item in enumerate(items):
            item["observation_id"] = f"same-group-{index}"
        _, explanation = resolver.resolve("agent-external-1", items, 2_100_000_000)
        self.assertEqual(1, len(explanation["influences"]))

    def test_ct_053_relays_do_not_create_reliability_or_weight(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        original = self.observation()
        relayed = dict(original)
        relayed["relay_chain"] = ["relay-a", "relay-b"]
        self.assertEqual(resolver.evaluate(original, 2_100_000_000).effective_influence_milli, resolver.evaluate(relayed, 2_100_000_000).effective_influence_milli)

    def test_ct_054_probation_cannot_independently_quarantine(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="probation", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        envelope, _ = resolver.resolve("agent-external-1", [self.observation()], 2_100_000_000)
        self.assertNotEqual("quarantined", envelope.state)

    def test_ct_055_historical_influence_is_prospective_by_default(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        item = self.observation()
        first = resolver.evaluate(item, 2_100_000_000)
        self.ledger.apply_batch([self.event("severe_compromise", 2_100_000_001)])
        second = resolver.evaluate(item, 2_100_000_002)
        self.assertEqual(first.effective_influence_milli, second.effective_influence_milli)

    def test_ct_056_compromise_window_is_explicit_and_bounded(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        item = self.observation()
        issued = 2_100_000_000
        window = CompromiseWindow("w", "domain-a", "group-b", "payment.transaction", (item["observation_id"],), issued, issued, "verified")
        self.assertTrue(resolver.evaluate(item, issued, [window]).retroactively_discounted)
        other = CompromiseWindow("x", "domain-a", "group-b", "payment.transaction", ("other",), issued, issued, "verified")
        self.assertFalse(resolver.evaluate(item, issued, [other]).retroactively_discounted)

    def test_ct_057_conflicting_reliability_evidence_is_preserved(self) -> None:
        self.ledger.apply_batch([
            self.event("clean", 1, supporting_observation_ids=("clean-1",)),
            self.event("negative", 2, contradicting_observation_ids=("bad-1",)),
        ])
        record = self.ledger.get("group-b", "payment.transaction", 2)
        self.assertIn("clean-1", record.supporting_observation_ids)
        self.assertIn("bad-1", record.contradicting_observation_ids)

    def test_ct_058_circular_accusations_are_reported(self) -> None:
        graph = accusation_graph([
            {"from_control_group_id": "a", "to_control_group_id": "b", "scope": "s", "at": 1},
            {"from_control_group_id": "b", "to_control_group_id": "a", "scope": "s", "at": 1},
        ])
        self.assertEqual(1, graph["cycle_count"])

    def test_ct_059_fixed_point_weighting_is_reproducible(self) -> None:
        self.assertEqual(108, multiply_milli(1000, 1000, 900, 400, 300, 1000))
        self.assertEqual(multiply_milli(700, 900), multiply_milli(700, 900))

    def test_ct_060_every_resolution_has_factor_explanation(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        resolver = WeightedResolver("domain-a", self.ledger)
        _, resolution = resolver.resolve("agent-external-1", [self.observation()], 2_100_000_000)
        self.assertIn("factors", resolution["influences"][0])
        self.assertIn("Observation", explanation_markdown([resolution]))

    def test_ct_061_reliability_code_cannot_access_benchmark_truth(self) -> None:
        import tcop.reliability as reliability

        self.assertNotIn("benchmark", reliability.__dict__)

    def test_ct_062_patrol_unavailable_does_not_increase_reliability(self) -> None:
        self.ledger.apply_batch([self.event("unavailable", 1, patrol_outcome="unavailable")])
        self.assertEqual("unknown", self.ledger.get("group-b", "payment.transaction", 1).issuer_state)

    def test_ct_063_clean_probation_evidence_stays_within_ramp(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="quarantined", now=0)
        self.ledger.apply_batch([self.event("recovery", 6), self.event("clean", 7)])
        record = self.ledger.get("group-b", "payment.transaction", 7)
        self.assertEqual("probation", record.issuer_state)
        self.assertLessEqual(self.profile.state_factor("probation", 7, record), 200)

    def test_ct_064_nonconforming_patrol_loses_reliability(self) -> None:
        self.ledger.seed("group-b", "payment.transaction", state="normal", now=0)
        self.ledger.apply_batch([self.event("nonconforming", 1, patrol_outcome="nonconforming")])
        self.assertEqual("suspicious", self.ledger.get("group-b", "payment.transaction", 1).issuer_state)

    def test_same_time_batch_uses_frozen_snapshot_and_no_transitive_propagation(self) -> None:
        self.ledger.seed("a", "payment.transaction", state="normal", now=0)
        self.ledger.apply_batch([
            self.event("negative", 1, group="a"),
            self.event("negative", 1, group="a"),
        ])
        inputs = [event for event in self.ledger.input_events if event["at"] == 1]
        self.assertEqual(["normal", "normal"], [event["pre_batch_state"] for event in inputs])
        self.assertEqual("unknown", self.ledger.get("b", "payment.transaction", 1).issuer_state)

    def test_reliability_artifact_validator_dispatches_separately_from_v02(self) -> None:
        event = self.event("clean", 1).as_dict()
        self.assertEqual((True, "reliability_input_valid"), VersionedReliabilityValidator().validate(event))
        self.assertEqual((False, "unsupported_reliability_version"), VersionedReliabilityValidator().validate({"protocol_version": "0.2"}))
