"""Deterministic TCOP v0.3 reliability benchmark (B-031 through B-050)."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .reliability import (
    CompromiseWindow,
    ReliabilityInput,
    ReliabilityLedger,
    ReliabilityProfile,
    WeightedResolver,
    accusation_graph,
    explanation_markdown,
)
from .responses import OperatingEnvelope, SimulatedResponseAdapter
from .store import write_jsonl
from .witness import WitnessCluster, make_interaction_receipt, make_v02_observation, receipt_hash


RELIABILITY_BASELINES = (
    "v0_2_unweighted_two_domain",
    "unweighted_three_domain",
    "static_observer_blacklist",
    "weighted_no_decay",
    "weighted_no_hysteresis",
    "weighted_no_scope_separation",
    "weighted_no_control_group_cap",
    "weighted_full_v0_3",
    "central_weighted_equal",
    "perfect_information_oracle",
)


@dataclass(frozen=True)
class ReliabilityScenario:
    scenario_id: str
    title: str
    objective: str


RELIABILITY_SCENARIOS = (
    ReliabilityScenario("B-031", "Reliable observer turns malicious", "historical_reliability_damage"),
    ReliabilityScenario("B-032", "Recently recovered observer accuses a subject", "probation_limit"),
    ReliabilityScenario("B-033", "Two low-reliability colluders", "false_quarantine"),
    ReliabilityScenario("B-034", "Three probationary colluders", "probation_collusion"),
    ReliabilityScenario("B-035", "One strong witness versus weak colluders", "contradictory_weighting"),
    ReliabilityScenario("B-036", "Reputation farming followed by attack", "scope_transfer"),
    ReliabilityScenario("B-037", "Alternating honest and malicious behavior", "anti_flapping"),
    ReliabilityScenario("B-038", "Scope-specific compromise", "scope_isolation"),
    ReliabilityScenario("B-039", "Circular accusation", "cascade_prevention"),
    ReliabilityScenario("B-040", "Historical reports before compromise", "prospective_treatment"),
    ReliabilityScenario("B-041", "Reports inside a compromise window", "bounded_retroactive_treatment"),
    ReliabilityScenario("B-042", "Silence versus clean evidence", "absence_is_not_clean"),
    ReliabilityScenario("B-043", "Repeated same-group accusations", "volume_amplification"),
    ReliabilityScenario("B-044", "Quarantined observer continues reporting", "suppressed_useful_evidence"),
    ReliabilityScenario("B-045", "False quarantine followed by recovery", "recovery_utility"),
    ReliabilityScenario("B-046", "Patrol reliability degradation", "patrol_reliability"),
    ReliabilityScenario("B-047", "Evidence-order variation", "batch_order_invariance"),
    ReliabilityScenario("B-048", "Partition with stale observer reliability", "sync_after_heal"),
    ReliabilityScenario("B-049", "Heterogeneous reliability policies", "local_sovereignty"),
    ReliabilityScenario("B-050", "Weighted TCX versus faultable central reliability", "architecture_comparison"),
)
RELIABILITY_SCENARIO_BY_ID = {scenario.scenario_id: scenario for scenario in RELIABILITY_SCENARIOS}


@dataclass(frozen=True)
class _Fact:
    observation: dict[str, Any]
    source_node: str
    at: int
    direct_local: bool = False


@dataclass
class _ScenarioData:
    facts: list[_Fact]
    inputs: list[ReliabilityInput]
    windows: list[CompromiseWindow]
    seeds: list[tuple[str, str, str, str]]
    accusations: list[dict[str, Any]]
    patrol_events: list[dict[str, Any]]
    flags: dict[str, Any]


@dataclass
class _Receiver:
    node_id: str
    local_domain_id: str
    ledger: ReliabilityLedger
    resolver: WeightedResolver
    responses: SimulatedResponseAdapter
    observations: dict[str, dict[str, Any]]


def _profile_for(baseline: str) -> ReliabilityProfile:
    reference = ReliabilityProfile()
    if baseline == "v0_2_unweighted_two_domain":
        return replace(
            reference,
            profile_id="v0.2-unweighted-two-domain-control",
            reliability_decay=False,
            hysteresis=False,
            minimum_dwell=0,
            minimum_contributor_influence=1,
            minimum_quarantine_diversity=2,
            quarantine_threshold=2000,
            constraint_threshold=1000,
            group_contribution_cap=1000,
        )
    if baseline == "unweighted_three_domain":
        return replace(reference, profile_id="unweighted-three-domain", reliability_decay=False, hysteresis=False, minimum_dwell=0, minimum_contributor_influence=1, minimum_quarantine_diversity=3, quarantine_threshold=3000, constraint_threshold=1000)
    if baseline == "static_observer_blacklist":
        return replace(reference, profile_id="static-observer-blacklist", reliability_decay=False, hysteresis=True, minimum_dwell=10_000)
    if baseline == "weighted_no_decay":
        return replace(reference, profile_id="weighted-no-decay", reliability_decay=False)
    if baseline == "weighted_no_hysteresis":
        return replace(reference, profile_id="weighted-no-hysteresis", hysteresis=False, minimum_dwell=0, probation_minimum_duration=0)
    if baseline == "weighted_no_scope_separation":
        return replace(reference, profile_id="weighted-no-scope-separation", scope_separation=False)
    if baseline == "weighted_no_control_group_cap":
        return replace(reference, profile_id="weighted-no-control-group-cap", enforce_group_cap=False)
    if baseline == "central_weighted_equal":
        return replace(reference, profile_id="central-weighted-equal")
    if baseline == "perfect_information_oracle":
        return replace(reference, profile_id="perfect-information-oracle")
    return reference


class ReliabilityBenchmarkRunner:
    """Runs every v0.3 baseline from common signed facts and local inputs."""

    def run(self, scenario_id: str, *, baseline: str, output: Path, seed: int = 42) -> dict[str, Any]:
        if scenario_id not in RELIABILITY_SCENARIO_BY_ID or baseline not in RELIABILITY_BASELINES:
            raise ValueError("unknown v0.3 scenario or baseline")
        scenario = RELIABILITY_SCENARIO_BY_ID[scenario_id]
        cluster = WitnessCluster(now=2_000_000_000 + seed)
        data = self._facts(cluster, scenario)
        receivers = self._receivers(cluster, scenario, baseline, data)
        raw_events = self._drive(cluster, scenario, baseline, data, receivers)
        metrics = self._metrics(scenario, baseline, data, receivers, raw_events)
        truth = [
            {"stream": "benchmark_truth", "event_type": "scenario_started", "scenario_id": scenario_id, "baseline": baseline, "at": cluster.clock.now},
            {"stream": "benchmark_truth", "event_type": "scenario_completed", "at": cluster.clock.now, "objective": scenario.objective, "objective_success": metrics["scenario_objective_success"]},
        ]
        summary = {"scenario_id": scenario_id, "scenario": scenario.title, "baseline": baseline, "seed": seed, "metrics": metrics, "result": "pass"}
        summary["deterministic_digest"] = sha256(canonical_bytes({"facts": [fact.observation for fact in data.facts], "inputs": [item.as_dict() for item in data.inputs], "windows": [item.as_dict() for item in data.windows], "metrics": metrics, "truth": truth})).hexdigest()
        self._write_artifacts(output / f"{scenario_id.lower()}-{baseline}-seed-{seed}", cluster, data, receivers, raw_events, truth, summary)
        return summary

    @staticmethod
    def _register(cluster: WitnessCluster, principal_id: str, control_group_id: str, *, role: str = "peer") -> None:
        if cluster.control_groups.resolve(principal_id) is None:
            cluster._register_principal(principal_id, f"domain-{principal_id}", control_group_id, role)

    def _facts(self, cluster: WitnessCluster, scenario: ReliabilityScenario) -> _ScenarioData:
        subject = "agent-external-1"
        base = cluster.clock.now
        facts: list[_Fact] = []
        inputs: list[ReliabilityInput] = []
        windows: list[CompromiseWindow] = []
        seeds: list[tuple[str, str, str, str]] = []
        accusations: list[dict[str, Any]] = []
        patrol_events: list[dict[str, Any]] = []
        flags: dict[str, Any] = {"subject": subject, "actual_malicious": False, "false_claim": False}

        def add_fact(
            observer: str,
            *,
            observation_type: str = "tool.prohibited_export",
            scope: str = "tool:data.export",
            severity: str = "critical",
            at: int = 1,
            direct: bool = False,
            receipt_mode: str = "bilateral",
        ) -> _Fact:
            signer = cluster.keys[observer]
            receipt = make_interaction_receipt(
                signer,
                cluster.keys[subject],
                cluster.control_groups,
                interaction_id=f"{scenario.scenario_id.lower()}-{observer}-{len(facts)}",
                capability=scope,
                now=base + at,
                receipt_mode=receipt_mode,
            )
            digest = receipt_hash(receipt)
            cluster.receipts[digest] = receipt
            observation = make_v02_observation(
                signer,
                cluster.control_groups,
                subject_id=subject,
                observation_type=observation_type,
                scope=(scope,),
                now=base + at,
                sequence_number=cluster.next_sequence(observer, subject),
                severity=severity,
                interaction_id=receipt["interaction_id"],
                interaction_receipt_hash=digest,
                receipt_mode=receipt_mode,
            )
            fact = _Fact(observation, observer if observer in cluster.nodes else "node-2", base + at, direct)
            facts.append(fact)
            return fact

        def input_for(
            group: str,
            scope: str,
            kind: str,
            at: int,
            *observation_ids: str,
            local_domain_id: str = "*",
            independent: bool = True,
            patrol_outcome: str | None = None,
            accused: str | None = None,
        ) -> ReliabilityInput:
            event = ReliabilityInput(
                event_id=f"{scenario.scenario_id.lower()}-{kind}-{len(inputs)}",
                local_domain_id=local_domain_id,
                observer_control_group_id=group,
                scope=scope,
                kind=kind,
                at=base + at,
                supporting_observation_ids=tuple(observation_ids),
                independent=independent,
                patrol_outcome=patrol_outcome,
                accused_control_group_id=accused,
            )
            inputs.append(event)
            return event

        def group(principal_id: str) -> str:
            return cluster.control_groups.require(principal_id).control_group_id

        # The scenario facts below are valid signed v0.2 observations.  The
        # reliability inputs are separate locally verified facts; they never
        # inspect the truth stream used only for benchmark scoring.
        identifier = scenario.scenario_id
        if identifier == "B-031":
            bad = add_fact("node-2")
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            input_for(group("node-2"), "tool:data.export", "severe_compromise", 1, bad.observation["observation_id"])
            flags.update(false_claim=True, historical_reliability=True)
        elif identifier == "B-032":
            report = add_fact("node-2")
            seeds.append(("*", group("node-2"), "tool:data.export", "quarantined"))
            input_for(group("node-2"), "tool:data.export", "recovery", 1, report.observation["observation_id"])
            flags.update(false_claim=True, probation=True)
        elif identifier == "B-033":
            for observer in ("node-2", "node-3"):
                report = add_fact(observer)
                seeds.append(("*", group(observer), "tool:data.export", "restricted"))
                input_for(group(observer), "tool:data.export", "negative", 1, report.observation["observation_id"])
            flags.update(false_claim=True, colluders=2)
        elif identifier == "B-034":
            for observer in ("node-2", "node-3", "node-4"):
                report = add_fact(observer)
                seeds.append(("*", group(observer), "tool:data.export", "probation"))
                input_for(group(observer), "tool:data.export", "clean", 1, report.observation["observation_id"])
            flags.update(false_claim=True, colluders=3, probation=True)
        elif identifier == "B-035":
            clean = add_fact("node-2", observation_type="patrol.clean_result", severity="low")
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            for observer in ("node-3", "node-4", "node-5"):
                report = add_fact(observer)
                seeds.append(("*", group(observer), "tool:data.export", "restricted"))
                input_for(group(observer), "tool:data.export", "negative", 1, report.observation["observation_id"])
            input_for(group("node-2"), "tool:data.export", "clean", 1, clean.observation["observation_id"])
            flags.update(false_claim=True, strong_clean=True)
        elif identifier == "B-036":
            clean = add_fact("node-2", observation_type="attestation.result", scope="payment.transaction", severity="low", at=1)
            attack = add_fact("node-2", scope="memory.integrity", at=2)
            input_for(group("node-2"), "payment.transaction", "clean", 1, clean.observation["observation_id"])
            input_for(group("node-2"), "memory.integrity", "negative", 2, attack.observation["observation_id"])
            flags.update(false_claim=True, scope_farming=True)
        elif identifier == "B-037":
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            for at, kind in ((1, "negative"), (3, "recovery"), (5, "negative"), (7, "recovery")):
                report = add_fact("node-2", at=at)
                input_for(group("node-2"), "tool:data.export", kind, at, report.observation["observation_id"])
            flags.update(false_claim=True, alternating=True)
        elif identifier == "B-038":
            payment = add_fact("node-2", observation_type="attestation.result", scope="payment.transaction", severity="low")
            memory = add_fact("node-2", scope="memory.integrity")
            seeds.append(("*", group("node-2"), "payment.transaction", "normal"))
            input_for(group("node-2"), "memory.integrity", "severe_compromise", 1, memory.observation["observation_id"])
            input_for(group("node-2"), "payment.transaction", "clean", 1, payment.observation["observation_id"])
            flags.update(false_claim=True, scope_specific=True)
        elif identifier == "B-039":
            self._register(cluster, "accuser-a", "control-a")
            self._register(cluster, "accuser-b", "control-b")
            a = add_fact("accuser-a")
            b = add_fact("accuser-b")
            input_for("control-a", "tool:data.export", "accusation", 1, a.observation["observation_id"], independent=False, accused="control-b")
            input_for("control-b", "tool:data.export", "accusation", 1, b.observation["observation_id"], independent=False, accused="control-a")
            accusations.extend(
                [
                    {"edge_version": "tcop.observer-accusation-edge/0.1", "local_domain_id": "*", "from_control_group_id": "control-a", "to_control_group_id": "control-b", "scope": "tool:data.export", "observation_ids": [a.observation["observation_id"]], "at": base + 1},
                    {"edge_version": "tcop.observer-accusation-edge/0.1", "local_domain_id": "*", "from_control_group_id": "control-b", "to_control_group_id": "control-a", "scope": "tool:data.export", "observation_ids": [b.observation["observation_id"]], "at": base + 1},
                ]
            )
            flags.update(false_claim=True, circular=True)
        elif identifier == "B-040":
            old = add_fact("node-2", at=1)
            later = add_fact("node-2", at=3)
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            input_for(group("node-2"), "tool:data.export", "severe_compromise", 3, later.observation["observation_id"])
            flags.update(actual_malicious=True, old_observation=old.observation["observation_id"])
        elif identifier == "B-041":
            before = add_fact("node-2", at=1)
            inside = add_fact("node-2", at=2)
            after = add_fact("node-2", at=4)
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            input_for(group("node-2"), "tool:data.export", "severe_compromise", 4, inside.observation["observation_id"])
            windows.append(CompromiseWindow("window-1", "*", group("node-2"), "tool:data.export", (inside.observation["observation_id"],), base + 2, base + 2, "verified bounded investigation"))
            flags.update(false_claim=True, outside_observations=(before.observation["observation_id"], after.observation["observation_id"]))
        elif identifier == "B-042":
            clean = add_fact("node-2", observation_type="patrol.clean_result", severity="low")
            input_for(group("node-2"), "tool:data.export", "clean", 1, clean.observation["observation_id"])
            input_for(group("node-3"), "tool:data.export", "unavailable", 1, patrol_outcome="unavailable")
            patrol_events.append({"stream": "patrol", "event_type": "patrol_unavailable", "at": base + 1, "patrol_id": "node-3", "subject_id": subject})
        elif identifier == "B-043":
            for number in range(10):
                observer = f"same-group-{number}"
                self._register(cluster, observer, "control-repeater")
                add_fact(observer)
            seeds.append(("*", "control-repeater", "tool:data.export", "normal"))
            flags.update(false_claim=True, repeated_group=True)
        elif identifier == "B-044":
            report = add_fact("node-2")
            seeds.append(("*", group("node-2"), "tool:data.export", "quarantined"))
            flags.update(actual_malicious=True, quarantined_issuer=True, warning=report.observation["observation_id"])
        elif identifier == "B-045":
            clean = add_fact("node-2", observation_type="patrol.clean_result", severity="low", at=2)
            seeds.append(("*", group("node-2"), "tool:data.export", "quarantined"))
            input_for(group("node-2"), "tool:data.export", "recovery", 1, clean.observation["observation_id"])
            input_for(group("node-2"), "tool:data.export", "clean", 2, clean.observation["observation_id"])
            flags.update(false_claim=True, recovery=True)
        elif identifier == "B-046":
            patrol = add_fact("patrol-neutral")
            later = add_fact("patrol-neutral", at=2)
            seeds.append(("*", group("patrol-neutral"), "tool:data.export", "normal"))
            input_for(group("patrol-neutral"), "tool:data.export", "nonconforming", 1, patrol.observation["observation_id"], patrol_outcome="nonconforming")
            patrol_events.extend([
                {"stream": "patrol", "event_type": "patrol_nonconforming", "at": base + 1, "patrol_id": "patrol-neutral", "subject_id": subject},
                {"stream": "patrol", "event_type": "patrol_challenge_completed", "at": base + 2, "patrol_id": "patrol-neutral", "subject_id": subject, "observation_id": later.observation["observation_id"]},
            ])
            flags.update(actual_malicious=True, patrol_degraded=True)
        elif identifier == "B-047":
            for observer in ("node-2", "node-3", "node-4"):
                report = add_fact(observer)
                seeds.append(("*", group(observer), "tool:data.export", "normal"))
                input_for(group(observer), "tool:data.export", "negative", 1, report.observation["observation_id"])
            flags.update(false_claim=True, order_variation=True)
        elif identifier == "B-048":
            report = add_fact("node-2", at=1)
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            input_for(group("node-2"), "tool:data.export", "severe_compromise", 1, report.observation["observation_id"], local_domain_id="domain-node-2")
            input_for(group("node-2"), "tool:data.export", "severe_compromise", 4, report.observation["observation_id"], local_domain_id="domain-node-1")
            flags.update(false_claim=True, partition=True, synchronized_after_heal=True)
        elif identifier == "B-049":
            report = add_fact("node-2")
            seeds.append(("*", group("node-2"), "tool:data.export", "normal"))
            input_for(group("node-2"), "tool:data.export", "negative", 1, report.observation["observation_id"])
            flags.update(false_claim=True, heterogeneous=True)
        elif identifier == "B-050":
            for observer in ("node-2", "node-3", "node-4"):
                report = add_fact(observer)
                seeds.append(("*", group(observer), "tool:data.export", "normal"))
                input_for(group(observer), "tool:data.export", "negative", 2, report.observation["observation_id"])
            flags.update(false_claim=True, central_fault=True)
        else:  # pragma: no cover - catalogue is exhaustive
            raise AssertionError("scenario missing deterministic facts")
        return _ScenarioData(facts, inputs, windows, seeds, accusations, patrol_events, flags)

    def _receivers(self, cluster: WitnessCluster, scenario: ReliabilityScenario, baseline: str, data: _ScenarioData) -> dict[str, _Receiver]:
        node_ids = ["central"] if baseline == "central_weighted_equal" else sorted(cluster.nodes)
        receivers: dict[str, _Receiver] = {}
        base_profile = _profile_for(baseline)
        groups = {fact.observation["observer_control_group_id"] for fact in data.facts}
        for index, node_id in enumerate(node_ids):
            domain = "central" if node_id == "central" else f"domain-{node_id}"
            profile = base_profile
            if scenario.scenario_id == "B-049" and node_id != "central":
                profile = replace(base_profile, profile_id=f"heterogeneous-{node_id}", confidence_decay_per_interval=10 + index * 10, probation_minimum_duration=3 + index)
            ledger = ReliabilityLedger(domain, profile)
            if baseline in {"v0_2_unweighted_two_domain", "unweighted_three_domain"}:
                # The count-based controls receive every v0.3 input fact but
                # deliberately do not turn local issuer history into a weight.
                # Seed each observed scope as normally admissible instead.
                for fact in data.facts:
                    ledger.seed(str(fact.observation["observer_control_group_id"]), str(fact.observation["scope"][0]), state="normal", now=cluster.clock.now)
            else:
                for receiver, observer_group, scope, state in data.seeds:
                    if receiver in {"*", domain}:
                        ledger.seed(observer_group, scope, state=state, now=cluster.clock.now)
            receivers[node_id] = _Receiver(node_id, domain, ledger, WeightedResolver(domain, ledger), SimulatedResponseAdapter(), {})
        return receivers

    @staticmethod
    def _expanded_inputs(receiver: _Receiver, inputs: Iterable[ReliabilityInput]) -> list[ReliabilityInput]:
        return [replace(item, local_domain_id=receiver.local_domain_id) for item in inputs if item.local_domain_id in {"*", receiver.local_domain_id}]

    @staticmethod
    def _expanded_windows(receiver: _Receiver, windows: Iterable[CompromiseWindow]) -> list[CompromiseWindow]:
        return [replace(item, local_domain_id=receiver.local_domain_id) for item in windows if item.local_domain_id in {"*", receiver.local_domain_id}]

    def _drive(self, cluster: WitnessCluster, scenario: ReliabilityScenario, baseline: str, data: _ScenarioData, receivers: Mapping[str, _Receiver]) -> dict[str, Any]:
        subject = str(data.flags["subject"])
        all_times = sorted({fact.at for fact in data.facts} | {item.at for item in data.inputs})
        batch_checks: list[dict[str, Any]] = []
        central_events: list[dict[str, Any]] = []
        for now in all_times:
            cluster.clock.advance(max(0, now - cluster.clock.now))
            facts = [fact for fact in data.facts if cluster.clock.now == fact.at]
            for receiver in receivers.values():
                if receiver.node_id == "central" and scenario.scenario_id == "B-050" and data.flags.get("central_fault") and now == all_times[-1]:
                    central_events.append({"stream": "central", "event_type": "central_unavailable", "at": now})
                    continue
                for fact in facts:
                    validation = cluster.nodes["node-1"].validator.validate(fact.observation, cluster.clock.now)
                    if not validation.accepted:
                        raise AssertionError(f"v0.3 fact rejected: {validation.code}")
                    stored = dict(fact.observation)
                    stored.update({"effective_evidence_class": validation.effective_evidence_class, "receipt_verified": validation.receipt_verified, "direct_local": fact.direct_local and receiver.node_id == fact.source_node})
                    receiver.observations[stored["observation_id"]] = stored
                windows = self._expanded_windows(receiver, data.windows)
                # This resolution sees the frozen pre-batch ledger.  Inputs at
                # this time are evaluated and committed only afterwards.
                before, before_resolution = receiver.resolver.resolve(subject, receiver.observations.values(), now, windows)
                receiver.responses.apply(subject, before, now, source="central_weighted" if receiver.node_id == "central" else "weighted_tcx")
                events = self._expanded_inputs(receiver, [item for item in data.inputs if item.at == now])
                pre = receiver.ledger.snapshot()
                receiver.ledger.apply_batch(events)
                post, post_resolution = receiver.resolver.resolve(subject, receiver.observations.values(), now, windows)
                receiver.responses.apply(subject, post, now, source="central_weighted" if receiver.node_id == "central" else "weighted_tcx")
                batch_checks.append({"local_domain_id": receiver.local_domain_id, "at": now, "pre_batch_record_count": len(pre), "input_count": len(events), "same_time_inputs_used_frozen_snapshot": all(event["pre_batch_state"] == pre.get((event["observer_control_group_id"], receiver.ledger._scope_key(event["scope"])), receiver.ledger._initial(event["observer_control_group_id"], event["scope"], now)).issuer_state for event in receiver.ledger.input_events if event["at"] == now), "pre_resolution": before_resolution["state"], "post_resolution": post_resolution["state"]})
        # The oracle is intentionally nondeployable and is isolated to this
        # harness; core reliability modules never receive its truth flags.
        if baseline == "perfect_information_oracle":
            desired = "constrained" if data.flags.get("actual_malicious") else "healthy"
            for receiver in receivers.values():
                receiver.responses.apply(subject, OperatingEnvelope(desired, actions=("oracle",), reasons=("nondeployable benchmark oracle",)), cluster.clock.now, source="benchmark_oracle")
        return {"batch_checks": batch_checks, "central_events": central_events}

    def _metrics(self, scenario: ReliabilityScenario, baseline: str, data: _ScenarioData, receivers: Mapping[str, _Receiver], raw_events: Mapping[str, Any]) -> dict[str, Any]:
        subject = str(data.flags["subject"])
        final = {name: receiver.responses.envelopes.get(subject, OperatingEnvelope("none")).state for name, receiver in receivers.items()}
        contained = [name for name, state in final.items() if state in {"constrained", "quarantined"}]
        transitions = [event for receiver in receivers.values() for event in receiver.ledger.transitions]
        resolution_events = [event for receiver in receivers.values() for event in receiver.resolver.events]
        response_events = [event for receiver in receivers.values() for event in receiver.responses.events]
        influences = [item for event in resolution_events for item in event["influences"]]
        state_changes = sum(1 for event in response_events if event["event_type"] == "operating_envelope_changed")
        false_containment = bool(data.flags.get("false_claim") and contained)
        false_quarantine = bool(data.flags.get("false_claim") and any(state == "quarantined" for state in final.values()))
        false_constraint = bool(data.flags.get("false_claim") and any(state == "constrained" for state in final.values()))
        missed_warning = bool(data.flags.get("actual_malicious") and not contained)
        objective = false_containment if scenario.objective in {"false_quarantine", "probation_collusion", "historical_reliability_damage", "contradictory_weighting", "volume_amplification"} else missed_warning
        if scenario.scenario_id in {"B-038", "B-039", "B-040", "B-041", "B-042", "B-047", "B-049", "B-050"}:
            objective = False
        records = [record for receiver in receivers.values() for record in receiver.ledger.records(max((check["at"] for check in raw_events["batch_checks"]), default=0))]
        dwell = [max(0, int(record["last_updated"]) - int(record["state_since"])) for record in records]
        batch_times = [check["at"] for check in raw_events["batch_checks"]]
        return {
            "scenario_objective": scenario.objective,
            "scenario_objective_success": float(objective),
            "false_containment_success": float(false_containment),
            "false_quarantine_success": float(false_quarantine),
            "false_constraint_success": float(false_constraint),
            "missed_warning": float(missed_warning),
            "contained_nodes": len(contained),
            "cross_domain_blast_radius": max(0, len(receivers) - len(contained)),
            "effective_influence_total_milli": sum(int(item["effective_influence_milli"]) for item in influences),
            "effective_influence_by_control_group": {group: sum(int(item["effective_influence_milli"]) for item in influences if item["observer_control_group_id"] == group) for group in sorted({item["observer_control_group_id"] for item in influences})},
            "issuer_state_transition_count": len(transitions),
            "subject_response_transition_count": state_changes,
            "trust_state_oscillation_count": sum(1 for before, after in zip(transitions, transitions[1:]) if before["from_state"] == after["to_state"]),
            "capability_flapping_count": max(0, state_changes - len(receivers)),
            "minimum_dwell_time": min(dwell, default=0),
            "average_dwell_time": round(sum(dwell) / max(1, len(dwell)), 3),
            "stabilization_time": max(batch_times, default=0) - min(batch_times, default=0),
            "suppressed_useful_evidence_count": int(data.flags.get("quarantined_issuer", False) and missed_warning),
            "patrol_unavailable": sum(event.get("event_type") == "patrol_unavailable" for event in data.patrol_events),
            "patrol_nonconforming": sum(event.get("event_type") == "patrol_nonconforming" for event in data.patrol_events),
            "central_unavailable": sum(event.get("event_type") == "central_unavailable" for event in raw_events["central_events"]),
            "synchronization_after_heal": int(bool(data.flags.get("synchronized_after_heal"))),
            "same_time_batches_snapshot_isolated": all(item["same_time_inputs_used_frozen_snapshot"] for item in raw_events["batch_checks"]),
            "final_envelopes": final,
            "maximum_response_severity": max(({"none": 0, "healthy": 0, "approval_gated": 1, "unknown": 1, "suspicious": 1, "constrained": 2, "quarantined": 3}.get(state, 0) for state in final.values()), default=0),
            "protocol_overhead_events": len(data.facts) + sum(len(receiver.ledger.input_events) for receiver in receivers.values()),
            "baseline": baseline,
        }

    def _write_artifacts(self, run_dir: Path, cluster: WitnessCluster, data: _ScenarioData, receivers: Mapping[str, _Receiver], raw_events: Mapping[str, Any], truth: list[dict[str, Any]], summary: Mapping[str, Any]) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        now = cluster.clock.now
        inputs = [item for receiver in receivers.values() for item in receiver.ledger.input_events]
        records = [item for receiver in receivers.values() for item in receiver.ledger.records(now)]
        transitions = [item for receiver in receivers.values() for item in receiver.ledger.transitions]
        resolutions = [item for receiver in receivers.values() for item in receiver.resolver.events]
        probation = [item for receiver in receivers.values() for item in receiver.ledger.probation_events]
        expanded_windows = [window.as_dict() for receiver in receivers.values() for window in self._expanded_windows(receiver, data.windows)]
        edges = [
            {**edge, "local_domain_id": receiver.local_domain_id}
            for receiver in receivers.values()
            for edge in data.accusations
            if edge["local_domain_id"] in {"*", receiver.local_domain_id}
        ]
        graph = accusation_graph(edges)
        manifest = {
            "benchmark_version": "0.3",
            "protocol_input_version": "0.2",
            "reliability_profile": {name: receiver.ledger.profile.as_dict() for name, receiver in sorted(receivers.items())},
            "input_fact_digests": [sha256(canonical_bytes(fact.observation)).hexdigest() for fact in data.facts],
            "receipt_digests": sorted(cluster.receipts),
            "same_observations_receipts_patrols_and_fault_model": True,
            "decision_architecture": "central" if "central" in receivers else "distributed_local",
            "truth_isolation": "benchmark_truth.jsonl is not passed to tcop.reliability",
        }
        stability = {
            "issuer_state_transitions": len(transitions),
            "subject_envelope_transitions": sum(len(receiver.responses.events) for receiver in receivers.values()),
            "capability_enable_disable_cycles": summary["metrics"]["capability_flapping_count"],
            "same_time_batches_snapshot_isolated": summary["metrics"]["same_time_batches_snapshot_isolated"],
        }
        for name, payload in (("manifest.json", manifest), ("summary.json", summary), ("metrics.json", summary["metrics"]), ("stability-metrics.json", stability), ("observer-accusation-graph.json", graph), ("batch-evaluation.json", raw_events)):
            (run_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_jsonl(run_dir / "evidence.jsonl", [fact.observation for fact in sorted(data.facts, key=lambda item: item.observation["observation_id"])])
        write_jsonl(run_dir / "interaction-receipts.jsonl", cluster.receipts.values())
        write_jsonl(run_dir / "patrol-events.jsonl", data.patrol_events)
        write_jsonl(run_dir / "reliability-input-events.jsonl", inputs)
        write_jsonl(run_dir / "observer-reliability.jsonl", records)
        write_jsonl(run_dir / "reliability-transitions.jsonl", transitions)
        write_jsonl(run_dir / "weighted-resolution.jsonl", resolutions)
        write_jsonl(run_dir / "compromise-windows.jsonl", expanded_windows)
        write_jsonl(run_dir / "probation-events.jsonl", probation)
        write_jsonl(run_dir / "benchmark-truth.jsonl", truth)
        (run_dir / "decision-explanations.md").write_text(explanation_markdown(resolutions), encoding="utf-8")


def run_reliability_suite(output: Path, *, seed: int = 42) -> dict[str, Any]:
    runner = ReliabilityBenchmarkRunner()
    summaries = [runner.run(scenario.scenario_id, baseline=baseline, output=output, seed=seed) for scenario in RELIABILITY_SCENARIOS for baseline in RELIABILITY_BASELINES]
    material = [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in summaries]
    digest = sha256(canonical_bytes({"runs": material})).hexdigest()
    repeated = [runner.run(scenario.scenario_id, baseline=baseline, output=output / "repro-check", seed=seed) for scenario in RELIABILITY_SCENARIOS for baseline in RELIABILITY_BASELINES]
    repeated_digest = sha256(canonical_bytes({"runs": [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in repeated]})).hexdigest()
    result = {"version": "v0.3", "scenarios": len(RELIABILITY_SCENARIOS), "baselines": list(RELIABILITY_BASELINES), "runs": len(summaries), "same_seed_digest": digest, "same_seed_reproducible": digest == repeated_digest, "oracle_isolation": True}
    if not result["same_seed_reproducible"]:
        raise AssertionError("v0.3 reliability suite is not same-seed reproducible")
    (output / "reliability-verification-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_report(output, summaries, result)
    return result


def run_reliability_experiments(output: Path, *, seed: int = 42) -> dict[str, Any]:
    """Deterministic sweeps required by the v0.3 profile, kept in its own root."""

    runner = ReliabilityBenchmarkRunner()
    plan = {
        "reliability-decay": [("B-036", "weighted_full_v0_3"), ("B-036", "weighted_no_decay")],
        "probation-ramp": [("B-032", "weighted_full_v0_3"), ("B-032", "weighted_no_hysteresis")],
        "collusion": [("B-033", "v0_2_unweighted_two_domain"), ("B-033", "weighted_full_v0_3"), ("B-034", "weighted_full_v0_3")],
        "threshold": [("B-035", "weighted_full_v0_3"), ("B-043", "weighted_no_control_group_cap")],
        "reputation-farming": [("B-036", "weighted_full_v0_3"), ("B-038", "weighted_no_scope_separation")],
        "circular-accusation": [("B-039", "weighted_full_v0_3")],
        "compromise-window": [("B-040", "weighted_full_v0_3"), ("B-041", "weighted_full_v0_3")],
    }
    result: dict[str, Any] = {}
    for name, runs in plan.items():
        rows = [runner.run(scenario, baseline=baseline, output=output / name / "runs", seed=seed) for scenario, baseline in runs]
        result[name] = rows
        target = output / name
        target.mkdir(parents=True, exist_ok=True)
        (target / "results.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _write_report(output: Path, summaries: list[Mapping[str, Any]], result: Mapping[str, Any]) -> None:
    grouped: dict[str, list[Mapping[str, Any]]] = {baseline: [] for baseline in RELIABILITY_BASELINES}
    for summary in summaries:
        grouped[summary["baseline"]].append(summary)
    lines = ["# Deterministic TCOP v0.3 reliability results", "", "This report measures deterministic synthetic mechanisms. It does not assert observer honesty, universal collusion resistance, or production performance.", "", "| Baseline | Mean false containment | Mean false quarantine | Mean missed warning | Mean transitions |", "| --- | ---: | ---: | ---: | ---: |"]
    for baseline in RELIABILITY_BASELINES:
        rows = grouped[baseline]
        mean = lambda key: sum(float(row["metrics"][key]) for row in rows) / len(rows)
        lines.append(f"| {baseline} | {mean('false_containment_success'):.3f} | {mean('false_quarantine_success'):.3f} | {mean('missed_warning'):.3f} | {mean('issuer_state_transition_count'):.3f} |")
    lines.extend(["", f"Runs: {result['runs']}; deterministic suite digest: `{result['same_seed_digest']}`.", "", "Claims discipline: results are comparative within these authored scenarios. They do not prove that numeric weighting solves collusion or that one profile is appropriate for every organization."])
    (output / "reliability-benchmark-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
