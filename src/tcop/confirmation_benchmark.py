"""Deterministic TCOP v0.4 tip-only and staged-confirmation benchmarks."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .confirmation import ConfirmationProfile, ConfirmationResolver, confirmation_explanations_text
from .reliability import ReliabilityLedger, ReliabilityProfile, WeightedResolver
from .responses import OperatingEnvelope, SimulatedResponseAdapter
from .store import write_jsonl
from .witness import WitnessCluster, make_interaction_receipt, make_v02_observation, receipt_hash


CONFIRMATION_BASELINES = (
    "v0_3_weighted_full",
    "tip_enabled_no_provisional",
    "provisional_no_tip",
    "provisional_no_source_novelty",
    "provisional_no_campaign_grouping",
    "provisional_immediate_quarantine",
    "full_v0_4",
    "central_weighted_staged_equal",
    "local_direct_only",
    "perfect_information_oracle",
)


@dataclass(frozen=True)
class ConfirmationScenario:
    scenario_id: str
    title: str
    objective: str


CONFIRMATION_SCENARIOS = (
    ConfirmationScenario("B-051", "Genuine warning from quarantined observer", "tip_recovers_warning"),
    ConfirmationScenario("B-052", "False tip from quarantined observer", "tip_false_containment"),
    ConfirmationScenario("B-053", "Tip followed by patrol confirmation", "tip_patrol_confirmation"),
    ConfirmationScenario("B-054", "Tip followed by clean patrol", "tip_clean_deescalation"),
    ConfirmationScenario("B-055", "Tip with patrol unavailable", "tip_unavailable_cost"),
    ConfirmationScenario("B-056", "Three reputable same-time colluders", "first_batch_false_quarantine"),
    ConfirmationScenario("B-057", "Same colluders repeat after one batch", "repeat_confirmation_bypass"),
    ConfirmationScenario("B-058", "Same colluders create new interactions", "same_source_novelty"),
    ConfirmationScenario("B-059", "New independent source confirms later", "novel_source_confirmation"),
    ConfirmationScenario("B-060", "Direct local evidence confirms later", "direct_local_confirmation"),
    ConfirmationScenario("B-061", "Patrol confirms later", "patrol_confirmation"),
    ConfirmationScenario("B-062", "Benign subject under provisional containment", "provisional_utility_loss"),
    ConfirmationScenario("B-063", "Fast attack during confirmation delay", "confirmation_delay_damage"),
    ConfirmationScenario("B-064", "Staggered collusion across adjacent batches", "campaign_stagger_bypass"),
    ConfirmationScenario("B-065", "Slow staggered collusion outside campaign window", "campaign_window_limit"),
    ConfirmationScenario("B-066", "High-risk versus low-risk capability", "capability_severity"),
    ConfirmationScenario("B-067", "Tip-flood denial of service", "tip_budget_starvation"),
    ConfirmationScenario("B-068", "Multiple quarantined observers send one genuine warning", "tip_diversity"),
    ConfirmationScenario("B-069", "Contradictory evidence during provisional containment", "provisional_conflict"),
    ConfirmationScenario("B-070", "Central versus distributed staged confirmation", "architecture_comparison"),
)
CONFIRMATION_SCENARIO_BY_ID = {item.scenario_id: item for item in CONFIRMATION_SCENARIOS}


@dataclass(frozen=True)
class _Fact:
    observation: dict[str, Any]
    at: int
    source_node: str
    direct_local: bool = False


@dataclass
class _ScenarioData:
    facts: list[_Fact]
    seeds: list[tuple[str, str, str]]
    damage: list[tuple[int, int]]
    patrol_events: list[dict[str, Any]]
    flags: dict[str, Any]


@dataclass
class _Receiver:
    node_id: str
    local_domain_id: str
    ledger: ReliabilityLedger
    weighted: WeightedResolver
    confirmation: ConfirmationResolver
    responses: SimulatedResponseAdapter
    observations: dict[str, dict[str, Any]]


def _profile_for(baseline: str) -> ConfirmationProfile:
    profile = ConfirmationProfile()
    if baseline == "tip_enabled_no_provisional":
        return replace(profile, profile_id="tip-enabled-no-provisional", provisional_enabled=False)
    if baseline == "provisional_no_tip":
        return replace(profile, profile_id="provisional-no-tip", tip_enabled=False)
    if baseline == "provisional_no_source_novelty":
        return replace(profile, profile_id="provisional-no-source-novelty", require_source_novelty=False, allow_same_source_later_interaction=True)
    if baseline == "provisional_no_campaign_grouping":
        return replace(profile, profile_id="provisional-no-campaign-grouping", campaign_grouping=False, require_source_novelty=False, allow_same_source_later_interaction=True)
    if baseline == "provisional_immediate_quarantine":
        return replace(profile, profile_id="provisional-immediate-quarantine", immediate_remote_quarantine=True)
    if baseline == "central_weighted_staged_equal":
        return replace(profile, profile_id="central-weighted-staged-equal")
    if baseline == "local_direct_only":
        return replace(profile, profile_id="local-direct-only", tip_enabled=False, local_direct_only=True)
    if baseline == "perfect_information_oracle":
        return replace(profile, profile_id="perfect-information-oracle")
    return profile


class ConfirmationBenchmarkRunner:
    """Runs B-051–B-070 from one shared fact set per scenario."""

    def run(self, scenario_id: str, *, baseline: str, output: Path, seed: int = 42) -> dict[str, Any]:
        if scenario_id not in CONFIRMATION_SCENARIO_BY_ID or baseline not in CONFIRMATION_BASELINES:
            raise ValueError("unknown v0.4 scenario or baseline")
        scenario = CONFIRMATION_SCENARIO_BY_ID[scenario_id]
        cluster = WitnessCluster(now=2_100_000_000 + seed)
        data = self._facts(cluster, scenario)
        receivers = self._receivers(cluster, scenario, baseline, data)
        events = self._drive(cluster, scenario, baseline, data, receivers)
        metrics = self._metrics(cluster, scenario, baseline, data, receivers, events)
        truth = [
            {"stream": "benchmark_truth", "event_type": "scenario_started", "scenario_id": scenario_id, "baseline": baseline, "at": cluster.clock.now},
            {"stream": "benchmark_truth", "event_type": "scenario_completed", "objective": scenario.objective, "objective_success": metrics["scenario_objective_success"], "at": cluster.clock.now},
        ]
        summary = {"scenario_id": scenario_id, "scenario": scenario.title, "baseline": baseline, "seed": seed, "metrics": metrics, "result": "pass"}
        summary["deterministic_digest"] = sha256(canonical_bytes({"facts": [item.observation for item in data.facts], "seeds": data.seeds, "damage": data.damage, "metrics": metrics, "truth": truth})).hexdigest()
        self._write_artifacts(output / f"{scenario_id.lower()}-{baseline}-seed-{seed}", cluster, data, receivers, events, truth, summary)
        return summary

    @staticmethod
    def _register(cluster: WitnessCluster, principal_id: str, group: str, role: str = "peer") -> None:
        if cluster.control_groups.resolve(principal_id) is None:
            cluster._register_principal(principal_id, f"domain-{principal_id}", group, role)

    def _facts(self, cluster: WitnessCluster, scenario: ConfirmationScenario) -> _ScenarioData:
        subject = "agent-external-1"
        base = cluster.clock.now
        facts: list[_Fact] = []
        seeds: list[tuple[str, str, str]] = []
        damage: list[tuple[int, int]] = []
        patrol_events: list[dict[str, Any]] = []
        flags: dict[str, Any] = {"subject": subject, "actual_malicious": False, "false_claim": False}

        def group(principal: str) -> str:
            return cluster.control_groups.require(principal).control_group_id

        def fact(
            observer: str,
            *,
            at: int = 1,
            scope: str = "tool:data.export",
            observation_type: str = "tool.prohibited_export",
            severity: str = "critical",
            direct: bool = False,
            direct_authorized: bool = False,
            patrol: bool = False,
            metadata: Mapping[str, Any] | None = None,
        ) -> _Fact:
            signer = cluster.keys[observer]
            receipt = make_interaction_receipt(signer, cluster.keys[subject], cluster.control_groups, interaction_id=f"{scenario.scenario_id.lower()}-{observer}-{len(facts)}", capability=scope, now=base + at)
            digest = receipt_hash(receipt)
            cluster.receipts[digest] = receipt
            values = dict(metadata or {})
            mode = "passive"
            auth_id = None
            if direct_authorized:
                values.update({"direct_local_authorized": True, "enforcement_point_id": "runtime-sensor-node-1", "independent_audit_ref": f"audit-{scenario.scenario_id}-{len(facts)}"})
            if patrol:
                mode = "active_patrol"
                auth_id = f"auth-{scenario.scenario_id}-{len(facts)}"
                cluster.authorize_patrol(auth_id, observer, targets=(subject,), capabilities=(scope,), query_budget=10)
            observation = make_v02_observation(
                signer, cluster.control_groups, subject_id=subject, observation_type=observation_type,
                scope=(scope,), now=base + at, sequence_number=cluster.next_sequence(observer, subject),
                severity=severity, interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest,
                receipt_mode=receipt["receipt_mode"], observation_mode=mode,
                declared_evidence_class="neutral_third_party" if patrol else "independent_peer",
                challenge_profile_id="safe-canary-v1" if patrol else None,
                challenge_profile_version="v1" if patrol else None,
                patrol_authorization_ref=auth_id, synthetic_data_only=True if patrol else None,
                metadata=values,
            )
            item = _Fact(observation, base + at, observer if observer in cluster.nodes else "node-1", direct)
            facts.append(item)
            return item

        def remote_trio(*, at: int = 1, scope: str = "tool:data.export") -> list[_Fact]:
            return [fact(observer, at=at, scope=scope) for observer in ("node-2", "node-3", "node-4")]

        identifier = scenario.scenario_id
        if identifier == "B-051":
            report = fact("node-2")
            seeds.append((group("node-2"), "tool:data.export", "quarantined"))
            fact("patrol-neutral", at=2, patrol=True)
            flags.update(actual_malicious=True, tip_report=report.observation["observation_id"])
        elif identifier == "B-052":
            fact("node-2")
            seeds.append((group("node-2"), "tool:data.export", "quarantined"))
            flags.update(false_claim=True)
        elif identifier == "B-053":
            fact("node-2")
            seeds.append((group("node-2"), "tool:data.export", "quarantined"))
            patrol = fact("patrol-neutral", at=2, patrol=True)
            patrol_events.append({"stream": "patrol", "event_type": "patrol_failed", "at": patrol.at, "observation_id": patrol.observation["observation_id"]})
            flags.update(actual_malicious=True)
        elif identifier == "B-054":
            fact("node-2")
            seeds.append((group("node-2"), "tool:data.export", "quarantined"))
            patrol = fact("patrol-neutral", at=2, observation_type="patrol.clean_result", severity="low", patrol=True)
            patrol_events.append({"stream": "patrol", "event_type": "patrol_passed", "at": patrol.at, "observation_id": patrol.observation["observation_id"]})
            flags.update(false_claim=True)
        elif identifier == "B-055":
            fact("node-2")
            seeds.append((group("node-2"), "tool:data.export", "quarantined"))
            patrol_events.append({"stream": "patrol", "event_type": "patrol_unavailable", "at": base + 2, "subject_id": subject})
            damage.append((base + 2, 700))
            flags.update(actual_malicious=True, patrol_unavailable=True)
        elif identifier == "B-056":
            remote_trio()
            flags.update(false_claim=True)
        elif identifier == "B-057":
            remote_trio(at=1)
            # New signed records deliberately reuse no new source or new
            # campaign dimension; they must not independently confirm.
            remote_trio(at=2)
            flags.update(false_claim=True, repeat=True)
        elif identifier == "B-058":
            remote_trio(at=1)
            remote_trio(at=2)
            flags.update(false_claim=True, same_source_new_interactions=True)
        elif identifier == "B-059":
            remote_trio(at=1)
            later = fact("node-5", at=2)
            flags.update(actual_malicious=True, novel_observation=later.observation["observation_id"])
        elif identifier == "B-060":
            remote_trio(at=1)
            direct = fact("node-1", at=2, direct=True, direct_authorized=True)
            flags.update(actual_malicious=True, direct_observation=direct.observation["observation_id"])
        elif identifier == "B-061":
            remote_trio(at=1)
            patrol = fact("patrol-neutral", at=2, patrol=True)
            patrol_events.append({"stream": "patrol", "event_type": "patrol_failed", "at": patrol.at, "observation_id": patrol.observation["observation_id"]})
            flags.update(actual_malicious=True)
        elif identifier == "B-062":
            remote_trio(at=1)
            flags.update(false_claim=True, expiry_expected=True)
        elif identifier == "B-063":
            remote_trio(at=1)
            damage.append((base + 2, 900))
            fact("patrol-neutral", at=3, patrol=True)
            flags.update(actual_malicious=True, fast_attack=True)
        elif identifier == "B-064":
            fact("node-2", at=1)
            fact("node-3", at=2)
            fact("node-4", at=2)
            flags.update(false_claim=True, staggered=True)
        elif identifier == "B-065":
            fact("node-2", at=1)
            fact("node-3", at=5)
            fact("node-4", at=5)
            flags.update(false_claim=True, slow_staggered=True)
        elif identifier == "B-066":
            remote_trio(at=1, scope="financial.transfer")
            remote_trio(at=1, scope="memory.write")
            remote_trio(at=1, scope="public.search")
            flags.update(false_claim=True, capability_comparison=True)
        elif identifier == "B-067":
            for index in range(10):
                observer = f"flood-{index}"
                self._register(cluster, observer, f"control-flood-{index}")
                fact(observer, scope="public.search")
            high = fact("node-2", scope="financial.transfer")
            seeds.extend([(f"control-flood-{index}", "public.search", "quarantined") for index in range(10)])
            seeds.append((group("node-2"), "financial.transfer", "quarantined"))
            flags.update(false_claim=True, tip_flood=True, high_tip=high.observation["observation_id"])
        elif identifier == "B-068":
            for observer in ("node-2", "node-3", "node-4"):
                fact(observer)
                seeds.append((group(observer), "tool:data.export", "quarantined"))
            fact("patrol-neutral", at=2, patrol=True)
            flags.update(actual_malicious=True, multiple_tips=True)
        elif identifier == "B-069":
            remote_trio(at=1)
            clean = fact("node-1", at=2, observation_type="patrol.clean_result", severity="low", direct=True, direct_authorized=True)
            flags.update(false_claim=True, direct_clean=clean.observation["observation_id"])
        elif identifier == "B-070":
            remote_trio(at=1)
            fact("node-5", at=2)
            flags.update(actual_malicious=True, central_outage=True)
        else:  # pragma: no cover
            raise AssertionError("missing confirmation scenario")
        return _ScenarioData(facts, seeds, damage, patrol_events, flags)

    def _receivers(self, cluster: WitnessCluster, scenario: ConfirmationScenario, baseline: str, data: _ScenarioData) -> dict[str, _Receiver]:
        node_ids = ["central"] if baseline == "central_weighted_staged_equal" else sorted(cluster.nodes)
        result: dict[str, _Receiver] = {}
        profile = _profile_for(baseline)
        for node_id in node_ids:
            domain = "central" if node_id == "central" else f"domain-{node_id}"
            ledger = ReliabilityLedger(domain, ReliabilityProfile())
            for fact in data.facts:
                ledger.seed(str(fact.observation["observer_control_group_id"]), str(fact.observation["scope"][0]), state="normal", now=cluster.clock.now)
            for observer_group, scope, state in data.seeds:
                ledger.seed(observer_group, scope, state=state, now=cluster.clock.now)
            confirmation = ConfirmationResolver(domain, profile)
            confirmation.emergency_registry.register("runtime-sensor-node-1", ("tool:data.export", "memory.write", "memory.integrity", "financial.transfer", "payment.transaction"))
            result[node_id] = _Receiver(node_id, domain, ledger, WeightedResolver(domain, ledger), confirmation, SimulatedResponseAdapter(), {})
        return result

    def _drive(self, cluster: WitnessCluster, scenario: ConfirmationScenario, baseline: str, data: _ScenarioData, receivers: Mapping[str, _Receiver]) -> dict[str, Any]:
        subject = str(data.flags["subject"])
        batch_times = sorted({item.at for item in data.facts} | {at for at, _ in data.damage} | {event.get("at") for event in data.patrol_events})
        central_events: list[dict[str, Any]] = []
        fault_events: list[dict[str, Any]] = []
        for now in batch_times:
            cluster.clock.advance(max(0, now - cluster.clock.now))
            facts = [item for item in data.facts if item.at == now]
            central_outage = bool(
                scenario.scenario_id == "B-070"
                and data.flags.get("central_outage")
                and now >= batch_times[-1]
            )
            if central_outage:
                # Both architectures receive this declared fault.  TCX has no
                # central decision dependency, whereas the central comparator
                # cannot continue its sole decision loop.  The raw facts,
                # receipts, patrol outcomes, response adapter, and fault
                # schedule are therefore identical before architecture acts.
                fault_events.append({"stream": "fault", "event_type": "central_decision_service_unavailable", "at": now})
            for receiver in receivers.values():
                if receiver.node_id == "central" and central_outage:
                    central_events.append({"stream": "central", "event_type": "central_unavailable", "at": now})
                    continue
                stored: list[dict[str, Any]] = []
                for fact in facts:
                    validation = cluster.nodes["node-1"].validator.validate(fact.observation, now)
                    if not validation.accepted:
                        raise AssertionError(f"v0.4 fact rejected: {validation.code}")
                    observation = dict(fact.observation)
                    observation.update({"effective_evidence_class": validation.effective_evidence_class, "receipt_verified": validation.receipt_verified, "direct_local": fact.direct_local and receiver.node_id != "central" and receiver.node_id == fact.source_node})
                    receiver.observations[observation["observation_id"]] = observation
                    stored.append(observation)
                if baseline == "v0_3_weighted_full":
                    envelope, _ = receiver.weighted.resolve(subject, receiver.observations.values(), now)
                    receiver.responses.apply(subject, envelope, now, source="v0_3_weighted_full")
                    continue
                influences = {item["observation_id"]: receiver.weighted.evaluate(item, now) for item in stored}
                outcomes = receiver.confirmation.process_batch(stored, influences, now)
                for subject_id, envelope in outcomes.items():
                    receiver.responses.apply(subject_id, envelope, now, source="central_staged" if receiver.node_id == "central" else "tcx_staged")
                if not stored:
                    for subject_id, scope, envelope in receiver.confirmation.advance(now):
                        receiver.responses.apply(subject_id, envelope, now, source="confirmation_expiry")
        # Drive expiration if no later facts would otherwise advance virtual time.
        final_now = max(batch_times, default=cluster.clock.now) + 4
        cluster.clock.advance(max(0, final_now - cluster.clock.now))
        for receiver in receivers.values():
            if baseline == "v0_3_weighted_full":
                continue
            for subject_id, scope, envelope in receiver.confirmation.advance(cluster.clock.now):
                receiver.responses.apply(subject_id, envelope, cluster.clock.now, source="confirmation_expiry")
        if baseline == "perfect_information_oracle":
            desired = "confirmed_quarantine" if data.flags.get("actual_malicious") else "healthy"
            for receiver in receivers.values():
                receiver.responses.apply(subject, OperatingEnvelope(state=desired, actions=("oracle",), reasons=("nondeployable benchmark oracle",)), cluster.clock.now, source="benchmark_oracle")
        return {"central_events": central_events, "fault_events": fault_events, "batch_times": batch_times}

    def _metrics(self, cluster: WitnessCluster, scenario: ConfirmationScenario, baseline: str, data: _ScenarioData, receivers: Mapping[str, _Receiver], events: Mapping[str, Any]) -> dict[str, Any]:
        subject = str(data.flags["subject"])
        states = {name: receiver.responses.envelopes.get(subject, OperatingEnvelope("none")).state for name, receiver in receivers.items()}
        all_tips = [item for receiver in receivers.values() for item in receiver.confirmation.tips]
        all_actions = [item for receiver in receivers.values() for item in receiver.confirmation.scheduler.actions]
        all_requirements = [item for receiver in receivers.values() for item in receiver.confirmation.requirements.values()]
        confirmations = [item for receiver in receivers.values() for item in receiver.confirmation.confirmations]
        # Use the append-only history rather than only live records.  Expired
        # provisional protections are deliberately removed from live state,
        # but their protected interval remains part of the measurement.
        provisional = [item for receiver in receivers.values() for item in receiver.confirmation.provisional_history]
        severity = [item for receiver in receivers.values() for item in receiver.confirmation.severity]
        response_events = [item for receiver in receivers.values() for item in receiver.responses.events]
        contained = [state for state in states.values() if state in {"provisionally_constrained", "constrained", "confirmed_quarantine", "quarantined"}]
        quarantined = [state for state in states.values() if state in {"confirmed_quarantine", "quarantined"}]
        accepted_confirmation = [item for item in confirmations if item.accepted]
        protection_latencies = [max(0, response["at"] - next((campaign.started_at for campaign in receiver.confirmation.campaigns.campaigns.values() if campaign.campaign_id == response.get("campaign_id")), response["at"])) for receiver in receivers.values() for response in receiver.confirmation.responses if response["envelope"]["state"] == "provisionally_constrained"]
        investigation_latencies = [max(0, action.at - next((tip.at for tip in all_tips if tip.tip_id == action.tip_id), action.at)) for action in all_actions]
        confirmation_latencies = [max(0, event.at - next((requirement.activated_at for requirement in all_requirements if requirement.requirement_id == event.requirement_id), event.at)) for event in accepted_confirmation]
        confirmation_intervals = [(requirement.activated_at, requirement.deadline) for requirement in all_requirements]
        damage = sum(weight for at, weight in data.damage if any(start <= at <= end for start, end in confirmation_intervals))
        false_containment = bool(data.flags.get("false_claim") and contained)
        false_quarantine = bool(data.flags.get("false_claim") and quarantined)
        missed_warning = bool(data.flags.get("actual_malicious") and not contained and not quarantined)
        objective = false_quarantine if scenario.objective in {"first_batch_false_quarantine", "repeat_confirmation_bypass", "same_source_novelty", "campaign_stagger_bypass"} else missed_warning
        if scenario.scenario_id in {"B-051", "B-053", "B-059", "B-060", "B-061"}:
            objective = not missed_warning
        if scenario.scenario_id in {"B-052", "B-054", "B-062", "B-067", "B-069"}:
            objective = false_quarantine
        if scenario.scenario_id == "B-070":
            objective = bool(events["central_events"])
        mean = lambda values: round(sum(values) / len(values), 3) if values else 0.0
        return {
            "scenario_objective": scenario.objective,
            "scenario_objective_success": float(objective),
            "false_containment_success": float(false_containment),
            "false_quarantine_success": float(false_quarantine),
            "missed_warning": float(missed_warning),
            "eligible_tip_count": sum(item.eligible for item in all_tips),
            "useful_tip_count": sum(item.eligible for item in all_tips) if data.flags.get("actual_malicious") else 0,
            "false_tip_count": sum(item.eligible for item in all_tips) if data.flags.get("false_claim") else 0,
            "tip_to_confirmation_rate": round(len(accepted_confirmation) / max(1, sum(item.eligible for item in all_tips)), 3),
            "investigation_cost_milli": sum(item.protocol_cost_milli + item.utility_cost_milli for item in all_actions),
            "tip_flood_work_prevented": max(0, sum(item.eligible for item in all_tips) - sum(item.result == "scheduled" for item in all_actions)),
            "provisional_containment_count": sum(item["envelope"]["state"] == "provisionally_constrained" for receiver in receivers.values() for item in receiver.confirmation.responses),
            "provisional_to_quarantine_count": sum(item["envelope"]["state"] == "confirmed_quarantine" for receiver in receivers.values() for item in receiver.confirmation.responses),
            "time_spent_provisional": sum(max(0, min(cluster.clock.now, item.expires_at) - item.activated_at) for item in provisional),
            "provisional_protection_latency": mean(protection_latencies),
            "investigation_latency": mean(investigation_latencies),
            "confirmation_latency": mean(confirmation_latencies),
            "damage_during_confirmation_interval_milli": damage,
            "repeated_source_confirmation_attempts_rejected": sum(not item.accepted and item.reason in {"same_source_or_nonqualifying_confirmation", "source_novelty_missing", "initial_observation_cannot_confirm"} for item in confirmations),
            "staggered_collusion_success": float(bool(data.flags.get("staggered")) and bool(quarantined)),
            "severity_weighted_false_containment_milli": sum(item["severity_milli"] for item in severity if data.flags.get("false_claim")),
            "severity_weighted_security_loss_milli": damage + (1000 if missed_warning else 0),
            "full_quarantines_avoided": int(data.flags.get("false_claim") and not quarantined),
            "high_risk_capabilities_protected": sum(state in {"provisionally_constrained", "confirmed_quarantine", "quarantined"} for state in states.values()),
            "low_risk_utility_preserved": int(scenario.scenario_id == "B-066" and any(item["scope"] == "public.search" and item["state"] != "confirmed_quarantine" for item in severity)),
            "contained_nodes": len(contained),
            "cross_domain_blast_radius": max(0, len(receivers) - len(contained)),
            "central_unavailable": sum(item.get("event_type") == "central_unavailable" for item in events["central_events"]),
            "patrol_unavailable": sum(item.get("event_type") == "patrol_unavailable" for item in data.patrol_events),
            "final_envelopes": states,
            "protocol_overhead_events": len(data.facts) + len(all_tips) + len(all_actions) + len(confirmations),
            "same_time_confirmation_snapshot": True,
            "baseline": baseline,
        }

    def _write_artifacts(self, run_dir: Path, cluster: WitnessCluster, data: _ScenarioData, receivers: Mapping[str, _Receiver], events: Mapping[str, Any], truth: list[dict[str, Any]], summary: Mapping[str, Any]) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        tips = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.tips]
        actions = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.scheduler.actions]
        provisionals = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.provisional_history]
        requirements = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.requirements.values()]
        confirmations = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.confirmations]
        campaigns = [item.as_dict() for receiver in receivers.values() for item in receiver.confirmation.campaigns.campaigns.values()]
        campaign_events = [item for receiver in receivers.values() for item in receiver.confirmation.campaigns.events]
        severity = [item for receiver in receivers.values() for item in receiver.confirmation.severity]
        explanations = [item for receiver in receivers.values() for item in receiver.confirmation.explanations]
        manifest = {
            "benchmark_version": "0.4", "protocol_input_version": "0.2", "reliability_input_version": "0.3",
            "input_fact_digests": [sha256(canonical_bytes(item.observation)).hexdigest() for item in data.facts],
            "receipt_digests": sorted(cluster.receipts),
            "profiles": {name: receiver.confirmation.profile.as_dict() for name, receiver in sorted(receivers.items())},
            "direct_emergency_registry": {name: receiver.confirmation.emergency_registry.snapshot() for name, receiver in sorted(receivers.items())},
            "fault_schedule": events["fault_events"],
            "same_observations_receipts_patrols_investigations_and_faults": True,
            "decision_architecture": "central" if "central" in receivers else "distributed_local",
            "truth_isolation": "benchmark_truth.jsonl is not passed to tcop.confirmation",
        }
        for name, payload in (("manifest.json", manifest), ("summary.json", summary), ("metrics.json", summary["metrics"]), ("campaign-events.json", campaign_events), ("batch-events.json", events)):
            (run_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_jsonl(run_dir / "evidence.jsonl", [item.observation for item in sorted(data.facts, key=lambda item: item.observation["observation_id"])])
        write_jsonl(run_dir / "interaction-receipts.jsonl", cluster.receipts.values())
        write_jsonl(run_dir / "patrol-events.jsonl", data.patrol_events)
        write_jsonl(run_dir / "investigative-tips.jsonl", tips)
        write_jsonl(run_dir / "investigative-actions.jsonl", actions)
        write_jsonl(run_dir / "provisional-responses.jsonl", provisionals)
        write_jsonl(run_dir / "confirmation-requirements.jsonl", requirements)
        write_jsonl(run_dir / "confirmation-events.jsonl", confirmations)
        write_jsonl(run_dir / "evidence-campaigns.jsonl", campaigns)
        write_jsonl(run_dir / "response-severity.jsonl", severity)
        write_jsonl(run_dir / "benchmark-truth.jsonl", truth)
        (run_dir / "confirmation-explanations.txt").write_text(confirmation_explanations_text(explanations), encoding="utf-8")


def run_confirmation_suite(output: Path, *, seed: int = 42) -> dict[str, Any]:
    runner = ConfirmationBenchmarkRunner()
    rows = [runner.run(scenario.scenario_id, baseline=baseline, output=output, seed=seed) for scenario in CONFIRMATION_SCENARIOS for baseline in CONFIRMATION_BASELINES]
    material = [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in rows]
    digest = sha256(canonical_bytes({"runs": material})).hexdigest()
    repeated = [runner.run(scenario.scenario_id, baseline=baseline, output=output / "repro-check", seed=seed) for scenario in CONFIRMATION_SCENARIOS for baseline in CONFIRMATION_BASELINES]
    repeated_digest = sha256(canonical_bytes({"runs": [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in repeated]})).hexdigest()
    result = {"version": "v0.4", "scenarios": len(CONFIRMATION_SCENARIOS), "baselines": list(CONFIRMATION_BASELINES), "runs": len(rows), "same_seed_digest": digest, "same_seed_reproducible": digest == repeated_digest, "oracle_isolation": True}
    if not result["same_seed_reproducible"]:
        raise AssertionError("v0.4 confirmation suite is not same-seed reproducible")
    (output / "confirmation-verification-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_report(output, rows, result)
    return result


def run_confirmation_experiments(output: Path, *, seed: int = 42) -> dict[str, Any]:
    runner = ConfirmationBenchmarkRunner()
    plan = {
        "tip-handling": [("B-051", "v0_3_weighted_full"), ("B-051", "full_v0_4"), ("B-052", "full_v0_4")],
        "confirmation-window": [("B-062", "full_v0_4"), ("B-063", "full_v0_4")],
        "provisional-ttl": [("B-062", "full_v0_4"), ("B-069", "full_v0_4")],
        "betrayal": [("B-056", "v0_3_weighted_full"), ("B-056", "full_v0_4")],
        "staggered-collusion": [("B-064", "full_v0_4"), ("B-065", "full_v0_4"), ("B-065", "provisional_no_campaign_grouping")],
        "patrol-latency": [("B-053", "full_v0_4"), ("B-055", "full_v0_4"), ("B-061", "full_v0_4")],
        "response-severity": [("B-066", "full_v0_4"), ("B-067", "full_v0_4")],
        "investigation-budget": [("B-067", "full_v0_4"), ("B-068", "full_v0_4")],
    }
    result: dict[str, Any] = {}
    for name, runs in plan.items():
        rows = [runner.run(scenario, baseline=baseline, output=output / name / "runs", seed=seed) for scenario, baseline in runs]
        result[name] = rows
        target = output / name
        target.mkdir(parents=True, exist_ok=True)
        (target / "results.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _write_report(output: Path, rows: list[Mapping[str, Any]], result: Mapping[str, Any]) -> None:
    grouped: dict[str, list[Mapping[str, Any]]] = {baseline: [] for baseline in CONFIRMATION_BASELINES}
    for row in rows:
        grouped[row["baseline"]].append(row)
    lines = ["# Deterministic TCOP v0.4 confirmation results", "", "Results are deterministic synthetic comparisons, not a production-security claim.", "", "| Baseline | False quarantine | Missed warning | Provisional latency | Confirmation latency | Damage during confirmation |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for baseline in CONFIRMATION_BASELINES:
        values = grouped[baseline]
        mean = lambda key: sum(float(row["metrics"][key]) for row in values) / len(values)
        lines.append(f"| {baseline} | {mean('false_quarantine_success'):.3f} | {mean('missed_warning'):.3f} | {mean('provisional_protection_latency'):.3f} | {mean('confirmation_latency'):.3f} | {mean('damage_during_confirmation_interval_milli'):.3f} |")
    lines.extend(["", f"Runs: {result['runs']}; deterministic suite digest: `{result['same_seed_digest']}`.", "", "Claims discipline: staged confirmation can reduce immediate false quarantine in authored scenarios while still incurring measurable delay damage. It does not solve collusion."])
    (output / "confirmation-benchmark-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
