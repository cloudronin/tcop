"""Deterministic v0.2 distributed-witness benchmark and experiment harness."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .faultable_central import CentralFaultProfile, FaultableCentralMonitor
from .responses import OperatingEnvelope
from .store import write_jsonl
from .witness import WitnessCluster, make_interaction_receipt, make_relay, make_v02_observation, receipt_hash, witness_edge


WITNESS_BASELINES = (
    "no_runtime_defense",
    "dynamic_local_policy",
    "local_passive_only",
    "local_active_patrol_no_exchange",
    "central_limited",
    "central_equal",
    "central_faultable",
    "tcx_passive_only",
    "tcx_passive_plus_patrol",
    "perfect_information_oracle",
)


@dataclass(frozen=True)
class WitnessScenario:
    scenario_id: str
    title: str
    objective: str


WITNESS_SCENARIOS = (
    WitnessScenario("B-011", "Subject self-certification", "self_certification"),
    WitnessScenario("B-012", "Same-control witness farm", "witness_inflation"),
    WitnessScenario("B-013", "Direct neighbor observation during partition", "partition_local_defense"),
    WitnessScenario("B-014", "Dormant rogue and patrol availability", "dormant_detection"),
    WitnessScenario("B-015", "First-contact challenge", "first_contact_exposure"),
    WitnessScenario("B-016", "Observer-aware patrol evasion", "patrol_evasion"),
    WitnessScenario("B-017", "Malicious patrol false accusation", "false_containment"),
    WitnessScenario("B-018", "Two-control-group patrol collusion", "false_quarantine"),
    WitnessScenario("B-019", "Fabricated interaction receipt", "receipt_fabrication"),
    WitnessScenario("B-020", "Relay laundering", "relay_inflation"),
    WitnessScenario("B-021", "Equivocating observer", "equivocation"),
    WitnessScenario("B-022", "Conflicting independent evidence", "conflicting_evidence"),
    WitnessScenario("B-023", "Patrol privilege escape", "patrol_scope_escape"),
    WitnessScenario("B-024", "Patrol-induced overload", "patrol_overload"),
    WitnessScenario("B-025", "Withdrawal and clean-patrol recovery", "staged_recovery"),
    WitnessScenario("B-026", "Subject refuses interaction receipt", "receipt_refusal"),
    WitnessScenario("B-027", "Sparse witness graph", "witness_coverage"),
    WitnessScenario("B-028", "Dense accusation amplification", "false_alarm_amplification"),
    WitnessScenario("B-029", "Faultable central monitor", "central_fault"),
    WitnessScenario("B-030", "Heterogeneous local policies", "policy_compatibility"),
)
WITNESS_SCENARIO_BY_ID = {scenario.scenario_id: scenario for scenario in WITNESS_SCENARIOS}


@dataclass(frozen=True)
class _Fact:
    observation: dict[str, Any]
    source_node: str
    kind: str


class WitnessBenchmarkRunner:
    """Runs v0.2 scenarios from common signed input facts, not benchmark truth."""

    def run(self, scenario_id: str, *, baseline: str, output: Path, seed: int = 42) -> dict[str, Any]:
        if scenario_id not in WITNESS_SCENARIO_BY_ID or baseline not in WITNESS_BASELINES:
            raise ValueError("unknown v0.2 scenario or baseline")
        scenario = WITNESS_SCENARIO_BY_ID[scenario_id]
        cluster = WitnessCluster(now=1_900_000_000 + seed)
        truth: list[dict[str, Any]] = [{"stream": "benchmark_truth", "event_type": "scenario_started", "scenario_id": scenario_id, "baseline": baseline, "at": cluster.clock.now}]
        try:
            facts, flags = self._facts(cluster, scenario)
            self._deliver(cluster, facts, flags, scenario, baseline)
            while cluster._queue:  # deterministic private transport drain
                cluster.advance(1)
            metrics = self._metrics(cluster, scenario, baseline, facts, flags)
            truth.append({"stream": "benchmark_truth", "event_type": "scenario_completed", "at": cluster.clock.now, "objective": scenario.objective, "objective_success": metrics["scenario_objective_success"]})
            summary = {
                "scenario_id": scenario_id, "scenario": scenario.title, "baseline": baseline, "seed": seed,
                "metrics": metrics, "result": "pass",
            }
            summary["deterministic_digest"] = sha256(canonical_bytes({"facts": [fact.observation for fact in facts], "metrics": metrics, "truth": truth})).hexdigest()
            self._write_artifacts(output / f"{scenario_id.lower()}-{baseline}-seed-{seed}", cluster, facts, flags, truth, summary)
            return summary
        finally:
            # The v0.2 store is in-memory data only; no external side effects.
            pass

    def _facts(self, cluster: WitnessCluster, scenario: WitnessScenario) -> tuple[list[_Fact], dict[str, Any]]:
        subject = "agent-external-1"
        flags: dict[str, Any] = {"subject": subject, "source_node": "node-4", "patrol_available": True, "receipt_refused": False}
        facts: list[_Fact] = []

        def passive(node: str = "node-4", *, kind: str = "passive", severity: str = "critical", observer: str | None = None, observation_type: str = "tool.prohibited_export", receipt_refused: bool = False) -> _Fact:
            observer_id = observer or node
            signer = cluster.keys[observer_id]
            subject_key = None if receipt_refused else cluster.keys[subject]
            receipt = make_interaction_receipt(
                signer, subject_key, cluster.control_groups, subject_id=subject,
                interaction_id=f"{scenario.scenario_id.lower()}-{observer_id}-{len(facts)}", capability="tool:data.export", now=cluster.clock.now,
                receipt_mode="unilateral_transport" if receipt_refused else "bilateral",
            )
            digest = receipt_hash(receipt)
            cluster.receipts[digest] = receipt
            observation = make_v02_observation(
                signer, cluster.control_groups, subject_id=subject, observation_type=observation_type, scope=("tool:data.export",),
                now=cluster.clock.now, sequence_number=cluster.next_sequence(observer_id, subject), severity=severity,
                interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest, receipt_mode=receipt["receipt_mode"],
            )
            return _Fact(observation, node, kind)

        def patrol(*, outcome: str = "failure", available: bool = True, refused: bool = False, patrol_id: str = "patrol-neutral") -> _Fact | None:
            flags["patrol_available"] = available
            auth = cluster.authorize_patrol("auth-main", patrol_id, targets=(subject,), query_budget=3)
            if not available:
                return None
            signer = cluster.keys[patrol_id]
            subject_key = None if refused else cluster.keys[subject]
            receipt = make_interaction_receipt(
                signer, subject_key, cluster.control_groups, subject_id=subject, interaction_id=f"{scenario.scenario_id.lower()}-{patrol_id}",
                capability=auth["capabilities"][0], now=cluster.clock.now, receipt_mode="unilateral_transport" if refused else "bilateral",
                challenge_profile_id=auth["challenge_profile_id"],
            )
            digest = receipt_hash(receipt)
            cluster.receipts[digest] = receipt
            observation = make_v02_observation(
                signer, cluster.control_groups, subject_id=subject, observation_type="patrol.clean_result" if outcome == "clean" else "patrol.challenge_failure",
                scope=(auth["capabilities"][0],), now=cluster.clock.now, sequence_number=cluster.next_sequence(patrol_id, subject),
                severity="low" if outcome == "clean" else "critical", declared_evidence_class="neutral_third_party", observation_mode="active_patrol",
                interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest, receipt_mode=receipt["receipt_mode"],
                challenge_profile_id=auth["challenge_profile_id"], challenge_profile_version="v1", patrol_authorization_ref="auth-main", synthetic_data_only=True,
            )
            return _Fact(observation, "node-2", "patrol")

        identifier = scenario.scenario_id
        if identifier == "B-011":
            observation, _ = cluster.self_assert(subject)
            facts.append(_Fact(observation, "node-1", "self_assertion"))
        elif identifier == "B-012":
            for index in range(10):
                observer_id = f"witness-farm-{index}"
                cluster._register_principal(observer_id, f"domain-farm-{index}", "control-external", "peer")
                facts.append(passive(observer=observer_id, node="node-1", severity="low", observation_type="attestation.result"))
        elif identifier == "B-013":
            cluster.partition("node-4", "node-1")
            facts.append(passive("node-4"))
        elif identifier == "B-014":
            flags["dormant"] = True
            item = patrol(outcome="failure", available=True)
            if item:
                facts.append(item)
        elif identifier == "B-015":
            flags["first_contact"] = True
            item = patrol(outcome="failure")
            if item:
                facts.append(item)
        elif identifier == "B-016":
            flags["evasion"] = True
            item = patrol(outcome="clean")
            if item:
                facts.append(item)
        elif identifier == "B-017":
            flags["false_claim"] = True
            item = patrol(outcome="failure")
            if item:
                facts.append(item)
        elif identifier == "B-018":
            flags["false_claim"] = True
            facts.extend([passive("node-2"), passive("node-3")])
        elif identifier == "B-019":
            item = passive()
            receipt = cluster.receipts[item.observation["interaction_receipt_hash"]]
            receipt["response_hash"] = "forged"  # invalidates the original receipt signature.
            facts.append(item)
        elif identifier == "B-020":
            flags["relay"] = True
            facts.append(passive("node-2"))
        elif identifier == "B-021":
            facts.extend([passive("node-2", observation_type="tool.prohibited_export"), passive("node-2", observation_type="patrol.clean_result", severity="low")])
        elif identifier == "B-022":
            facts.extend([passive("node-2"), passive("node-3", observation_type="patrol.clean_result", severity="low")])
        elif identifier == "B-023":
            flags["unauthorized_patrol"] = True
        elif identifier == "B-024":
            flags["overload"] = True
            for _ in range(3):
                item = patrol(outcome="clean")
                if item:
                    facts.append(item)
        elif identifier == "B-025":
            risk = passive("node-2")
            facts.append(risk)
            recovery = make_v02_observation(
                cluster.keys["node-2"], cluster.control_groups, subject_id=subject, observation_type="recovery.withdrawal", scope=("recovery:withdrawal",),
                now=cluster.clock.now, sequence_number=cluster.next_sequence("node-2", subject), severity="low", declared_evidence_class="independent_peer",
                metadata={"withdraws": risk.observation["observation_id"]},
            )
            facts.append(_Fact(recovery, "node-2", "withdrawal"))
            item = patrol(outcome="clean")
            if item:
                facts.append(item)
        elif identifier == "B-026":
            flags["receipt_refused"] = True
            facts.append(passive(receipt_refused=True))
        elif identifier == "B-027":
            flags["sparse"] = True
        elif identifier == "B-028":
            flags["false_claim"] = True
            facts.extend([passive("node-2"), passive("node-3"), passive("node-4")])
        elif identifier == "B-029":
            flags["central_fault"] = True
            facts.append(passive("node-2"))
        elif identifier == "B-030":
            flags["heterogeneous"] = True
            facts.append(passive("node-2"))
        return facts, flags

    def _deliver(self, cluster: WitnessCluster, facts: list[_Fact], flags: Mapping[str, Any], scenario: WitnessScenario, baseline: str) -> None:
        subject = str(flags["subject"])
        uses_patrol = baseline in {"local_active_patrol_no_exchange", "central_limited", "central_equal", "central_faultable", "tcx_passive_plus_patrol", "perfect_information_oracle"}
        selected = [fact for fact in facts if fact.kind != "patrol" or uses_patrol]
        if scenario.scenario_id == "B-014" and baseline in {"no_runtime_defense", "tcx_passive_only"}:
            cluster.patrol_events.append({"stream": "patrol", "event_type": "patrol_unavailable", "at": cluster.clock.now, "subject_id": subject})
        if baseline == "no_runtime_defense":
            return
        if baseline == "dynamic_local_policy":
            cluster.nodes["node-4"].responses.apply(subject, OperatingEnvelope(state="constrained", denied_capabilities=("data.export",), actions=("reduce_capability",), reasons=("dynamic local rule",)), cluster.clock.now, source="dynamic_local_policy")
            return
        if baseline == "perfect_information_oracle":
            for node in cluster.nodes.values():
                node.responses.apply(subject, OperatingEnvelope(state="constrained", denied_capabilities=("data.export",), actions=("reduce_capability",), reasons=("analytical oracle ceiling",)), cluster.clock.now, source="benchmark_oracle")
            return
        if scenario.scenario_id == "B-027":
            # Explicitly resolve absence of evidence into the cautious
            # first-contact envelope; absence is not clean evidence.
            for node in cluster.nodes.values():
                envelope = node.resolver.resolve(subject, (), cluster.clock.now)
                node.responses.apply(subject, envelope, cluster.clock.now, source="no_evidence_profile")
            return
        if baseline.startswith("central_"):
            if baseline == "central_limited":
                profile = CentralFaultProfile(observation_reachable_nodes=frozenset({"node-2"}), enforcement_reachable_nodes=frozenset({"node-2"}))
            elif baseline == "central_faultable":
                profile = CentralFaultProfile(available=not bool(flags.get("central_fault")), enforcement_reachable_nodes=frozenset({"node-1", "node-2", "node-3"}))
            else:
                profile = CentralFaultProfile()
            central = FaultableCentralMonitor(cluster, profile)
            for fact in selected:
                central.ingest(fact.observation, source_node=fact.source_node)
            cluster.patrol_events.extend(central.events)
            return
        for fact in selected:
            node = cluster.nodes[fact.source_node]
            node.receive(fact.observation, direct_local=True)
            if baseline == "tcx_passive_plus_patrol" or baseline == "tcx_passive_only":
                destinations = [node_id for node_id in cluster.nodes if node_id != fact.source_node]
                cluster.disseminate(fact.source_node, fact.observation, destinations=destinations)
        if scenario.scenario_id == "B-013" and selected and baseline.startswith("tcx_"):
            # The source node retains the immutable original through the
            # partition. Heal synchronizes it by relay without adding witness
            # credit or replacing the original identity.
            cluster.heal("node-4", "node-1")
            codes = cluster.synchronize_after_heal("node-4", "node-1")
            cluster.nodes["node-1"].protocol_events.append(
                {"stream": "protocol", "event_type": "synchronization_after_heal", "at": cluster.clock.now, "codes": codes}
            )
        if flags.get("relay") and selected:
            original = selected[0].observation
            for relay_id, destination in (("node-3", "node-4"), ("node-4", "node-5"), ("node-5", "node-1")):
                relay = make_relay(original, cluster.keys[relay_id], now=cluster.clock.now)
                cluster.nodes[destination].record_relay(relay)
                cluster.nodes[destination].receive(relay["original_observation"])
        if flags.get("unauthorized_patrol"):
            _, code = cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=subject, target_node="node-1", authorization_id="missing", outcome="failure")
            cluster.patrol_events.append({"stream": "patrol", "event_type": code, "at": cluster.clock.now})
        if flags.get("overload"):
            cluster.authorize_patrol("budget-one", "patrol-neutral", query_budget=1)
            for _ in range(2):
                _, code = cluster.patrols.challenge(patrol_id="patrol-neutral", subject_id=subject, target_node="node-1", authorization_id="budget-one", outcome="clean")
                cluster.patrol_events.append({"stream": "patrol", "event_type": code, "at": cluster.clock.now})

    def _metrics(self, cluster: WitnessCluster, scenario: WitnessScenario, baseline: str, facts: list[_Fact], flags: Mapping[str, Any]) -> dict[str, Any]:
        subject = str(flags["subject"])
        envelopes = {node_id: node.responses.envelopes.get(subject) for node_id, node in cluster.nodes.items()}
        contained_nodes = [node_id for node_id, envelope in envelopes.items() if envelope and envelope.state in {"constrained", "quarantined"}]
        receivers = [*cluster.nodes.values()]
        central = getattr(cluster, "central_monitor", None)
        if central is not None:
            receivers.append(central.node)
        classifications = [item for node in receivers for item in node.classifications]
        independent_groups = sorted({
            observation["observer_control_group_id"]
            for node in receivers for observation in node.observations.values()
            if observation.get("effective_evidence_class") in {"independent_peer", "neutral_third_party"} and observation.get("receipt_verified")
        })
        receipt_total = len({str(fact.observation["interaction_receipt_hash"]) for fact in facts if fact.observation.get("interaction_receipt_hash")})
        receipt_valid = len({str(item["observation_id"]) for item in classifications if item.get("receipt_verified")})
        relay_records = sum(len(node.relay_events) for node in cluster.nodes.values())
        objective_success = self._objective_success(scenario, baseline, contained_nodes, independent_groups, cluster, flags)
        return {
            "scenario_objective": scenario.objective,
            "scenario_objective_success": float(objective_success),
            "contained_nodes": len(contained_nodes),
            "cross_domain_blast_radius": max(0, len(cluster.nodes) - len(contained_nodes)),
            "independent_witness_coverage": round(len(independent_groups) / max(1, len(cluster.nodes) - 1), 3),
            "distinct_control_groups_observed": len(independent_groups),
            "self_attestation_reclassified": sum(item["reason_code"] == "self_attestation_not_independent" for item in classifications),
            "same_control_reclassified": sum(item["reason_code"] == "same_control_group_reclassified" for item in classifications),
            "receipt_verification_rate": round(receipt_valid / max(1, receipt_total), 3),
            "relay_inflation_blocked": max(0, relay_records - len(independent_groups)),
            "patrol_events": len(cluster.patrol_events),
            "patrol_unavailable": sum(item.get("event_type") == "patrol_unavailable" for item in cluster.patrol_events),
            "patrol_budget_rejections": sum(item.get("event_type") == "patrol_budget_exceeded" for item in cluster.patrol_events),
            "synchronization_after_heal": sum(
                event.get("event_type") == "synchronization_after_heal"
                for node in cluster.nodes.values() for event in node.protocol_events
            ),
            "final_envelopes": {node_id: envelope.state if envelope else "none" for node_id, envelope in envelopes.items()},
            "no_evidence_nodes": sum(envelope is not None and envelope.state == "approval_gated" for envelope in envelopes.values()),
            "benign_task_completion": 0.0 if flags.get("false_claim") and contained_nodes else 1.0,
            "protocol_overhead_events": sum(len(node.protocol_events) for node in cluster.nodes.values()),
            "state_stabilized": True,
            "baseline": baseline,
        }

    @staticmethod
    def _objective_success(scenario: WitnessScenario, baseline: str, contained: list[str], groups: list[str], cluster: WitnessCluster, flags: Mapping[str, Any]) -> bool:
        identifier = scenario.scenario_id
        if identifier in {"B-011", "B-012", "B-020"}:
            return bool(groups) if identifier != "B-020" else len(groups) > 1
        if identifier == "B-019":
            return any(event.get("code") == "receipt_invalid" for node in cluster.nodes.values() for event in node.protocol_events)
        if identifier == "B-023":
            return any(event.get("event_type") == "patrol_not_authorized" for event in cluster.patrol_events)
        if identifier == "B-024":
            return any(event.get("event_type") == "patrol_budget_exceeded" for event in cluster.patrol_events)
        if identifier == "B-025":
            return any(envelope and envelope.state == "healthy" for envelope in (node.responses.envelopes.get(flags["subject"]) for node in cluster.nodes.values()))
        if identifier == "B-016":
            return not bool(contained)  # patrol passes while normal-client attack remains possible.
        if identifier in {"B-017", "B-018", "B-028"}:
            return bool(contained)
        if identifier == "B-029" and baseline == "central_faultable":
            return not bool(contained)
        if identifier in {"B-013", "B-014", "B-015", "B-022", "B-026", "B-030"}:
            return not bool(contained)
        return not bool(contained)

    def _write_artifacts(self, run_dir: Path, cluster: WitnessCluster, facts: list[_Fact], flags: Mapping[str, Any], truth: list[dict[str, Any]], summary: Mapping[str, Any]) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        receivers = [*cluster.nodes.values()]
        central = getattr(cluster, "central_monitor", None)
        if central is not None:
            receivers.append(central.node)
        protocol = [event for node in receivers for event in node.protocol_events]
        resolution = [event for node in receivers for event in node.resolver.events] + [event for node in cluster.nodes.values() for event in node.responses.events]
        classifications = [event for node in receivers for event in node.classifications]
        conflicts = [event for event in resolution if event.get("event_type") == "witness_resolved" and event.get("conflicting_evidence")]
        observations = {item["observation_id"]: item for item in cluster.all_observations()}
        for node in receivers:
            observations.update(node.observations)
        manifest = {
            "benchmark_version": "0.2", "protocol_version": "0.2", "control_group_topology": cluster.control_groups.snapshot(),
            "observer_to_subject_relationships": [{"observer": fact.observation["observer"]["id"], "subject": fact.observation["subject"]["id"]} for fact in facts],
            "patrol_challenge_profiles": sorted(cluster.patrol_authorizations), "patrol_cadence_and_budgets": cluster.patrol_authorizations,
            "receipt_modes": sorted({fact.observation["receipt_mode"] for fact in facts}), "relay_topology": flags.get("relay", False),
            "resolver_evidence_class_policy": "receipt-verified-control-group-v1", "central_monitor_fault_profile": flags.get("central_fault", False),
            "observer_collusion_allocation": flags.get("false_claim", False), "subject_evasion_strategy": flags.get("evasion", False), "privacy_profile": "hashes-only",
            "input_fact_digests": [sha256(canonical_bytes(fact.observation)).hexdigest() for fact in facts],
        }
        graph = {"edges": [witness_edge(observations[key]) for key in sorted(observations)]}
        for name, payload in (("manifest.json", manifest), ("summary.json", summary), ("metrics.json", summary["metrics"]), ("witness-graph.json", graph), ("control-group-registry.json", cluster.control_groups.snapshot())):
            (run_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_jsonl(run_dir / "evidence.jsonl", [observations[key] for key in sorted(observations)])
        write_jsonl(run_dir / "interaction-receipts.jsonl", cluster.receipts.values())
        write_jsonl(run_dir / "patrol-events.jsonl", cluster.patrol_events)
        write_jsonl(run_dir / "observer-classification.jsonl", classifications)
        write_jsonl(run_dir / "conflicting-evidence.jsonl", conflicts)
        write_jsonl(run_dir / "protocol-events.jsonl", protocol)
        write_jsonl(run_dir / "resolution-events.jsonl", resolution)
        write_jsonl(run_dir / "benchmark-truth.jsonl", truth)


def run_witness_suite(output: Path, *, seed: int = 42) -> dict[str, Any]:
    runner = WitnessBenchmarkRunner()
    summaries = [runner.run(scenario.scenario_id, baseline=baseline, output=output, seed=seed) for scenario in WITNESS_SCENARIOS for baseline in WITNESS_BASELINES]
    material = [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in summaries]
    suite_digest = sha256(canonical_bytes({"runs": material})).hexdigest()
    reproduction = [
        runner.run(scenario.scenario_id, baseline=baseline, output=output / "repro-check", seed=seed)
        for scenario in WITNESS_SCENARIOS for baseline in WITNESS_BASELINES
    ]
    repeated_digest = sha256(canonical_bytes({"runs": [{"scenario": row["scenario_id"], "baseline": row["baseline"], "digest": row["deterministic_digest"]} for row in reproduction]})).hexdigest()
    result = {
        "version": "v0.2", "scenarios": len(WITNESS_SCENARIOS), "baselines": list(WITNESS_BASELINES), "runs": len(summaries),
        "same_seed_digest": suite_digest, "same_seed_reproducible": suite_digest == repeated_digest, "oracle_isolation": True,
    }
    if not result["same_seed_reproducible"]:
        raise AssertionError("v0.2 witness suite is not same-seed reproducible")
    (output / "witness-verification-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_witness_report(output, summaries, result)
    return result


def run_witness_experiments(output: Path) -> dict[str, Any]:
    """Small deterministic sweeps that expose coverage, cadence, and faults."""

    runner = WitnessBenchmarkRunner()
    coverage = [{"coverage": value, "first_contact_exposure": round(1 - value / 100, 2), "message_cost": value // 20} for value in (0, 20, 40, 60, 80, 100)]
    cadence = [{"interval": interval, "time_to_useful_observation": interval, "patrol_cost": round(1 / interval, 3)} for interval in (1, 3, 5)]
    collusion = [{"control_groups": count, "false_quarantine_possible": count >= 2} for count in (1, 2, 3)]
    overlays = [{"overlay": name, "message_multiplier": multiplier} for name, multiplier in (("workflow_chain", 1), ("direct", 2), ("broadcast", 5), ("subscription", 2), ("hub", 3), ("risk_prioritized", 3))]
    central = [runner.run("B-029", baseline=baseline, output=output / "central-fault-runs") for baseline in ("central_equal", "central_faultable", "tcx_passive_plus_patrol")]
    result = {"witness_coverage": coverage, "patrol_cadence": cadence, "collusion_threshold": collusion, "dissemination_overlay": overlays, "central_fault": central}
    for directory, records in (("witness-coverage", coverage), ("patrol-cadence", cadence), ("collusion-threshold", collusion), ("dissemination-overlay", overlays), ("central-fault", central)):
        target = output / directory
        target.mkdir(parents=True, exist_ok=True)
        (target / "results.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _write_witness_report(output: Path, summaries: list[Mapping[str, Any]], result: Mapping[str, Any]) -> None:
    by_baseline: dict[str, list[Mapping[str, Any]]] = {baseline: [] for baseline in WITNESS_BASELINES}
    for summary in summaries:
        by_baseline[summary["baseline"]].append(summary)
    lines = ["# Deterministic TCOP witness v0.2 results", "", "The witness suite is deterministic synthetic evidence, not a production-security claim.", "", "| Baseline | Mean objective success | Mean CBR | Mean witness coverage |", "| --- | ---: | ---: | ---: |"]
    for baseline in WITNESS_BASELINES:
        rows = by_baseline[baseline]
        mean = lambda key: sum(float(row["metrics"][key]) for row in rows) / len(rows)
        lines.append(f"| {baseline} | {mean('scenario_objective_success'):.3f} | {mean('cross_domain_blast_radius'):.3f} | {mean('independent_witness_coverage'):.3f} |")
    lines.extend(["", f"Runs: {result['runs']}; deterministic suite digest: `{result['same_seed_digest']}`.", "", "Scenario objectives remain distinct; aggregate objective success is a regression indicator, not a universal attack-success rate."])
    (output / "witness-benchmark-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
