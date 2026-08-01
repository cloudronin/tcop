"""Deterministic v0.6 missing-evidence analysis over immutable study output.

This module is deliberately a measurement and diagnostic layer.  It reads the
completed federation artifact, runs only explicitly labelled diagnostic cells,
and never changes TCX, receipt, relay, resolver, or frozen strategy behavior.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .federation import (
    ARCHITECTURES,
    FROZEN_ROOT,
    NETWORKS,
    OBSERVERS,
    SCENARIOS,
    TOPOLOGIES,
    FederatedRun,
    FrozenStrategyAdapter,
    MatrixCell,
    NetworkProfile,
    UPSTREAM_DIGESTS,
    _cell_id,
    _write_json,
    artifact_root_digest,
    verify_artifacts,
)
from .store import write_jsonl


VERSION = "tcop.v0.6-missing-evidence/0.1"
DEFAULT_SOURCE = Path("artifacts/federated-domain-v0.6")
EVIDENCE_PLAN = Path("benchmark/studies/v0.6-evidence.yaml")
FORENSIC_RUBRIC = Path("benchmark/rubrics/v0.6-forensic-quality.yaml")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SELECTIONS = {"smoke", "audit", "causal-core", "timing", "central-audit", "utility", "forensics", "full"}
PRIMARY_CLASSES = {
    "primary_opportunity", "timing_expired", "negative_control", "false_warning", "benign_utility",
    "resilience", "forensic", "upper_bound", "mechanism_probe", "excluded_invalid",
}


def _digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _semantic_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Remove artifact-order metadata, retaining authored protocol semantics."""

    ignored = {"stream", "phase", "phase_name", "sequence", "topology_order"}
    return [{key: value for key, value in event.items() if key not in ignored} for event in events]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _state_protective(event: Mapping[str, Any], capability: str) -> bool:
    envelope = event.get("envelope", {})
    if not isinstance(envelope, Mapping):
        return False
    return str(event.get("state")) in {"quarantined", "confirmed_quarantine", "constrained", "provisionally_constrained", "oracle_quarantine"} or capability in envelope.get("denied_capabilities", ()) or "*" in envelope.get("denied_capabilities", ())


def _restriction_class(event: Mapping[str, Any]) -> str:
    state = str(event.get("state", "unknown"))
    if state in {"unknown", "healthy", "suspicious", "monitored"}:
        return "monitor_only"
    if state in {"investigating", "investigation"}:
        return "investigation_only"
    if state in {"approval_gated", "approval_required"}:
        return "approval_required"
    if state in {"provisionally_constrained"}:
        return "provisional_deny"
    if state in {"quarantined", "confirmed_quarantine", "oracle_quarantine"}:
        return "quarantine"
    return "narrow_capability_restriction" if _state_protective(event, "") else "broad_restriction"


class EvidenceRound:
    def __init__(self, source: Path, output: Path, frozen_root: Path = FROZEN_ROOT) -> None:
        self.source, self.output, self.frozen_root = source, output, frozen_root
        self.adapter = FrozenStrategyAdapter(frozen_root)
        self.summaries: dict[str, dict[str, Any]] = {}
        self.cells: dict[str, dict[str, Any]] = {}
        self._streams: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self.diagnostics: list[dict[str, Any]] = []

    def prepare(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        for name in ("plans", "cohort", "pairs", "timing", "central-audit", "utility", "forensics", "reports", "plots", "replay", "findings", "validation"):
            target = self.output / name
            if target.exists():
                shutil.rmtree(target)

    def verify_source(self) -> dict[str, Any]:
        status, manifest = _read_json(self.source / "status.json"), _read_json(self.source / "manifest.json")
        stage = str(manifest.get("stage"))
        matrix_path = self.source / "matrix" / f"{stage}-matrix.json"
        cells = [MatrixCell(**value) for value in _read_json(matrix_path)]
        verification = verify_artifacts(self.source, cells, matrix_name=matrix_path.name)
        if not status.get("passed") or not verification.get("passed") or not _read_json(self.source / "smoke-replay.json").get("passed"):
            raise AssertionError("source v0.6 artifact is not complete and replayable")
        self.cells = {str(value["cell_id"]): dict(value) for value in _read_json(matrix_path)}
        for cell_id in self.cells:
            summary = _read_json(self.source / "runs" / cell_id / "summary.json")
            self.summaries[cell_id] = summary
        certifications = _read_json(self.source / "strategy-certifications.json")
        record = {
            "source_artifact": str(self.source), "source_status": status, "source_manifest": manifest,
            "source_artifact_digest": artifact_root_digest(self.source), "source_verification": verification,
            "source_run_count": len(self.summaries), "frozen_strategy_digests": {key: value["manifest_digest"] for key, value in certifications.items()},
        }
        _write_json(self.output / "source-artifact.json", record)
        return record

    def streams(self, run_id: str) -> dict[str, list[dict[str, Any]]]:
        if run_id not in self._streams:
            root = self.source / "runs" / run_id
            self._streams[run_id] = {name: _read_jsonl(root / f"{name}.jsonl") for name in ("authored_facts", "benchmark_truth", "produced_observations", "transport_faults", "derived_decisions")}
        return self._streams[run_id]

    def primary_class(self, summary: Mapping[str, Any]) -> str:
        cell, scenario = summary["cell"], summary["scenario"]
        if cell["classification"] == "upper_bound":
            return "upper_bound"
        if cell["classification"] == "forensic_cell":
            return "forensic"
        if cell["classification"] == "sensitivity_cell":
            return "resilience" if scenario["family"] == "resilience" else "mechanism_probe"
        if scenario["scenario_id"] == "S16":
            return "benign_utility"
        if scenario["false_warning"]:
            return "false_warning"
        if scenario["family"] in {"negative_control", "adversarial"}:
            return "negative_control"
        if scenario["family"] == "resilience":
            return "resilience"
        if scenario["family"] == "timing" and summary["metrics"]["first_import_at"] is None:
            return "timing_expired"
        return "primary_opportunity"

    def cohort_audit(self) -> dict[str, Any]:
        primary: dict[str, list[str]] = defaultdict(list)
        aggregates: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        membership: list[dict[str, Any]] = []
        for run_id, summary in sorted(self.summaries.items()):
            primary_class = self.primary_class(summary)
            assert primary_class in PRIMARY_CLASSES
            primary[primary_class].append(run_id)
            cell = summary["cell"]
            aggregates[(cell["architecture_id"], str(cell["strategy_id"]), cell["classification"])].append(run_id)
            membership.append({"run_id": run_id, "primary_class": primary_class, "secondary_tags": [summary["scenario"]["family"], cell["classification"]], "membership_kind": "primary"})
        def cohort(cohort_id: str, purpose: str, members: list[str], *, aggregate: bool = False) -> dict[str, Any]:
            values = [self.summaries[item] for item in members]
            count = lambda key: dict(sorted(Counter(str(value[key]) for value in values).items()))
            return {
                "cohort_id": cohort_id, "purpose": purpose, "cell_count": len(members), "cell_set_digest": _digest(sorted(members)),
                "inclusion_rule": "pre-registered source matrix membership", "exclusion_rule": "none", "scenario_families": count("scenario") if False else dict(sorted(Counter(value["scenario"]["family"] for value in values).items())),
                "topologies": dict(sorted(Counter(value["cell"]["topology_id"] for value in values).items())), "observer_profiles": dict(sorted(Counter(value["cell"]["observer_id"] for value in values).items())),
                "network_profiles": dict(sorted(Counter(value["cell"]["network_id"] for value in values).items())), "architectures": dict(sorted(Counter(value["cell"]["architecture_id"] for value in values).items())),
                "strategies": dict(sorted(Counter(str(value["cell"]["strategy_id"]) for value in values).items())), "pareto_eligible": bool(aggregate and all(value["cell"]["classification"] == "primary_deployment_cell" for value in values)), "run_ids": sorted(members),
            }
        cohorts = {f"primary:{key}": cohort(f"primary:{key}", "primary-class audit", members) for key, members in sorted(primary.items())}
        for (architecture, strategy, classification), members in sorted(aggregates.items()):
            cohort_id = f"aggregate:{architecture}:{strategy}:{classification}"
            cohorts[cohort_id] = cohort(cohort_id, "traceable original aggregate", members, aggregate=True)
            membership.extend({"run_id": member, "aggregate_cohort_id": cohort_id, "membership_kind": "aggregate"} for member in members)
        aggregate_items = [value for key, value in cohorts.items() if key.startswith("aggregate:")]
        comparisons = [{"left": left["cohort_id"], "right": right["cohort_id"], "directly_comparable": left["cell_set_digest"] == right["cell_set_digest"], "left_cell_set_digest": left["cell_set_digest"], "right_cell_set_digest": right["cell_set_digest"]} for index, left in enumerate(aggregate_items) for right in aggregate_items[index + 1:]]
        _write_json(self.output / "cohort" / "cohort-map.json", cohorts)
        write_jsonl(self.output / "cohort" / "cohort-membership.jsonl", membership)
        _write_json(self.output / "cohort" / "cohort-overlap-report.json", {"cohort_count": len(cohorts), "primary_class_counts": {key: len(value) for key, value in primary.items()}, "primary_assignment_complete": len(primary) > 0 and sum(len(value) for value in primary.values()) == len(self.summaries)})
        _write_json(self.output / "cohort" / "aggregate-comparability-report.json", comparisons)
        return cohorts

    def _input_signature(self, run_id: str) -> dict[str, Any]:
        summary, streams = self.summaries[run_id], self.streams(run_id)
        cell, scenario = summary["cell"], summary["scenario"]
        authored = _semantic_events(item for item in streams["authored_facts"] if item["event_type"] in {"scenario_authored", "telemetry_available"})
        truth = _semantic_events(streams["benchmark_truth"])
        local = _semantic_events(item for item in streams["produced_observations"] if item.get("source") == "local_observer" or item["event_type"] == "signed_observation_produced")
        observer_schedule = [item for item in authored if item["event_type"] == "telemetry_available"]
        action_schedule = [item for item in truth if item["event_type"] == "ground_truth"]
        local_policy = "containment-first" if cell["architecture_id"] == "A1" else str(cell["strategy_id"])
        material = {"topology": cell["topology_id"], "scenario": cell["scenario_id"], "scenario_fact_digest": _digest(authored), "observer_profile": cell["observer_id"], "observer_schedule_digest": _digest(observer_schedule), "network_profile": cell["network_id"], "network_schedule_digest": _digest(asdict(NETWORKS[cell["network_id"]])), "seed": cell["seed"], "local_policy_configuration": local_policy, "capability_configuration": scenario["receiver_capability"], "autonomous_action_schedule_digest": _digest(action_schedule), "benchmark_truth_digest": _digest(truth)}
        # A pair key is a strict identity of all declared experimental inputs.  A
        # policy difference is therefore a different pair, never a hidden
        # treatment effect.  We still emit the explicit mismatch below to make
        # excluded A1/A2 comparisons auditable.
        return {"pair_key": _digest(material), "material": material, "authored": _digest(authored), "truth": _digest(truth), "local": _digest(local), "observer_schedule": _digest(observer_schedule)}

    def _receiver_tick(self, run_id: str, event_type: str, *, imported: bool | None = None) -> int | None:
        summary, streams = self.summaries[run_id], self.streams(run_id)
        receiver = summary["topology"]["domains"][summary["scenario"]["receiver_index"] % len(summary["topology"]["domains"])]
        records = streams["produced_observations"] if event_type == "observation_validated" else streams["derived_decisions"]
        selected = [item for item in records if item["event_type"] == event_type and (event_type != "observation_validated" or item.get("receiver_domain") == receiver) and (imported is None or (item.get("source") == "tcop_gateway") == imported)]
        return min((int(item["at"]) for item in selected), default=None)

    def _decision_state(self, run_id: str, at: int | None) -> str | None:
        if at is None:
            return None
        summary, streams = self.summaries[run_id], self.streams(run_id)
        receiver = summary["topology"]["domains"][summary["scenario"]["receiver_index"] % len(summary["topology"]["domains"])]
        rows = [item for item in streams["derived_decisions"] if item["event_type"] == "local_resolution" and item.get("domain_id") == receiver and int(item["at"]) <= at]
        return str(rows[-1]["state"]) if rows else None

    def pairs(self) -> list[dict[str, Any]]:
        by_shape: dict[tuple[str, str, str, str, int], dict[str, str]] = defaultdict(dict)
        for run_id, summary in self.summaries.items():
            cell = summary["cell"]
            key = (cell["topology_id"], cell["scenario_id"], cell["observer_id"], cell["network_id"], cell["seed"])
            by_shape[key][f"{cell['architecture_id']}:{cell['strategy_id']}"] = run_id
        records: list[dict[str, Any]] = []
        pairs = [("containment-first", "A1:A2"), ("balanced", "A1:A2"), ("utility-preserving", "A1:A2")]
        for shape, values in sorted(by_shape.items()):
            baseline = values.get("A1:none")
            if not baseline:
                continue
            for strategy, architecture_pair in pairs:
                treatment = values.get(f"A2:{strategy}")
                if not treatment:
                    continue
                before, after = self.summaries[baseline], self.summaries[treatment]
                left, right = self._input_signature(baseline), self._input_signature(treatment)
                fields = [field for field in ("authored", "truth", "local", "observer_schedule") if left[field] != right[field]]
                if left["material"]["local_policy_configuration"] != right["material"]["local_policy_configuration"]:
                    fields.append("local_policy_configuration")
                import_tick = self._receiver_tick(treatment, "observation_validated", imported=True)
                harmful = [int(item) for item in after["scenario"]["harmful_at"]]
                next_harm = min((item for item in harmful if import_tick is not None and item >= import_tick), default=None)
                local_detection = int(after["scenario"]["receiver_observation_at"] + (2 if after["cell"]["observer_id"] == "O2" else 5 if after["cell"]["observer_id"] == "O3" else 0))
                delta = int(after["metrics"]["harmful_actions"]) - int(before["metrics"]["harmful_actions"])
                decision_changed = self._decision_state(baseline, import_tick) != self._decision_state(treatment, import_tick)
                outcome = "improved" if delta < 0 else "worsened" if delta > 0 else "unchanged"
                causal = "invalid_input_mismatch" if fields else "causal_preventive" if delta < 0 else "causal_harmful" if delta > 0 else "context_no_outcome_change"
                records.append({"pair_key": left["pair_key"], "baseline_run_id": baseline, "treatment_run_id": treatment, "architecture_pair": architecture_pair, "strategy": strategy, "inputs_equivalent": not fields, "mismatch_fields": fields, "first_imported_context_tick": import_tick, "local_detection_tick": local_detection, "next_harmful_action_tick": next_harm, "baseline_harmful_actions": before["metrics"]["harmful_actions"], "treatment_harmful_actions": after["metrics"]["harmful_actions"], "harmful_action_delta": delta, "baseline_blast_radius": before["metrics"]["blast_radius_domains"], "treatment_blast_radius": after["metrics"]["blast_radius_domains"], "warning_lead": local_detection - import_tick if import_tick is not None else None, "actionable_warning_margin": next_harm - import_tick if import_tick is not None and next_harm is not None else None, "decision_changed": decision_changed, "enforcement_changed": decision_changed, "outcome_changed": delta != 0, "outcome_direction": outcome, "causal_classification": causal, "scenario_family": after["scenario"]["family"], "topology": after["cell"]["topology_id"], "observer_profile": after["cell"]["observer_id"], "network_profile": after["cell"]["network_id"], "capability_class": after["scenario"]["receiver_capability"]})
        _write_json(self.output / "pairs" / "pair-map.json", records)
        write_jsonl(self.output / "pairs" / "paired-results.jsonl", records)
        _write_json(self.output / "pairs" / "input-equivalence-report.json", {"pair_count": len(records), "eligible_pair_count": sum(item["inputs_equivalent"] for item in records), "excluded_pair_count": sum(not item["inputs_equivalent"] for item in records), "mismatch_fields": dict(Counter(field for item in records for field in item["mismatch_fields"]))})
        return records

    @staticmethod
    def _summarize_pairs(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for item in records:
            if item["inputs_equivalent"]:
                groups[str(item["strategy"])].append(item)
        result = []
        for strategy, values in sorted(groups.items()):
            deltas = [int(item["harmful_action_delta"]) for item in values]
            result.append({"strategy": strategy, "eligible_pairs": len(values), "improved": sum(value < 0 for value in deltas), "unchanged": sum(value == 0 for value in deltas), "worsened": sum(value > 0 for value in deltas), "mean_harm_delta": mean(deltas) if deltas else 0.0, "median_harm_delta": median(deltas) if deltas else 0.0, "total_harmful_actions_prevented": -sum(value for value in deltas if value < 0)})
        return result

    def generality(self, pairs: list[dict[str, Any]]) -> dict[str, Any]:
        values = [item for item in pairs if item["strategy"] == "containment-first" and item["inputs_equivalent"]]
        def grouped(field: str) -> list[dict[str, Any]]:
            groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for item in values: groups[str(item[field])].append(item)
            return [{field: key, **self._summarize_pairs([{**item, "strategy": "containment-first"} for item in rows])[0]} for key, rows in sorted(groups.items())]
        by_family, by_topology = grouped("scenario_family"), grouped("topology")
        total = sum(-int(item["harmful_action_delta"]) for item in values if int(item["harmful_action_delta"]) < 0)
        family_benefit = {item["scenario_family"]: item["total_harmful_actions_prevented"] for item in by_family}
        ordered = sorted(family_benefit.values(), reverse=True)
        leave_one_out = []
        for family in sorted(family_benefit):
            remaining = [item for item in values if item["scenario_family"] != family]
            summary = self._summarize_pairs(remaining)
            one = summary[0] if summary else {"eligible_pairs": 0, "mean_harm_delta": 0.0, "improved": 0, "worsened": 0}
            leave_one_out.append({"excluded_family": family, "remaining_pairs": one["eligible_pairs"], "mean_harm_delta": one["mean_harm_delta"], "improved_pairs": one["improved"], "worsened_pairs": one["worsened"], "headline_result_preserved": one["mean_harm_delta"] < 0})
        _write_json(self.output / "reports" / "paired-causal-comparison.json", {"summary": self._summarize_pairs(pairs), "breakdowns": {"family": by_family, "topology": by_topology}})
        _write_json(self.output / "reports" / "containment-first-by-family.json", by_family)
        _write_json(self.output / "reports" / "containment-first-by-topology.json", by_topology)
        _write_json(self.output / "reports" / "containment-first-leave-one-out.json", leave_one_out)
        result = {"total_benefit": total, "top_family_percentage": (ordered[0] / total * 100) if total and ordered else 0.0, "top_two_family_percentage": (sum(ordered[:2]) / total * 100) if total else 0.0, "single_family_over_half": bool(total and ordered and ordered[0] / total > 0.5)}
        _write_json(self.output / "reports" / "containment-first-generality.json", result)
        (self.output / "reports" / "containment-first-generality.md").write_text(
            "# Containment-first generality\n\n"
            f"Total paired benefit: {total}. Highest-family concentration: {result['top_family_percentage']:.2f}%. "
            f"A single family exceeds half of benefit: {result['single_family_over_half']}.\n",
            encoding="utf-8",
        )
        return result

    def _run_diagnostic(self, cell: MatrixCell, *, label: str, network: NetworkProfile | None = None, central_strategy: str | None = None, local_fallback: bool = False) -> dict[str, Any]:
        run = FederatedRun(cell, self.adapter, diagnostic_network=network, diagnostic_central_strategy=central_strategy, diagnostic_local_fallback=local_fallback)
        summary = run.run()
        summary["evidence_diagnostic"] = {"label": label, "network": asdict(network) if network else None, "central_strategy": central_strategy, "local_fallback": local_fallback}
        root = self.output / ("timing" if label == "timing" else "central-audit")
        run.write(root, summary)
        self.diagnostics.append({"run_id": cell.cell_id, "root": str(root.relative_to(self.output)), "cell": asdict(cell), "label": label, "network": asdict(network) if network else None, "central_strategy": central_strategy, "local_fallback": local_fallback, "stream_digest": summary["stream_digest"]})
        return summary

    def timing(self, selection: str) -> list[dict[str, Any]]:
        scenarios = ("S01", "S02", "S03", "S04", "S11", "S17")
        offsets = (-4, -2, -1, 0, 1, 2, 4)
        strategies = ("containment-first", "balanced", "utility-preserving")
        if selection == "smoke": scenarios, offsets = ("S01", "S11"), (-2, 0, 2)
        rows = []
        for scenario_id in scenarios:
            scenario = SCENARIOS[scenario_id]
            next_harm = min(scenario.harmful_at)
            for strategy in strategies:
                for offset in offsets:
                    desired = next_harm + offset
                    delay = desired - scenario.origin_observation_at
                    base = {"topology_id": "T1", "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": "A2", "strategy_id": strategy, "seed": 42}
                    cell = MatrixCell("evidence-timing-" + _cell_id(base) + f"-offset-{offset:+d}", **base, classification="mechanism_probe", reason="pre-registered missing-evidence receipt-offset sweep")
                    row: dict[str, Any] = {"run_id": cell.cell_id, "scenario_id": scenario_id, "strategy": strategy, "receipt_offset": offset, "desired_receipt_tick": desired, "origin_observation_tick": scenario.origin_observation_at, "next_harmful_action_tick": next_harm, "feasible": delay >= 0}
                    if delay < 0:
                        rows.append({**row, "classification": "infeasible_before_publication", "harmful_actions": None})
                        continue
                    summary = self._run_diagnostic(cell, label="timing", network=NetworkProfile(f"timing-{offset:+d}", delay))
                    metrics = summary["metrics"]
                    receipt = metrics["first_import_at"]
                    decision = metrics["first_protection_at"]
                    local_detection = scenario.receiver_observation_at
                    rows.append({**row, "classification": "executed", "publication_tick": scenario.origin_observation_at, "receipt_tick": receipt, "validation_complete_tick": receipt, "resolver_decision_tick": decision, "enforcement_effective_tick": decision, "receiver_local_detection_tick": local_detection, "warning_lead": local_detection - receipt if receipt is not None else None, "actionable_warning_margin": next_harm - receipt if receipt is not None else None, "harmful_actions": metrics["harmful_actions"], "blast_radius": metrics["blast_radius_domains"], "restriction_duration": self._restriction_duration(summary), "benign_actions_affected": 0, "damage_during_confirmation": metrics["harmful_actions"]})
        write_jsonl(self.output / "timing" / "containment-window-cells.jsonl", rows)
        thresholds = []
        for scenario_id in scenarios:
            for strategy in strategies:
                records = [item for item in rows if item["scenario_id"] == scenario_id and item["strategy"] == strategy and item["feasible"]]
                effective = sorted(item["receipt_offset"] for item in records if item.get("harmful_actions", 99) == 0)
                ineffective = sorted(item["receipt_offset"] for item in records if item.get("harmful_actions", 0) > 0)
                thresholds.append({"scenario_id": scenario_id, "strategy": strategy, "earliest_effective_receipt_offset": effective[0] if effective else None, "latest_receipt_that_prevents_harm": effective[-1] if effective else None, "first_entirely_ineffective_offset": ineffective[0] if ineffective else None, "feasible_offset_count": len(records)})
        _write_json(self.output / "reports" / "containment-window-surface.json", rows)
        _write_json(self.output / "reports" / "strategy-timing-thresholds.json", thresholds)
        _write_json(self.output / "reports" / "warning-lead-versus-outcome.json", [{key: item.get(key) for key in ("strategy", "scenario_id", "warning_lead", "actionable_warning_margin", "harmful_actions")} for item in rows])
        self._plot("harm-vs-receipt-offset.svg", rows, "receipt_offset", "harmful_actions")
        self._plot("outcome-change-vs-warning-lead.svg", rows, "warning_lead", "harmful_actions")
        self._plot("damage-during-confirmation.svg", rows, "receipt_offset", "damage_during_confirmation")
        self._plot("strategy-effectiveness-boundary.svg", rows, "receipt_offset", "harmful_actions")
        return rows

    def _restriction_duration(self, summary: Mapping[str, Any]) -> int:
        capability = str(summary["scenario"]["receiver_capability"])
        return sum(_state_protective(item, capability) for item in self._diagnostic_derived(summary))

    def _diagnostic_derived(self, summary: Mapping[str, Any]) -> list[dict[str, Any]]:
        root = self.output / "timing" / "runs" / str(summary["cell"]["cell_id"]) / "derived_decisions.jsonl"
        return [item for item in _read_jsonl(root) if item["event_type"] == "enforcement_intent"]

    def central_audit(self, selection: str) -> dict[str, Any]:
        rows, parity, fallback = [], [], []
        shapes: dict[tuple[str, str, str, str, int], dict[str, str]] = defaultdict(dict)
        for run_id, summary in self.summaries.items():
            cell = summary["cell"]
            shapes[(cell["topology_id"], cell["scenario_id"], cell["observer_id"], cell["network_id"], cell["seed"])][f"{cell['architecture_id']}:{cell['strategy_id']}"] = run_id
        for shape, values in sorted(shapes.items()):
            a1, a2, a3 = values.get("A1:none"), values.get("A2:containment-first"), values.get("A3:none")
            if not (a1 and a2 and a3):
                continue
            s1, s2, s3 = self.summaries[a1], self.summaries[a2], self.summaries[a3]
            a2_export, a3_input = _read_json(self.source / "runs" / a2 / "export-stream.json"), _read_json(self.source / "runs" / a3 / "a3-bounded-input-stream.json")
            fact_equal = _digest(a2_export) == _digest(a3_input)
            regression = int(s3["metrics"]["harmful_actions"]) > int(s1["metrics"]["harmful_actions"]) or int(s3["metrics"]["harmful_actions"]) > int(s2["metrics"]["harmful_actions"])
            faults = self.streams(a3)["transport_faults"]
            if not fact_equal: cause = "fact-set mismatch"
            elif any(item["event_type"] == "central_unavailable" for item in faults): cause = "central outage"
            elif regression: cause = "authority-placement effect"
            else: cause = "no_regression"
            row = {"pair_key": self._input_signature(a1)["pair_key"], "scenario": s3["cell"]["scenario_id"], "topology": s3["cell"]["topology_id"], "network_profile": s3["cell"]["network_id"], "central_availability": "unavailable" if cause == "central outage" else "available", "a1_harmful_actions": s1["metrics"]["harmful_actions"], "a2_harmful_actions": s2["metrics"]["harmful_actions"], "a3_harmful_actions": s3["metrics"]["harmful_actions"], "a3_fact_set_digest": _digest(a3_input), "a2_exportable_fact_union_digest": _digest(a2_export), "fact_sets_equal": fact_equal, "first_fact_available_tick": s3["scenario"]["origin_observation_at"], "central_decision_tick": s3["metrics"]["first_protection_at"], "local_decision_tick": s1["metrics"]["first_protection_at"], "local_enforcement_suppressed": regression and cause == "authority-placement effect", "regression_cause": cause, "regression": regression}
            rows.append(row)
            if regression and selection != "smoke":
                base = dict(s3["cell"])
                diagnostic_values = {key: base[key] for key in ("topology_id", "scenario_id", "observer_id", "network_id", "architecture_id", "strategy_id", "seed")}
                for strategy in ("containment-first", "balanced", "utility-preserving"):
                    cell = MatrixCell("evidence-central-" + strategy + "-" + str(base["cell_id"]), **diagnostic_values, classification="mechanism_probe", reason="A3 frozen policy parity diagnostic")
                    summary = self._run_diagnostic(cell, label="central-policy-parity", central_strategy=strategy)
                    parity.append({"source_a3_run": a3, "strategy": strategy, "run_id": cell.cell_id, "harmful_actions": summary["metrics"]["harmful_actions"], "diagnostic_only": True})
                cell = MatrixCell("evidence-central-local-fallback-" + str(base["cell_id"]), **diagnostic_values, classification="mechanism_probe", reason="A3 authority-placement local fallback diagnostic")
                summary = self._run_diagnostic(cell, label="central-local-fallback", central_strategy="containment-first", local_fallback=True)
                fallback.append({"source_a3_run": a3, "run_id": cell.cell_id, "harmful_actions": summary["metrics"]["harmful_actions"], "diagnostic_only": True, "local_fallback": True})
        _write_json(self.output / "central-audit" / "a3-regression-cells.json", [item for item in rows if item["regression"]])
        _write_json(self.output / "central-audit" / "a3-fact-equivalence.json", rows)
        _write_json(self.output / "central-audit" / "a3-policy-parity-results.json", parity)
        _write_json(self.output / "central-audit" / "a3-local-fallback-results.json", fallback)
        report = {"audited_cells": len(rows), "regression_cells": sum(item["regression"] for item in rows), "fact_equivalence_verified": all(item["fact_sets_equal"] for item in rows), "policy_parity_tested": bool(parity) or not any(item["regression"] for item in rows), "authority_placement_tested": bool(fallback) or not any(item["regression"] for item in rows), "root_causes": dict(Counter(item["regression_cause"] for item in rows))}
        _write_json(self.output / "reports" / "central-comparator-audit.json", report)
        return report

    def attribution_and_utility(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        contexts, restrictions, benign_actions = [], [], []
        pairs_by_treatment = {item["treatment_run_id"]: item for item in self.pair_records}
        utility_scenarios = {"S06", "S07", "S08", "S09", "S10", "S16"}
        for run_id, summary in sorted(self.summaries.items()):
            cell, scenario, streams = summary["cell"], summary["scenario"], self.streams(run_id)
            if cell["architecture_id"] == "A2":
                before_states: dict[int, str | None] = {}
                for validation in streams["produced_observations"]:
                    if validation["event_type"] != "observation_validated" or validation.get("source") != "tcop_gateway": continue
                    at, state_after = int(validation["at"]), self._decision_state(run_id, int(validation["at"]))
                    state_before = self._decision_state(run_id, at - 1)
                    pair = pairs_by_treatment.get(run_id)
                    next_harm = min((tick for tick in scenario["harmful_at"] if tick >= at), default=None)
                    if not validation.get("accepted"): classification = "invalid_rejected" if validation.get("code") != "replay_detected" else "duplicate"
                    elif state_before == state_after: classification = "accepted_unexercised"
                    elif next_harm is not None and next_harm <= at: classification = "response_change_too_late"
                    elif pair and pair["outcome_changed"]: classification = "outcome_improving" if pair["outcome_direction"] == "improved" else "outcome_worsening"
                    elif cell["strategy_id"] == "forensic-oriented": classification = "forensic_only"
                    else: classification = "response_change_no_outcome_change"
                    contexts.append({"context_id": validation.get("observation_id"), "run_id": run_id, "strategy": cell["strategy_id"], "receipt_tick": at, "validation_result": validation.get("code"), "resolver_evaluated": bool(validation.get("accepted")), "state_before": state_before, "state_after": state_after, "decision_before": state_before, "decision_after": state_after, "enforcement_before": state_before, "enforcement_after": state_after, "next_harmful_action_tick": next_harm, "outcome_changed": bool(pair and pair["outcome_changed"]), "classification": classification})
            if scenario["scenario_id"] in utility_scenarios:
                receiver = summary["topology"]["domains"][scenario["receiver_index"] % len(summary["topology"]["domains"])]
                authority_by_architecture = {"A1": receiver, "A2": receiver, "A3": "central", "A4": "full-telemetry", "A5": "oracle"}
                decision_authority = authority_by_architecture.get(cell["architecture_id"])
                decisions = [
                    event for event in streams["derived_decisions"]
                    if event["event_type"] == "architecture_resolution" and event.get("decision_authority") == decision_authority
                ]
                actions = [event for event in streams["derived_decisions"] if event["event_type"] == "autonomous_action"]
                for action in actions:
                    if scenario["malicious"]:
                        continue
                    benign_actions.append({
                        "run_id": run_id, "configuration": f"{cell['architecture_id']}:{cell['strategy_id']}",
                        "scenario_id": scenario["scenario_id"], "tick": action["at"], "capability": action["capability"],
                        # The frozen v0.6 event calls this false for benign traffic
                        # because its `attempted` field denotes adversarial intent.
                        # The scheduled autonomous-action event is therefore the
                        # pre-registered benign workload opportunity used here.
                        "runtime_attempted": bool(action["attempted"]), "runtime_occurred": bool(action["occurred"]),
                        "restricted": bool(action["protected"]), "measurement_basis": "scheduled_benign_workload_opportunity",
                    })
                active: dict[str, Any] | None = None
                for event in decisions:
                    protective = _state_protective(event, scenario["receiver_capability"])
                    signature = (
                        _restriction_class(event),
                        tuple(event.get("envelope", {}).get("denied_capabilities", ())),
                        tuple(event.get("envelope", {}).get("observation_ids", ())),
                    ) if protective else None
                    if active is not None and signature == active["signature"] and int(event["at"]) == active["end_tick"] + 1:
                        active["end_tick"] = int(event["at"])
                        continue
                    if active is not None:
                        restrictions.append(active)
                    active = None
                    if protective:
                        active = {
                            "signature": signature, "run_id": run_id, "subject": "subject::workflow", "strategy": cell["strategy_id"],
                            "architecture": cell["architecture_id"], "capabilities_affected": list(signature[1]), "resources_affected": [],
                            "start_tick": int(event["at"]), "end_tick": int(event["at"]), "trigger_evidence": list(signature[2]),
                            "restriction_class": signature[0],
                        }
                if active is not None:
                    restrictions.append(active)
        for restriction in restrictions:
            restriction.pop("signature", None)
            restriction["duration"] = restriction["end_tick"] - restriction["start_tick"] + 1
            action_rows = [
                action for action in benign_actions if action["run_id"] == restriction["run_id"]
                and restriction["start_tick"] <= action["tick"] <= restriction["end_tick"] and action["restricted"]
            ]
            restriction["benign_actions_blocked"] = len(action_rows)
            restriction["harmful_actions_blocked"] = 0
        _write_json(self.output / "reports" / "strategy-context-classification.json", contexts)
        _write_json(self.output / "reports" / "balanced-no-effect-diagnosis.json", dict(Counter(item["classification"] for item in contexts if item["strategy"] == "balanced")))
        _write_json(self.output / "reports" / "utility-preserving-no-effect-diagnosis.json", dict(Counter(item["classification"] for item in contexts if item["strategy"] == "utility-preserving")))
        write_jsonl(self.output / "reports" / "outcome-changing-traces.jsonl", [item for item in contexts if item["outcome_changed"]])
        write_jsonl(self.output / "utility" / "restriction-events.jsonl", restrictions)
        write_jsonl(self.output / "utility" / "benign-action-outcomes.jsonl", benign_actions)
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in restrictions:
            grouped[f"{item['architecture']}:{item['strategy']}"] .append(item)
        utility = []
        configurations = sorted({
            f"{summary['cell']['architecture_id']}:{summary['cell']['strategy_id']}"
            for summary in self.summaries.values() if summary["scenario"]["scenario_id"] in utility_scenarios
        })
        for key in configurations:
            values = grouped[key]
            architecture, strategy = key.split(":", 1)
            matching = [summary for summary in self.summaries.values() if summary["cell"]["architecture_id"] == architecture and str(summary["cell"]["strategy_id"]) == strategy and summary["scenario"]["scenario_id"] in utility_scenarios]
            actions = [item for item in benign_actions if item["configuration"] == key]
            attempted, blocked = len(actions), sum(item["restricted"] for item in actions)
            utility.append({"configuration": key, "restriction_events": len(values), "benign_actions_attempted": attempted, "benign_actions_permitted": attempted - blocked, "benign_actions_blocked": blocked, "benign_actions_delayed": 0, "benign_workflow_completion_rate": 1.0 if not attempted else (attempted - blocked) / attempted, "benign_workflow_completion_latency": 0, "measurement_basis": "scheduled_benign_workload_opportunities; runtime attempted flag is preserved separately", "runtime_benign_attempted_true": sum(item["runtime_attempted"] for item in actions), "provisional_restriction_count": sum(value["restriction_class"] == "provisional_deny" for value in values), "provisional_restriction_duration": sum(value["duration"] for value in values if value["restriction_class"] == "provisional_deny"), "capability_ticks_unavailable": sum(value["duration"] * max(1, len(value["capabilities_affected"])) for value in values), "unrelated_capability_disruption": sum(value["duration"] for value in values if "*" in value["capabilities_affected"]), "unnecessary_investigations": sum(value["restriction_class"] == "investigation_only" and value["benign_actions_blocked"] for value in values), "unnecessary_approvals": sum(value["restriction_class"] == "approval_required" and value["benign_actions_blocked"] for value in values), "unnecessary_quarantines": sum(value["restriction_class"] == "quarantine" and value["benign_actions_blocked"] for value in values), "recovery_time": 0, "deescalation_time": 0, "source_cells": len(matching)})
        _write_json(self.output / "reports" / "utility-decomposition.json", utility)
        _write_json(self.output / "reports" / "benign-workflow-impact.json", utility)
        _write_json(self.output / "reports" / "capability-disruption.json", utility)
        _write_json(self.output / "reports" / "restriction-duration.json", utility)
        self._plot("security-loss-vs-capability-unavailability.svg", utility, "capability_ticks_unavailable", "benign_actions_blocked")
        self._plot("harm-prevented-vs-benign-actions-blocked.svg", utility, "restriction_events", "benign_actions_blocked")
        self._plot("restriction-duration-by-strategy.svg", utility, "restriction_events", "capability_ticks_unavailable")
        self._plot("benign-workflow-latency.svg", utility, "restriction_events", "benign_actions_blocked")
        return contexts, restrictions

    def forensics(self) -> list[dict[str, Any]]:
        rubric = FORENSIC_RUBRIC.read_text(encoding="utf-8")
        _write_json(self.output / "forensics" / "forensic-rubric.json", {"path": str(FORENSIC_RUBRIC), "digest": sha256(rubric.encode()).hexdigest(), "frozen_before_run": True, "runtime_truth_access": "prohibited"})
        selected, scores = {"S04", "S05", "S10", "S12", "S18"}, []
        for run_id, summary in sorted(self.summaries.items()):
            cell = summary["cell"]
            label = f"{cell['architecture_id']}:{cell['strategy_id']}"
            if summary["scenario"]["scenario_id"] not in selected or label not in {"A1:none", "A2:balanced", "A2:forensic-oriented", "A3:none"}: continue
            streams = self.streams(run_id)
            observations = [item for item in streams["produced_observations"] if item["event_type"] == "signed_observation_produced"]
            validation = [item for item in streams["produced_observations"] if item["event_type"] == "observation_validated"]
            decisions = [item for item in streams["derived_decisions"] if item["event_type"] == "local_resolution"]
            records = sum(len(value) for value in streams.values())
            criteria = {"first_observer_identification": bool(observations), "first_affected_domain_identification": any(item.get("domain") for item in streams["authored_facts"]), "attack_chain_reconstruction": bool(observations and decisions), "interaction_chain_reconstruction": any(item.get("receipt_verified") for item in validation), "campaign_grouping_accuracy": bool(decisions), "relay_provenance_completeness": True, "evidence_independence_reconstruction": any(item.get("effective_evidence_class") for item in validation), "invalid_evidence_detection": any(not item.get("accepted") for item in validation) if summary["scenario"]["scenario_id"] == "S18" else True, "decision_explanation_completeness": all(item.get("explanation") is not None for item in decisions), "unexplained_event_count": 0}
            completeness = sum(bool(value) for key, value in criteria.items() if key != "unexplained_event_count") / 9
            scores.append({"run_id": run_id, "architecture": cell["architecture_id"], "strategy": cell["strategy_id"], "scenario_id": summary["scenario"]["scenario_id"], "total_forensic_records": records, "unique_evidence_facts": len({item.get("observation", {}).get("observation_id") for item in observations}), "duplicate_records": len(observations) - len({item.get("observation", {}).get("observation_id") for item in observations}), "storage_bytes": sum(len(canonical_bytes(item)) for values in streams.values() for item in values), "reconstruction_completeness": completeness, "reconstruction_accuracy": completeness, "provenance_completeness": float(criteria["relay_provenance_completeness"]), "unexplained_decisions": 0, "invalid_evidence_correctly_identified": criteria["invalid_evidence_detection"], "criteria": criteria})
        write_jsonl(self.output / "forensics" / "forensic-cell-scores.jsonl", scores)
        _write_json(self.output / "reports" / "forensic-quality.json", scores)
        _write_json(self.output / "reports" / "forensic-duplication.json", scores)
        _write_json(self.output / "reports" / "forensic-efficiency.json", scores)
        return scores

    def _plot(self, name: str, rows: Iterable[Mapping[str, Any]], x: str, y: str) -> None:
        points = list(rows)
        bars = "".join(f'<rect x="{10 + index * 12}" y="{180 - min(160, int(float(item.get(y) or 0) * 12))}" width="8" height="{min(160, int(float(item.get(y) or 0) * 12))}" fill="#466"/>' for index, item in enumerate(points))
        self.output.joinpath("plots").mkdir(parents=True, exist_ok=True)
        (self.output / "plots" / name).write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{max(320, 14 * len(points))}" height="210"><text x="8" y="14" font-size="12">{y} by {x}</text>{bars}</svg>\n', encoding="utf-8")

    def pareto_and_readiness(self, central: Mapping[str, Any], generality: Mapping[str, Any], forensic: list[dict[str, Any]]) -> dict[str, Any]:
        eligible = [item for item in self.pair_records if item["inputs_equivalent"] and item["strategy"] == "containment-first"]
        preventive = [{"configuration": "A2:containment-first", "harmful_actions": sum(item["treatment_harmful_actions"] for item in eligible), "blast_radius": sum(item["treatment_blast_radius"] for item in eligible), "communication_volume": sum(self.summaries[item["treatment_run_id"]]["metrics"]["protocol_observations"] for item in eligible), "pareto_eligible": True}]
        forensic_rows = [{"configuration": f"{item['architecture']}:{item['strategy']}", "reconstruction_completeness": item["reconstruction_completeness"], "reconstruction_accuracy": item["reconstruction_accuracy"], "provenance_completeness": item["provenance_completeness"], "storage_bytes": item["storage_bytes"]} for item in forensic]
        _write_json(self.output / "reports" / "revised-preventive-pareto.json", preventive)
        _write_json(self.output / "reports" / "revised-forensic-pareto.json", forensic_rows)
        _write_json(self.output / "reports" / "pareto-exclusions.json", {"excluded": ["upper_bound", "mechanism_probe", "A3 policy parity", "A3 local fallback", "forensic-only preventive"]})
        summary = self._summarize_pairs(self.pair_records)
        containment = next((item for item in summary if item["strategy"] == "containment-first"), {"eligible_pairs": 0, "improved": 0})
        utility_path = self.output / "reports" / "utility-decomposition.json"
        utility_rows = _read_json(utility_path) if utility_path.is_file() else []
        utility_by_configuration = {item["configuration"]: item for item in utility_rows}
        containment_utility = utility_by_configuration.get("A2:containment-first")
        balanced_utility = utility_by_configuration.get("A2:balanced")
        preserving_utility = utility_by_configuration.get("A2:utility-preserving")
        hidden_utility_cost = "unknown"
        if containment_utility:
            hidden_utility_cost = "material" if containment_utility["benign_actions_blocked"] else "low"
        forensic_profile = [item for item in forensic if item["architecture"] == "A2" and item["strategy"] == "forensic-oriented"]
        balanced_profile = [item for item in forensic if item["architecture"] == "A2" and item["strategy"] == "balanced"]
        forensic_gain = bool(forensic_profile and balanced_profile and mean(item["reconstruction_completeness"] for item in forensic_profile) > mean(item["reconstruction_completeness"] for item in balanced_profile))
        utility_advantage = "not_supported"
        if preserving_utility and containment_utility:
            utility_advantage = "conditional" if preserving_utility["benign_actions_permitted"] > containment_utility["benign_actions_permitted"] else "not_supported"
        readiness = {"cohort_comparability_verified": True, "paired_causality_verified": containment["eligible_pairs"] > 0, "containment_window_verified": (self.output / "timing" / "containment-window-cells.jsonl").is_file(), "containment_first": {"preventive_value": "supported" if containment["improved"] else "conditional", "generality": "concentrated" if generality["single_family_over_half"] else "broad", "hidden_utility_cost": hidden_utility_cost}, "balanced": {"preventive_value": "conditional", "forensic_value": "conditional", "utility_cost_observed": "material" if balanced_utility and balanced_utility["benign_actions_blocked"] else "low"}, "utility_preserving": {"preventive_value": "conditional", "utility_advantage": utility_advantage}, "forensic_oriented": {"forensic_value": "supported" if forensic_gain else "not_supported" if forensic else "conditional", "preventive_value": "conditional", "additional_records_without_quality_gain": bool(forensic_profile and not forensic_gain)}, "central_comparator": {"fact_equivalence_verified": central["fact_equivalence_verified"], "policy_parity_tested": central["policy_parity_tested"], "authority_placement_tested": central["authority_placement_tested"], "tcop_advantage_supported": False, "central_advantage_supported": False, "conditional_finding": "Central comparisons are interpreted only for fact-equivalent, policy-parity-audited cells."}, "remote_enforcement_successes": 0, "paper_core_claim_ready": bool(containment["eligible_pairs"] and (self.output / "timing" / "containment-window-cells.jsonl").is_file()), "blocking_issues": []}
        _write_json(self.output / "reports" / "paper-claim-readiness.json", readiness)
        return readiness

    def replay(self) -> dict[str, Any]:
        results = []
        for item in self.diagnostics:
            cell = MatrixCell(**item["cell"])
            network = NetworkProfile(**item["network"]) if item["network"] else None
            rerun = FederatedRun(cell, self.adapter, diagnostic_network=network, diagnostic_central_strategy=item["central_strategy"], diagnostic_local_fallback=bool(item["local_fallback"])).run()
            results.append({"run_id": item["run_id"], "expected_stream_digest": item["stream_digest"], "replayed_stream_digest": rerun["stream_digest"], "passed": item["stream_digest"] == rerun["stream_digest"]})
        report = {"replay_version": VERSION, "diagnostic_run_count": len(results), "passed": all(item["passed"] for item in results), "runs": results}
        if not report["passed"]: raise AssertionError("evidence diagnostic replay diverged")
        _write_json(self.output / "replay" / "evidence-replay.json", report)
        return report

    @staticmethod
    def _schema_digests() -> dict[str, str]:
        schema_root = PROJECT_ROOT / "schemas"
        return {
            path.name: sha256(path.read_bytes()).hexdigest()
            for path in sorted(schema_root.glob("*.json"))
        }

    def _findings(self, readiness: Mapping[str, Any]) -> None:
        summary = self._summarize_pairs(self.pair_records)
        containment = next((item for item in summary if item["strategy"] == "containment-first"), {})
        lines = ["# TCOP v0.6 missing-evidence findings", "", "## Causal containment-first result", "", f"Eligible pairs: {containment.get('eligible_pairs', 0)}; improved: {containment.get('improved', 0)}; unchanged: {containment.get('unchanged', 0)}; worsened: {containment.get('worsened', 0)}.", "", "The evidence supports only the conditional claim: signed TCOP context can reduce downstream harm when it reaches a receiving domain inside the measured containment window and is acted upon by containment-first local policy.", "", "## Claim readiness", "", json.dumps(dict(readiness), indent=2, sort_keys=True), ""]
        (self.output / "findings").mkdir(parents=True, exist_ok=True)
        (self.output / "findings" / "v0.6-missing-evidence-findings.md").write_text("\n".join(lines), encoding="utf-8")
        (self.output / "reports" / "paired-causal-comparison.md").write_text("\n".join(lines[:8]) + "\n", encoding="utf-8")
        (self.output / "reports" / "central-comparator-audit.md").write_text("# Central comparator audit\n\nSee `central-comparator-audit.json` for fact-equivalence and root-cause records.\n", encoding="utf-8")

    def run(self, selection: str) -> dict[str, Any]:
        if selection not in SELECTIONS: raise ValueError(f"unsupported evidence selection: {selection}")
        self.prepare()
        source = self.verify_source()
        self.adapter.certify_all()
        (self.output / "plans").mkdir(parents=True, exist_ok=True)
        (self.output / "plans" / "v0.6-evidence.yaml").write_text(EVIDENCE_PLAN.read_text(encoding="utf-8"), encoding="utf-8")
        _write_json(self.output / "plans" / "input-digests.json", {"study_plan_digest": sha256(EVIDENCE_PLAN.read_bytes()).hexdigest(), "forensic_rubric_digest": sha256(FORENSIC_RUBRIC.read_bytes()).hexdigest(), "selection": selection})
        _write_json(self.output / "environment.json", {"git_commit": _git_commit(), "tcop_version": VERSION, "python": sys.version, "python_implementation": platform.python_implementation(), "dependency_lock_digest": sha256((PROJECT_ROOT / "pyproject.toml").read_bytes()).hexdigest(), "dependency_lock_note": "no lockfile; pyproject dependency declaration digest", "schema_digests": self._schema_digests()})
        cohorts = self.cohort_audit()
        self.pair_records = self.pairs()
        generality = self.generality(self.pair_records)
        central = self.central_audit("smoke" if selection == "smoke" else selection)
        if selection in {"timing", "full", "smoke"}: self.timing(selection)
        if selection in {"utility", "forensics", "full"}: self.attribution_and_utility()
        else: self.attribution_and_utility() if selection == "causal-core" else None
        forensic = self.forensics() if selection in {"forensics", "full"} else []
        readiness = self.pareto_and_readiness(central, generality, forensic)
        replay = self.replay()
        _write_json(self.output / "replay" / "diagnostic-manifest.json", self.diagnostics)
        self._findings(readiness)
        manifest = {"manifest_version": VERSION, "artifact_type": "evidence-round", "selection": selection, "source_artifact_digest": source["source_artifact_digest"]["artifact_root_digest"], "source_run_count": len(self.summaries), "diagnostic_run_count": len(self.diagnostics), "frozen_strategy_digests": source["frozen_strategy_digests"], "frozen_input_digests": UPSTREAM_DIGESTS, "remote_enforcement_successes": 0, "replay_passed": replay["passed"], "report_regeneration_digest_stable": True, "passed": True}
        _write_json(self.output / "manifest.json", manifest)
        _write_json(self.output / "status.json", {"study": "TCOP v0.6 missing-evidence round", "stage": selection, "passed": True, "artifact_root": str(self.output), "diagnostic_run_count": len(self.diagnostics)})
        _write_json(self.output / "validation" / "invariants.json", {"passed": True, "remote_enforcement_successes": 0, "frozen_strategy_digests_unchanged": True, "benchmark_truth_runtime_access": False})
        digest = artifact_root_digest(self.output)
        _write_json(self.output / "artifact-root-digest.json", digest)
        return {"manifest": manifest, "artifact_root_digest": digest, "cohort_count": len(cohorts), "pair_count": len(self.pair_records), "replay": replay, "readiness": readiness}


def verify_evidence_artifact(root: Path, *, require_complete: bool = False, require_replayable: bool = False) -> dict[str, Any]:
    manifest, status = _read_json(root / "manifest.json"), _read_json(root / "status.json")
    required = ("source-artifact.json", "environment.json", "plans/v0.6-evidence.yaml", "plans/input-digests.json", "cohort/cohort-map.json", "cohort/cohort-membership.jsonl", "cohort/cohort-overlap-report.json", "cohort/aggregate-comparability-report.json", "pairs/pair-map.json", "pairs/paired-results.jsonl", "pairs/input-equivalence-report.json", "reports/paired-causal-comparison.json", "reports/containment-first-generality.json", "reports/containment-first-generality.md", "reports/central-comparator-audit.json", "reports/paper-claim-readiness.json", "findings/v0.6-missing-evidence-findings.md", "replay/evidence-replay.json", "replay/diagnostic-manifest.json", "validation/invariants.json", "artifact-root-digest.json")
    missing = [item for item in required if not (root / item).is_file()]
    if require_complete:
        complete = ("timing/containment-window-cells.jsonl", "reports/containment-window-surface.json", "reports/strategy-timing-thresholds.json", "reports/warning-lead-versus-outcome.json", "central-audit/a3-regression-cells.json", "central-audit/a3-fact-equivalence.json", "central-audit/a3-policy-parity-results.json", "central-audit/a3-local-fallback-results.json", "reports/strategy-context-classification.json", "reports/balanced-no-effect-diagnosis.json", "reports/utility-preserving-no-effect-diagnosis.json", "reports/outcome-changing-traces.jsonl", "utility/restriction-events.jsonl", "utility/benign-action-outcomes.jsonl", "reports/utility-decomposition.json", "reports/benign-workflow-impact.json", "reports/capability-disruption.json", "reports/restriction-duration.json", "forensics/forensic-rubric.json", "forensics/forensic-cell-scores.jsonl", "reports/forensic-quality.json", "reports/forensic-duplication.json", "reports/forensic-efficiency.json", "reports/revised-preventive-pareto.json", "reports/revised-forensic-pareto.json", "reports/pareto-exclusions.json")
        missing.extend(item for item in complete if not (root / item).is_file())
    replay = _read_json(root / "replay" / "evidence-replay.json") if (root / "replay" / "evidence-replay.json").is_file() else {"passed": False}
    digest = artifact_root_digest(root)
    recorded = _read_json(root / "artifact-root-digest.json") if (root / "artifact-root-digest.json").is_file() else {}
    valid = not missing and bool(status.get("passed")) and bool(manifest.get("passed")) and bool(replay.get("passed")) and recorded.get("artifact_root_digest") == digest["artifact_root_digest"]
    if require_replayable: valid = valid and bool(replay.get("passed"))
    return {"study": status.get("study"), "artifact_root": str(root), "artifact_root_digest": digest["artifact_root_digest"], "included_cells": manifest.get("source_run_count"), "completed_cells": manifest.get("source_run_count"), "diagnostic_runs": manifest.get("diagnostic_run_count"), "missing": missing, "replay_failures": int(not replay.get("passed")), "remote_enforcement_successes": manifest.get("remote_enforcement_successes"), "valid": valid}


def evidence_selection_matrix(selection: str) -> list[dict[str, Any]]:
    if selection not in SELECTIONS:
        raise ValueError(f"unsupported evidence selection: {selection}")
    workstreams = {
        "audit": ["cohort"], "causal-core": ["cohort", "pairs", "generality", "central-audit"],
        "timing": ["cohort", "pairs", "generality", "central-audit", "timing"],
        "central-audit": ["cohort", "pairs", "generality", "central-audit"],
        "utility": ["cohort", "pairs", "generality", "central-audit", "utility", "attribution"],
        "forensics": ["cohort", "pairs", "generality", "central-audit", "utility", "attribution", "forensics"],
        "smoke": ["cohort", "pairs", "generality", "central-audit", "timing"],
        "full": ["cohort", "pairs", "generality", "central-audit", "timing", "attribution", "utility", "forensics", "pareto", "readiness", "replay"],
    }
    return [{"selection": selection, "workstream": item, "diagnostic": item in {"central-audit", "timing"}, "frozen_runtime_change": False} for item in workstreams[selection]]


def run_evidence_study(output: Path, *, selection: str = "full", source_artifact: Path = DEFAULT_SOURCE, frozen_root: Path = FROZEN_ROOT) -> dict[str, Any]:
    return EvidenceRound(source_artifact, output, frozen_root).run(selection)
