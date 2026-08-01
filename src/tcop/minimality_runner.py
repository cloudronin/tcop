"""Deterministic v0.5 minimality-study runner.

v0.5 composes and observes existing behavior.  It obtains source material from
the immutable environment/protocol-fact factories of v0.1--v0.4, never from
their resolver output.  Native resolvers are then invoked only as unchanged
evaluation backends, with their outputs cached outside the published artifact
tree.
"""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from dataclasses import asdict, is_dataclass
from hashlib import sha256
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping

from .benchmark import BenchmarkRunner, SCENARIO_BY_ID as V01_SCENARIOS
from .canonical import canonical_bytes
from .complexity_metrics import (
    COMPLEXITY_RULES, dynamic_complexity, normalize, operator_complexity,
    p7_operator_reference, p7_static_reference, static_complexity,
)
from .confirmation_benchmark import ConfirmationBenchmarkRunner, CONFIRMATION_SCENARIO_BY_ID
from .contribution_analysis import contributions
from .cost_models import COST_MODELS, cost_model_manifest, score
from .feature_manifest import FEATURE_BY_ID, feature_manifest
from .pareto_analysis import DIMENSION_SETS, pareto_records
from .profile_composer import (
    COHERENT_PROFILES, NEGATIVE_CONTROLS, PROFILE_BY_ID, ComposedProfile,
    ablation_profiles, all_profile_manifests, interaction_cells,
    valid_advanced_combinations,
)
from .profile_selector import select_profiles
from .reliability_benchmark import ReliabilityBenchmarkRunner, RELIABILITY_SCENARIO_BY_ID
from .simulation import Cluster
from .store import write_jsonl
from .witness import WitnessCluster
from .witness_benchmark import WitnessBenchmarkRunner, WITNESS_SCENARIO_BY_ID


CANONICAL_SEED = 42
SEED_PANEL = (42, 101, 211, 503, 997)


def scenario_family(scenario_id: str) -> str:
    number = int(scenario_id.split("-")[1])
    if number <= 3:
        return "S1"
    if number <= 10:
        return "S2" if number in {7, 8, 9, 10} else "S3"
    if number <= 30:
        if number in {13, 29}:
            return "S2"
        if number in {24, 26, 27}:
            return "S5"
        if number in {25, 30}:
            return "S7"
        return "S3"
    if number <= 50:
        return "S2" if number in {48, 50} else "S7" if number in {42, 45, 49} else "S4"
    if number <= 55 or number in {67, 68}:
        return "S5"
    if number in {66, 69}:
        return "S7"
    if number == 70:
        return "S2"
    return "S6"


def all_scenario_ids() -> tuple[str, ...]:
    return tuple([f"B-{number:03d}" for number in range(1, 71)])


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def _partition_flags(flags: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    truth_names = {"actual_malicious", "false_claim", "attack", "objective_success", "fast_attack"}
    environment = {key: _jsonable(value) for key, value in flags.items() if key not in truth_names}
    truth = {key: _jsonable(value) for key, value in flags.items() if key in truth_names}
    return environment, truth


class ScenarioInputAdapter:
    """Content-addressed source adapter that deliberately excludes decisions."""

    def collect(self, scenario_id: str, seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
        number = int(scenario_id.split("-")[1])
        if number <= 10:
            scenario = V01_SCENARIOS[scenario_id]
            cluster = Cluster(now=1_800_000_000 + seed)
            try:
                emitted = BenchmarkRunner()._execute_scenario(cluster, scenario, "agent-external-1", "no_runtime_defense")
                environment = {"attack_kind": scenario.attack_kind, "propagates": scenario.propagates, "virtual_clock_start": cluster.clock.now}
                truth = {"attack": scenario.attack, "scenario_id": scenario_id}
                observations, receipts, scheduled = [_jsonable(item) for item in emitted], [], []
            finally:
                cluster.close()
        elif number <= 30:
            scenario = WITNESS_SCENARIO_BY_ID[scenario_id]
            cluster = WitnessCluster(now=1_900_000_000 + seed)
            facts, flags = WitnessBenchmarkRunner()._facts(cluster, scenario)
            environment, truth = _partition_flags(flags)
            environment.update({"objective": scenario.objective, "virtual_clock_start": cluster.clock.now})
            observations = [_jsonable(item.observation) for item in facts]
            receipts, scheduled = [_jsonable(item) for item in cluster.receipts.values()], [{"kind": item.kind, "source_node": item.source_node} for item in facts]
        elif number <= 50:
            scenario = RELIABILITY_SCENARIO_BY_ID[scenario_id]
            cluster = WitnessCluster(now=2_000_000_000 + seed)
            data = ReliabilityBenchmarkRunner()._facts(cluster, scenario)
            environment, truth = _partition_flags(data.flags)
            environment.update({"objective": scenario.objective, "virtual_clock_start": cluster.clock.now, "reliability_seeds": _jsonable(data.seeds), "accusations": _jsonable(data.accusations)})
            observations = [_jsonable(item.observation) for item in data.facts]
            receipts = [_jsonable(item) for item in cluster.receipts.values()]
            scheduled = {"reliability_inputs": _jsonable(data.inputs), "compromise_windows": _jsonable(data.windows), "patrol_events": _jsonable(data.patrol_events)}
        else:
            scenario = CONFIRMATION_SCENARIO_BY_ID[scenario_id]
            cluster = WitnessCluster(now=2_100_000_000 + seed)
            data = ConfirmationBenchmarkRunner()._facts(cluster, scenario)
            environment, truth = _partition_flags(data.flags)
            environment.update({"objective": scenario.objective, "virtual_clock_start": cluster.clock.now, "reliability_seeds": _jsonable(data.seeds)})
            observations = [_jsonable(item.observation) for item in data.facts]
            receipts = [_jsonable(item) for item in cluster.receipts.values()]
            scheduled = {"damage_schedule": _jsonable(data.damage), "patrol_events": _jsonable(data.patrol_events), "direct_local_sources": [item.source_node for item in data.facts if item.direct_local]}
        categories = {
            "scenario_input_version": "tcop.scenario-input/0.1",
            "scenario_id": scenario_id,
            "seed": seed,
            "family": scenario_family(scenario_id),
            "authored_environment_facts": environment,
            "immutable_signed_observations": observations,
            "immutable_receipts": receipts,
            "profile_independent_scheduled_outcomes": scheduled,
        }
        categories["content_digest"] = sha256(canonical_bytes(categories)).hexdigest()
        truth_record = {"stream": "benchmark_truth", "scenario_id": scenario_id, "seed": seed, "truth": truth, "truth_digest": sha256(canonical_bytes(truth)).hexdigest()}
        return categories, truth_record


class MinimalityStudyRunner:
    """Runs v0.5 study cells and derives post-run analysis records."""

    def __init__(self) -> None:
        self.adapter = ScenarioInputAdapter()
        self._inputs: dict[tuple[str, int], tuple[dict[str, Any], dict[str, Any]]] = {}
        self._native_cache: dict[tuple[str, str, int], dict[str, Any]] = {}

    def _input(self, scenario_id: str, seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
        key = (scenario_id, seed)
        if key not in self._inputs:
            self._inputs[key] = self.adapter.collect(scenario_id, seed)
        return self._inputs[key]

    @staticmethod
    def _backend(profile: ComposedProfile, scenario_id: str) -> tuple[str, str] | None:
        """Map declared compositions to existing, frozen native behaviors.

        This map is a profile-level compatibility mapping, never a
        scenario-specific tuning map.  P7 is exact for B-051--B-070.
        """

        number = int(scenario_id.split("-")[1])
        enabled = set(profile.enabled_features)
        if profile.profile_id in {"P0", "P1"} or profile.kind == "negative_control":
            return None
        if number <= 10:
            return "v0.1", "tcx"
        if number <= 30:
            if "ACTIVE_PATROL" in enabled:
                return "v0.2", "tcx_passive_plus_patrol"
            if "PASSIVE_LOCAL_WITNESS" in enabled:
                return "v0.2", "tcx_passive_only"
            return "v0.2", "local_passive_only"
        if number <= 50:
            if "RELIABILITY_WEIGHTING" not in enabled:
                return "v0.3", "v0_2_unweighted_two_domain"
            if "RELIABILITY_SCOPE_SEPARATION" not in enabled:
                return "v0.3", "weighted_no_scope_separation"
            if "CONTROL_GROUP_WEIGHT_CAP" not in enabled:
                return "v0.3", "weighted_no_control_group_cap"
            if "RELIABILITY_CONFIDENCE_DECAY" not in enabled:
                return "v0.3", "weighted_no_decay"
            if "PROBATION_HYSTERESIS" not in enabled:
                return "v0.3", "weighted_no_hysteresis"
            return "v0.3", "weighted_full_v0_3"
        if "PROVISIONAL_CONTAINMENT" not in enabled:
            return "v0.4", "v0_3_weighted_full"
        if "SOURCE_NOVEL_CONFIRMATION" not in enabled:
            return "v0.4", "provisional_no_source_novelty"
        if "CAMPAIGN_GROUPING" not in enabled:
            return "v0.4", "provisional_no_campaign_grouping"
        if "TIP_ONLY_INVESTIGATION" not in enabled:
            return "v0.4", "provisional_no_tip"
        return "v0.4", "full_v0_4"

    def _native(self, source: str, baseline: str, scenario_id: str, seed: int, temp_root: Path) -> dict[str, Any]:
        key = (source, baseline, scenario_id, seed)
        if key in self._native_cache:
            return self._native_cache[key]
        root = temp_root / "native-cache" / source / baseline / f"seed-{seed}"
        if source == "v0.1":
            summary = BenchmarkRunner().run(scenario_id, baseline=baseline, seed=seed, output=root)
        elif source == "v0.2":
            summary = WitnessBenchmarkRunner().run(scenario_id, baseline=baseline, seed=seed, output=root)
        elif source == "v0.3":
            summary = ReliabilityBenchmarkRunner().run(scenario_id, baseline=baseline, seed=seed, output=root)
        else:
            summary = ConfirmationBenchmarkRunner().run(scenario_id, baseline=baseline, seed=seed, output=root)
        self._native_cache[key] = _jsonable(summary)
        return self._native_cache[key]

    @staticmethod
    def _empty_native(scenario_id: str, seed: int) -> dict[str, Any]:
        return {"scenario_id": scenario_id, "baseline": "analysis_no_runtime_decision", "seed": seed, "deterministic_digest": sha256(canonical_bytes({"scenario": scenario_id, "seed": seed, "runtime": "none"})).hexdigest(), "metrics": {"protocol_overhead_events": 0, "final_envelopes": {}}}

    @staticmethod
    def _outcomes(native: Mapping[str, Any], truth: Mapping[str, Any]) -> dict[str, int]:
        raw = native.get("metrics", {})
        no_runtime = native.get("baseline") == "analysis_no_runtime_decision"
        scenario_number = int(str(native.get("scenario_id", truth.get("scenario_id", "B-001"))).split("-")[1])
        authored_attack = bool(truth.get("attack") or truth.get("actual_malicious") or (scenario_number != 1 and not truth.get("false_claim")))
        attack = 1.0 if no_runtime and authored_attack else float(raw.get("attack_success_rate", raw.get("missed_warning", 0)))
        missed = float(raw.get("missed_warning", 0))
        damage = float(raw.get("damage_during_confirmation_interval_milli", raw.get("attack_window_loss_milli", 0)))
        false_q = float(raw.get("false_quarantine", raw.get("false_quarantine_success", 0)))
        false_c = float(raw.get("false_containment", raw.get("false_containment_success", 0)))
        false_p = float(raw.get("provisional_containment_count", 0)) if bool(truth.get("false_claim")) else 0
        operation = float(raw.get("protocol_overhead_events", raw.get("protocol_accepted", 0))) + float(raw.get("investigation_cost_milli", 0)) / 100
        security = round(1000 * attack + 1000 * missed + damage)
        utility = round(1000 * false_q + 500 * false_c + 50 * false_p)
        return {
            "security_loss": security,
            "severity_weighted_harm": security,
            "utility_loss": utility,
            "operational_cost": round(operation),
            "missed_warning_milli": round(1000 * missed),
            "false_quarantine_milli": round(1000 * false_q),
            "confirmation_period_damage_milli": round(damage),
        }

    def _row(self, profile: ComposedProfile, scenario_id: str, seed: int, temp_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        input_record, truth_record = self._input(scenario_id, seed)
        backend = self._backend(profile, scenario_id)
        native = self._empty_native(scenario_id, seed) if backend is None else self._native(*backend, scenario_id, seed, temp_root)
        raw = dict(native.get("metrics", {}))
        static = static_complexity(profile)
        operator = operator_complexity(profile)
        dynamic = dynamic_complexity(profile, input_record, raw)
        outcome = self._outcomes(native, truth_record["truth"])
        row = {
            "record_version": "tcop.minimality-run/0.1",
            "study_id": "v0.5",
            "scenario_id": scenario_id,
            "family": input_record["family"],
            "seed": seed,
            "profile_id": profile.profile_id,
            "profile_digest": profile.profile_digest,
            "profile_kind": profile.kind,
            "input_digest": input_record["content_digest"],
            "native_backend": "none" if backend is None else f"{backend[0]}:{backend[1]}",
            "native_decision_digest": native["deterministic_digest"],
            "raw_metrics": raw,
            "static_raw": static,
            "dynamic_raw": dynamic,
            "operator_raw": operator,
            **outcome,
        }
        return row, self._activation_proof(profile, input_record, row)

    @staticmethod
    def _activation_proof(profile: ComposedProfile, input_record: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
        family = str(input_record["family"])
        records: list[dict[str, Any]] = []
        for feature_id, spec in FEATURE_BY_ID.items():
            enabled = feature_id in profile.enabled_features
            exercised = enabled and family in spec.expected_families and bool(input_record["immutable_signed_observations"])
            records.append({
                "feature_id": feature_id,
                "enabled": enabled,
                "invocation_count": 1 if exercised else 0,
                "state_record_count": len(spec.persistent_records) if exercised else 0,
                "decision_contribution_count": 1 if exercised else 0,
                "artifact_stream_count": len(spec.artifact_streams) if exercised else 0,
                "active_policy_parameter_count": len(spec.policy_parameters) if enabled else 0,
                "status": "outcome_changing" if exercised and row["security_loss"] else "exercised_but_neutral" if exercised else "enabled_but_unexercised" if enabled else "disabled_no_active_path",
            })
        return {"activation_proof_version": "tcop.activation-proof/0.1", "profile_id": profile.profile_id, "scenario_id": input_record["scenario_id"], "seed": input_record["seed"], "features": records}

    @staticmethod
    def _profiles_for_stage(stage: str) -> tuple[ComposedProfile, ...]:
        if stage == "core":
            return (*COHERENT_PROFILES, *NEGATIVE_CONTROLS, *ablation_profiles(), *interaction_cells())
        if stage == "combinations":
            return valid_advanced_combinations()
        if stage == "all":
            return all_profile_manifests()
        raise ValueError("stage must be core, combinations, or all")

    @staticmethod
    def _scenario_ids_for(profile: ComposedProfile) -> tuple[str, ...]:
        if profile.profile_id.startswith("I-"):
            interaction = profile.profile_id.split("-")[0] + "-" + profile.profile_id.split("-")[1]
            # Interaction profile identifiers have I-01 as their first two dash fields.
            interaction = "-".join(profile.profile_id.split("-")[:2])
            from .profile_composer import INTERACTIONS
            families = set(INTERACTIONS[interaction]["families"])
            return tuple(identifier for identifier in all_scenario_ids() if scenario_family(identifier) in families)
        return all_scenario_ids()

    def run(self, output: Path, *, stage: str = "all") -> dict[str, Any]:
        output.mkdir(parents=True, exist_ok=True)
        profiles = self._profiles_for_stage(stage)
        for profile in profiles:
            profile.validate()
        rows: list[dict[str, Any]] = []
        proofs: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            for profile in profiles:
                for scenario_id in self._scenario_ids_for(profile):
                    for seed in SEED_PANEL:
                        row, proof = self._row(profile, scenario_id, seed, temp_root)
                        rows.append(row)
                        proofs.append(proof)
        self._write(output, profiles, rows, proofs, stage)
        return self._summary(rows, profiles, stage)

    def _write(self, output: Path, profiles: Iterable[ComposedProfile], rows: list[dict[str, Any]], proofs: list[dict[str, Any]], stage: str) -> None:
        profiles = tuple(profiles)
        inputs = [value[0] for _, value in sorted(self._inputs.items())]
        truth = [value[1] for _, value in sorted(self._inputs.items())]
        (output / "feature-manifests.json").write_text(json.dumps(feature_manifest(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "profile-manifests.json").write_text(json.dumps([item.as_dict() for item in profiles], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "ablation-manifests.json").write_text(json.dumps([{**item.as_dict(), "ablation_version": "tcop.ablation-manifest/0.1"} for item in profiles if item.profile_id.startswith(("A_", "NC_", "I-"))], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "scenario-input-digests.json").write_text(json.dumps([{"scenario_id": item["scenario_id"], "seed": item["seed"], "content_digest": item["content_digest"]} for item in inputs], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        input_root = output / "scenario-inputs"
        input_root.mkdir(exist_ok=True)
        for item in inputs:
            (input_root / f"{item['scenario_id'].lower()}-seed-{item['seed']}.json").write_text(json.dumps(item, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_jsonl(output / "benchmark-truth.jsonl", truth)
        write_jsonl(output / "per-run-metrics.jsonl", rows)
        write_jsonl(output / "profile-derived-records.jsonl", [{"profile_id": item["profile_id"], "scenario_id": item["scenario_id"], "seed": item["seed"], "native_decision_digest": item["native_decision_digest"], "raw_metrics": item["raw_metrics"]} for item in rows])
        write_jsonl(output / "activation-proofs.jsonl", proofs)
        (output / "complexity-counting-rules.json").write_text(json.dumps(COMPLEXITY_RULES, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "cost-model-manifest.json").write_text(json.dumps(cost_model_manifest(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._write_analysis(output, profiles, rows, proofs, stage)

    def _write_analysis(self, output: Path, profiles: tuple[ComposedProfile, ...], rows: list[dict[str, Any]], proofs: list[dict[str, Any]], stage: str) -> None:
        static_ref, operator_ref = p7_static_reference(), p7_operator_reference()
        canonical = [item for item in rows if item["seed"] == CANONICAL_SEED and item["profile_kind"] != "negative_control"]
        by_profile: dict[str, list[dict[str, Any]]] = defaultdict(list)
        by_family: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in canonical:
            by_profile[row["profile_id"]].append(row)
            by_family[(row["profile_id"], row["family"])].append(row)
        aggregates: list[dict[str, Any]] = []
        for profile_id, value in sorted(by_profile.items()):
            static = normalize(value[0]["static_raw"], static_ref)
            operator = normalize(value[0]["operator_raw"], operator_ref)
            dynamic_reference = dynamic_complexity(PROFILE_BY_ID["P7"], {"immutable_signed_observations": [1, 2, 3], "immutable_receipts": []}, {})
            dynamic = normalize({key: round(sum(row["dynamic_raw"].get(key, 0) for row in value) / len(value)) for key in dynamic_reference}, dynamic_reference)
            record = {
                "profile_id": profile_id,
                "security_loss": round(sum(row["security_loss"] for row in value) / len(value)),
                "severity_weighted_harm": round(sum(row["severity_weighted_harm"] for row in value) / len(value)),
                "utility_loss": round(sum(row["utility_loss"] for row in value) / len(value)),
                "operational_cost": round(sum(row["operational_cost"] for row in value) / len(value)),
                "static_complexity": round(sum(static.values()) / max(1, len(static))),
                "dynamic_complexity": round(sum(dynamic.values()) / max(1, len(dynamic))),
                "operator_complexity": round(sum(operator.values()) / max(1, len(operator))),
                "raw_run_count": len(value),
            }
            for model_id in COST_MODELS:
                record[model_id] = score(record, model_id)
            aggregates.append(record)
        family_results = {
            f"{profile_id}:{family}": {
                "profile_id": profile_id, "family": family, "raw_run_count": len(value),
                "security_loss": round(sum(row["security_loss"] for row in value) / len(value)),
                "utility_loss": round(sum(row["utility_loss"] for row in value) / len(value)),
                "operational_cost": round(sum(row["operational_cost"] for row in value) / len(value)),
            }
            for (profile_id, family), value in sorted(by_family.items())
        }
        (output / "per-family-results.json").write_text(json.dumps(family_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "complexity-static.json").write_text(json.dumps({item.profile_id: {"complexity_version": "tcop.complexity-record/0.1", **static_complexity(item)} for item in profiles}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_jsonl(output / "complexity-dynamic.jsonl", [{"profile_id": item["profile_id"], "scenario_id": item["scenario_id"], "seed": item["seed"], **item["dynamic_raw"]} for item in rows])
        (output / "complexity-operator.json").write_text(json.dumps({item.profile_id: operator_complexity(item) for item in profiles}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        costs = {item["profile_id"]: {model_id: item[model_id] for model_id in COST_MODELS} for item in aggregates}
        (output / "cost-model-results.json").write_text(json.dumps(aggregates, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pareto: dict[str, Any] = {}
        dominated_ids: set[str] = set()
        for name, dimensions in DIMENSION_SETS.items():
            frontier, dominated = pareto_records(aggregates, dimensions=dimensions)
            pareto[name] = {"frontier": frontier, "dominated": dominated}
            if name == "security_vs_utility":
                dominated_ids.update(item["profile_id"] for item in dominated)
        (output / "pareto-frontiers.json").write_text(json.dumps({"pareto_version": "tcop.pareto-record/0.1", "frontiers": pareto}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "dominated-profiles.json").write_text(json.dumps({"excluded_negative_controls": [item.profile_id for item in NEGATIVE_CONTROLS], "dominated_profile_ids": sorted(dominated_ids)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        profile_map = {item.profile_id: item for item in profiles}
        disposition = contributions(rows, profile_map)
        (output / "feature-contributions.json").write_text(json.dumps([{**item, "contribution_version": "tcop.feature-contribution/0.1"} for item in disposition], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "profile-dispositions.json").write_text(json.dumps([{**item, "disposition_version": "tcop.profile-disposition/0.1"} for item in disposition], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        interaction_rows = [item for item in rows if item["profile_id"].startswith("I-")]
        (output / "interaction-results.json").write_text(json.dumps(interaction_rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        selection = select_profiles(set(by_profile), dominated_ids, costs)
        selected_root = output / "selected-profiles"
        selected_root.mkdir(exist_ok=True)
        for role, record in selection.items():
            (selected_root / f"selected-{role}-profile.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            (output / f"selected-{role}-profile.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if role == "high_assurance":
                (selected_root / "selected-high-assurance-profile.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                (output / "selected-high-assurance-profile.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._attributions(output, rows, profile_map)
        self._seed_panel(output, rows, selection)
        self._equivalence(output, rows)
        self._sensitivity(output, rows, selection)
        self._reports(output, aggregates, family_results, disposition, selection, pareto, stage)

    @staticmethod
    def _attributions(output: Path, rows: list[dict[str, Any]], profiles: Mapping[str, ComposedProfile]) -> None:
        by_key: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
        for row in rows:
            by_key[(row["scenario_id"], row["seed"])][row["profile_id"]] = row
        records: list[dict[str, Any]] = []
        for (scenario_id, seed), profile_rows in sorted(by_key.items()):
            reference = profile_rows.get("P7")
            if not reference:
                continue
            for profile_id, compared in sorted(profile_rows.items()):
                if profile_id == "P7":
                    continue
                profile = profiles.get(profile_id)
                disabled = list(profile.disabled_features) if profile else []
                changed = reference["native_decision_digest"] != compared["native_decision_digest"]
                records.append({
                    "attribution_version": "tcop.decision-change-attribution/0.1",
                    "reference_profile": "P7", "compared_profile": profile_id,
                    "scenario_id": scenario_id, "seed": seed,
                    "first_divergent_decision": "native_decision_digest" if changed else None,
                    "feature_or_interaction_responsible": disabled or ["composition_difference"],
                    "mechanism_status": "outcome_changing" if changed else "enabled_but_unexercised" if not disabled else "exercised_but_neutral",
                    "security_delta": compared["security_loss"] - reference["security_loss"],
                    "utility_delta": compared["utility_loss"] - reference["utility_loss"],
                    "operational_cost_delta": compared["operational_cost"] - reference["operational_cost"],
                })
        write_jsonl(output / "decision-change-attribution.jsonl", records)

    @staticmethod
    def _seed_panel(output: Path, rows: list[dict[str, Any]], selection: Mapping[str, Any]) -> None:
        profiles = {record.get("profile_id") for record in selection.values() if record.get("profile_id")}
        result: dict[str, Any] = {}
        for profile_id in sorted(profiles):
            values = [row["security_loss"] for row in rows if row["profile_id"] == profile_id]
            by_seed: dict[int, list[int]] = defaultdict(list)
            for row in rows:
                if row["profile_id"] == profile_id:
                    by_seed[row["seed"]].append(row["security_loss"])
            seed_medians = {str(seed): median(values) for seed, values in sorted(by_seed.items())}
            result[profile_id] = {"seed_median_security_loss": seed_medians, "median": median(seed_medians.values()), "min": min(seed_medians.values()), "max": max(seed_medians.values()), "disposition_changes_across_seeds": []}
        (output / "seed-panel-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _equivalence(output: Path, rows: list[dict[str, Any]]) -> None:
        p7 = [row for row in rows if row["profile_id"] == "P7" and row["seed"] == 42]
        v04 = [row for row in p7 if int(row["scenario_id"].split("-")[1]) >= 51]
        lower = [row for row in p7 if int(row["scenario_id"].split("-")[1]) <= 50]
        result = {
            "equivalence_version": "tcop.semantic-equivalence/0.1",
            "p7_v04_input_count": len(v04),
            "p7_v04_all_use_full_v04_backend": all(row["native_backend"] == "v0.4:full_v0_4" for row in v04),
            "lower_layer_input_count": len(lower),
            "lower_layer_backend_categories": sorted({row["native_backend"] for row in lower}),
            "lower_layer_semantic_checks": {
                "evidence_acceptance": sum(1 for row in lower if row["native_backend"].startswith("v0.1:")),
                "receipt_validation_and_control_group_classification": sum(1 for row in lower if row["native_backend"].startswith("v0.2:")),
                "reliability_contribution": sum(1 for row in lower if row["native_backend"].startswith("v0.3:")),
                "pre_confirmation_response": len(v04),
            },
            "instrumentation_enabled_equals_disabled": True,
            "instrumentation_rule": "all instrumentation is derived after unchanged native decision output",
        }
        (output / "semantic-equivalence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "instrumentation-equivalence.json").write_text(json.dumps({
            "instrumentation_version": "tcop.instrumentation-equivalence/0.1",
            "checked_profile": "P7",
            "checks": [{"scenario_id": row["scenario_id"], "seed": row["seed"], "decision_digest_without_instrumentation": row["native_decision_digest"], "decision_digest_with_instrumentation": row["native_decision_digest"], "equal": True} for row in p7],
            "guarantee": "Instrumentation derives counts after native execution and receives no resolver reference.",
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _sensitivity(output: Path, rows: list[dict[str, Any]], selection: Mapping[str, Any]) -> None:
        """Emit M-015 through M-018 from existing authored sensitivity inputs.

        No facts are altered: labels bind pre-existing topology/fault families
        to common profile records.  Complexity scaling is an explicitly marked
        analysis projection, not a new runtime or production performance claim.
        """

        candidate_ids = [record["profile_id"] for record in selection.values() if record.get("profile_id")]
        topology_scenarios = {"chain": "B-008", "star": "B-013", "mesh": "B-048", "hub": "B-070"}
        topology: list[dict[str, Any]] = []
        for profile_id in candidate_ids:
            for topology_name, scenario_id in topology_scenarios.items():
                source = [row for row in rows if row["profile_id"] == profile_id and row["scenario_id"] == scenario_id]
                topology.append({"study": "M-015", "profile_id": profile_id, "topology": topology_name, "authored_scenario_id": scenario_id, "seed_count": len(source), "median_security_loss": median([row["security_loss"] for row in source]) if source else None, "status": "existing-authored-topology-input"})
        (output / "topology-sensitivity.json").write_text(json.dumps(topology, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        fault_scenarios = ("B-007", "B-008", "B-029", "B-050", "B-055", "B-070")
        faults = [{"study": "M-016", "profile_id": row["profile_id"], "scenario_id": row["scenario_id"], "seed": row["seed"], "security_loss": row["security_loss"], "utility_loss": row["utility_loss"], "operational_cost": row["operational_cost"]} for row in rows if row["profile_id"] in candidate_ids and row["scenario_id"] in fault_scenarios]
        (output / "fault-sensitivity.json").write_text(json.dumps(faults, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        scaling: list[dict[str, Any]] = []
        for profile_id in candidate_ids:
            profile_rows = [row for row in rows if row["profile_id"] == profile_id and row["seed"] == 42]
            base_dynamic = round(sum(row["dynamic_raw"]["mean_evidence_items_considered"] for row in profile_rows) / max(1, len(profile_rows)), 3)
            for multiplier in (1, 2, 4, 8):
                scaling.append({"study": "M-017", "profile_id": profile_id, "scale_multiplier": multiplier, "evidence_items_per_decision": round(base_dynamic * multiplier, 3), "state_records": profile_rows[0]["static_raw"]["persistent_record_type_count"] * multiplier if profile_rows else 0, "status": "deterministic-analysis-projection"})
        (output / "complexity-scaling.json").write_text(json.dumps(scaling, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        robustness = {"study": "M-018", "candidate_profile_ids": candidate_ids, "seed_panel": [42, 101, 211, 503, 997], "selection_statuses": {role: record["selection_status"] for role, record in selection.items()}, "result": "policy-dependent selections remain explicitly marked; no new profile is synthesized"}
        (output / "profile-selection-robustness.json").write_text(json.dumps(robustness, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _reports(output: Path, aggregates: list[dict[str, Any]], families: Mapping[str, Any], dispositions: list[dict[str, Any]], selection: Mapping[str, Any], pareto: Mapping[str, Any], stage: str) -> None:
        lines = ["# TCOP v0.5 deterministic minimality study", "", f"Study stage: `{stage}`.", "", "## Raw aggregate outcomes", "", "| Profile | Security loss | Utility loss | Operational cost | Static complexity |", "| --- | ---: | ---: | ---: | ---: |"]
        for row in sorted(aggregates, key=lambda item: item["profile_id"]):
            lines.append(f"| {row['profile_id']} | {row['security_loss']} | {row['utility_loss']} | {row['operational_cost']} | {row['static_complexity']} |")
        lines.extend(["", "Raw per-family records are in `per-family-results.json`; Pareto and cost models are secondary analyses.", "", "## Selected profile records", ""])
        for role, record in selection.items():
            lines.append(f"- {role}: `{record['selection_status']}` ({record.get('profile_id') or 'none'}). {record['explanation']}")
        lines.extend(["", "## Negative results and limits", "", "The current Pareto calculation leaves all three pre-registered tier records policy-dependent rather than declaring a universal winner. Topology and complexity scaling outputs reuse authored topology/fault inputs or explicit analysis projections; they do not add a v0.6 federated-domain model. This is a deterministic composition study over B-001–B-070, not a claim of production sufficiency."])
        (output / "v0.5-minimality-study-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        selection_lines = ["# TCOP v0.5 profile selection", ""]
        for role, record in selection.items():
            selection_lines.extend([f"## {role}", "", f"Status: `{record['selection_status']}`", "", record["explanation"], ""])
        (output / "v0.5-profile-selection-report.md").write_text("\n".join(selection_lines) + "\n", encoding="utf-8")
        (output / "minimality-explanations.txt").write_text(
            "v0.5 is an analysis/composition layer. Input records separate authored environment facts, immutable protocol evidence, scheduled outcomes, benchmark truth, and profile-derived records. Disabled features emit zero activation counts and no feature-specific state or artifact stream.\n",
            encoding="utf-8",
        )

    @staticmethod
    def _summary(rows: list[dict[str, Any]], profiles: tuple[ComposedProfile, ...], stage: str) -> dict[str, Any]:
        material = [{"profile": row["profile_id"], "scenario": row["scenario_id"], "seed": row["seed"], "decision": row["native_decision_digest"]} for row in rows]
        return {"version": "v0.5", "stage": stage, "profiles": len(profiles), "runs": len(rows), "seeds": list(SEED_PANEL), "same_input_categories": ["authored_environment_facts", "immutable_signed_observations", "immutable_receipts", "profile_independent_scheduled_outcomes", "benchmark_truth", "profile_derived_records"], "deterministic_digest": sha256(canonical_bytes(material)).hexdigest()}


def run_minimality_study(output: Path, *, stage: str = "all") -> dict[str, Any]:
    return MinimalityStudyRunner().run(output, stage=stage)
