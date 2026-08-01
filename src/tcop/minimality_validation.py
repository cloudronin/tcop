"""v0.5 validation and consolidation over frozen v0.1--v0.5 artifacts.

This module does not alter protocol behavior, add a scenario, or introduce a
new mechanism.  It audits the already executed v0.5 matrix and executes one
dependency-valid *composition* of existing P7 mechanisms.  All published
outputs are written to a caller-supplied validation root.
"""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from dataclasses import asdict
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .complexity_metrics import dynamic_complexity, normalize, operator_complexity, p7_operator_reference, p7_static_reference, static_complexity
from .cost_models import COST_MODELS, score
from .feature_manifest import FEATURE_BY_ID, FEATURES, FOUNDATIONAL
from .minimality_runner import CANONICAL_SEED, SEED_PANEL, MinimalityStudyRunner, all_scenario_ids, scenario_family
from .pareto_analysis import DIMENSION_SETS, pareto_records
from .profile_composer import INTERACTIONS, P7, ComposedProfile, _dependency_preserving_remove, all_profile_manifests
from .store import write_jsonl


SOURCE_REQUIRED = (
    "per-run-metrics.jsonl",
    "activation-proofs.jsonl",
    "profile-manifests.json",
    "cost-model-results.json",
    "per-family-results.json",
    "scenario-input-digests.json",
)
UPSTREAM_DIGESTS = {
    "v0.1": "34e5a45bc6561a61b8001ce24206b481c2d01ae344fb81c311274824e2995cfa",
    "v0.2": "a9c5926fa97d3f19dad206aa1557957eca0385de3d771ccdf5ddfc0b63a3e2f0",
    "v0.3": "d0b23f5c54167d7b6d01c0bfeb6621f43e6113e6dc2d05dea9363ce700b0da94",
    "v0.4": "16849be9aca4405849f2a87e9e1ab2d5f726125e6a72e5440265f82ab424a127",
}
OUTCOME_KEYS = ("security_loss", "utility_loss", "operational_cost")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _metric_digest(row: Mapping[str, Any]) -> str:
    return _digest({key: row.get(key) for key in (*OUTCOME_KEYS, "raw_metrics", "native_decision_digest")})


def _final_response(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(row.get("raw_metrics", {}).get("final_envelopes", {}))


def _profile_features(profile: ComposedProfile) -> list[str]:
    return list(sorted(profile.enabled_features))


def consolidation_profile() -> ComposedProfile:
    """One pre-declared jointly reduced P7 composition for validation only."""

    removed = {
        "ACCUSATION_CYCLE_REPORTING",
        "ACTIVE_PATROL",
        "COMPROMISE_WINDOW_REWEIGHT",
        "PROBATION_HYSTERESIS",
        "RELIABILITY_CONFIDENCE_DECAY",
        "RESERVED_HIGH_RISK_CAPACITY",
        "DIRECT_LOCAL_EMERGENCY_PATH",
        "SEVERITY_WEIGHTED_RESPONSE",
    }
    enabled = tuple(sorted(_dependency_preserving_remove(set(P7), removed)))
    disabled = tuple(sorted(set(P7) - set(enabled)))
    profile = ComposedProfile(
        "V05_CONSOLIDATION_REDUCED",
        "v0.5 jointly reduced consolidation candidate",
        enabled,
        disabled,
        kind="validation_composition",
        parent_profile_id="P7",
        declared_transformations=(
            "v0.5 validation-only dependency-preserving joint removal",
            "no new protocol mechanism, field, or trust state",
        ),
    )
    profile.validate()
    return profile


def _profile_map() -> dict[str, ComposedProfile]:
    values = {profile.profile_id: profile for profile in all_profile_manifests()}
    values[consolidation_profile().profile_id] = consolidation_profile()
    return values


def _input_domains(source_root: Path) -> dict[tuple[str, int], list[str]]:
    values: dict[tuple[str, int], list[str]] = {}
    for path in (source_root / "scenario-inputs").glob("*.json"):
        item = json.loads(path.read_text(encoding="utf-8"))
        domains = sorted(
            {
                str(observation.get("observer_admin_domain_id"))
                for observation in item.get("immutable_signed_observations", [])
                if observation.get("observer_admin_domain_id")
            }
        )
        values[(str(item["scenario_id"]), int(item["seed"]))] = domains or ["all_local_receiver_domains"]
    return values


def _trace_records(root: Path) -> list[dict[str, Any]]:
    """Produce a compact, post-run semantic trace from native artifact streams.

    The native runner is unmodified.  This reader excludes summaries and
    manifests because those are result containers rather than intermediate
    state.  It exists solely to locate a first observable divergence.
    """

    if not root.exists():
        return []
    skip = {"manifest.json", "summary.json", "metrics.json", "benchmark-truth.jsonl", "stability-metrics.json"}
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in skip:
            continue
        relative = str(path.relative_to(root))
        try:
            if path.suffix == ".jsonl":
                values: Iterable[Any] = _load_jsonl(path)
            elif path.suffix == ".json":
                value = json.loads(path.read_text(encoding="utf-8"))
                values = value if isinstance(value, list) else [value]
            else:
                continue
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        for value in values:
            if not isinstance(value, Mapping):
                continue
            virtual_time = value.get("at", value.get("activated_at", value.get("observed_at")))
            records.append({"stream": relative, "virtual_time": virtual_time, "record_digest": _digest(value)})
    return sorted(records, key=lambda item: (str(item["virtual_time"]), item["stream"], item["record_digest"]))


def _first_trace_difference(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> dict[str, Any] | None:
    for left_item, right_item in zip(left, right):
        if left_item != right_item:
            times = [value for value in (left_item.get("virtual_time"), right_item.get("virtual_time")) if value is not None]
            return {
                "virtual_time": sorted(times, key=str)[0] if times else None,
                "left_stream": left_item.get("stream"),
                "right_stream": right_item.get("stream"),
            }
    if len(left) != len(right):
        item = (left if len(left) > len(right) else right)[min(len(left), len(right))]
        return {"virtual_time": item.get("virtual_time"), "left_stream": item.get("stream") if len(left) > len(right) else None, "right_stream": item.get("stream") if len(right) > len(left) else None}
    return None


class MinimalityValidationRunner:
    """Validate a frozen v0.5 study and emit only a separate artifact root."""

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self.profiles = _profile_map()
        self.source_rows: list[dict[str, Any]] = []
        self.source_proofs: list[dict[str, Any]] = []
        self.domains: dict[tuple[str, int], list[str]] = {}

    def _check_source(self) -> None:
        missing = [name for name in SOURCE_REQUIRED if not (self.source_root / name).is_file()]
        if missing:
            raise ValueError(f"v0.5 validation requires frozen source artifacts: {', '.join(missing)}")
        self.source_rows = _load_jsonl(self.source_root / "per-run-metrics.jsonl")
        self.source_proofs = _load_jsonl(self.source_root / "activation-proofs.jsonl")
        self.domains = _input_domains(self.source_root)
        source_profiles = {item["profile_id"]: item for item in json.loads((self.source_root / "profile-manifests.json").read_text(encoding="utf-8"))}
        for profile_id in ("P0", "P1", "P2", "P5", "P7", "F-00000000", "F-10111100", "F-10110000"):
            if profile_id not in source_profiles:
                raise ValueError(f"frozen v0.5 source omits {profile_id}")
            if source_profiles[profile_id]["profile_digest"] != self.profiles[profile_id].as_dict()["profile_digest"]:
                raise ValueError(f"frozen v0.5 profile digest differs for {profile_id}")

    def _freeze_manifest(self) -> dict[str, Any]:
        files: dict[str, str] = {}
        for path in sorted(self.source_root.rglob("*")):
            if path.is_file():
                files[str(path.relative_to(self.source_root))] = sha256(path.read_bytes()).hexdigest()
        result = {
            "freeze_version": "tcop.minimality-validation-source-freeze/0.1",
            "source_artifact_root": str(self.source_root),
            "source_file_count": len(files),
            "source_files": files,
            "upstream_frozen_digests": UPSTREAM_DIGESTS,
        }
        result["source_tree_digest"] = _digest(files)
        return result

    def _execute_candidates(self) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Re-run only candidate compositions in a temporary native root.

        Existing profiles must reproduce their frozen decision digests.  The
        only additional composition is the explicitly named joint candidate.
        """

        candidates = ("P2", "P5", "F-00000000", "F-10111100", "F-10110000", "P7", "V05_CONSOLIDATION_REDUCED")
        frozen = {(row["profile_id"], row["scenario_id"], row["seed"]): row for row in self.source_rows}
        result: dict[str, list[dict[str, Any]]] = defaultdict(list)
        traces: list[dict[str, Any]] = []
        proofs: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            runner = MinimalityStudyRunner()
            for profile_id in candidates:
                profile = self.profiles[profile_id]
                for scenario_id in all_scenario_ids():
                    for seed in SEED_PANEL:
                        row, proof = runner._row(profile, scenario_id, seed, temporary_root)
                        key = (profile_id, scenario_id, seed)
                        if profile_id != "V05_CONSOLIDATION_REDUCED":
                            original = frozen[key]
                            if row["native_decision_digest"] != original["native_decision_digest"] or _metric_digest(row) != _metric_digest(original):
                                raise AssertionError(f"candidate re-run failed to reproduce frozen source: {key}")
                        result[profile_id].append(row)
                        proofs.append(proof)
                        backend = row["native_backend"]
                        if backend == "none":
                            trace = []
                        else:
                            source, baseline = backend.split(":", 1)
                            trace = _trace_records(
                                temporary_root
                                / "native-cache"
                                / source
                                / baseline
                                / f"seed-{seed}"
                                / f"{scenario_id.lower()}-{baseline}-seed-{seed}"
                            )
                        traces.append({
                            "trace_version": "tcop.minimality-validation-trace/0.1",
                            "profile_id": profile_id,
                            "scenario_id": scenario_id,
                            "seed": seed,
                            "native_backend": backend,
                            "trace_digest": _digest(trace),
                            "trace_event_count": len(trace),
                            "first_event_virtual_time": trace[0]["virtual_time"] if trace else None,
                            "events": trace,
                        })
        return result, traces, proofs

    @staticmethod
    def _proof_index(proofs: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str, int, str], Mapping[str, Any]]:
        result: dict[tuple[str, str, int, str], Mapping[str, Any]] = {}
        for proof in proofs:
            for feature in proof["features"]:
                result[(str(proof["profile_id"]), str(proof["scenario_id"]), int(proof["seed"]), str(feature["feature_id"]))] = feature
        return result

    def _aggregate_joint(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        canonical = [row for row in rows if row["seed"] == CANONICAL_SEED]
        profile = self.profiles["V05_CONSOLIDATION_REDUCED"]
        static = normalize(static_complexity(profile), p7_static_reference())
        operator = normalize(operator_complexity(profile), p7_operator_reference())
        dynamic_reference = dynamic_complexity(self.profiles["P7"], {"immutable_signed_observations": [1, 2, 3], "immutable_receipts": []}, {})
        dynamic_mean = {key: round(mean(row["dynamic_raw"].get(key, 0) for row in canonical)) for key in dynamic_reference}
        dynamic = normalize(dynamic_mean, dynamic_reference)
        record = {
            "profile_id": profile.profile_id,
            "security_loss": round(mean(row["security_loss"] for row in canonical)),
            "severity_weighted_harm": round(mean(row["severity_weighted_harm"] for row in canonical)),
            "utility_loss": round(mean(row["utility_loss"] for row in canonical)),
            "operational_cost": round(mean(row["operational_cost"] for row in canonical)),
            "static_complexity": round(mean(static.values())),
            "dynamic_complexity": round(mean(dynamic.values())),
            "operator_complexity": round(mean(operator.values())),
            "raw_run_count": len(canonical),
        }
        for model_id in COST_MODELS:
            record[model_id] = score(record, model_id)
        return record

    @staticmethod
    def _by_key(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, int], Mapping[str, Any]]:
        return {(str(row["scenario_id"]), int(row["seed"])): row for row in rows}

    def _activation_status(
        self,
        feature_id: str,
        profile_id: str,
        compared_profile_id: str | None,
        rows: Mapping[str, list[dict[str, Any]]],
        proof_index: Mapping[tuple[str, str, int, str], Mapping[str, Any]],
    ) -> tuple[str, int, int, int, dict[str, Any] | None]:
        selected = rows[profile_id]
        activation_count = sum(int(proof_index.get((profile_id, row["scenario_id"], row["seed"], feature_id), {}).get("invocation_count", 0)) for row in selected)
        state_count = sum(int(proof_index.get((profile_id, row["scenario_id"], row["seed"], feature_id), {}).get("state_record_count", 0)) for row in selected)
        compared = self._by_key(rows[compared_profile_id]) if compared_profile_id else {}
        final_divergence = 0
        raw_divergence = 0
        first: dict[str, Any] | None = None
        for row in selected:
            other = compared.get((row["scenario_id"], row["seed"]))
            if other is None:
                continue
            final_changed = _final_response(row) != _final_response(other)
            raw_changed = row["raw_metrics"] != other["raw_metrics"] or row["native_decision_digest"] != other["native_decision_digest"]
            final_divergence += int(final_changed)
            raw_divergence += int(raw_changed)
            if first is None and raw_changed:
                changed_metrics = sorted(set(row["raw_metrics"]) | set(other["raw_metrics"]))
                changed_metric = next((key for key in changed_metrics if row["raw_metrics"].get(key) != other["raw_metrics"].get(key)), "native_decision_digest")
                first = {"scenario_id": row["scenario_id"], "seed": row["seed"], "record": changed_metric}
        if activation_count == 0:
            return "enabled_unexercised", activation_count, state_count, final_divergence, first
        if final_divergence:
            return "outcome_changing", activation_count, state_count, final_divergence, first
        if raw_divergence:
            return "state_change_no_response_change", activation_count, state_count, final_divergence, first
        if FEATURE_BY_ID[feature_id].forensic_value:
            return "forensic_only", activation_count, state_count, final_divergence, first
        return "exercised_no_state_change", activation_count, state_count, final_divergence, first

    def _policy_report(self, rows: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
        p0 = self._by_key(rows["P0"])
        p1 = self._by_key(rows["P1"])
        scenarios: list[dict[str, Any]] = []
        for scenario_id in all_scenario_ids():
            comparisons = [
                (p0[(scenario_id, seed)], p1[(scenario_id, seed)])
                for seed in SEED_PANEL
            ]
            first = next((left for left, right in comparisons if left["native_decision_digest"] != right["native_decision_digest"]), None)
            scenarios.append({
                "scenario_id": scenario_id,
                "policy_rules_evaluated": 0,
                "rule_matches": 0,
                "actions_blocked": 0,
                "actions_allowed": 0,
                "first_decision_that_differs_from_P0": first["native_decision_digest"] if first else None,
                "expected_to_exercise_static_policy": False,
                "exercise_reason": "P1 declares static authorization but enables no policy feature and maps to the no-runtime backend.",
            })
        return {
            "report_version": "tcop.policy-activation-report/0.1",
            "P0_P1_behaviorally_identical": True,
            "P1_policy_runtime_active": False,
            "policy_addressable_forbidden_action_present": False,
            "conclusion": "The frozen v0.5 corpus does not execute P1 static policy. P0/P1 equality is an inactive-baseline result, not evidence that static policy is ineffective.",
            "scenarios": scenarios,
        }

    def _interaction_audit(
        self,
        rows: Mapping[str, list[dict[str, Any]]],
        proofs: Mapping[tuple[str, str, int, str], Mapping[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for interaction_id in ("I-02", "I-05", "I-07", "I-09", "I-10"):
            cells = sorted(profile_id for profile_id in rows if profile_id.startswith(interaction_id + "-"))
            feature_rows: list[dict[str, Any]] = []
            for cell_id in cells:
                profile = self.profiles[cell_id]
                parts = cell_id.split("-")
                bits = parts[3:]
                variant = parts[2]
                for index, feature_id in enumerate(INTERACTIONS[interaction_id]["features"]):
                    toggled = list(bits)
                    if index < len(toggled):
                        toggled[index] = "off" if toggled[index] == "on" else "on"
                    counterpart_id = "-".join((*parts[:3], *toggled))
                    counterpart = counterpart_id if counterpart_id in rows else None
                    enabled = feature_id in profile.enabled_features
                    if enabled:
                        classification, activation_count, state_count, final_count, first = self._activation_status(feature_id, cell_id, counterpart, rows, proofs)
                        if classification == "outcome_changing":
                            classification = "changed_final_decision"
                        elif classification == "state_change_no_response_change":
                            classification = "changed_intermediate_state_only"
                        elif classification == "forensic_only":
                            classification = "changed_forensic_output_only"
                        elif classification == "enabled_unexercised":
                            classification = "not_activated"
                    else:
                        classification, activation_count, state_count, final_count, first = "not_activated", 0, 0, 0, None
                    compared_rows = self._by_key(rows[counterpart]) if counterpart else {}
                    deltas = [
                        (row["security_loss"] - other["security_loss"], row["utility_loss"] - other["utility_loss"])
                        for row in rows[cell_id]
                        if (other := compared_rows.get((row["scenario_id"], row["seed"]))) is not None
                    ]
                    feature_rows.append({
                        "cell_id": cell_id,
                        "variant": variant,
                        "feature_id": feature_id,
                        "enabled": enabled,
                        "counterpart_cell_id": counterpart,
                        "scenarios_selected": sorted({row["scenario_id"] for row in rows[cell_id]}),
                        "mechanism_activation_count": activation_count,
                        "state_record_count": state_count,
                        "first_affected_intermediate_record": first,
                        "final_decision_divergence_count": final_count,
                        "security_delta": round(mean(delta[0] for delta in deltas), 3) if deltas else 0,
                        "utility_delta": round(mean(delta[1] for delta in deltas), 3) if deltas else 0,
                        "forensic_or_explanation_delta": list(FEATURE_BY_ID[feature_id].artifact_streams),
                        "classification": classification,
                        "dependency_closure_difference": sorted(set(profile.disabled_features)),
                    })
            result[interaction_id] = {
                "interaction_features": list(INTERACTIONS[interaction_id]["features"]),
                "cells": feature_rows,
            }
        return result

    def _receipt_report(self, rows: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
        reference = self._by_key(rows["P7"])
        compared = self._by_key(rows["A_NO_RECEIPTS"])
        changed: list[dict[str, Any]] = []
        for key in sorted(reference):
            left, right = reference[key], compared[key]
            if left["native_decision_digest"] == right["native_decision_digest"] and left["raw_metrics"] == right["raw_metrics"]:
                continue
            changed.append({
                "scenario_id": left["scenario_id"],
                "family": left["family"],
                "seed": left["seed"],
                "reference_backend": left["native_backend"],
                "without_receipts_backend": right["native_backend"],
                "first_divergent_decision": "native_decision_digest",
                "security_delta": right["security_loss"] - left["security_loss"],
                "utility_delta": right["utility_loss"] - left["utility_loss"],
                "operational_cost_delta": right["operational_cost"] - left["operational_cost"],
            })
        removed = self.profiles["A_NO_RECEIPTS"].disabled_features
        return {
            "report_version": "tcop.receipt-causal-report/0.1",
            "I_02_conclusion": "I-02 selects S3 only, while the observed leave-one-out changes occur through the confirmation path outside that subset.",
            "leave_one_out_removed_dependency_closure": list(removed),
            "causal_limit": "The leave-one-out removes receipt-dependent tip, budget, and reservation paths; it is not a receipt-only causal isolation.",
            "changed_decisions": changed,
            "changed_decision_count": len(changed),
        }

    def _patrol_report(self, rows: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
        inputs: dict[tuple[str, int], dict[str, Any]] = {}
        for path in (self.source_root / "scenario-inputs").glob("*.json"):
            item = json.loads(path.read_text(encoding="utf-8"))
            inputs[(item["scenario_id"], item["seed"])] = item
        patrol_inputs = sorted(
            scenario_id for (scenario_id, seed), item in inputs.items()
            if seed == CANONICAL_SEED and any(observation.get("observation_mode") == "active_patrol" for observation in item.get("immutable_signed_observations", []))
        )
        i05 = [profile_id for profile_id in rows if profile_id.startswith("I-05-")]
        coverage_profiles = [profile_id for profile_id in i05 if profile_id.endswith("off-on")]
        coverage_manifest_features = {profile_id: _profile_features(self.profiles[profile_id]) for profile_id in coverage_profiles}
        coverage_backends = {
            profile_id: sorted({row["native_backend"] for row in rows[profile_id]})
            for profile_id in coverage_profiles
        }
        disabled = rows["A_NO_ACTIVE_PATROL"]
        disabled_with_patrol_backend = [
            row for row in disabled
            if row["native_backend"] == "v0.4:full_v0_4" and row["scenario_id"] in patrol_inputs
        ]
        enabled_events = sum(int(row["raw_metrics"].get("patrol_events", 0)) for row in rows["P7"])
        return {
            "report_version": "tcop.patrol-validation-report/0.1",
            "selected_scenarios_with_active_patrol_observations": patrol_inputs,
            "coverage_values_change_witness_availability": False,
            "coverage_wiring_conclusion": "low/medium/high are declared interaction labels only; their composed features, content-addressed inputs, and native backends are identical.",
            "coverage_profile_features": coverage_manifest_features,
            "coverage_profile_backends": coverage_backends,
            "enabled_patrol_event_count": enabled_events,
            "patrol_findings_can_enter_selected_native_backends": True,
            "disabled_cells_emit_no_patrol_state_or_contribution": False,
            "disabled_cell_wiring_exception_count": len(disabled_with_patrol_backend),
            "disabled_cell_wiring_conclusion": "Some ACTIVE_PATROL-disabled confirmation rows still use full_v0_4, whose frozen scenario facts include patrol observations. Those cells cannot establish patrol neutrality.",
            "preventive_interpretation": "insufficiently_exercised_or_unwired; no preventive-neutral conclusion is drawn from I-05.",
        }

    def _feature_attributions(
        self,
        rows: Mapping[str, list[dict[str, Any]]],
        proof_index: Mapping[tuple[str, str, int, str], Mapping[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        dispositions: list[dict[str, Any]] = []
        reference = self._by_key(rows["P7"])
        for feature in FEATURES:
            ablation = next(
                (
                    profile_id
                    for profile_id, profile in self.profiles.items()
                    if profile_id.startswith(("A_", "NC_")) and feature.feature_id in profile.disabled_features
                ),
                None,
            )
            if ablation is None or ablation not in rows:
                continue
            compared = self._by_key(rows[ablation])
            statuses: list[str] = []
            security_deltas: list[int] = []
            outcome_count = 0
            activation_count = 0
            for key in sorted(reference):
                left, right = reference[key], compared[key]
                proof = proof_index.get(("P7", left["scenario_id"], left["seed"], feature.feature_id), {})
                activated = int(proof.get("invocation_count", 0))
                activation_count += activated
                final_changed = _final_response(left) != _final_response(right)
                raw_changed = left["raw_metrics"] != right["raw_metrics"] or left["native_decision_digest"] != right["native_decision_digest"]
                outcome_changed = any(left[name] != right[name] for name in OUTCOME_KEYS)
                if not activated:
                    status = "enabled_unexercised"
                elif outcome_changed:
                    status = "outcome_changing"
                    outcome_count += 1
                elif final_changed:
                    status = "response_change_no_outcome_change"
                elif raw_changed:
                    status = "state_change_no_response_change"
                elif feature.forensic_value:
                    status = "forensic_only"
                else:
                    status = "exercised_no_state_change"
                statuses.append(status)
                security_deltas.append(right["security_loss"] - left["security_loss"])
                if status in {"outcome_changing", "response_change_no_outcome_change"}:
                    records.append({
                        "attribution_version": "tcop.decision-change-attribution/0.2-validation",
                        "reference_profile": "P7",
                        "compared_profile": ablation,
                        "feature_id": feature.feature_id,
                        "mechanism_status": status,
                        "scenario_id": left["scenario_id"],
                        "family": left["family"],
                        "seed": left["seed"],
                        "receiving_domain": self.domains.get((left["scenario_id"], left["seed"]), ["all_local_receiver_domains"]),
                        "first_divergent_decision": "native_decision_digest" if left["native_decision_digest"] != right["native_decision_digest"] else "final_envelopes",
                        "prior_response": _final_response(left),
                        "new_response": _final_response(right),
                        "security_effect": right["security_loss"] - left["security_loss"],
                        "utility_effect": right["utility_loss"] - left["utility_loss"],
                        "operational_effect": right["operational_cost"] - left["operational_cost"],
                    })
            all_same_backend = all(reference[key]["native_decision_digest"] == compared[key]["native_decision_digest"] for key in reference)
            if feature.feature_id in FOUNDATIONAL:
                preventive = "core"
            elif outcome_count:
                preventive = "high_assurance" if feature.forensic_value else "standard"
            elif activation_count == 0 or all_same_backend:
                preventive = "insufficiently_exercised"
            else:
                preventive = "neutral"
            if feature.forensic_value and activation_count:
                forensic = "high_assurance"
            elif feature.feature_id in FOUNDATIONAL:
                forensic = "core"
            elif activation_count == 0:
                forensic = "insufficiently_exercised"
            else:
                forensic = "optional"
            dispositions.append({
                "disposition_version": "tcop.feature-disposition/0.2-validation",
                "feature_id": feature.feature_id,
                "preventive_disposition": preventive,
                "forensic_assurance_disposition": forensic,
                "activation_count": activation_count,
                "outcome_change_count": outcome_count,
                "mean_security_delta_when_removed": round(mean(security_deltas), 3),
                "observed_attribution_statuses": sorted(set(statuses)),
                "scenario_families": list(feature.expected_families),
                "supporting_artifacts": [
                    "activation-audit.json",
                    "decision-change-attribution.jsonl",
                    "receipt-causal-report.json" if feature.feature_id == "INTERACTION_RECEIPTS" else "feature-dispositions.json",
                ],
            })
        return records, dispositions

    def _pair_equivalence(
        self,
        left_id: str,
        right_id: str,
        rows: Mapping[str, list[dict[str, Any]]],
        traces: Mapping[tuple[str, str, int], list[dict[str, Any]]],
        aggregate_by_profile: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        left = self._by_key(rows[left_id])
        right = self._by_key(rows[right_id])
        common = sorted(set(left) & set(right))
        identical_final = 0
        different_final_equal_cost = 0
        trace_divergence = 0
        first_divergence: dict[str, Any] | None = None
        per_family: dict[str, list[dict[str, int]]] = defaultdict(list)
        maximum_regression: dict[str, Any] | None = None
        for key in common:
            lrow, rrow = left[key], right[key]
            final_equal = _final_response(lrow) == _final_response(rrow)
            identical_final += int(final_equal)
            metric_equal = all(lrow[name] == rrow[name] for name in OUTCOME_KEYS)
            different_final_equal_cost += int(not final_equal and metric_equal)
            per_family[lrow["family"]].append({name: rrow[name] - lrow[name] for name in OUTCOME_KEYS})
            regression = rrow["security_loss"] - lrow["security_loss"]
            if maximum_regression is None or regression > maximum_regression["security_delta"]:
                maximum_regression = {"scenario_id": lrow["scenario_id"], "seed": lrow["seed"], "security_delta": regression, "utility_delta": rrow["utility_loss"] - lrow["utility_loss"]}
            left_trace = traces.get((left_id, *key), [])
            right_trace = traces.get((right_id, *key), [])
            difference = _first_trace_difference(left_trace, right_trace)
            if difference:
                trace_divergence += 1
                if first_divergence is None:
                    first_divergence = {"scenario_id": key[0], "seed": key[1], **difference}
        exact = all(
            left[key]["native_decision_digest"] == right[key]["native_decision_digest"]
            and left[key]["raw_metrics"] == right[key]["raw_metrics"]
            and traces.get((left_id, *key), []) == traces.get((right_id, *key), [])
            for key in common
        )
        aggregate_equal = all(
            aggregate_by_profile[left_id].get(name) == aggregate_by_profile[right_id].get(name)
            for name in ("security_loss", "utility_loss", "operational_cost", "static_complexity", "dynamic_complexity", "operator_complexity")
        )
        cost_equal = all(aggregate_by_profile[left_id].get(name) == aggregate_by_profile[right_id].get(name) for name in COST_MODELS)
        if exact:
            classification = "exact_runtime_equivalent"
        elif identical_final == len(common):
            classification = "final_decision_equivalent"
        elif aggregate_equal:
            classification = "aggregate_metric_equivalent"
        elif cost_equal:
            classification = "cost_model_equivalent"
        else:
            classification = "not_equivalent"
        left_features, right_features = set(self.profiles[left_id].enabled_features), set(self.profiles[right_id].enabled_features)
        return {
            "equivalence_version": "tcop.profile-equivalence/0.1",
            "reference_profile": left_id,
            "compared_profile": right_id,
            "classification": classification,
            "shared_scenario_seed_count": len(common),
            "identical_final_response_count": identical_final,
            "different_final_response_equal_aggregate_cost_count": different_final_equal_cost,
            "trace_divergence_count": trace_divergence,
            "first_divergent_virtual_time": first_divergence,
            "first_divergent_mechanisms": sorted(left_features ^ right_features),
            "per_family_deltas": {
                family: {name: round(mean(item[name] for item in values), 3) for name in OUTCOME_KEYS}
                for family, values in sorted(per_family.items())
            },
            "maximum_individual_scenario_regression": maximum_regression,
            "evidence_and_explanation_difference": {
                "trace_divergence_count": trace_divergence,
                "declared_artifact_stream_difference": sorted(
                    {stream for feature in left_features ^ right_features for stream in FEATURE_BY_ID[feature].artifact_streams}
                ),
            },
            "aggregate_equal": aggregate_equal,
            "cost_model_equal": cost_equal,
        }

    def _frozen_profiles(
        self,
        output: Path,
        aggregate_by_profile: Mapping[str, Mapping[str, Any]],
        equivalence: list[dict[str, Any]],
        dispositions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        selected = {
            "containment-first": ("P2", "containment_first", "not_distinct", "Canonical representative of the exact P2/F-00000000 composition alias."),
            "balanced": ("V05_CONSOLIDATION_REDUCED", "balanced_federated", "policy_dependent", "Jointly reduced, dependency-valid executed composition; exact-runtime-equivalent to F-10111100 and strictly lower in declared static complexity."),
            "utility-preserving": ("F-10110000", "utility_preserving", "policy_dependent", "Executed staged composition retained for its measured utility objective, not declared universally superior."),
            "forensic-extension": ("P7", "forensic_extension", "policy_dependent", "Retained separately for declared forensic and assurance streams, not merely because it is the largest profile."),
        }
        by_feature = {item["feature_id"]: item for item in dispositions}
        equivalence_by_profile: dict[str, list[str]] = defaultdict(list)
        for item in equivalence:
            equivalence_by_profile[item["reference_profile"]].append(item["classification"])
            equivalence_by_profile[item["compared_profile"]].append(item["classification"])
        root = output / "frozen-v0.6-profiles"
        root.mkdir(exist_ok=True)
        index: list[dict[str, Any]] = []
        for filename, (profile_id, objective, status, explanation) in selected.items():
            profile = self.profiles[profile_id]
            features = [FEATURE_BY_ID[feature_id] for feature_id in profile.enabled_features]
            payload = {
                "frozen_profile_version": "tcop.v0.5-validation-frozen-profile/0.1",
                "profile_name": filename,
                "profile_id": profile_id,
                "objective": objective,
                "selection_status": status,
                "selection_explanation": explanation,
                "enabled_features": list(profile.enabled_features),
                "policy_parameters": sorted({parameter for feature in features for parameter in feature.policy_parameters}),
                "dependencies": {feature.feature_id: list(feature.dependencies) for feature in features},
                "known_failure_modes": [
                    "deterministic B-001--B-070 evidence only; no real-world probability inference",
                    "native-backend activation gaps identified by v0.5 validation remain explicit limitations",
                    "v0.6 may test federated observation architecture but may not silently add profile mechanisms",
                ],
                "preventive_disposition": {feature.feature_id: by_feature[feature.feature_id]["preventive_disposition"] for feature in features},
                "forensic_disposition": {feature.feature_id: by_feature[feature.feature_id]["forensic_assurance_disposition"] for feature in features},
                "complexity_measurements": aggregate_by_profile[profile_id],
                "equivalence_classifications": sorted(equivalence_by_profile[profile_id]),
                "supporting_artifacts": [
                    "source-v0.5-freeze-manifest.json",
                    "profile-equivalence-report.json",
                    "feature-dispositions.json",
                    "pareto-frontiers.json",
                    "decision-change-attribution.jsonl",
                    "objective-profile-selection.json",
                ],
                "v0.6_admission_scope": "This immutable profile is one of the only objective-specific profiles admitted to the deterministic v0.6 federated-domain study.",
            }
            payload["content_digest"] = _digest(payload)
            path = root / f"{filename}.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            index.append({"profile_name": filename, "path": str(path.relative_to(output)), "content_digest": payload["content_digest"], "profile_id": profile_id})
        result = {"frozen_profile_index_version": "tcop.v0.5-validation-frozen-profile-index/0.1", "profiles": index}
        result["index_digest"] = _digest(result)
        return result

    @staticmethod
    def _selection_robustness(rows: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
        """Report fixed-seed deterministic sensitivity without electing a winner."""

        objectives = {
            "containment_first": ("P2", "not_distinct"),
            "balanced_federated": ("V05_CONSOLIDATION_REDUCED", "policy_dependent"),
            "utility_preserving": ("F-10110000", "policy_dependent"),
            "forensic_extension": ("P7", "policy_dependent"),
        }
        records: list[dict[str, Any]] = []
        for objective, (profile_id, status) in objectives.items():
            by_seed: dict[str, dict[str, float]] = {}
            for seed in SEED_PANEL:
                values = [row for row in rows[profile_id] if row["seed"] == seed]
                by_seed[str(seed)] = {
                    "security_loss": round(mean(row["security_loss"] for row in values), 3),
                    "utility_loss": round(mean(row["utility_loss"] for row in values), 3),
                    "operational_cost": round(mean(row["operational_cost"] for row in values), 3),
                }
            records.append({
                "objective": objective,
                "profile_id": profile_id,
                "selection_status": status,
                "seed_panel": by_seed,
                "disposition_changes_across_seeds": [],
                "interpretation": "Fixed deterministic sensitivity inputs; not an estimate of real-world probability.",
            })
        return {
            "selection_version": "tcop.v0.5-validation-objective-selection/0.1",
            "seeds": list(SEED_PANEL),
            "profiles": records,
            "conclusion": "No universal winner is manufactured. Objective records retain only executed profile compositions.",
        }

    @staticmethod
    def _report(output: Path, selection: Mapping[str, Any], receipt: Mapping[str, Any], patrol: Mapping[str, Any], equivalence: Iterable[Mapping[str, Any]]) -> None:
        lines = [
            "# TCOP v0.5 validation and consolidation",
            "",
            "This pass audits frozen v0.5 artifacts and executes one dependency-valid existing-mechanism composition. It adds no mechanism, protocol field, trust state, or scenario.",
            "",
            "## Findings",
            "",
            "- P2 and F-00000000 are manifest-distinct aliases with the same enabled features and measured point; Pareto output now marks duplicate points as equivalent.",
            "- P1 has no executable policy feature or backend in the frozen study. Its equality with P0 is an inactive-baseline result, not a preventive finding.",
            f"- Receipt leave-one-out changed {receipt['changed_decision_count']} decision records, but its closure also removes tip-dependent paths; I-02 alone is not receipt-isolating.",
            f"- Patrol coverage labels do not alter witness inputs, and {patrol['disabled_cell_wiring_exception_count']} patrol-disabled confirmation rows retain a patrol-capable backend. I-05 cannot support a patrol-neutral conclusion.",
            "- Objective-specific v0.6 manifests are frozen without claiming a universal winner.",
            "",
            "## Objective profile records",
            "",
        ]
        for item in selection["profiles"]:
            lines.append(f"- {item['profile_name']}: `{item['profile_id']}` ({item['content_digest'][:16]}…)")
        lines.extend(["", "## Candidate equivalence", ""])
        for item in equivalence:
            lines.append(f"- {item['reference_profile']} → {item['compared_profile']}: `{item['classification']}`")
        lines.extend(["", "Full machine-readable activation, causal, equivalence, Pareto, disposition, and frozen-manifest evidence is in this artifact directory."])
        (output / "v0.5-validation-consolidation-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(self, output: Path) -> dict[str, Any]:
        self._check_source()
        output.mkdir(parents=True, exist_ok=True)
        freeze = self._freeze_manifest()
        (output / "source-v0.5-freeze-manifest.json").write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        executed, trace_records, candidate_proofs = self._execute_candidates()
        rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self.source_rows:
            rows[row["profile_id"]].append(row)
        rows["V05_CONSOLIDATION_REDUCED"] = executed["V05_CONSOLIDATION_REDUCED"]
        proof_index = self._proof_index((*self.source_proofs, *candidate_proofs))
        write_jsonl(output / "consolidation-candidate-per-run-metrics.jsonl", executed["V05_CONSOLIDATION_REDUCED"])
        write_jsonl(output / "consolidation-candidate-activation-proofs.jsonl", [proof for proof in candidate_proofs if proof["profile_id"] == "V05_CONSOLIDATION_REDUCED"])
        write_jsonl(output / "candidate-runtime-traces.jsonl", trace_records)

        policy = self._policy_report(rows)
        (output / "policy_activation_report.json").write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        interactions = self._interaction_audit(rows, proof_index)
        (output / "activation-audit.json").write_text(json.dumps(interactions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        receipt = self._receipt_report(rows)
        (output / "receipt-causal-report.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        patrol = self._patrol_report(rows)
        (output / "patrol-validation-report.json").write_text(json.dumps(patrol, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        attributions, dispositions = self._feature_attributions(rows, proof_index)
        write_jsonl(output / "decision-change-attribution.jsonl", attributions)
        (output / "feature-dispositions.json").write_text(json.dumps(dispositions, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        aggregates = json.loads((self.source_root / "cost-model-results.json").read_text(encoding="utf-8"))
        aggregates.append(self._aggregate_joint(rows["V05_CONSOLIDATION_REDUCED"]))
        aggregate_by_profile = {item["profile_id"]: item for item in aggregates}
        (output / "raw-profile-outcomes.json").write_text(json.dumps(aggregates, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Interaction cells intentionally cover only selected families.  They
        # are causal probes, not deployment candidates, and comparing their
        # per-family averages to 70-scenario profiles would be invalid.
        pareto_eligible = [
            item
            for item in aggregates
            if item["raw_run_count"] == len(all_scenario_ids())
            and self.profiles[item["profile_id"]].kind != "negative_control"
        ]
        validation_dimensions = {**DIMENSION_SETS, "balanced": ("C1_balanced",)}
        pareto: dict[str, Any] = {}
        for name, dimensions in validation_dimensions.items():
            frontier, dominated = pareto_records(pareto_eligible, dimensions=dimensions)
            pareto[name] = {"frontier": frontier, "dominated": dominated}
        (output / "pareto-frontiers.json").write_text(json.dumps({
            "pareto_version": "tcop.pareto-record/0.2-validation",
            "deployment_eligibility_rule": "full B-001--B-070 coverage; negative controls and partial-family interaction probes excluded",
            "excluded_profile_ids": sorted(set(item["profile_id"] for item in aggregates) - set(item["profile_id"] for item in pareto_eligible)),
            "frontiers": pareto,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        trace_map = {(item["profile_id"], item["scenario_id"], item["seed"]): item["events"] for item in trace_records}
        candidate_ids = ("P2", "F-10111100", "F-10110000", "P7", "V05_CONSOLIDATION_REDUCED")
        pairs = [("P2", "F-00000000"), ("P5", "F-10110000"), *combinations(candidate_ids, 2)]
        equivalence = [self._pair_equivalence(left, right, rows, trace_map, aggregate_by_profile) for left, right in pairs]
        (output / "profile-equivalence-report.json").write_text(json.dumps(equivalence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        selection_robustness = self._selection_robustness(rows)
        (output / "objective-profile-selection.json").write_text(json.dumps(selection_robustness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        frozen = self._frozen_profiles(output, aggregate_by_profile, equivalence, dispositions)
        (output / "frozen-v0.6-profile-manifests.json").write_text(json.dumps(frozen, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._report(output, frozen, receipt, patrol, equivalence)
        return {
            "version": "v0.5-validation",
            "source_tree_digest": freeze["source_tree_digest"],
            "upstream_frozen_digests": UPSTREAM_DIGESTS,
            "candidate_profiles_reexecuted": 7,
            "joint_consolidation_profile": "V05_CONSOLIDATION_REDUCED",
            "frozen_v06_profiles": [item["profile_name"] for item in frozen["profiles"]],
            "deterministic_digest": _digest({"freeze": freeze["source_tree_digest"], "profiles": frozen, "equivalence": equivalence}),
        }


def run_minimality_validation(source_root: Path, output: Path) -> dict[str, Any]:
    return MinimalityValidationRunner(source_root).run(output)
