"""Pre-registered static, dynamic, and operator complexity accounting."""

from __future__ import annotations

from typing import Any, Mapping

from .feature_manifest import FEATURE_BY_ID
from .profile_composer import ComposedProfile, PROFILE_BY_ID


# These rules are intentionally declaration based.  A shared module is counted
# only through feature-tagged symbols, never once for every profile that imports
# it.  Physical LOC is secondary and uses these fixed symbol allocations.
COMPLEXITY_RULES: dict[str, Any] = {
    "version": "tcop.complexity-rules/0.1",
    "policy_parameter_rule": "count distinct enabled feature-declared parameters",
    "state_machine_rule": "count feature-declared resolver state families",
    "operator_state_rule": "count distinct externally visible state labels unlocked by enabled features",
    "schema_rule": "count distinct enabled feature-declared schemas",
    "artifact_rule": "count distinct enabled feature-declared artifact streams",
    "shared_module_rule": "deduplicate feature-tagged symbols; never attribute a complete shared source file",
    "explanation_rule": "count distinct enabled feature-declared operator concepts",
    "executable_line_rule": "sum fixed pre-registered tagged-symbol line weights, deduplicated by symbol",
    "normalization_rule": "each dimension is scaled to P7 = 1000; absent P7 denominator is zero",
}

_SYMBOL_LINE_WEIGHTS = {feature_id: 8 + len(spec.source_symbols) * 7 + len(spec.persistent_records) * 4 for feature_id, spec in FEATURE_BY_ID.items()}


def static_complexity(profile: ComposedProfile) -> dict[str, int]:
    features = [FEATURE_BY_ID[item] for item in profile.enabled_features]
    records = {value for item in features for value in item.persistent_records}
    schemas = {value for item in features for value in item.schemas}
    streams = {value for item in features for value in item.artifact_streams}
    symbols = {value for item in features for value in item.source_symbols}
    params = {value for item in features for value in item.policy_parameters}
    concepts = {value for item in features for value in item.operator_concepts}
    state_families = {
        "reliability" if item.feature_id.startswith("RELIABILITY") or item.feature_id in {"PROBATION_HYSTERESIS", "COMPROMISE_WINDOW_REWEIGHT", "ACCUSATION_CYCLE_REPORTING"} else "confirmation" if item.feature_id in {"PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION", "CAMPAIGN_GROUPING"} else "response" if item.feature_id == "CAPABILITY_SPECIFIC_RESPONSE" else None
        for item in features
    } - {None}
    executable_lines = sum(_SYMBOL_LINE_WEIGHTS[item.feature_id] for item in features)
    return {
        "enabled_feature_count": len(features),
        "policy_parameter_count": len(params),
        "persistent_record_type_count": len(records),
        "schema_count": len(schemas),
        "state_machine_count": len(state_families),
        "named_state_count": (6 if "reliability" in state_families else 0) + (3 if "confirmation" in state_families else 0) + (4 if "response" in state_families else 0),
        "transition_rule_count": (8 if "reliability" in state_families else 0) + (5 if "confirmation" in state_families else 0) + (3 if "response" in state_families else 0),
        "reason_code_count": len(concepts),
        "artifact_stream_count": len(streams),
        "feature_dependency_count": sum(len(item.dependencies) for item in features),
        "feature_tagged_symbol_count": len(symbols),
        "feature_tagged_executable_lines": executable_lines,
        "explanation_concept_count": len(concepts),
    }


def operator_complexity(profile: ComposedProfile) -> dict[str, int]:
    features = [FEATURE_BY_ID[item] for item in profile.enabled_features]
    concepts = {value for item in features for value in item.operator_concepts}
    response_states = {"monitoring", "constrained"} if "CAPABILITY_SPECIFIC_RESPONSE" in profile.enabled_features else set()
    if "PROVISIONAL_CONTAINMENT" in profile.enabled_features:
        response_states.add("provisionally_constrained")
    if "SOURCE_NOVEL_CONFIRMATION" in profile.enabled_features or "DIRECT_LOCAL_EMERGENCY_PATH" in profile.enabled_features:
        response_states.add("confirmed_quarantine")
    actions = {"observe", "reduce_capability"} if response_states else set()
    if "ACTIVE_PATROL" in profile.enabled_features:
        actions.add("authorize_patrol")
    if "TIP_ONLY_INVESTIGATION" in profile.enabled_features:
        actions.add("schedule_investigation")
    unresolved = int("INTERACTION_RECEIPTS" in profile.enabled_features) + int("PROVISIONAL_CONTAINMENT" in profile.enabled_features) + int("ACCUSATION_CYCLE_REPORTING" in profile.enabled_features)
    return {
        "operator_visible_state_count": len(response_states),
        "operator_action_count": len(actions),
        "policy_choice_count": len({value for item in features for value in item.policy_parameters}),
        "unresolved_evidence_condition_count": unresolved,
        "explanation_concept_count": len(concepts),
    }


def dynamic_complexity(profile: ComposedProfile, scenario_input: Mapping[str, Any], raw_metrics: Mapping[str, Any]) -> dict[str, int]:
    """Read-only post-decision trace.  It cannot influence the native run."""

    evidence = len(scenario_input.get("immutable_signed_observations", []))
    receipts = len(scenario_input.get("immutable_receipts", []))
    features = set(profile.enabled_features)
    factors = 5 if "RELIABILITY_WEIGHTING" in features else 1
    state_lookups = int("RELIABILITY_WEIGHTING" in features) * max(1, evidence) + int("PROVISIONAL_CONTAINMENT" in features) + int("CAMPAIGN_GROUPING" in features)
    branches = 2 + int("INTERACTION_RECEIPTS" in features) + int("RELIABILITY_WEIGHTING" in features) * 3 + int("PROVISIONAL_CONTAINMENT" in features) * 3 + int("TIP_ONLY_INVESTIGATION" in features) * 2
    explanation = len({value for feature in features for value in FEATURE_BY_ID[feature].operator_concepts})
    advanced = {"RELIABILITY_WEIGHTING", "PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION", "TIP_ONLY_INVESTIGATION", "CAMPAIGN_GROUPING", "ACTIVE_PATROL"}
    return {
        "mean_evidence_items_considered": evidence,
        "maximum_evidence_items_considered": evidence,
        "mean_weighting_factors_applied": factors,
        "mean_state_lookups": state_lookups,
        "mean_decision_branches": branches,
        "mean_explanation_length": explanation,
        "maximum_explanation_length": explanation,
        "multi_advanced_mechanism_decision_milli": 1000 if len(features & advanced) > 1 else 0,
        "exercised_feature_count": sum(1 for feature in features if FEATURE_BY_ID[feature].expected_families),
        "receipt_input_count": receipts,
        "native_protocol_events": int(raw_metrics.get("protocol_overhead_events", raw_metrics.get("protocol_accepted", 0))),
    }


def normalize(values: Mapping[str, int], reference: Mapping[str, int]) -> dict[str, int]:
    return {key: 0 if not reference.get(key, 0) else round(1000 * value / reference[key]) for key, value in values.items()}


def p7_static_reference() -> dict[str, int]:
    return static_complexity(PROFILE_BY_ID["P7"])


def p7_operator_reference() -> dict[str, int]:
    return operator_complexity(PROFILE_BY_ID["P7"])
