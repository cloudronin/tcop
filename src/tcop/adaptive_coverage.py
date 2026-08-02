"""Fail-closed contracts for Amendment 002 adaptive and mismatch evidence."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


BRANCHES = ("A0", "A1", "A2", "A3", "A4")
DISPOSITIONS = frozenset({"executed", "not_triggered", "not_representable", "environment_failure", "policy_failure", "excluded_before_execution"})
FORBIDDEN_ADAPTATION_FIELDS = frozenset({"tcx_contents", "receiver_policy_state", "monitor_records", "receipt_validity", "campaign_classification", "benchmark_labels", "future_outcomes", "detector_ground_truth", "harmful_ground_truth"})
MISMATCH_DIMENSIONS = frozenset({"subject", "receipt_session", "resource_namespace", "capability", "scope"})


class AdaptiveContractError(ValueError):
    pass


def _forbidden(value: Any, path: str = "") -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for key, child in value.items():
            name = str(key)
            current = f"{path}.{name}" if path else name
            if name in FORBIDDEN_ADAPTATION_FIELDS:
                result.append(current)
            result.extend(_forbidden(child, current))
        return result
    if isinstance(value, list):
        return [entry for index, child in enumerate(value) for entry in _forbidden(child, f"{path}[{index}]")]
    return []


def validate_adaptation_view(value: Mapping[str, Any]) -> dict[str, Any]:
    """The adaptive actor may see only the ordinary local gateway response."""

    if set(value) != {"gateway_result"} or not isinstance(value.get("gateway_result"), str):
        raise AdaptiveContractError("adaptive_view_must_contain_only_gateway_result")
    leaked = _forbidden(value)
    if leaked:
        raise AdaptiveContractError("prohibited_adaptation_input:" + ",".join(leaked))
    return dict(value)


def validate_coverage_ledger(rows: Iterable[Mapping[str, Any]], source_cases: Iterable[str], conditions: Iterable[str]) -> dict[str, Any]:
    """Require one closing A0-A4 disposition for every case and condition."""

    expected = {(case, condition, branch) for case in source_cases for condition in conditions for branch in BRANCHES}
    seen: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for row in rows:
        key = (str(row.get("corpus_case_id")), str(row.get("condition")), str(row.get("branch_id")))
        if key not in expected or key in seen:
            raise AdaptiveContractError("adaptive_coverage_row_unexpected_or_duplicate")
        if row.get("disposition") not in DISPOSITIONS:
            raise AdaptiveContractError("adaptive_coverage_disposition_invalid")
        if row.get("branch_id") == "A3" and row.get("disposition") == "executed":
            if row.get("subject_relation") != "new_subject_or_workload" or row.get("campaign_relation") != "declared_shared_campaign":
                raise AdaptiveContractError("A3_requires_new_subject_and_declared_campaign_relation")
        if row.get("branch_id") == "A4" and row.get("disposition") == "executed" and row.get("harmful_action") is not False:
            raise AdaptiveContractError("A4_must_be_benign_continuation")
        seen[key] = row
    missing = expected - set(seen)
    if missing:
        raise AdaptiveContractError("adaptive_coverage_branch_missing")
    return {"passed": True, "row_count": len(seen), "expected_row_count": len(expected)}


def validate_valid_broader_risk(row: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the evaluator-only mismatch definition without exposing truth."""

    required_true = ("detector_independent", "protocol_valid_at_receiver", "evaluator_ground_truth_harmful", "receiver_relevant_relation")
    if not all(row.get(key) is True for key in required_true):
        raise AdaptiveContractError("valid_broader_risk_required_predicate_missing")
    mismatch = row.get("mismatch_dimensions")
    if not isinstance(mismatch, list) or not mismatch or not set(mismatch).issubset(MISMATCH_DIMENSIONS):
        raise AdaptiveContractError("valid_broader_risk_mismatch_dimension_invalid")
    runtime = row.get("runtime_inputs", {})
    if not isinstance(runtime, Mapping) or _forbidden(runtime):
        raise AdaptiveContractError("evaluator_ground_truth_leaked_to_runtime")
    return {"passed": True, "mismatch_dimensions": list(mismatch), "evaluator_only": True}


def valid_broader_risk_summary(candidate_count: int, confirmed_count: int) -> dict[str, Any]:
    if candidate_count < 0 or confirmed_count < 0 or confirmed_count > candidate_count:
        raise AdaptiveContractError("valid_broader_risk_census_invalid")
    return {"candidate_count": candidate_count, "confirmed_count": confirmed_count, "G12_VALID_BROADER_RISK_NONEMPTY": confirmed_count > 0, "mismatch_escalation_status": "eligible" if confirmed_count else "incomplete_for_mismatch_escalation_claims"}
