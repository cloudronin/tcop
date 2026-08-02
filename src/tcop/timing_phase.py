"""Network-interface timing-grid contracts for Amendment 002."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


NETWORK_DELAYS_MS = (10, 50, 100, 250)
ACTION_INTERVALS_MS = (25, 100, 250, 500)
OUTCOMES = frozenset({"prospective_prevention", "post_first_action_blast_radius_reduction", "forensic_or_monitor_only", "too_late_for_affected_action", "no_warning", "protocol_rejected"})
TIMESTAMPS = ("t_detector_output_at_A", "t_message_serialized_at_A", "t_message_published_at_A", "t_message_observed_by_B", "t_policy_input_at_B", "t_opa_decision_at_B", "t_gateway_disposition_at_B", "t_first_affected_action_at_B")


class TimingContractError(ValueError):
    pass


def timing_matrix_plan() -> list[dict[str, int]]:
    return [{"network_delay_ms": delay, "action_interval_ms": interval} for delay in NETWORK_DELAYS_MS for interval in ACTION_INTERVALS_MS]


def validate_network_impairment(record: Mapping[str, Any]) -> dict[str, Any]:
    if record.get("implementation") != "isolated_two_host_network_interface":
        raise TimingContractError("network_impairment_must_be_at_two_host_interface")
    if record.get("application_sleep"):
        raise TimingContractError("application_sleep_cannot_implement_network_delay")
    if not isinstance(record.get("host_route"), str) or not isinstance(record.get("clock_offset_bound_ms"), (int, float)):
        raise TimingContractError("network_impairment_observation_missing")
    return dict(record)


def validate_timing_rows(rows: Iterable[Mapping[str, Any]], conditions: Iterable[str]) -> dict[str, Any]:
    expected = {(cell["network_delay_ms"], cell["action_interval_ms"], condition) for cell in timing_matrix_plan() for condition in conditions}
    seen: set[tuple[int, int, str]] = set()
    for row in rows:
        key = (row.get("network_delay_ms"), row.get("action_interval_ms"), row.get("condition"))
        if key not in expected or key in seen:
            raise TimingContractError("timing_cell_unexpected_or_duplicate")
        seen.add(key)
        if row.get("environment_failure"):
            if not row.get("environment_failure_reason"):
                raise TimingContractError("timing_environment_failure_reason_missing")
            continue
        missing = [field for field in TIMESTAMPS if not isinstance(row.get(field), (int, float))]
        if missing:
            raise TimingContractError("timing_timestamp_missing:" + ",".join(missing))
        outcome = row.get("timing_outcome")
        if not isinstance(outcome, str) or outcome not in OUTCOMES:
            raise TimingContractError("timing_outcome_partition_invalid")
    if expected - seen:
        raise TimingContractError("timing_grid_cell_missing")
    return {"passed": True, "cell_count": len(seen), "expected_cell_count": len(expected)}
