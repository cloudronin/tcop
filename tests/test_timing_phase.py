from __future__ import annotations

import unittest

from tcop.timing_phase import ACTION_INTERVALS_MS, NETWORK_DELAYS_MS, TIMESTAMPS, TimingContractError, timing_matrix_plan, validate_network_impairment, validate_timing_rows


def _rows() -> list[dict[str, object]]:
    rows = []
    for delay in NETWORK_DELAYS_MS:
        for interval in ACTION_INTERVALS_MS:
            row: dict[str, object] = {"network_delay_ms": delay, "action_interval_ms": interval, "condition": "E2E", "timing_outcome": "prospective_prevention"}
            row.update({field: index for index, field in enumerate(TIMESTAMPS)})
            rows.append(row)
    return rows


class TimingPhaseTests(unittest.TestCase):
    def test_complete_grid_and_timestamp_contract(self) -> None:
        self.assertEqual(len(timing_matrix_plan()), 16)
        self.assertTrue(validate_timing_rows(_rows(), ["E2E"])["passed"])
        with self.assertRaises(TimingContractError):
            validate_timing_rows(_rows()[:-1], ["E2E"])

    def test_network_impairment_cannot_be_application_sleep(self) -> None:
        value = {"implementation": "isolated_two_host_network_interface", "application_sleep": False, "host_route": "A->B", "clock_offset_bound_ms": 1}
        self.assertEqual(validate_network_impairment(value)["host_route"], "A->B")
        value["application_sleep"] = True
        with self.assertRaises(TimingContractError):
            validate_network_impairment(value)

    def test_each_timing_row_has_one_partition_and_all_timestamps(self) -> None:
        rows = _rows(); rows[0]["timing_outcome"] = ["prospective_prevention", "too_late_for_affected_action"]
        with self.assertRaises(TimingContractError):
            validate_timing_rows(rows, ["E2E"])
        rows = _rows(); del rows[0][TIMESTAMPS[0]]
        with self.assertRaises(TimingContractError):
            validate_timing_rows(rows, ["E2E"])
