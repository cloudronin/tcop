"""Prediction and comparison boundary for the synthetic cross-host simulator.

This module never seals anything. Phase 1's verifier checks existing seals;
the generator produces compatible records for a later, gated seal workflow.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .canonical import canonical_bytes
from .crosshost_sim import (FAMILIES, ROWS, VERSION, place_grid, simulate_grid,
                            simulator_hash, validate_calibration)
from .external_expected_pattern import validate_expected_pattern, verify_expected_pattern
from .external_foundation_seals import digest, ensure_unsealed_output, hash256, require

_ROOTS = {"plan_sha256", "census_sha256", "admission_sha256"}
_GATES = {"amendment_004_sha256", "grid_finalization_sha256"}
COMPARISON_FIELDS = ("timing_outcome", "runtime_decision", "runtime_decision_reason",
                     "time_to_detect_ms", "time_to_block_ms", "harmful_actions_executed",
                     "harmful_actions_prevented", "a0_prevented", "useful_work", "damage_prevented",
                     "binding", "submission_condition", "timeline_ms", "harmful_attempts", "a4_work", "events")


def generate_prediction(calibration: dict[str, Any], profiles: Iterable[dict[str, Any]], *, seed: int,
                        bindings: dict[str, str] | None = None,
                        gate_hashes: dict[str, str] | None = None,
                        sealed_eligible: bool = False, transition_samples: int = 1024) -> dict[str, Any]:
    """Requesting eligibility is an error for provisional calibration, never a downgrade.

    A draft is intentionally rejected by Phase 1 validators. Eligibility means
    ready for later owner/gate verification, not that anything is sealed here.
    """
    validate_calibration(calibration)
    require(not sealed_eligible or calibration["status"] == "calibrated",
            "provisional calibration cannot produce a sealed-eligible prediction")
    profiles = list(profiles)
    placement = place_grid(calibration, profiles, seed=seed, samples=transition_samples)
    simulation = simulate_grid(calibration, profiles, seed=seed,
                               action_intervals_ms=placement["grid"]["action_intervals_ms"])
    bindings = bindings or {}
    gates = gate_hashes or {}
    if sealed_eligible:
        require(set(bindings) == _ROOTS and set(gates) == _GATES, "sealed input/gate hashes required")
        for key, value in {**bindings, **gates}.items():
            hash256(value, key)
    families = {}
    for family in FAMILIES:
        rows = [e for e in simulation["episodes"] if e["family"] == family]
        fragments = []
        for row in ROWS:
            selected = [e for e in rows if e["row"] == row]
            fragments.append(f"{row}: A0 denied {sum(e['a0_prevented'] for e in selected)}/{len(selected)}, "
                             f"harmful executed {sum(e['harmful_actions_executed'] for e in selected)}, "
                             f"A4 completed {sum(e['useful_work']['numerator'] for e in selected)}/"
                             f"{sum(e['useful_work']['denominator'] for e in selected)}")
        statement = ("All modes use native egress; no extension primitive differs." if family == "S-A" else
                     "Native egress versus harness instant cut is a same-action latency comparison." if family == "S-B" else
                     "Native whole-provider detach versus harness freeze is a mixed-action comparison.")
        if family != "S-A":
            statement += " Native A0 prevention is zero below its episode effect time; success triggers no retries."
        families[family] = statement + " " + "; ".join(fragments)
    return {"schema": "tcop.external-expected-pattern/1.0",
            "status": "preregistered" if sealed_eligible else "unsealed-pending-owner",
            "open_owner_issues": [] if sealed_eligible else ["simulator draft; calibration and seal gates pending"],
            "pool_e2_modes": False, "pool_native_extended": False, "pool_poll_configurations": False,
            "bindings": bindings, "families": families,
            "post_hoc": False, "sealed_eligible": sealed_eligible,
            "simulator": {"version": VERSION, "sha256": simulator_hash(), "seed": seed,
                          "calibration_sha256": digest(calibration), "calibration": calibration,
                          "profiles_sha256": digest(sorted(profiles, key=lambda p: p["family"])),
                          "profiles": sorted(profiles, key=lambda p: p["family"]),
                          "gate_hashes": gates, "grid": simulation["grid"], "placement": placement},
            "predictions": simulation}


def validate_prediction(record: dict[str, Any]) -> None:
    """Use before Phase 1 sealing or any prediction-path write.

    Checking the embedded full simulation prevents a sweep from being relabeled
    eligible. Verification is deterministic replay, never parameter fitting.
    """
    require(record.get("post_hoc") is False and record.get("sealed_eligible") is True,
            "prediction path rejects post-hoc or ineligible records")
    validate_expected_pattern(record)
    require(record.get("pool_native_extended") is False and record.get("pool_poll_configurations") is False,
            "binding and poll modes must remain separate")
    meta = record.get("simulator", {})
    calibration = meta.get("calibration", {})
    validate_calibration(calibration)
    require(calibration["status"] == "calibrated", "provisional prediction rejected")
    require(meta.get("calibration_sha256") == digest(calibration), "changed calibration")
    require(meta.get("version") == VERSION and meta.get("sha256") == simulator_hash(), "simulator version changed")
    profiles = meta.get("profiles", [])
    require(meta.get("profiles_sha256") == digest(profiles), "changed script profiles")
    gates = meta.get("gate_hashes", {})
    require(set(gates) == _GATES, "amendment and finalized grid evidence required")
    for key, value in gates.items():
        hash256(value, key)
    placement = meta.get("placement", {})
    require(type(placement.get("sample_count")) is int, "transition sample count required")
    regenerated = generate_prediction(calibration, profiles, seed=meta.get("seed"),
                                     bindings=record["bindings"], gate_hashes=gates,
                                     sealed_eligible=True, transition_samples=placement["sample_count"])
    require(canonical_bytes(record) == canonical_bytes(regenerated), "prediction differs from fixed-input simulation")


def write_prediction(record: dict[str, Any], output: Path) -> None:
    """Write an eligible canonical candidate, never a seal or a post-hoc sweep."""
    validate_prediction(record)
    ensure_unsealed_output(output)
    require(not output.exists(), "prediction output already exists")
    with output.open("xb") as stream:
        stream.write(canonical_bytes(record) + b"\n")


def _key(record: dict[str, Any]) -> tuple:
    return tuple(record.get(k) for k in ("script_sha256", "family", "script_id", "row", "seed",
                                        "network_delay_ms", "action_interval_ms"))


def _differences(expected: Any, actual: Any, path: str):
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                yield {"field": f"{path}.{key}", "kind": "unexpected_field" if key not in expected else "missing_field",
                       "expected": expected.get(key), "actual": actual.get(key)}
            else:
                yield from _differences(expected[key], actual[key], f"{path}.{key}")
    elif isinstance(expected, list) and isinstance(actual, list):
        for index in range(max(len(expected), len(actual))):
            if index >= len(expected) or index >= len(actual):
                yield {"field": f"{path}[{index}]", "kind": "list_length_mismatch",
                       "expected": expected[index] if index < len(expected) else None,
                       "actual": actual[index] if index < len(actual) else None}
            else:
                yield from _differences(expected[index], actual[index], f"{path}[{index}]")
    elif canonical_bytes({"v": expected}) != canonical_bytes({"v": actual}):
        yield {"field": path, "kind": "value_mismatch", "expected": expected, "actual": actual}


def compare_live(sealed_prediction: Path, live_episodes: Iterable[dict[str, Any]], *,
                 bindings: dict[str, str] | None = None) -> dict[str, Any]:
    """Read an integrity-verified seal and report EVERY difference in the declared
    comparison fields, including missing/extra/duplicate episodes. Exact times;
    no tolerance selection, fitting, reseeding, or live execution takes place.
    Live harness records need a versioned mapping to these episode fields.
    """
    verified = verify_expected_pattern(sealed_prediction, bindings=bindings)
    prediction = verified["record"]
    validate_prediction(prediction)
    expected = {_key(e): e for e in prediction["predictions"]["episodes"]}
    seen = set()
    findings = []
    for index, actual in enumerate(live_episodes):
        key = _key(actual)
        if key in seen:
            findings.append({"kind": "duplicate_episode", "live_index": index, "key": list(key)})
        seen.add(key)
        if key not in expected:
            findings.append({"kind": "unexpected_episode", "live_index": index, "key": list(key)})
            continue
        for field in COMPARISON_FIELDS:
            if field not in actual:
                differences = [{"field": field, "kind": "missing_field", "expected": expected[key][field], "actual": None}]
            else:
                differences = list(_differences(expected[key][field], actual[field], field))
            findings.extend({"key": list(key), "live_index": index, **d} for d in differences)
    for key in sorted(set(expected) - seen):
        findings.append({"kind": "missing_episode", "key": list(key)})
    return {"schema": "tcop.crosshost-live-comparison/1.0", "post_hoc": False,
            "prediction_sha256": verified["record_sha256"],
            "artifact_root_digest": verified["artifact_root_digest"],
            "fitting_performed": False, "findings": findings, "finding_count": len(findings)}
