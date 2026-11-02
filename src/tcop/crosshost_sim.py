"""Synthetic millisecond discrete-event model of amendments 002--004.

No runtime calls, clock reads, fitting, sealing, or CLI integration. Public
records contain only JSON values; canonical_bytes(record) is the wire form.
"""
from __future__ import annotations

import heapq
import math
import random
from pathlib import Path
from typing import Any, Iterable

from .canonical import canonical_bytes
from .external_foundation_seals import digest, hash256, read_json, require
from .timing_phase import NETWORK_DELAYS_MS, OUTCOMES

VERSION = "tcop.crosshost-simulator/1.0"
ROWS = ("E0", "E1", "E2-native-a", "E2-native-b", "E2-native-min-a",
        "E2-extended-a", "E2-extended-b")
FAMILIES = ("S-A", "S-B", "S-C")
PROVISIONAL_INTERVALS_MS = (25, 400, 5000, 20000)
LAGS = ("detection", "signing", "validation", "native_persistence",
        "native_egress_processing", "native_detach_processing",
        "harness_cut", "harness_freeze", "effect_observation")


def simulator_hash() -> str:
    """Bind both implementation files and the reused semantics to predictions."""
    names = ("crosshost_sim.py", "crosshost_sim_predictions.py", "canonical.py",
             "timing_phase.py", "external_expected_pattern.py",
             "external_foundation_seals.py")
    return digest({name: Path(__file__).with_name(name).read_text() for name in names})


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    require(type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0), f"invalid {label}")
    return value


def _distribution(record: dict[str, Any], label: str) -> None:
    require(isinstance(record, dict), f"{label} distribution required")
    require(isinstance(record.get("source"), str) and bool(record["source"].strip()),
            f"{label} source required")
    kind = record.get("kind")
    if kind == "empirical":
        values = record.get("samples_ms")
        require(isinstance(values, list) and bool(values), f"{label} samples required")
        for value in values:
            _number(value, label)
    elif kind == "uniform":
        _number(record.get("low_ms"), label); _number(record.get("high_ms"), label)
        require(record["low_ms"] <= record["high_ms"], f"{label} inverted support")
    elif kind == "fixed":
        _number(record.get("value_ms"), label)
    else:
        require(False, f"unsupported {label} distribution")


def validate_calibration(record: dict[str, Any]) -> None:
    require(record.get("schema") == "tcop.crosshost-calibration/1.0", "calibration schema")
    require(record.get("status") in ("provisional", "calibrated"), "calibration status")
    require(record.get("D_ms") == 3000, "004 fixes simulated operator latency D=3000 ms")
    require(record.get("poll_ms") == {"default": 10000, "minimum": 1000}, "004 poll settings")
    require(set(record.get("lags", {})) == set(LAGS), "every lag distribution required")
    for name in LAGS:
        _distribution(record["lags"][name], name)
    _number(record.get("decision_deadline_after_ready_ms"), "decision deadline", positive=True)
    require(record["decision_deadline_after_ready_ms"] >= record["D_ms"],
            "decision deadline must include D")
    require(record.get("poll_phase") == "uniform_at_baseline", "unbiased baseline poll phase required")
    sources = record.get("sources")
    require(isinstance(sources, dict) and all(isinstance(sources.get(k), str)
            and sources[k].strip() for k in ("poll", "D", "deadline")), "setting sources required")
    if record["status"] == "calibrated":
        checks = record.get("conformance_sha256", {})
        require(set(checks) == {"C1", "C2", "C3"}, "calibrated C1/C2/C3 evidence required")
        for key, value in checks.items():
            hash256(value, key)
    digest(record)


def load_calibration(path: Path) -> dict[str, Any]:
    record = read_json(path)
    validate_calibration(record)
    require(path.read_bytes() in (canonical_bytes(record), canonical_bytes(record) + b"\n"),
            "calibration file must be canonical JSON (optional final newline)")
    return record


def validate_profile(profile: dict[str, Any]) -> None:
    require(profile.get("schema") == "tcop.crosshost-script-profile/1.0", "script profile schema")
    require(profile.get("family") in FAMILIES, "script family required")
    require(isinstance(profile.get("script_id"), str) and bool(profile["script_id"]), "script ID required")
    require(profile.get("independent_of_harmful_side_effects") is True, "A4 independence required")
    for key in ("target", "provider"):
        require(isinstance(profile.get(key), str) and bool(profile[key]), f"script {key} required")
    attempts = profile.get("harmful")
    require(isinstance(attempts, list) and [a.get("id") for a in attempts] == ["A0", "A1", "A2", "A3"],
            "fixed A0-A3 ladder required")
    for action in attempts + profile.get("a4", []):
        require(type(action.get("representable")) is bool, "representability required")
        for key in ("targets", "providers"):
            require(isinstance(action.get(key), list) and all(isinstance(x, str) and x for x in action[key]),
                    f"action {key} inventory required")
        require(type(action.get("e1_denied")) is bool, "baseline action disposition required")
    require(attempts[0]["e1_denied"] == (profile["family"] == "S-A"), "family A0 baseline mismatch")
    gaps = profile.get("retry_intervals_ms")
    require(isinstance(gaps, list) and len(gaps) == 3, "three retry intervals required")
    for gap in gaps:
        _number(gap, "retry interval", positive=True)
    _number(profile.get("a4_after_stop_ms"), "A4 start gap")
    require(isinstance(profile.get("a4"), list), "A4 opportunity inventory required")
    ids = []
    for work in profile["a4"]:
        require(isinstance(work.get("id"), str) and bool(work["id"]), "A4 work ID required")
        ids.append(work["id"])
        _number(work.get("offset_ms"), "A4 offset")
        _number(work.get("duration_ms"), "A4 duration")
        require(not work["e1_denied"], "baseline must permit every scripted A4")
    require(len(set(ids)) == len(ids), "duplicate A4 work ID")
    require(profile.get("warning", "valid") in ("valid", "no_warning", "protocol_rejected"), "warning condition")
    for flag in ("request_rejected", "observation_missing"):
        require(type(profile.get(flag, False)) is bool, f"invalid {flag}")
    digest(profile)


def binding_for(family: str, row: str) -> dict[str, Any] | None:
    require(family in FAMILIES and row in ROWS, "unknown family or row")
    if row in ("E0", "E1"):
        return None
    extended = row.startswith("E2-extended")
    if family == "S-C":
        action, implementation = (("freeze_sandbox", "harness_freeze") if extended
                                  else ("revoke_credential", "native_detach"))
    else:
        action = "deny_egress"
        implementation = "harness_cut" if family == "S-B" and extended else "native_egress"
    native = implementation.startswith("native")
    return {"abstract_action": action, "binding": implementation,
            "tag": "native" if native else "harness",
            "grade": "meets more coarsely" if implementation == "native_detach" else "meets",
            "grade_basis": "model assumption; not conformance evidence",
            "layering": "pure layering" if native else "extension"}


def _rng(seed: int, profile: dict[str, Any], stream: str) -> random.Random:
    # Common random numbers across cells/rows. No cell/outcome-dependent reseeding.
    return random.Random(int(digest([seed, profile["family"], profile["script_id"], stream]), 16))


def _sample(calibration: dict[str, Any], profile: dict[str, Any], seed: int, name: str) -> float:
    d = calibration["lags"][name]
    rng = _rng(seed, profile, name)
    if d["kind"] == "fixed":
        return float(d["value_ms"])
    if d["kind"] == "empirical":
        return float(d["samples_ms"][rng.randrange(len(d["samples_ms"]))])
    return rng.uniform(d["low_ms"], d["high_ms"])


def _timeline(calibration: dict[str, Any], profile: dict[str, Any], seed: int,
              row: str, delay: float) -> dict[str, Any]:
    binding = binding_for(profile["family"], row)
    if binding is None:
        return {}
    detect = _sample(calibration, profile, seed, "detection")
    signed = detect + _sample(calibration, profile, seed, "signing")
    arrival = signed + delay
    ready = arrival + _sample(calibration, profile, seed, "validation")
    submit = ready + (calibration["D_ms"] if row.endswith("-b") else 0)
    implementation = binding["binding"]
    phase = poll = persisted = None
    if implementation.startswith("native"):
        poll = calibration["poll_ms"]["minimum" if row == "E2-native-min-a" else "default"]
        phase = _rng(seed, profile, "poll_phase").random() * poll
        persisted = submit + _sample(calibration, profile, seed, "native_persistence")
        next_poll = phase + max(0, math.ceil((persisted - phase) / poll)) * poll
        effect = next_poll + _sample(calibration, profile, seed, implementation + "_processing")
    else:
        effect = submit + _sample(calibration, profile, seed, implementation)
    observation = effect + _sample(calibration, profile, seed, "effect_observation")
    return {"detected_at_ms": detect, "signed_at_ms": signed, "tcx_arrival_at_ms": arrival,
            "ready_at_ms": ready, "scheduled_submission_at_ms": submit, "submitted_at_ms": submit,
            "submission_deviation_ms": 0, "persisted_at_ms": persisted,
            "effect_at_ms": effect, "effect_observed_at_ms": observation,
            "deadline_at_ms": ready + calibration["decision_deadline_after_ready_ms"],
            "poll_interval_ms": poll, "poll_phase_ms": phase,
            "binding_lag_ms": effect - submit}


def ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else "undefined"}


def simulate_episode(calibration: dict[str, Any], profile: dict[str, Any], *, seed: int,
                     row: str, network_delay_ms: float, action_interval_ms: float) -> dict[str, Any]:
    """Effects at a timestamp precede action starts there; freeze precedes completion.

    A successful harmful action is atomic. A4 resource checks happen at start;
    a freeze can additionally interrupt an already started A4 work unit.
    """
    validate_calibration(calibration); validate_profile(profile)
    require(type(seed) is int, "integer seed required")
    _number(network_delay_ms, "interface delay"); _number(action_interval_ms, "action interval")
    binding = binding_for(profile["family"], row)
    timeline = _timeline(calibration, profile, seed, row, network_delay_ms)
    warning = profile.get("warning", "valid")
    applies = binding is not None and warning == "valid" and not profile.get("request_rejected", False)
    # S-A's named relay is absent from the baseline allowlist. Preserve no-change.
    no_change = applies and profile["family"] == "S-A"
    if no_change:
        applies = False
    decision = None
    if binding:
        decision = ("rejected" if not applies else "timed_out" if profile.get("observation_missing", False)
                    or timeline["effect_observed_at_ms"] > timeline["deadline_at_ms"] else "accepted")
    scheduled_effect = timeline.get("effect_at_ms") if applies else None
    if not applies and timeline:
        for key in ("persisted_at_ms", "effect_at_ms", "effect_observed_at_ms", "binding_lag_ms"):
            timeline[key] = None
    if profile.get("observation_missing", False) and timeline:
        timeline["effect_observed_at_ms"] = None
    if warning != "valid":
        timeline = {}  # no validated request and no fabricated submission
    if timeline:
        timeline["runtime_decision_at_ms"] = (timeline["submitted_at_ms"] if decision == "rejected" else
            timeline["deadline_at_ms"] if decision == "timed_out" else timeline["effect_observed_at_ms"])

    queue: list[tuple[float, int, int, str, Any]] = []
    sequence = 0
    events: list[dict[str, Any]] = []

    def push(at: float, priority: int, kind: str, payload: Any = None) -> None:
        nonlocal sequence
        sequence += 1
        heapq.heappush(queue, (at, priority, sequence, kind, payload))

    if binding and warning == "valid":
        for key in ("detected_at_ms", "signed_at_ms", "tcx_arrival_at_ms", "ready_at_ms", "submitted_at_ms"):
            push(timeline[key], 0, key)
        if scheduled_effect is not None:
            push(scheduled_effect, 0, "binding_effect")
            if timeline["effect_observed_at_ms"] is not None:
                push(timeline["effect_observed_at_ms"], 0, "effect_observed")
        push(timeline["runtime_decision_at_ms"], 0, "runtime_decision", decision)
    effective = False
    stopped = False
    first_block = None
    harmful = [{"id": a["id"], "disposition": "not_triggered" if a["representable"] else "not_representable"}
               for a in profile["harmful"]]
    work = {a["id"]: {"id": a["id"], "disposition": "not_triggered" if a["representable"] else "not_representable"}
            for a in profile["a4"]}

    def blocked(action: dict[str, Any]) -> str | None:
        if row != "E0" and action["e1_denied"]:
            return "baseline_policy"
        if not effective:
            return None
        action_type = binding["abstract_action"]
        if action_type == "freeze_sandbox":
            return "sandbox_paused"
        if action_type == "deny_egress" and profile["target"] in action["targets"]:
            return "egress_denied"
        if action_type == "revoke_credential" and profile["provider"] in action["providers"]:
            return "provider_detached"
        return None

    def stop(at: float) -> None:
        nonlocal stopped
        if stopped:
            return
        stopped = True
        events.append({"at_ms": at, "event": "harmful_branch_stopped"})
        for item in profile["a4"]:
            if item["representable"]:
                push(at + profile["a4_after_stop_ms"] + item["offset_ms"], 1, "a4_start", item)

    push(action_interval_ms, 1, "harmful", 0)
    while queue:
        at, _, _, kind, payload = heapq.heappop(queue)
        event = {"at_ms": at, "event": kind}
        if kind == "binding_effect":
            effective = True
        elif kind == "harmful":
            index = payload
            action = profile["harmful"][index]
            result = harmful[index]
            if not action["representable"]:
                if index > 0 and index < 3:
                    push(at + profile["retry_intervals_ms"][index], 1, "harmful", index + 1)
                else:
                    stop(at)
            else:
                reason = blocked(action)
                result.update(at_ms=at, disposition="executed", result="denied" if reason else "succeeded",
                              denial_reason=reason)
                event.update(action=action["id"], result=result["result"], denial_reason=reason)
                if reason and first_block is None:
                    first_block = at
                if reason and index < 3:
                    push(at + profile["retry_intervals_ms"][index], 1, "harmful", index + 1)
                else:
                    stop(at)
        elif kind == "a4_start":
            reason = blocked(payload)
            result = work[payload["id"]]
            result.update(started_at_ms=at, disposition="executed", result="blocked" if reason else "running",
                          denial_reason=reason)
            event.update(action=payload["id"], result=result["result"])
            if not reason:
                push(at + payload["duration_ms"], 2, "a4_complete", payload)
        elif kind == "a4_complete":
            interrupted = effective and binding["abstract_action"] == "freeze_sandbox"
            work[payload["id"]].update(completed_at_ms=at if not interrupted else None,
                                       result="interrupted_by_freeze" if interrupted else "completed")
            event.update(action=payload["id"], result=work[payload["id"]]["result"])
        elif kind == "runtime_decision":
            event["decision"] = payload
        events.append(event)
    # A nonrepresentable A0 cannot create a denial-driven retry.
    executed = sum(a.get("result") == "succeeded" for a in harmful)
    baseline = int(profile["harmful"][0]["representable"])
    prevented = baseline - executed
    a0_denied = harmful[0].get("result") == "denied"
    if binding is None or warning == "no_warning":
        outcome = "no_warning"
    elif warning == "protocol_rejected":
        outcome = "protocol_rejected"
    elif not executed and first_block is not None:
        outcome = "prospective_prevention"
    elif scheduled_effect is not None and timeline["effect_at_ms"] <= action_interval_ms:
        outcome = "forensic_or_monitor_only"
    elif timeline.get("tcx_arrival_at_ms", math.inf) <= action_interval_ms:
        outcome = "forensic_or_monitor_only"
    else:
        outcome = "too_late_for_affected_action"
    require(outcome in OUTCOMES, "outcome partition")
    identity = {"script_id": profile["script_id"], "script_sha256": digest(profile),
                "family": profile["family"], "row": row, "seed": seed,
                "network_delay_ms": network_delay_ms, "action_interval_ms": action_interval_ms}
    return {**identity, "episode_id": digest(identity), "synthetic": True,
            "timing_outcome": outcome, "runtime_decision": decision,
            "runtime_decision_reason": "absent_entry_no_change" if no_change else
                "no_validated_request" if binding and warning != "valid" else None,
            "binding": binding, "submission_condition": None if not binding else
                {"mode": "b" if row.endswith("-b") else "a", "D_ms": calibration["D_ms"] if row.endswith("-b") else 0,
                 "tag": "harness" if row.endswith("-b") else None,
                 "basis": "simulated operator latency; attentive operator always approves"},
            "timeline_ms": timeline,
            "time_to_detect_ms": timeline["detected_at_ms"] - action_interval_ms if timeline else None,
            "time_to_block_ms": first_block - action_interval_ms if first_block is not None else None,
            "a0_prevented": a0_denied, "harmful_actions_executed": executed,
            "harmful_actions_prevented": prevented,
            "damage_prevented": ratio(prevented, baseline),
            "useful_work": ratio(sum(w.get("result") == "completed" for w in work.values()), len(work)),
            "harmful_attempts": harmful, "a4_work": list(work.values()), "events": events}


def _frontier(episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    keys = sorted({(e["family"], e["script_id"], e["row"]) for e in episodes})
    for family, script, row in keys:
        selected = [e for e in episodes if (e["family"], e["script_id"], e["row"]) == (family, script, row)]
        spread = [{"network_delay_ms": e["network_delay_ms"], "action_interval_ms": e["action_interval_ms"],
                   "seed": e["seed"], "useful_work": e["useful_work"], "damage_prevented": e["damage_prevented"]}
                  for e in selected]
        result.append({"family": family, "script_id": script, "row": row, "binding": selected[0]["binding"],
                       **{metric: ratio(sum(e[metric]["numerator"] for e in selected),
                                        sum(e[metric]["denominator"] for e in selected))
                          for metric in ("useful_work", "damage_prevented")}, "grid_spread": spread})
    return result


def simulate_grid(calibration: dict[str, Any], profiles: Iterable[dict[str, Any]], *, seed: int,
                  action_intervals_ms: Iterable[float] = PROVISIONAL_INTERVALS_MS,
                  network_delays_ms: Iterable[float] = NETWORK_DELAYS_MS) -> dict[str, Any]:
    """The study grid is exactly 4x4, with all seven rows in every family/cell."""
    profiles = list(profiles)
    require(len(profiles) == 3 and {p["family"] for p in profiles} == set(FAMILIES), "one profile per family required")
    intervals, delays = list(action_intervals_ms), list(network_delays_ms)
    require(len(intervals) == 4 and intervals == sorted(set(intervals)), "four increasing action intervals required")
    require(delays == list(NETWORK_DELAYS_MS), "004 interface-delay axis required")
    return _simulate_cells(calibration, profiles, seed, intervals, delays)


def _simulate_cells(calibration, profiles, seed, intervals, delays):
    episodes = [simulate_episode(calibration, profile, seed=seed, row=row,
                                 network_delay_ms=delay, action_interval_ms=interval)
                for profile in sorted(profiles, key=lambda p: p["family"])
                for delay in delays for interval in intervals for row in ROWS]
    # Explicitly anchor damage denominators to the E0 execution from the SAME cell/script/seed.
    anchors = {(e["family"], e["network_delay_ms"], e["action_interval_ms"]): e
               for e in episodes if e["row"] == "E0"}
    for e in episodes:
        anchor = anchors[e["family"], e["network_delay_ms"], e["action_interval_ms"]]
        denominator = anchor["harmful_actions_executed"]
        e["harmful_actions_prevented"] = denominator - e["harmful_actions_executed"]
        e["damage_prevented"] = ratio(e["harmful_actions_prevented"], denominator)
    return {"schema": "tcop.crosshost-simulation/1.0", "simulator_version": VERSION,
            "simulator_sha256": simulator_hash(), "calibration_sha256": digest(calibration),
            "calibration_status": calibration["status"], "seed": seed, "synthetic": True,
            "post_hoc": False, "grid": {"network_delays_ms": delays, "action_intervals_ms": intervals},
            "episodes": episodes, "frontier": _frontier(episodes)}


def place_grid(calibration: dict[str, Any], profiles: Iterable[dict[str, Any]], *, seed: int,
               samples: int = 1024) -> dict[str, Any]:
    """Empirical model CDF crossing of 1/2 using fixed common random numbers.

    No efficacy results are accepted. Placements use a rows and the minimum
    interface delay, excluding D; b transitions are reported separately.
    """
    validate_calibration(calibration)
    profiles = list(profiles)
    require({p["family"] for p in profiles} >= {"S-B", "S-C"}, "non-E1-blocked families required")
    require(type(samples) is int and samples >= 2, "at least two transition samples required")
    transitions = []
    for profile in sorted(profiles, key=lambda p: p["family"]):
        validate_profile(profile)
        if profile["family"] == "S-A":
            continue
        require(profile.get("warning", "valid") == "valid" and not profile.get("request_rejected", False),
                "transitions require valid applicable warnings")
        a0 = profile["harmful"][0]
        require(a0["representable"] and profile["target"] in a0["targets"]
                and (profile["family"] != "S-C" or profile["provider"] in a0["providers"]),
                "transition action must use selected target/provider")
        for row in ROWS[2:]:
            lags = sorted(_timeline(calibration, profile, seed + i, row, NETWORK_DELAYS_MS[0])["effect_at_ms"]
                          for i in range(samples))
            transitions.append({"family": profile["family"], "row": row,
                                "binding": binding_for(profile["family"], row),
                                "transition_ms": lags[math.ceil(samples / 2) - 1],
                                "sample_count": samples})
    def selected(rows):
        return [t["transition_ms"] for t in transitions if t["row"] in rows]
    harness = selected({"E2-extended-a"})
    minimum = min(selected({"E2-native-min-a"}))
    default = max(selected({"E2-native-a"}))
    require(0 < min(harness) and max(harness) < minimum, "calibration cannot separate harness/minimum-native transitions")
    first = min(harness) / 2
    second = (max(harness) + minimum) / 2
    poll = calibration["poll_ms"]["default"]
    require(max(second, minimum) < poll, "no placement inside default poll window")
    third = (max(second, minimum) + poll) / 2
    fourth = 2 * max(poll, default, third)
    return {"schema": "tcop.crosshost-grid-placement/1.0", "calibration_sha256": digest(calibration),
            "simulator_sha256": simulator_hash(), "seed": seed, "sample_count": samples,
            "reference_network_delay_ms": NETWORK_DELAYS_MS[0], "transitions": transitions,
            "rule": "half-fastest-harness; midpoint-slowest-harness/min-native; midpoint-min-native/default-window; twice-beyond-default",
            "grid": {"network_delays_ms": list(NETWORK_DELAYS_MS),
                     "action_intervals_ms": [first, second, third, fourth]},
            "sealed_eligible": calibration["status"] == "calibrated", "post_hoc": False}


def post_hoc_sweep(calibration: dict[str, Any], profiles: Iterable[dict[str, Any]], *, seed: int,
                   action_intervals_ms: Iterable[float], network_delays_ms: Iterable[float]) -> dict[str, Any]:
    profiles, intervals, delays = list(profiles), list(action_intervals_ms), list(network_delays_ms)
    require(bool(intervals) and bool(delays), "nonempty sweep axes required")
    for value in intervals + delays:
        _number(value, "sweep axis")
    require(len(profiles) == 3 and {p["family"] for p in profiles} == set(FAMILIES), "sweep family census")
    result = _simulate_cells(calibration, profiles, seed, sorted(set(intervals)), sorted(set(delays)))
    result.update(schema="tcop.crosshost-post-hoc-sweep/1.0", post_hoc=True, sealed_eligible=False)
    return result
