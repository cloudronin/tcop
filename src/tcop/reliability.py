"""Deterministic TCOP v0.3 local observer-reliability profile.

This module is deliberately separate from the frozen v0.1 and v0.2 paths.
It consumes already validated witness observations and keeps a *local* ledger
for every ``(receiver domain, observer control group, scope)`` tuple.  It has
no dependency on benchmark truth and never transfers a reliability judgement
from one control group to another.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Iterable, Mapping

from .responses import OperatingEnvelope
from .time import parse_rfc3339


MILLI = 1000
RELIABILITY_STATES = ("unknown", "normal", "suspicious", "restricted", "quarantined", "probation")
PATROL_OUTCOMES = ("passed", "failed", "inconclusive", "not_performed", "unavailable", "expired", "nonconforming")
THREAT_TYPES = {"tool.prohibited_export", "memory.contamination", "patrol.challenge_failure"}
CLEAN_TYPES = {"patrol.clean_result", "attestation.result", "recovery.clean_checkpoint"}


def _clamp(value: int, lower: int = 0, upper: int = MILLI) -> int:
    return max(lower, min(upper, int(value)))


def multiply_milli(*factors: int) -> int:
    """Multiply fixed-point factors left-to-right, flooring at each step."""

    result = MILLI
    for factor in factors:
        result = (result * _clamp(factor)) // MILLI
    return result


@dataclass(frozen=True)
class ReliabilityProfile:
    """Checked-in reference-profile parameters; none are protocol constants."""

    profile_id: str = "high-risk-v0.3"
    unknown_state_factor: int = 400
    normal_state_factor: int = 1000
    suspicious_state_factor: int = 500
    restricted_state_factor: int = 200
    quarantined_state_factor: int = 0
    probation_start_factor: int = 100
    probation_step_factor: int = 100
    probation_max_factor: int = 900
    probation_minimum_duration: int = 5
    minimum_dwell: int = 5
    positive_clean_increment: int = 500
    negative_increment: int = 500
    severe_negative_increment: int = 1200
    positive_decay_per_interval: int = 25
    negative_decay_per_interval: int = 10
    confidence_decay_per_interval: int = 20
    normal_threshold: int = 800
    suspicious_threshold: int = 500
    restricted_threshold: int = 900
    constraint_threshold: int = 700
    quarantine_threshold: int = 1800
    minimum_contributor_influence: int = 400
    minimum_quarantine_diversity: int = 3
    group_contribution_cap: int = 1000
    scope_separation: bool = True
    enforce_group_cap: bool = True
    hysteresis: bool = True
    observation_freshness: bool = True
    reliability_decay: bool = True
    direct_local_constraint: bool = True

    def state_factor(self, state: str, now: int, record: "ReliabilityRecord") -> int:
        if state == "probation":
            elapsed = max(0, now - (record.probation_started_at or record.state_since))
            return min(self.probation_max_factor, self.probation_start_factor + elapsed * self.probation_step_factor)
        return {
            "unknown": self.unknown_state_factor,
            "normal": self.normal_state_factor,
            "suspicious": self.suspicious_state_factor,
            "restricted": self.restricted_state_factor,
            "quarantined": self.quarantined_state_factor,
        }[state]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReliabilityInput:
    """Locally verifiable input used to assess an issuer, never benchmark truth."""

    event_id: str
    local_domain_id: str
    observer_control_group_id: str
    scope: str
    kind: str
    at: int
    supporting_observation_ids: tuple[str, ...] = ()
    contradicting_observation_ids: tuple[str, ...] = ()
    independent: bool = True
    patrol_outcome: str | None = None
    accused_control_group_id: str | None = None
    compromise_observation_ids: tuple[str, ...] = ()
    compromise_start: int | None = None
    compromise_end: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_version": "tcop.reliability-input/0.1",
            "event_id": self.event_id,
            "local_domain_id": self.local_domain_id,
            "observer_control_group_id": self.observer_control_group_id,
            "scope": self.scope,
            "kind": self.kind,
            "at": self.at,
            "supporting_observation_ids": list(self.supporting_observation_ids),
            "contradicting_observation_ids": list(self.contradicting_observation_ids),
            "independent": self.independent,
            "patrol_outcome": self.patrol_outcome,
            "accused_control_group_id": self.accused_control_group_id,
            "compromise_observation_ids": list(self.compromise_observation_ids),
            "compromise_start": self.compromise_start,
            "compromise_end": self.compromise_end,
        }


@dataclass(frozen=True)
class CompromiseWindow:
    """An explicit and bounded retrospective re-evaluation authorisation."""

    window_id: str
    local_domain_id: str
    observer_control_group_id: str
    scope: str
    observation_ids: tuple[str, ...]
    start: int
    end: int
    reason: str

    def affects(self, observation: Mapping[str, Any]) -> bool:
        """Both an explicit identity and an inclusive time interval are required."""

        if observation.get("observation_id") not in self.observation_ids:
            return False
        try:
            issued = parse_rfc3339(str(observation["issued_at"]))
        except (KeyError, ValueError):
            return False
        return self.start <= issued <= self.end

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_version": "tcop.compromise-window/0.1",
            "window_id": self.window_id,
            "local_domain_id": self.local_domain_id,
            "observer_control_group_id": self.observer_control_group_id,
            "scope": self.scope,
            "observation_ids": list(self.observation_ids),
            "start": self.start,
            "end": self.end,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ReliabilityRecord:
    local_domain_id: str
    observer_control_group_id: str
    scope: str
    issuer_state: str = "unknown"
    reliability_factor_milli: int = 400
    confidence_milli: int = 400
    positive_evidence_accumulator: int = 0
    negative_evidence_accumulator: int = 0
    state_since: int = 0
    last_updated: int = 0
    minimum_dwell_until: int = 0
    probation_started_at: int | None = None
    probation_target_end: int | None = None
    supporting_observation_ids: tuple[str, ...] = ()
    contradicting_observation_ids: tuple[str, ...] = ()
    transition_reason: str = "initial_unknown"
    policy_profile: str = "high-risk-v0.3"

    def as_dict(self, *, now: int, profile: ReliabilityProfile) -> dict[str, Any]:
        value = asdict(self)
        value.update(
            {
                "record_version": "tcop.observer-reliability/0.1",
                "reliability_factor_milli": _clamp(self.reliability_factor_milli),
                "confidence_milli": _clamp(self.confidence_milli),
                "issuer_state_factor_milli": profile.state_factor(self.issuer_state, now, self),
                "supporting_observation_ids": list(self.supporting_observation_ids),
                "contradicting_observation_ids": list(self.contradicting_observation_ids),
            }
        )
        return value


class VersionedReliabilityValidator:
    """Strict dispatcher for v0.3-derived local artifact records.

    Wire observations remain owned by the frozen v0.2 validator.  This
    dispatcher validates only the new receiver-local records and makes that
    profile boundary explicit.
    """

    def validate(self, payload: Mapping[str, Any]) -> tuple[bool, str]:
        if payload.get("event_version") == "tcop.reliability-input/0.1":
            required = {"event_id", "local_domain_id", "observer_control_group_id", "scope", "kind", "at", "supporting_observation_ids", "independent"}
            if required <= set(payload) and payload.get("kind") in {"clean", "negative", "severe_compromise", "recovery", "unavailable", "nonconforming", "accusation"} and isinstance(payload.get("at"), int):
                return True, "reliability_input_valid"
            return False, "reliability_input_invalid"
        if payload.get("record_version") == "tcop.observer-reliability/0.1":
            if payload.get("issuer_state") in RELIABILITY_STATES and all(isinstance(payload.get(key), int) and 0 <= int(payload[key]) <= MILLI for key in ("reliability_factor_milli", "confidence_milli")):
                return True, "reliability_record_valid"
            return False, "reliability_record_invalid"
        if payload.get("window_version") == "tcop.compromise-window/0.1":
            observations = payload.get("observation_ids")
            if isinstance(observations, list) and observations and isinstance(payload.get("start"), int) and isinstance(payload.get("end"), int) and int(payload["start"]) <= int(payload["end"]):
                return True, "compromise_window_valid"
            return False, "compromise_window_invalid"
        return False, "unsupported_reliability_version"


@dataclass(frozen=True)
class Influence:
    observation_id: str
    observer_control_group_id: str
    scope: str
    effective_influence_milli: int
    factors: Mapping[str, int]
    issuer_state: str
    retroactively_discounted: bool = False
    cap_applied: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "observer_control_group_id": self.observer_control_group_id,
            "scope": self.scope,
            "effective_influence_milli": self.effective_influence_milli,
            "factors": dict(self.factors),
            "issuer_state": self.issuer_state,
            "retroactively_discounted": self.retroactively_discounted,
            "cap_applied": self.cap_applied,
        }


class ReliabilityLedger:
    """Append-only local reliability state with snapshot-isolated batch updates."""

    def __init__(self, local_domain_id: str, profile: ReliabilityProfile = ReliabilityProfile()) -> None:
        self.local_domain_id = local_domain_id
        self.profile = profile
        self._records: dict[tuple[str, str], ReliabilityRecord] = {}
        self.transitions: list[dict[str, Any]] = []
        self.input_events: list[dict[str, Any]] = []
        self.probation_events: list[dict[str, Any]] = []
        self.validator = VersionedReliabilityValidator()

    def _scope_key(self, scope: str) -> str:
        return scope if self.profile.scope_separation else "*"

    def _key(self, observer_control_group_id: str, scope: str) -> tuple[str, str]:
        return observer_control_group_id, self._scope_key(scope)

    def _initial(self, observer_control_group_id: str, scope: str, now: int) -> ReliabilityRecord:
        return ReliabilityRecord(
            local_domain_id=self.local_domain_id,
            observer_control_group_id=observer_control_group_id,
            scope=self._scope_key(scope),
            state_since=now,
            last_updated=now,
            minimum_dwell_until=now,
            policy_profile=self.profile.profile_id,
        )

    def get(self, observer_control_group_id: str, scope: str, now: int) -> ReliabilityRecord:
        return self._records.get(self._key(observer_control_group_id, scope), self._initial(observer_control_group_id, scope, now))

    def snapshot(self) -> dict[tuple[str, str], ReliabilityRecord]:
        return deepcopy(self._records)

    def seed(
        self,
        observer_control_group_id: str,
        scope: str,
        *,
        state: str = "normal",
        now: int = 0,
        reliability_factor_milli: int | None = None,
        confidence_milli: int | None = None,
    ) -> None:
        if state not in RELIABILITY_STATES:
            raise ValueError("invalid reliability state")
        factor = self.profile.state_factor(state, now, self._initial(observer_control_group_id, scope, now))
        record = ReliabilityRecord(
            local_domain_id=self.local_domain_id,
            observer_control_group_id=observer_control_group_id,
            scope=self._scope_key(scope),
            issuer_state=state,
            reliability_factor_milli=_clamp(factor if reliability_factor_milli is None else reliability_factor_milli),
            confidence_milli=_clamp(factor if confidence_milli is None else confidence_milli),
            positive_evidence_accumulator=self.profile.normal_threshold if state == "normal" else 0,
            negative_evidence_accumulator=self.profile.restricted_threshold if state in {"restricted", "quarantined"} else 0,
            state_since=now,
            last_updated=now,
            minimum_dwell_until=now + (self.profile.minimum_dwell if state != "normal" else 0),
            probation_started_at=now if state == "probation" else None,
            probation_target_end=now + self.profile.probation_minimum_duration if state == "probation" else None,
            transition_reason="seeded_for_deterministic_scenario",
            policy_profile=self.profile.profile_id,
        )
        self._records[self._key(observer_control_group_id, scope)] = record

    def _decayed(self, record: ReliabilityRecord, now: int) -> ReliabilityRecord:
        elapsed = max(0, now - record.last_updated)
        if not elapsed:
            return record
        if not self.profile.reliability_decay:
            return replace(record, last_updated=now)
        positive = max(0, record.positive_evidence_accumulator - elapsed * self.profile.positive_decay_per_interval)
        negative = max(0, record.negative_evidence_accumulator - elapsed * self.profile.negative_decay_per_interval)
        confidence = max(0, record.confidence_milli - elapsed * self.profile.confidence_decay_per_interval)
        reliability = _clamp((positive + 400 - negative // 2 + confidence) // 2)
        state = record.issuer_state
        reason = record.transition_reason
        probation_started = record.probation_started_at
        probation_end = record.probation_target_end
        if state == "probation" and now >= (probation_end or now) and positive >= self.profile.normal_threshold and negative < self.profile.suspicious_threshold:
            state, reason, probation_started, probation_end = "normal", "probation_completed", None, None
        elif state == "normal" and confidence == 0:
            state, reason = "unknown", "confidence_decayed_to_uncertainty"
        return replace(
            record,
            issuer_state=state,
            reliability_factor_milli=reliability,
            confidence_milli=confidence,
            positive_evidence_accumulator=positive,
            negative_evidence_accumulator=negative,
            last_updated=now,
            probation_started_at=probation_started,
            probation_target_end=probation_end,
            transition_reason=reason,
        )

    def advance(self, now: int) -> None:
        """Advance decay/ramp without creating evidence or cross-group effects."""

        for key, before in sorted(self._records.items()):
            after = self._decayed(before, now)
            self._records[key] = after
            if after.issuer_state != before.issuer_state:
                self._transition(before, after, now, "time_based_decay_or_probation")

    def _evaluate_input(self, event: ReliabilityInput, snapshot: Mapping[tuple[str, str], ReliabilityRecord]) -> dict[str, Any]:
        if event.local_domain_id != self.local_domain_id:
            raise ValueError("reliability input belongs to a different receiver")
        if event.kind not in {"clean", "negative", "severe_compromise", "recovery", "unavailable", "nonconforming", "accusation"}:
            raise ValueError("invalid reliability input kind")
        if event.patrol_outcome is not None and event.patrol_outcome not in PATROL_OUTCOMES:
            raise ValueError("invalid patrol outcome")
        record = snapshot.get(self._key(event.observer_control_group_id, event.scope), self._initial(event.observer_control_group_id, event.scope, event.at))
        # An unsupported accusation is retained for graphing, but cannot change
        # reliability.  This prevents circular/transitive reputation cascades.
        independent = event.independent and event.kind != "accusation"
        positive = self.profile.positive_clean_increment if event.kind == "clean" and independent else 0
        negative = 0
        severe = False
        if event.kind in {"negative", "nonconforming"} and independent:
            negative = self.profile.negative_increment
        if event.kind == "severe_compromise" and independent:
            negative, severe = self.profile.severe_negative_increment, True
        if event.kind == "recovery" and independent:
            positive = self.profile.positive_clean_increment
        if event.kind in {"unavailable", "accusation"}:
            positive = negative = 0
        # A nonconforming patrol is explicitly negative even if it found a real
        # subject issue; target truth is unavailable here by construction.
        if event.patrol_outcome in {"unavailable", "not_performed", "expired", "inconclusive"}:
            positive = 0
        if event.patrol_outcome == "nonconforming":
            negative = self.profile.negative_increment
        return {
            "event": event,
            "pre_state": record.issuer_state,
            "pre_reliability_factor_milli": record.reliability_factor_milli,
            "pre_state_factor_milli": self.profile.state_factor(record.issuer_state, event.at, record),
            "positive_delta": positive,
            "negative_delta": negative,
            "severe": severe,
        }

    def _next_record(self, before: ReliabilityRecord, evaluations: list[dict[str, Any]], now: int) -> ReliabilityRecord:
        positive = before.positive_evidence_accumulator + sum(item["positive_delta"] for item in evaluations)
        negative = before.negative_evidence_accumulator + sum(item["negative_delta"] for item in evaluations)
        has_recovery = any(item["event"].kind == "recovery" and item["positive_delta"] for item in evaluations)
        severe = any(item["severe"] for item in evaluations)
        state = before.issuer_state
        reason = before.transition_reason
        probation_started = before.probation_started_at
        probation_end = before.probation_target_end
        dwell_allows = (not self.profile.hysteresis) or now >= before.minimum_dwell_until
        if severe:
            state, reason = "quarantined", "independent_severe_compromise"
        elif state == "quarantined":
            if has_recovery and dwell_allows:
                state, reason = "probation", "verified_recovery_enters_probation"
                probation_started, probation_end = now, now + self.profile.probation_minimum_duration
            else:
                # Decay or a too-early recovery cannot silently downgrade a
                # quarantined issuer before its minimum dwell is complete.
                state, reason = "quarantined", "minimum_dwell_preserves_quarantine"
        elif state in {"restricted", "suspicious"} and has_recovery and dwell_allows:
            state, reason = "probation", "verified_recovery_enters_probation"
            probation_started, probation_end = now, now + self.profile.probation_minimum_duration
        elif state == "probation" and any(item["negative_delta"] for item in evaluations):
            state, reason = "restricted", "negative_evidence_reverses_probation"
            probation_started, probation_end = None, None
        elif state == "probation":
            # Historical negative evidence remains in the audit record, but a
            # clean probation interval does not itself undo the recovery ramp.
            state, reason = "probation", "probation_ramp_continues"
        elif negative >= self.profile.restricted_threshold:
            state, reason = "restricted", "independent_negative_evidence_threshold"
        elif negative >= self.profile.suspicious_threshold:
            state, reason = "suspicious", "independent_negative_evidence_threshold"
        elif before.issuer_state == "unknown" and positive >= self.profile.normal_threshold:
            state, reason = "normal", "sufficient_independent_clean_evidence"
        reliability = _clamp((positive + 400 - negative // 2 + min(MILLI, before.confidence_milli + positive // 4)) // 2)
        if state == "quarantined":
            reliability = 0
        if state == "probation":
            reliability = min(reliability, self.profile.state_factor("probation", now, before))
        confidence = _clamp(before.confidence_milli + sum(item["positive_delta"] for item in evaluations) // 2 - sum(item["negative_delta"] for item in evaluations) // 2)
        return ReliabilityRecord(
            local_domain_id=before.local_domain_id,
            observer_control_group_id=before.observer_control_group_id,
            scope=before.scope,
            issuer_state=state,
            reliability_factor_milli=reliability,
            confidence_milli=confidence,
            positive_evidence_accumulator=positive,
            negative_evidence_accumulator=negative,
            state_since=before.state_since if state == before.issuer_state else now,
            last_updated=now,
            minimum_dwell_until=(before.minimum_dwell_until if state == before.issuer_state else now + (self.profile.minimum_dwell if state != "normal" else 0)),
            probation_started_at=probation_started,
            probation_target_end=probation_end,
            supporting_observation_ids=tuple(sorted({*before.supporting_observation_ids, *(oid for item in evaluations for oid in item["event"].supporting_observation_ids)})),
            contradicting_observation_ids=tuple(sorted({*before.contradicting_observation_ids, *(oid for item in evaluations for oid in item["event"].contradicting_observation_ids)})),
            transition_reason=reason,
            policy_profile=self.profile.profile_id,
        )

    def _transition(self, before: ReliabilityRecord, after: ReliabilityRecord, now: int, reason: str) -> None:
        self.transitions.append(
            {
                "transition_version": "tcop.reliability-transition/0.1",
                "local_domain_id": self.local_domain_id,
                "observer_control_group_id": after.observer_control_group_id,
                "scope": after.scope,
                "at": now,
                "from_state": before.issuer_state,
                "to_state": after.issuer_state,
                "reason": reason,
                "supporting_observation_ids": list(after.supporting_observation_ids),
                "contradicting_observation_ids": list(after.contradicting_observation_ids),
            }
        )
        if after.issuer_state == "probation":
            self.probation_events.append({"event_type": "probation_entered", "at": now, "observer_control_group_id": after.observer_control_group_id, "scope": after.scope, "factor_milli": self.profile.state_factor("probation", now, after)})

    def apply_batch(self, events: Iterable[ReliabilityInput]) -> None:
        """Evaluate every same-time input against one frozen pre-batch ledger.

        All results are committed only after evaluation.  Therefore an event
        cannot influence its own effective weight or a sibling event's weight.
        """

        ordered = sorted(events, key=lambda item: (item.at, item.event_id))
        index = 0
        while index < len(ordered):
            at = ordered[index].at
            batch: list[ReliabilityInput] = []
            while index < len(ordered) and ordered[index].at == at:
                batch.append(ordered[index])
                index += 1
            for event in batch:
                valid, code = self.validator.validate(event.as_dict())
                if not valid:
                    raise ValueError(code)
            self.advance(at)
            snapshot = self.snapshot()
            evaluations = [self._evaluate_input(event, snapshot) for event in batch]
            grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for evaluation in evaluations:
                event = evaluation["event"]
                grouped.setdefault(self._key(event.observer_control_group_id, event.scope), []).append(evaluation)
                self.input_events.append(
                    {
                        **event.as_dict(),
                        "pre_batch_state": evaluation["pre_state"],
                        "pre_batch_reliability_factor_milli": evaluation["pre_reliability_factor_milli"],
                        "pre_batch_state_factor_milli": evaluation["pre_state_factor_milli"],
                        "positive_delta": evaluation["positive_delta"],
                        "negative_delta": evaluation["negative_delta"],
                    }
                )
            committed: dict[tuple[str, str], ReliabilityRecord] = {}
            for key, group in sorted(grouped.items()):
                sample = group[0]["event"]
                before = snapshot.get(key, self._initial(sample.observer_control_group_id, sample.scope, at))
                committed[key] = self._next_record(before, group, at)
            # Atomic replacement follows complete evaluation of this time batch.
            self._records.update(committed)
            for key, after in sorted(committed.items()):
                before = snapshot.get(key, self._initial(after.observer_control_group_id, after.scope, at))
                if before.issuer_state != after.issuer_state:
                    self._transition(before, after, at, after.transition_reason)

    def records(self, now: int) -> list[dict[str, Any]]:
        self.advance(now)
        return [record.as_dict(now=now, profile=self.profile) for _, record in sorted(self._records.items())]


class WeightedResolver:
    """Scope-aware local resolver using ledger snapshots and explicit factors."""

    def __init__(self, local_domain_id: str, ledger: ReliabilityLedger) -> None:
        self.local_domain_id = local_domain_id
        self.ledger = ledger
        self.events: list[dict[str, Any]] = []
        self._issued_evaluations: dict[str, Influence] = {}

    def _scope(self, observation: Mapping[str, Any]) -> str:
        scope = observation.get("scope", ())
        return str(scope[0]) if scope else "unknown"

    def _freshness(self, observation: Mapping[str, Any], now: int) -> int:
        if not self.ledger.profile.observation_freshness:
            return MILLI
        try:
            issued = parse_rfc3339(str(observation["issued_at"]))
            expires = parse_rfc3339(str(observation["expires_at"]))
        except (KeyError, ValueError):
            return 0
        if now > expires:
            return 0
        lifetime = max(1, expires - issued)
        return _clamp(((expires - now) * MILLI) // lifetime)

    @staticmethod
    def _receipt_quality(observation: Mapping[str, Any]) -> int:
        if not observation.get("receipt_verified"):
            return 0
        return {
            "bilateral": 1000,
            "unilateral_transport": 700,
            "third_party_witnessed": 850,
            "none": 0,
        }.get(str(observation.get("receipt_mode")), 0)

    def _new_influence(self, observation: Mapping[str, Any], now: int) -> Influence:
        scope = self._scope(observation)
        group = str(observation.get("observer_control_group_id", "unknown"))
        record = self.ledger.get(group, scope, now)
        authority = 0 if observation.get("metadata", {}).get("scope_authorized") is False else MILLI
        factors = {
            "scope_authority_milli": authority,
            "evidence_quality_milli": self._receipt_quality(observation),
            "freshness_milli": self._freshness(observation, now),
            "observer_reliability_milli": record.reliability_factor_milli,
            "issuer_state_factor_milli": self.ledger.profile.state_factor(record.issuer_state, now, record),
            "independence_factor_milli": MILLI if observation.get("effective_evidence_class") in {"independent_peer", "neutral_third_party"} else 0,
        }
        return Influence(
            observation_id=str(observation["observation_id"]),
            observer_control_group_id=group,
            scope=scope,
            effective_influence_milli=multiply_milli(*factors.values()),
            factors=factors,
            issuer_state=record.issuer_state,
        )

    def evaluate(self, observation: Mapping[str, Any], now: int, windows: Iterable[CompromiseWindow] = ()) -> Influence:
        observation_id = str(observation["observation_id"])
        # Default treatment is prospective: retain the factor applied when this
        # receiver first saw the immutable observation.
        influence = self._issued_evaluations.get(observation_id)
        if influence is None:
            influence = self._new_influence(observation, now)
            self._issued_evaluations[observation_id] = influence
        matching = [window for window in windows if window.local_domain_id == self.local_domain_id and window.observer_control_group_id == influence.observer_control_group_id and (window.scope == influence.scope or window.scope == "*") and window.affects(observation)]
        if matching:
            factors = {**influence.factors, "compromise_window_milli": 0}
            return replace(influence, effective_influence_milli=0, factors=factors, retroactively_discounted=True)
        return influence

    def resolve(
        self,
        subject_id: str,
        observations: Iterable[Mapping[str, Any]],
        now: int,
        windows: Iterable[CompromiseWindow] = (),
    ) -> tuple[OperatingEnvelope, dict[str, Any]]:
        relevant = [item for item in observations if item.get("subject", {}).get("id") == subject_id]
        active = [item for item in relevant if self._freshness(item, now) > 0]
        threats = [item for item in active if item.get("observation_type") in THREAT_TYPES and item.get("severity") in {"high", "critical"}]
        clean = [item for item in active if item.get("observation_type") in CLEAN_TYPES]
        influences = [self.evaluate(item, now, windows) for item in threats]
        group_values: dict[str, list[Influence]] = {}
        for item in influences:
            group_values.setdefault(item.observer_control_group_id, []).append(item)
        capped: list[Influence] = []
        for group, values in sorted(group_values.items()):
            if self.ledger.profile.enforce_group_cap:
                strongest = max(values, key=lambda item: (item.effective_influence_milli, item.observation_id))
                cap = min(self.ledger.profile.group_contribution_cap, strongest.effective_influence_milli)
                capped.append(replace(strongest, effective_influence_milli=cap, cap_applied=len(values) > 1 or cap != strongest.effective_influence_milli))
            else:
                capped.extend(values)
        qualified = [item for item in capped if item.effective_influence_milli >= self.ledger.profile.minimum_contributor_influence and item.issuer_state != "probation"]
        total = sum(item.effective_influence_milli for item in qualified)
        direct = any(item.get("direct_local") and item.get("severity") == "critical" for item in threats)
        clean_strength = sum(self.evaluate(item, now, windows).effective_influence_milli for item in clean)
        ids = tuple(str(item["observation_id"]) for item in active)
        if self.ledger.profile.direct_local_constraint and direct:
            envelope = OperatingEnvelope("constrained", denied_capabilities=("data.export",), actions=("reduce_capability", "observe"), reasons=("direct local critical observation",), observation_ids=ids)
        elif len(qualified) >= self.ledger.profile.minimum_quarantine_diversity and total >= self.ledger.profile.quarantine_threshold and clean_strength < self.ledger.profile.constraint_threshold:
            envelope = OperatingEnvelope("quarantined", denied_capabilities=("*",), actions=("quarantine",), reasons=("weighted independent corroboration",), observation_ids=ids)
        elif total >= self.ledger.profile.constraint_threshold:
            envelope = OperatingEnvelope("constrained", denied_capabilities=("data.export",), actions=("reduce_capability", "observe"), reasons=("weighted evidence threshold",), observation_ids=ids)
        elif threats:
            envelope = OperatingEnvelope("suspicious", actions=("observe",), reasons=("insufficient weighted threat evidence",), observation_ids=ids)
        elif clean:
            envelope = OperatingEnvelope("healthy", actions=("allow",), reasons=("clean admissible evidence",), observation_ids=ids)
        else:
            envelope = OperatingEnvelope("approval_gated", denied_capabilities=("financial.transfer", "memory.write"), actions=("observe", "require_approval"), reasons=("no evidence is not clean evidence",), observation_ids=())
        resolution = {
            "resolution_version": "tcop.weighted-resolution/0.1",
            "local_domain_id": self.local_domain_id,
            "subject_id": subject_id,
            "at": now,
            "state": envelope.state,
            "thresholds": {
                "constraint_milli": self.ledger.profile.constraint_threshold,
                "quarantine_milli": self.ledger.profile.quarantine_threshold,
                "minimum_contributor_milli": self.ledger.profile.minimum_contributor_influence,
                "minimum_diversity": self.ledger.profile.minimum_quarantine_diversity,
            },
            "influences": [item.as_dict() for item in sorted(capped, key=lambda item: item.observation_id)],
            "total_qualified_influence_milli": total,
            "qualified_control_groups": sorted(item.observer_control_group_id for item in qualified),
            "contradictory_clean_influence_milli": clean_strength,
            "direct_local": direct,
            "reason": envelope.reasons[0],
            "state_and_dwell": [record for record in self.ledger.records(now)],
        }
        self.events.append(resolution)
        return envelope, resolution


def explanation_markdown(resolutions: Iterable[Mapping[str, Any]]) -> str:
    """Human-readable counterpart to the immutable weighted-resolution stream."""

    lines = ["# v0.3 weighted decision explanations", ""]
    for resolution in resolutions:
        lines.extend([f"## {resolution['local_domain_id']} / {resolution['subject_id']} at {resolution['at']}", ""])
        if not resolution["influences"]:
            lines.extend([f"Result: **{resolution['state']}** — {resolution['reason']}.", ""])
            continue
        for influence in resolution["influences"]:
            factors = influence["factors"]
            lines.append(
                f"Observation `{influence['observation_id']}` from `{influence['observer_control_group_id']}`: "
                f"influence {influence['effective_influence_milli']}/1000; scope={factors['scope_authority_milli']}, "
                f"receipt={factors['evidence_quality_milli']}, freshness={factors['freshness_milli']}, "
                f"reliability={factors['observer_reliability_milli']}, state={influence['issuer_state']} "
                f"({factors['issuer_state_factor_milli']})."
            )
        lines.extend([f"Result: **{resolution['state']}** — {resolution['reason']}; qualified total {resolution['total_qualified_influence_milli']}/1000.", ""])
    return "\n".join(lines) + "\n"


def accusation_graph(edges: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return a deterministic graph and unresolved strongly connected cycles.

    Edges are audit records only.  No cycle is converted into a reliability
    update, which keeps accusations non-transitive across control groups.
    """

    ordered = [dict(edge) for edge in sorted(edges, key=lambda edge: (str(edge.get("from_control_group_id")), str(edge.get("to_control_group_id")), str(edge.get("scope")), str(edge.get("at"))))]
    adjacency: dict[str, list[str]] = {}
    for edge in ordered:
        source = str(edge["from_control_group_id"])
        target = str(edge["to_control_group_id"])
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    cycles: set[tuple[str, ...]] = set()
    for start in sorted(adjacency):
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        while stack:
            node, path = stack.pop()
            for neighbor in sorted(adjacency.get(node, ())):
                if neighbor == start and len(path) > 1:
                    cycles.add(tuple(sorted(path)))
                elif neighbor not in path and len(path) < len(adjacency):
                    stack.append((neighbor, [*path, neighbor]))
    return {
        "graph_version": "tcop.observer-accusation-graph/0.1",
        "edges": ordered,
        "unresolved_cycles": [list(cycle) for cycle in sorted(cycles)],
        "cycle_count": len(cycles),
        "resolution_policy": "record_cycles_without_transitive_reliability_propagation",
    }
