"""Deterministic TCOP v0.4 tip-only and staged-confirmation profile.

This profile consumes validated v0.2 observations and receiver-local v0.3
reliability projections.  It does not change either wire protocol.  The two
channels below are intentionally independent: a zero-credit issuer can prompt
bounded investigation, but cannot gain corroborative authority from doing so.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .reliability import CLEAN_TYPES, THREAT_TYPES, Influence
from .responses import OperatingEnvelope


MILLI = 1000
TIP_ACTIONS = (
    "increase_monitoring",
    "launch_patrol",
    "request_independent_corroboration",
    "request_evidence_disclosure",
    "shorten_credential_ttl",
    "require_human_approval",
    "temporarily_gate_high_risk_capability",
    "no_action",
)
CONFIRMATION_TYPES = (
    "direct_local",
    "failed_independent_patrol",
    "new_independent_control_group",
    "later_independent_interaction",
    "established_compromise",
    "human_adjudication",
)


def _risk_milli(scope: str) -> int:
    if scope in {"financial.transfer", "payment.transaction"}:
        return 1000
    if scope in {"memory.write", "memory.integrity"}:
        return 850
    if scope in {"tool:data.export", "external.communication"}:
        return 800
    return 300


def _scope(observation: Mapping[str, Any]) -> str:
    values = observation.get("scope", ())
    return str(values[0]) if values else "unknown"


def _claim_family(observation: Mapping[str, Any]) -> str:
    value = str(observation.get("observation_type", "unknown"))
    if value.startswith("patrol."):
        return "prohibited_behavior"
    return value.split(".", 1)[0]


@dataclass(frozen=True)
class ConfirmationProfile:
    profile_id: str = "confirmation-high-risk-v0.4"
    tip_enabled: bool = True
    provisional_enabled: bool = True
    require_source_novelty: bool = True
    campaign_grouping: bool = True
    immediate_remote_quarantine: bool = False
    local_direct_only: bool = False
    confirmation_window: int = 3
    provisional_ttl: int = 3
    campaign_window: int = 3
    remote_minimum_diversity: int = 3
    remote_minimum_influence_milli: int = 400
    remote_threshold_milli: int = 1800
    global_investigation_budget: int = 3
    high_risk_reserved_capacity: int = 1
    per_control_group_tip_cap: int = 2
    tip_cooldown: int = 2
    maximum_approval_gate_duration: int = 3
    provisional_severity_milli: int = 700
    default_expiry_action: str = "deescalate_to_monitored"
    allow_same_source_later_interaction: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TipRecord:
    tip_id: str
    local_domain_id: str
    observation_id: str
    observer_control_group_id: str
    scope: str
    at: int
    issuer_state: str
    corroborative_influence_milli: int
    tip_value_milli: int
    eligible: bool
    reason: str
    tip_key: str

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["tip_version"] = "tcop.investigative-tip/0.1"
        return value


@dataclass(frozen=True)
class InvestigativeAction:
    action_id: str
    local_domain_id: str
    tip_id: str
    observation_ids: tuple[str, ...]
    observer_control_group_id: str
    scope: str
    action: str
    at: int
    permitted_until: int
    maximum_response_severity_milli: int
    result: str
    useful_confirmation_produced: bool = False
    protocol_cost_milli: int = 0
    utility_cost_milli: int = 0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.update({"action_version": "tcop.investigative-action/0.1", "observation_ids": list(self.observation_ids)})
        return value


@dataclass(frozen=True)
class EvidenceCampaign:
    campaign_id: str
    local_domain_id: str
    subject_id: str
    scope: str
    claim_family: str
    started_at: int
    last_seen_at: int
    observation_ids: tuple[str, ...]
    control_group_ids: tuple[str, ...]
    interaction_ids: tuple[str, ...]
    revision: int = 1
    status: str = "active"
    merged_into: str | None = None
    split_from: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.update(
            {
                "campaign_version": "tcop.evidence-campaign/0.1",
                "observation_ids": list(self.observation_ids),
                "control_group_ids": list(self.control_group_ids),
                "interaction_ids": list(self.interaction_ids),
            }
        )
        return value


@dataclass(frozen=True)
class ConfirmationRequirement:
    requirement_id: str
    local_domain_id: str
    subject_id: str
    scope: str
    campaign_id: str
    initial_observation_ids: tuple[str, ...]
    initial_control_group_ids: tuple[str, ...]
    activated_at: int
    deadline: int
    permitted_types: tuple[str, ...] = CONFIRMATION_TYPES
    source_novelty_required: bool = True
    status: str = "pending"

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.update(
            {
                "requirement_version": "tcop.confirmation-requirement/0.1",
                "initial_observation_ids": list(self.initial_observation_ids),
                "initial_control_group_ids": list(self.initial_control_group_ids),
                "permitted_types": list(self.permitted_types),
            }
        )
        return value


@dataclass(frozen=True)
class ProvisionalResponse:
    response_id: str
    local_domain_id: str
    subject_id: str
    scope: str
    campaign_id: str
    activated_at: int
    expires_at: int
    confirmation_deadline: int
    state: str = "provisionally_constrained"
    default_expiry_action: str = "deescalate_to_monitored"
    maximum_severity_milli: int = 700
    reason: str = "remote_only_initial_campaign"

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["response_version"] = "tcop.provisional-response/0.1"
        return value


@dataclass(frozen=True)
class ConfirmationEvent:
    event_id: str
    local_domain_id: str
    requirement_id: str
    observation_id: str | None
    at: int
    candidate_type: str
    source_control_group_id: str | None
    source_novel: bool
    campaign_relation: str
    accepted: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["confirmation_version"] = "tcop.confirmation-event/0.1"
        return value


class VersionedConfirmationValidator:
    """Version dispatcher for v0.4-derived local artifacts only."""

    _required = {
        "tcop.investigative-tip/0.1": ("tip_version", "tip_id", "local_domain_id", "observation_id", "scope", "eligible"),
        "tcop.investigative-action/0.1": ("action_version", "action_id", "local_domain_id", "tip_id", "scope", "action", "result"),
        "tcop.provisional-response/0.1": ("response_version", "response_id", "local_domain_id", "subject_id", "scope", "expires_at", "confirmation_deadline"),
        "tcop.confirmation-requirement/0.1": ("requirement_version", "requirement_id", "local_domain_id", "subject_id", "scope", "deadline"),
        "tcop.confirmation-event/0.1": ("confirmation_version", "event_id", "local_domain_id", "requirement_id", "candidate_type", "accepted"),
        "tcop.evidence-campaign/0.1": ("campaign_version", "campaign_id", "local_domain_id", "subject_id", "scope", "revision"),
    }

    def validate(self, payload: Mapping[str, Any]) -> tuple[bool, str]:
        for version, (field, *required) in self._required.items():
            if payload.get(field) == version:
                return (all(key in payload for key in required), "confirmation_artifact_valid" if all(key in payload for key in required) else "confirmation_artifact_invalid")
        return False, "unsupported_confirmation_version"


class DirectEmergencyRegistry:
    """Static local registry for auditable scoped direct-emergency authority."""

    def __init__(self) -> None:
        self._points: dict[str, tuple[str, ...]] = {}

    def register(self, point_id: str, scopes: Iterable[str]) -> None:
        self._points[point_id] = tuple(sorted(set(scopes)))

    def authorize(self, observation: Mapping[str, Any]) -> tuple[bool, str]:
        if not observation.get("direct_local"):
            return False, "not_direct_local"
        metadata = observation.get("metadata", {})
        if not isinstance(metadata, Mapping) or metadata.get("direct_local_authorized") is not True:
            return False, "direct_authorization_missing"
        point = str(metadata.get("enforcement_point_id", ""))
        scopes = self._points.get(point)
        scope = _scope(observation)
        if not scopes or ("*" not in scopes and scope not in scopes):
            return False, "direct_scope_not_authorized"
        if not metadata.get("independent_audit_ref"):
            return False, "direct_audit_reference_missing"
        return True, "authorized_direct_emergency"

    def snapshot(self) -> dict[str, list[str]]:
        return {point: list(scopes) for point, scopes in sorted(self._points.items())}


class EvidenceCampaignManager:
    """Deterministic campaign merge, split, and revision ledger."""

    def __init__(self, local_domain_id: str, profile: ConfirmationProfile) -> None:
        self.local_domain_id = local_domain_id
        self.profile = profile
        self.campaigns: dict[str, EvidenceCampaign] = {}
        self.events: list[dict[str, Any]] = []

    def _compatible(self, campaign: EvidenceCampaign, observation: Mapping[str, Any], now: int) -> bool:
        return (
            campaign.status == "active"
            and campaign.subject_id == str(observation.get("subject", {}).get("id"))
            and campaign.scope == _scope(observation)
            and campaign.claim_family == _claim_family(observation)
            and now - campaign.last_seen_at <= self.profile.campaign_window
        )

    def _new_id(self, observation: Mapping[str, Any], now: int) -> str:
        material = {"domain": self.local_domain_id, "subject": observation.get("subject", {}).get("id"), "scope": _scope(observation), "family": _claim_family(observation), "at": now, "observation": observation.get("observation_id")}
        return "campaign-" + sha256(canonical_bytes(material)).hexdigest()[:16]

    @staticmethod
    def _with_observation(campaign: EvidenceCampaign, observation: Mapping[str, Any], now: int) -> EvidenceCampaign:
        return replace(
            campaign,
            last_seen_at=now,
            observation_ids=tuple(sorted({*campaign.observation_ids, str(observation["observation_id"])})),
            control_group_ids=tuple(sorted({*campaign.control_group_ids, str(observation.get("observer_control_group_id"))})),
            interaction_ids=tuple(sorted({*campaign.interaction_ids, str(observation.get("interaction_id"))})),
            revision=campaign.revision + 1,
        )

    def ingest(self, observation: Mapping[str, Any], now: int) -> EvidenceCampaign:
        if not self.profile.campaign_grouping:
            matches: list[EvidenceCampaign] = []
        else:
            matches = [item for item in self.campaigns.values() if self._compatible(item, observation, now)]
        if not matches:
            related = [item for item in self.campaigns.values() if item.status == "active" and item.subject_id == str(observation.get("subject", {}).get("id"))]
            campaign = EvidenceCampaign(
                campaign_id=self._new_id(observation, now),
                local_domain_id=self.local_domain_id,
                subject_id=str(observation.get("subject", {}).get("id")),
                scope=_scope(observation),
                claim_family=_claim_family(observation),
                started_at=now,
                last_seen_at=now,
                observation_ids=(str(observation["observation_id"]),),
                control_group_ids=(str(observation.get("observer_control_group_id")),),
                interaction_ids=(str(observation.get("interaction_id")),),
                split_from=min((item.campaign_id for item in related), default=None),
            )
            self.campaigns[campaign.campaign_id] = campaign
            self.events.append({"event_type": "campaign_split" if related else "campaign_created", "at": now, "campaign_id": campaign.campaign_id, "split_from": campaign.split_from, "reason": "incompatible_scope_claim_or_window" if related else "first_matching_evidence"})
            return campaign
        ordered = sorted(matches, key=lambda item: item.campaign_id)
        primary = self._with_observation(ordered[0], observation, now)
        self.campaigns[primary.campaign_id] = primary
        if len(ordered) > 1:
            merged_observations = set(primary.observation_ids)
            merged_groups = set(primary.control_group_ids)
            merged_interactions = set(primary.interaction_ids)
            for item in ordered[1:]:
                merged_observations.update(item.observation_ids)
                merged_groups.update(item.control_group_ids)
                merged_interactions.update(item.interaction_ids)
                self.campaigns[item.campaign_id] = replace(item, status="merged", merged_into=primary.campaign_id, revision=item.revision + 1)
            primary = replace(primary, observation_ids=tuple(sorted(merged_observations)), control_group_ids=tuple(sorted(merged_groups)), interaction_ids=tuple(sorted(merged_interactions)), revision=primary.revision + 1)
            self.campaigns[primary.campaign_id] = primary
            self.events.append({"event_type": "campaign_merged", "at": now, "campaign_id": primary.campaign_id, "merged_campaign_ids": [item.campaign_id for item in ordered[1:]], "reason": "deterministic_compatible_campaign_merge"})
        else:
            self.events.append({"event_type": "campaign_revised", "at": now, "campaign_id": primary.campaign_id, "reason": "compatible_evidence_added", "revision": primary.revision})
        return primary


class InvestigationScheduler:
    """Deterministic budget scheduler that reserves high-risk capacity."""

    def __init__(self, local_domain_id: str, profile: ConfirmationProfile) -> None:
        self.local_domain_id = local_domain_id
        self.profile = profile
        self.actions: list[InvestigativeAction] = []
        self._seen_tip_keys: set[str] = set()

    def schedule(self, tips: Iterable[TipRecord], now: int) -> list[InvestigativeAction]:
        candidates = sorted((tip for tip in tips if tip.eligible), key=lambda tip: (-tip.tip_value_milli, tip.tip_id))
        high = [tip for tip in candidates if _risk_milli(tip.scope) >= 800]
        low = [tip for tip in candidates if tip not in high]
        selected: list[TipRecord] = []
        group_count: dict[str, int] = {}

        def admit(tip: TipRecord, *, capacity: int) -> bool:
            if len(selected) >= capacity or tip.tip_key in self._seen_tip_keys:
                return False
            if group_count.get(tip.observer_control_group_id, 0) >= self.profile.per_control_group_tip_cap:
                return False
            selected.append(tip)
            self._seen_tip_keys.add(tip.tip_key)
            group_count[tip.observer_control_group_id] = group_count.get(tip.observer_control_group_id, 0) + 1
            return True

        for tip in high:
            if len(selected) >= self.profile.high_risk_reserved_capacity:
                break
            admit(tip, capacity=self.profile.high_risk_reserved_capacity)
        # Low-risk work cannot consume the reserved slot before high-risk tips.
        low_capacity = max(0, self.profile.global_investigation_budget - self.profile.high_risk_reserved_capacity)
        for tip in [*high[len(selected):], *low]:
            if tip in low and sum(1 for item in selected if _risk_milli(item.scope) < 800) >= low_capacity:
                continue
            admit(tip, capacity=self.profile.global_investigation_budget)

        records: list[InvestigativeAction] = []
        selected_ids = {tip.tip_id for tip in selected}
        for tip in candidates:
            accepted = tip.tip_id in selected_ids
            high_risk = _risk_milli(tip.scope) >= 800
            action = "launch_patrol" if high_risk else "increase_monitoring"
            result = "scheduled" if accepted else ("duplicate_suppressed" if tip.tip_key in self._seen_tip_keys and tip.tip_id not in selected_ids else "budget_or_group_cap")
            record = InvestigativeAction(
                action_id=f"action-{tip.tip_id}", local_domain_id=self.local_domain_id, tip_id=tip.tip_id,
                observation_ids=(tip.observation_id,), observer_control_group_id=tip.observer_control_group_id,
                scope=tip.scope, action=action if accepted else "no_action", at=now,
                permitted_until=now + self.profile.maximum_approval_gate_duration,
                maximum_response_severity_milli=450 if high_risk else 50,
                result=result, protocol_cost_milli=100 if accepted else 0,
                utility_cost_milli=50 if accepted and high_risk else 10 if accepted else 0,
                reason="reserved_high_risk_capacity" if accepted and high_risk else "deterministic_tip_budget",
            )
            records.append(record)
        self.actions.extend(records)
        return records


class ConfirmationResolver:
    """Local staged resolver with immutable evidence explanations."""

    def __init__(self, local_domain_id: str, profile: ConfirmationProfile = ConfirmationProfile()) -> None:
        self.local_domain_id = local_domain_id
        self.profile = profile
        self.emergency_registry = DirectEmergencyRegistry()
        self.campaigns = EvidenceCampaignManager(local_domain_id, profile)
        self.scheduler = InvestigationScheduler(local_domain_id, profile)
        self.requirements: dict[tuple[str, str], ConfirmationRequirement] = {}
        self.provisionals: dict[tuple[str, str], ProvisionalResponse] = {}
        self.provisional_history: list[ProvisionalResponse] = []
        self.tips: list[TipRecord] = []
        self.confirmations: list[ConfirmationEvent] = []
        self.influences: dict[str, Influence] = {}
        self.responses: list[dict[str, Any]] = []
        self.severity: list[dict[str, Any]] = []
        self.explanations: list[dict[str, Any]] = []
        self.validator = VersionedConfirmationValidator()

    @staticmethod
    def _key(subject_id: str, scope: str) -> tuple[str, str]:
        return subject_id, scope

    def _tip(self, observation: Mapping[str, Any], influence: Influence, now: int) -> TipRecord:
        scope = _scope(observation)
        group = str(observation.get("observer_control_group_id"))
        accepted = (
            self.profile.tip_enabled
            and influence.issuer_state in {"restricted", "quarantined"}
            and bool(observation.get("receipt_verified"))
            and influence.factors.get("freshness_milli", 0) > 0
            and observation.get("observation_type") in THREAT_TYPES
            and not influence.retroactively_discounted
        )
        reason = "eligible_zero_credit_investigative_tip" if accepted else "not_eligible_for_tip_channel"
        tip = TipRecord(
            tip_id="tip-" + str(observation["observation_id"]), local_domain_id=self.local_domain_id,
            observation_id=str(observation["observation_id"]), observer_control_group_id=group, scope=scope,
            at=now, issuer_state=influence.issuer_state,
            corroborative_influence_milli=influence.effective_influence_milli,
            tip_value_milli=(_risk_milli(scope) if accepted else 0), eligible=accepted, reason=reason,
            tip_key=sha256(canonical_bytes({"group": group, "scope": scope, "observation": observation.get("observation_id")})).hexdigest(),
        )
        valid, code = self.validator.validate(tip.as_dict())
        if not valid:
            raise ValueError(code)
        self.tips.append(tip)
        return tip

    @staticmethod
    def _provisional_envelope(scope: str, reason: str, observation_ids: Iterable[str]) -> OperatingEnvelope:
        capability = {
            "financial.transfer": "financial.transfer",
            "payment.transaction": "financial.transfer",
            "memory.write": "memory.write",
            "memory.integrity": "memory.write",
            "tool:data.export": "data.export",
            "external.communication": "external.communication",
        }.get(scope, "high_risk")
        return OperatingEnvelope(
            state="provisionally_constrained", denied_capabilities=(capability,),
            actions=("reduce_capability", "observe", "require_confirmation"), reasons=(reason,),
            observation_ids=tuple(sorted(observation_ids)),
        )

    @staticmethod
    def _monitored_envelope(reason: str, observation_ids: Iterable[str]) -> OperatingEnvelope:
        return OperatingEnvelope(state="monitored", actions=("observe",), reasons=(reason,), observation_ids=tuple(sorted(observation_ids)))

    @staticmethod
    def _quarantine_envelope(reason: str, observation_ids: Iterable[str]) -> OperatingEnvelope:
        return OperatingEnvelope(state="confirmed_quarantine", allowed_capabilities=(), denied_capabilities=("*",), actions=("quarantine",), reasons=(reason,), observation_ids=tuple(sorted(observation_ids)))

    def _record_response(self, subject_id: str, scope: str, envelope: OperatingEnvelope, now: int, *, reason: str, campaign_id: str | None = None) -> None:
        weights = {"monitored": 50, "approval_gated": 250, "constrained": 450, "provisionally_constrained": self.profile.provisional_severity_milli, "confirmed_quarantine": 1000}
        record = {
            "response_version": "tcop.response-severity/0.1", "local_domain_id": self.local_domain_id,
            "subject_id": subject_id, "scope": scope, "at": now, "state": envelope.state,
            "severity_milli": weights.get(envelope.state, 0), "reason": reason, "campaign_id": campaign_id,
            "observation_ids": list(envelope.observation_ids),
        }
        self.responses.append({"at": now, "subject_id": subject_id, "scope": scope, "envelope": envelope.to_dict(), "reason": reason, "campaign_id": campaign_id})
        self.severity.append(record)

    def _create_provisional(self, subject_id: str, scope: str, campaign: EvidenceCampaign, now: int, *, reason: str = "remote_only_first_campaign") -> OperatingEnvelope:
        key = self._key(subject_id, scope)
        response = ProvisionalResponse(
            response_id=f"provisional-{campaign.campaign_id}", local_domain_id=self.local_domain_id,
            subject_id=subject_id, scope=scope, campaign_id=campaign.campaign_id, activated_at=now,
            expires_at=now + self.profile.provisional_ttl, confirmation_deadline=now + self.profile.confirmation_window,
            maximum_severity_milli=self.profile.provisional_severity_milli,
            default_expiry_action=self.profile.default_expiry_action,
            reason=reason,
        )
        requirement = ConfirmationRequirement(
            requirement_id=f"requirement-{campaign.campaign_id}", local_domain_id=self.local_domain_id,
            subject_id=subject_id, scope=scope, campaign_id=campaign.campaign_id,
            initial_observation_ids=campaign.observation_ids, initial_control_group_ids=campaign.control_group_ids,
            activated_at=now, deadline=response.confirmation_deadline,
            source_novelty_required=self.profile.require_source_novelty,
        )
        self.provisionals[key] = response
        self.provisional_history.append(response)
        self.requirements[key] = requirement
        envelope = self._provisional_envelope(scope, f"{reason}_capped_at_provisional", campaign.observation_ids)
        self._record_response(subject_id, scope, envelope, now, reason=reason, campaign_id=campaign.campaign_id)
        return envelope

    def _deescalate(self, key: tuple[str, str], now: int, reason: str) -> OperatingEnvelope:
        provisional = self.provisionals.pop(key, None)
        requirement = self.requirements.get(key)
        if requirement is not None:
            self.requirements[key] = replace(requirement, status="deescalated")
        subject_id, scope = key
        envelope = self._monitored_envelope(reason, provisional and (provisional.campaign_id,) or ())
        self._record_response(subject_id, scope, envelope, now, reason=reason, campaign_id=provisional.campaign_id if provisional else None)
        return envelope

    def advance(self, now: int) -> list[tuple[str, str, OperatingEnvelope]]:
        expired: list[tuple[str, str, OperatingEnvelope]] = []
        for key, provisional in sorted(self.provisionals.items()):
            # Confirmation is valid through the recorded deadline; expiration
            # happens only afterwards and never escalates solely from time.
            if now > provisional.confirmation_deadline or now > provisional.expires_at:
                expired.append((key[0], key[1], self._deescalate(key, now, "provisional_expired_without_confirmation")))
        return expired

    def _confirmation_candidate(
        self,
        requirement: ConfirmationRequirement,
        observation: Mapping[str, Any],
        campaign: EvidenceCampaign,
        now: int,
    ) -> ConfirmationEvent:
        observation_id = str(observation["observation_id"])
        group = str(observation.get("observer_control_group_id"))
        direct, direct_reason = self.emergency_registry.authorize(observation)
        mode = str(observation.get("observation_mode"))
        candidate_type: str | None = None
        if direct and observation.get("observation_type") in THREAT_TYPES:
            candidate_type = "direct_local"
        elif mode == "active_patrol" and observation.get("observation_type") == "patrol.challenge_failure" and observation.get("receipt_verified"):
            candidate_type = "failed_independent_patrol"
        elif observation.get("observation_type") in THREAT_TYPES and group not in requirement.initial_control_group_ids and observation.get("receipt_verified"):
            candidate_type = "new_independent_control_group"
        elif observation.get("observation_type") in THREAT_TYPES and (not self.profile.require_source_novelty or self.profile.allow_same_source_later_interaction) and observation.get("interaction_id") not in {"", None} and observation_id not in requirement.initial_observation_ids:
            candidate_type = "later_independent_interaction"
        relation = "same_campaign" if campaign.campaign_id == requirement.campaign_id else "later_campaign"
        source_novel = group not in requirement.initial_control_group_ids
        if observation_id in requirement.initial_observation_ids:
            accepted, reason = False, "initial_observation_cannot_confirm"
        elif candidate_type is None:
            accepted, reason = False, "same_source_or_nonqualifying_confirmation"
        elif requirement.source_novelty_required and candidate_type not in {"direct_local", "failed_independent_patrol"} and not source_novel:
            accepted, reason = False, "source_novelty_missing"
        elif candidate_type not in requirement.permitted_types:
            accepted, reason = False, "confirmation_type_not_permitted"
        else:
            accepted, reason = True, candidate_type
        return ConfirmationEvent(
            event_id=f"confirmation-{requirement.requirement_id}-{observation_id}", local_domain_id=self.local_domain_id,
            requirement_id=requirement.requirement_id, observation_id=observation_id, at=now,
            candidate_type=candidate_type or "nonqualifying", source_control_group_id=group,
            source_novel=source_novel, campaign_relation=relation, accepted=accepted,
            reason=reason if not direct_reason.startswith("authorized") else reason,
        )

    def process_batch(
        self,
        observations: Iterable[Mapping[str, Any]],
        influences: Mapping[str, Influence],
        now: int,
    ) -> dict[str, OperatingEnvelope]:
        """Apply one virtual-time batch using frozen pre-batch requirements.

        New requirements are created after this batch's confirmation evaluation,
        so a remote report cannot create and satisfy its own confirmation stage.
        """

        outcomes: dict[str, OperatingEnvelope] = {}
        for subject_id, scope, envelope in self.advance(now):
            outcomes[subject_id] = envelope
        requirement_snapshot = deepcopy(self.requirements)
        provisional_snapshot = deepcopy(self.provisionals)
        ordered = sorted(observations, key=lambda item: str(item["observation_id"]))
        campaign_for: dict[str, EvidenceCampaign] = {}
        tips: list[TipRecord] = []
        for observation in ordered:
            influence = influences[str(observation["observation_id"])]
            self.influences[str(observation["observation_id"])] = influence
            campaign = self.campaigns.ingest(observation, now)
            campaign_for[str(observation["observation_id"])] = campaign
            tips.append(self._tip(observation, influence, now))
        actions = self.scheduler.schedule(tips, now)
        # A high-risk, zero-credit tip can launch a *scoped provisional
        # investigation gate*.  It cannot quarantine or add corroborative
        # influence; a later independently qualifying result is still needed.
        if self.profile.provisional_enabled:
            tips_by_id = {tip.tip_id: tip for tip in tips}
            observations_by_id = {str(item["observation_id"]): item for item in ordered}
            for action in actions:
                tip = tips_by_id.get(action.tip_id)
                if action.result != "scheduled" or action.action != "launch_patrol" or tip is None:
                    continue
                observation = observations_by_id[tip.observation_id]
                subject_id = str(observation.get("subject", {}).get("id"))
                scope = _scope(observation)
                key = self._key(subject_id, scope)
                if key not in self.provisionals:
                    outcomes[subject_id] = self._create_provisional(subject_id, scope, campaign_for[tip.observation_id], now, reason="tip_triggered_scoped_investigation")
        # Existing provisional requirements only: frozen snapshot ensures
        # same-time confirmations cannot validate their own creation batch.
        for key, requirement in sorted(requirement_snapshot.items()):
            if requirement.status != "pending" or key not in provisional_snapshot:
                continue
            subject_id, scope = key
            for observation in ordered:
                if str(observation.get("subject", {}).get("id")) != subject_id or _scope(observation) != scope:
                    continue
                event = self._confirmation_candidate(requirement, observation, campaign_for[str(observation["observation_id"])], now)
                self.confirmations.append(event)
                if event.accepted:
                    envelope = self._quarantine_envelope(f"confirmed_by_{event.candidate_type}", (str(observation["observation_id"]),))
                    self.provisionals.pop(key, None)
                    self.requirements[key] = replace(requirement, status="confirmed")
                    self._record_response(subject_id, scope, envelope, now, reason=event.reason, campaign_id=requirement.campaign_id)
                    outcomes[subject_id] = envelope
                    break
                clean_patrol = observation.get("observation_mode") == "active_patrol" and observation.get("receipt_verified")
                if observation.get("observation_type") in CLEAN_TYPES and (observation.get("direct_local") or clean_patrol):
                    outcomes[subject_id] = self._deescalate(key, now, "strong_clean_direct_or_patrol_evidence")
                    break
        # Scoped authorized direct-local severe evidence is an explicit local
        # emergency path and remains independently auditable in explanations.
        for observation in ordered:
            subject_id = str(observation.get("subject", {}).get("id"))
            scope = _scope(observation)
            authorized, code = self.emergency_registry.authorize(observation)
            if authorized and observation.get("observation_type") in THREAT_TYPES:
                envelope = self._quarantine_envelope("authorized_direct_local_emergency", (str(observation["observation_id"]),))
                self.provisionals.pop(self._key(subject_id, scope), None)
                self._record_response(subject_id, scope, envelope, now, reason=code, campaign_id=campaign_for[str(observation["observation_id"])].campaign_id)
                outcomes[subject_id] = envelope
        # Finally create remote-only provisional states from campaigns whose
        # evidence qualifies.  A v0.4 first campaign may not directly force a
        # full remote quarantine under the default profile.
        for campaign in sorted(self.campaigns.campaigns.values(), key=lambda item: item.campaign_id):
            if campaign.status != "active":
                continue
            key = self._key(campaign.subject_id, campaign.scope)
            if key in self.provisionals or campaign.subject_id in outcomes:
                continue
            matching = [self.influences[observation_id] for observation_id in campaign.observation_ids if observation_id in self.influences]
            qualified = [item for item in matching if item.effective_influence_milli >= self.profile.remote_minimum_influence_milli]
            groups = {item.observer_control_group_id for item in qualified}
            total = sum(item.effective_influence_milli for item in qualified)
            if self.profile.local_direct_only:
                continue
            if len(groups) >= self.profile.remote_minimum_diversity and total >= self.profile.remote_threshold_milli:
                if self.profile.immediate_remote_quarantine:
                    envelope = self._quarantine_envelope("remote_immediate_quarantine_ablation", campaign.observation_ids)
                    self._record_response(campaign.subject_id, campaign.scope, envelope, now, reason="immediate_remote_ablation", campaign_id=campaign.campaign_id)
                    outcomes[campaign.subject_id] = envelope
                elif self.profile.provisional_enabled:
                    outcomes[campaign.subject_id] = self._create_provisional(campaign.subject_id, campaign.scope, campaign, now)
                else:
                    envelope = OperatingEnvelope(state="constrained", denied_capabilities=("high_risk",), actions=("reduce_capability", "observe"), reasons=("remote_weighted_constraint",), observation_ids=campaign.observation_ids)
                    self._record_response(campaign.subject_id, campaign.scope, envelope, now, reason="provisional_disabled", campaign_id=campaign.campaign_id)
                    outcomes[campaign.subject_id] = envelope
        for observation in ordered:
            influence = influences[str(observation["observation_id"])]
            tip = next(item for item in tips if item.observation_id == observation["observation_id"])
            self.explanations.append(
                {
                    "local_domain_id": self.local_domain_id, "at": now, "observation_id": observation["observation_id"],
                    "corroborative_influence_milli": influence.effective_influence_milli,
                    "investigative_tip_eligible": tip.eligible, "tip_reason": tip.reason,
                    "issuer_state": influence.issuer_state, "campaign_id": campaign_for[str(observation["observation_id"])].campaign_id,
                    "same_time_confirmation_snapshot": True,
                    "direct_emergency_authorization": self.emergency_registry.authorize(observation)[1],
                    # The signed immutable observation carries this reference;
                    # projecting it here makes an emergency decision auditable
                    # without reconstructing the whole evidence stream.
                    "direct_emergency_audit_ref": observation.get("metadata", {}).get("independent_audit_ref"),
                }
            )
        return outcomes


def confirmation_explanations_text(events: Iterable[Mapping[str, Any]]) -> str:
    lines = ["# v0.4 confirmation explanations", ""]
    for item in events:
        lines.extend([
            f"Observation {item['observation_id']} at {item['at']}",
            f"Corroborative influence: {item['corroborative_influence_milli']}/1000",
            f"Investigative tip: {'accepted' if item['investigative_tip_eligible'] else 'not eligible'} ({item['tip_reason']})",
            f"Campaign: {item['campaign_id']}; same-time snapshot: {item['same_time_confirmation_snapshot']}",
            f"Direct emergency authority: {item['direct_emergency_authorization']}",
            f"Direct emergency audit reference: {item['direct_emergency_audit_ref'] or 'none'}",
            "",
        ])
    return "\n".join(lines)
