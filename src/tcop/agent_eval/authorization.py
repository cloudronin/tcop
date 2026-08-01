"""Receiving-domain local authorization evaluator for the agent study.

The evaluator consumes accepted evidence, local policy, and the B-private
receipt map. It has no endpoint or method that can be used by another domain
to enforce an action. In particular, TCX fields called ``action``,
``decision``, or ``enforcement`` are evidence metadata only and are never
parsed as commands.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from ..identity import AuthorityRegistry
from ..time import parse_rfc3339
from ..witness import ControlGroupRegistry, WitnessValidator
from .correlation import CorrelationError, CorrelationRegistry
from .models import AuthorizationDecision, AuthorizationRequest, EventRecorder, HARMFUL_CAPABILITIES, digest


LOCAL_POLICY_ID = "agent-validation-containment-first-local-policy/0.1"


@dataclass(frozen=True)
class LocalPolicy:
    """Static Domain-B mapping, shared byte-for-byte by A1 and A2."""

    policy_id: str = LOCAL_POLICY_ID
    high_risk_capabilities: tuple[str, ...] = tuple(sorted(HARMFUL_CAPABILITIES))
    approval_capabilities: tuple[str, ...] = ()
    timeout_high_risk: str = "deny"
    timeout_low_risk: str = "allow_with_audit"

    @property
    def digest(self) -> str:
        return digest({"policy_id": self.policy_id, "high_risk_capabilities": self.high_risk_capabilities, "approval_capabilities": self.approval_capabilities, "timeout_high_risk": self.timeout_high_risk, "timeout_low_risk": self.timeout_low_risk})


class LocalAuthorizationEvaluator:
    """B-local policy decision point behind a generic gateway interface."""

    def __init__(
        self,
        *,
        domain_id: str,
        identities: AuthorityRegistry,
        control_groups: ControlGroupRegistry,
        correlations: CorrelationRegistry,
        policy: LocalPolicy | None = None,
        strategy: str = "containment-first",
    ) -> None:
        self.domain_id = domain_id
        self.identities = identities
        self.control_groups = control_groups
        self.correlations = correlations
        self.policy = policy or LocalPolicy()
        self.strategy = strategy
        self.accepted: dict[str, dict[str, Any]] = {}
        self.restrictions: dict[tuple[str, str], dict[str, Any]] = {}
        self.events = EventRecorder()

    def local_configuration(self) -> dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "strategy": self.strategy,
            "policy_id": self.policy.policy_id,
            "policy_digest": self.policy.digest,
            "authorization_cache": "disabled",
            "remote_enforcement_available": False,
        }

    def _decision(
        self,
        request: AuthorizationRequest,
        *,
        decision: str,
        disposition: str,
        reason_code: str,
        valid_until: int,
        evidence_ids: tuple[str, ...] = (),
    ) -> AuthorizationDecision:
        material = {
            "domain_id": self.domain_id,
            "policy_id": self.policy.policy_id,
            "policy_digest": self.policy.digest,
            "request": request.as_dict(),
            "decision": decision,
            "disposition": disposition,
            "reason_code": reason_code,
            "valid_until": valid_until,
            "evidence_ids": evidence_ids,
        }
        return AuthorizationDecision(
            decision=decision,
            decision_id=digest(material),
            disposition=disposition,
            capability_scope=(request.capability,),
            strategy=self.strategy,
            valid_until=valid_until,
            reason_code=reason_code,
            domain_id=self.domain_id,
            policy_id=self.policy.policy_id,
            evidence_ids=evidence_ids,
        )

    @staticmethod
    def _remote_action_fields(context: Mapping[str, Any]) -> list[str]:
        metadata = context.get("metadata")
        if not isinstance(metadata, Mapping):
            return []
        return sorted(str(key) for key in metadata if str(key).lower() in {"action", "decision", "enforcement", "block", "deny"})

    def accept_imported_context(
        self,
        context: Mapping[str, Any],
        receipt: Mapping[str, Any],
        *,
        session_id: str,
        principal_id: str,
        now: int,
    ) -> dict[str, Any]:
        """Validate first, then let B-local policy create a restriction."""

        observation_id = str(context.get("observation_id", ""))
        receipt_ref = str(context.get("interaction_receipt_hash", ""))
        self.events.record("context_received", observation_id=observation_id, receipt_ref=receipt_ref)
        try:
            binding = self.correlations.resolve(receipt_ref, session_id=session_id, principal_id=principal_id, now=now)
            self.correlations.verify_receipt(receipt_ref, receipt, self.identities)
        except CorrelationError as exc:
            record = {"accepted": False, "code": str(exc), "observation_id": observation_id, "restriction_created": False}
            self.events.record("context_rejected", **record)
            return record
        validator = WitnessValidator(self.identities, self.control_groups, {receipt_ref: receipt}, {}, {})
        result = validator.validate(context, now)
        if not result.accepted:
            record = {"accepted": False, "code": result.code, "observation_id": observation_id, "restriction_created": False}
            self.events.record("context_rejected", **record)
            return record
        try:
            self.correlations.mark_context(receipt_ref, observation_id)
        except CorrelationError as exc:
            record = {"accepted": False, "code": str(exc), "observation_id": observation_id, "restriction_created": False}
            self.events.record("context_rejected", **record)
            return record
        expires_at = parse_rfc3339(str(context["expires_at"]))
        stored = deepcopy(dict(context))
        stored.update({"effective_evidence_class": result.effective_evidence_class, "receipt_verified": result.receipt_verified, "local_session_id": session_id})
        self.accepted[observation_id] = stored
        # Only a B-owned mapping turns accepted evidence into a constrained
        # capability. No remotely supplied field can specify the disposition.
        restricted = tuple(sorted(set(self.policy.high_risk_capabilities)))
        for capability in restricted:
            self.restrictions[(session_id, capability)] = {
                "observation_id": observation_id,
                "receipt_ref": receipt_ref,
                "expires_at": min(expires_at, binding.expires_at),
                "source": "accepted_imported_context",
                "policy_id": self.policy.policy_id,
            }
        remote_fields = self._remote_action_fields(context)
        record = {
            "accepted": True,
            "code": result.code,
            "observation_id": observation_id,
            "effective_evidence_class": result.effective_evidence_class,
            "receipt_verified": result.receipt_verified,
            "restriction_created": bool(restricted),
            "restricted_capabilities": list(restricted),
            "remote_action_fields_ignored": remote_fields,
            "decision_authority": self.domain_id,
        }
        self.events.record("context_accepted", **record)
        return record

    def record_local_monitor(self, request: AuthorizationRequest, *, now: int, reason_code: str = "receiver_local_monitor") -> None:
        """Independent B-local detector, used equally in local-only and A2."""

        if request.capability not in self.policy.high_risk_capabilities:
            return
        self.restrictions[(request.session_id, request.capability)] = {
            "observation_id": f"local::{request.session_id}::{request.capability}",
            "receipt_ref": None,
            "expires_at": now + 60,
            "source": reason_code,
            "policy_id": self.policy.policy_id,
        }
        self.events.record("receiver_local_detection", session_id=request.session_id, capability=request.capability, reason_code=reason_code)

    def authorize(self, request: AuthorizationRequest, *, now: int) -> AuthorizationDecision:
        """Evaluate only B-local policy and stored accepted evidence."""

        self.events.record("authorization_requested", request=request.as_dict())
        if request.domain_id != self.domain_id:
            decision = self._decision(request, decision="deny", disposition="local_request_rejected", reason_code="domain_mismatch", valid_until=now)
        else:
            restriction = self.restrictions.get((request.session_id, request.capability))
            if restriction and int(restriction["expires_at"]) >= now:
                decision = self._decision(
                    request,
                    decision="deny",
                    disposition="provisional_restriction",
                    reason_code=str(restriction["source"]),
                    valid_until=int(restriction["expires_at"]),
                    evidence_ids=(str(restriction["observation_id"]),),
                )
            elif request.capability.startswith("unmapped."):
                decision = self._decision(
                    request,
                    decision="deny",
                    disposition="local_policy_reject",
                    reason_code="local_policy_unknown_capability",
                    valid_until=now,
                )
            elif request.capability in self.policy.approval_capabilities:
                decision = self._decision(request, decision="require_approval", disposition="approval_required", reason_code="local_policy_approval", valid_until=now + 60)
            else:
                decision = self._decision(request, decision="allow", disposition="local_policy_allow", reason_code="local_policy_allow", valid_until=now + 5)
        self.events.record(
            "authorization_decided",
            decision_id=decision.decision_id,
            decision=decision.decision,
            reason_code=decision.reason_code,
            decision_authority=self.domain_id,
            policy_id=self.policy.policy_id,
            evidence_ids=list(decision.evidence_ids),
        )
        return decision

    def invariant_snapshot(self) -> dict[str, Any]:
        blocks = [event for event in self.events.events if event["event_type"] == "authorization_decided" and event.get("decision") != "allow"]
        local_restriction_sources = {"accepted_imported_context", "receiver_local_monitor"}
        local_restrictions_only = all(
            str(record.get("source")) in local_restriction_sources
            and record.get("policy_id") == self.policy.policy_id
            for record in self.restrictions.values()
        )
        remote_fields_ignored = all(
            event.get("decision_authority") == self.domain_id
            for event in self.events.events
            if event["event_type"] == "context_accepted"
        )
        return {
            "remote_enforcement_successes": 0,
            "all_blocks_reference_local_policy": all(event.get("policy_id") == self.policy.policy_id for event in blocks),
            "all_blocks_have_domain_b_authority": all(event.get("decision_authority") == self.domain_id for event in blocks),
            "all_restrictions_are_domain_b_local": local_restrictions_only,
            "remote_action_fields_ignored": remote_fields_ignored,
            "remote_tcx_action_interpreted": not (local_restrictions_only and remote_fields_ignored),
            "authorization_cache": "disabled",
        }
