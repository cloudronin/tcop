"""Deterministic TCX v0.2 distributed-witness reference plane.

This module is deliberately separate from the frozen v0.1 implementation. It
models receiver-side evidence classification, immutable interaction receipts,
provenance-preserving relays, passive witnesses, and authorized patrols. None
of these classes import benchmark truth or perform real-world enforcement.
"""

from __future__ import annotations

import heapq
import itertools
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes, unsigned_envelope
from .identity import AuthorityRegistry, KeyMaterial, observer_block, verify_signature
from .protocol import observation_id
from .responses import OperatingEnvelope, SimulatedResponseAdapter
from .time import VirtualClock, as_rfc3339, parse_rfc3339


EVIDENCE_CLASSES = {
    "self_assertion",
    "first_party",
    "independent_peer",
    "neutral_third_party",
    "infrastructure_attestation",
    "relayed",
}
OBSERVATION_MODES = {"passive", "active_patrol", "attestation", "relay"}
RECEIPT_MODES = {"bilateral", "unilateral_transport", "third_party_witnessed", "none"}
THREAT_TYPES = {"tool.prohibited_export", "memory.contamination", "patrol.challenge_failure"}
CLEAN_TYPES = {"patrol.clean_result", "attestation.result", "recovery.clean_checkpoint"}


@dataclass(frozen=True)
class Principal:
    principal_id: str
    admin_domain_id: str
    control_group_id: str
    role: str = "subject"


class ControlGroupRegistry:
    """Static identity relationship registry used only for receiver decisions."""

    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}

    def register(self, principal: Principal) -> None:
        self._principals[principal.principal_id] = principal

    def resolve(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)

    def require(self, principal_id: str) -> Principal:
        principal = self.resolve(principal_id)
        if principal is None:
            raise KeyError(f"unregistered principal: {principal_id}")
        return principal

    def classify(self, observer_id: str, subject_id: str, mode: str, declared: str) -> tuple[str, str]:
        """Return effective evidence class and auditable receiver reason code."""

        observer = self.require(observer_id)
        subject = self.require(subject_id)
        if observer_id == subject_id:
            return "self_assertion", "self_attestation_not_independent"
        if observer.control_group_id == subject.control_group_id:
            return "first_party", "same_control_group_reclassified"
        if mode == "attestation":
            return "infrastructure_attestation", "accepted_attestation"
        if mode == "active_patrol" and observer.role == "patrol":
            return "neutral_third_party", "accepted_neutral_patrol"
        if mode == "relay":
            return "relayed", "accepted_relay"
        if declared not in EVIDENCE_CLASSES:
            return "first_party", "invalid_evidence_class"
        return "independent_peer", "accepted_independent_peer"

    def snapshot(self) -> list[dict[str, str]]:
        return [
            {
                "principal_id": principal.principal_id,
                "admin_domain_id": principal.admin_domain_id,
                "control_group_id": principal.control_group_id,
                "role": principal.role,
            }
            for principal in sorted(self._principals.values(), key=lambda value: value.principal_id)
        ]


def receipt_hash(receipt: Mapping[str, Any]) -> str:
    return sha256(canonical_bytes(dict(receipt))).hexdigest()


def _unsigned_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"observer_signature", "subject_ack_signature"}
    }


def make_interaction_receipt(
    observer: KeyMaterial,
    subject: KeyMaterial | None,
    registry: ControlGroupRegistry,
    *,
    interaction_id: str,
    capability: str,
    now: int,
    request: str = "synthetic-request",
    response: str = "synthetic-response",
    receipt_mode: str = "bilateral",
    subject_id: str | None = None,
    workflow_id: str | None = None,
    challenge_profile_id: str | None = None,
    transport_evidence: str | None = "virtual-transport",
) -> dict[str, Any]:
    """Create a receipt whose acknowledgement proves occurrence only."""

    if receipt_mode not in RECEIPT_MODES - {"none"}:
        raise ValueError("invalid interaction receipt mode")
    observer_principal = registry.require(observer.identity.observer_id)
    resolved_subject_id = subject.identity.observer_id if subject else subject_id
    if resolved_subject_id is None:
        raise ValueError("subject_id is required for an unacknowledged receipt")
    subject_principal = registry.require(resolved_subject_id)
    unsigned = {
        "receipt_version": "tcop.receipt/0.1",
        "interaction_id": interaction_id,
        "observer_id": observer.identity.observer_id,
        "observer_key_id": observer.identity.key_id,
        "observer_admin_domain_id": observer_principal.admin_domain_id,
        "subject_id": resolved_subject_id,
        "subject_admin_domain_id": subject_principal.admin_domain_id,
        "subject_ack_key_id": subject.identity.key_id if subject else None,
        "started_at": as_rfc3339(now),
        "completed_at": as_rfc3339(now),
        "request_hash": sha256(request.encode("utf-8")).hexdigest(),
        "response_hash": sha256(response.encode("utf-8")).hexdigest(),
        "capability": capability,
        "workflow_id": workflow_id,
        "challenge_profile_id": challenge_profile_id,
        "transport_evidence_hash": sha256(transport_evidence.encode("utf-8")).hexdigest() if transport_evidence else None,
        "receipt_mode": receipt_mode,
    }
    payload = canonical_bytes(unsigned)
    receipt = {
        **unsigned,
        "observer_signature": {"algorithm": "ed25519", "value": observer.sign(payload)},
        "subject_ack_signature": (
            {"algorithm": "ed25519", "value": subject.sign(payload)} if subject and receipt_mode == "bilateral" else None
        ),
    }
    return receipt


def verify_interaction_receipt(receipt: Mapping[str, Any], registry: AuthorityRegistry) -> tuple[bool, str]:
    """Verify receipt signatures; a missing acknowledgement remains valid evidence."""

    required = {
        "receipt_version", "interaction_id", "observer_id", "observer_key_id", "subject_id", "subject_ack_key_id",
        "receipt_mode", "observer_signature", "subject_ack_signature", "request_hash", "response_hash",
    }
    if not required <= set(receipt) or receipt.get("receipt_version") != "tcop.receipt/0.1":
        return False, "receipt_invalid"
    observer = registry.resolve(str(receipt["observer_id"]), str(receipt["observer_key_id"]))
    if observer is None or not verify_signature(
        observer, canonical_bytes(_unsigned_receipt(receipt)), str(receipt["observer_signature"].get("value", ""))
    ):
        return False, "receipt_invalid"
    acknowledgement = receipt.get("subject_ack_signature")
    if acknowledgement is None:
        return True, "receipt_subject_refused"
    subject_key_id = receipt.get("subject_ack_key_id")
    subject = registry.resolve(str(receipt["subject_id"]), str(subject_key_id)) if subject_key_id else None
    if subject is None or not verify_signature(
        subject, canonical_bytes(_unsigned_receipt(receipt)), str(acknowledgement.get("value", ""))
    ):
        return False, "receipt_invalid"
    return True, "receipt_verified"


def make_v02_observation(
    signer: KeyMaterial,
    control_groups: ControlGroupRegistry,
    *,
    subject_id: str,
    observation_type: str,
    scope: tuple[str, ...] | list[str],
    now: int,
    sequence_number: int = 1,
    ttl: int = 60,
    severity: str = "high",
    declared_evidence_class: str = "independent_peer",
    observation_mode: str = "passive",
    interaction_id: str | None = None,
    interaction_receipt_hash: str | None = None,
    receipt_mode: str = "none",
    original_observation_id: str | None = None,
    relay_chain: Iterable[str] = (),
    challenge_profile_id: str | None = None,
    challenge_profile_version: str | None = None,
    patrol_authorization_ref: str | None = None,
    privacy_profile: str = "hashes-only",
    synthetic_data_only: bool | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a signed v0.2 observation. Classification remains receiver-side."""

    observer_principal = control_groups.require(signer.identity.observer_id)
    subject_principal = control_groups.require(subject_id)
    envelope: dict[str, Any] = {
        "protocol_version": "0.2",
        "message_type": "observation",
        "observation_id": observation_id("v0.2", signer.identity.observer_id, subject_id, sequence_number, now, observation_type),
        "observer": observer_block(signer.identity),
        "subject": {"id": subject_id, "type": "agent"},
        "observation_type": observation_type,
        "scope": list(scope),
        "tenant": "shared",
        "sequence_number": sequence_number,
        "observed_at": as_rfc3339(now),
        "issued_at": as_rfc3339(now),
        "expires_at": as_rfc3339(now + ttl),
        "confidence": 0.9,
        "severity": severity,
        "evidence": [{"type": "trace_hash", "digest": sha256(f"{subject_id}:{now}:{observation_type}".encode()).hexdigest()}],
        "metadata": dict(metadata or {}),
        "declared_evidence_class": declared_evidence_class,
        "observation_mode": observation_mode,
        "observer_admin_domain_id": observer_principal.admin_domain_id,
        "observer_control_group_id": observer_principal.control_group_id,
        "subject_admin_domain_id": subject_principal.admin_domain_id,
        "subject_control_group_id": subject_principal.control_group_id,
        "interaction_id": interaction_id,
        "interaction_receipt_hash": interaction_receipt_hash,
        "receipt_mode": receipt_mode,
        "original_observation_id": original_observation_id,
        "relay_chain": list(relay_chain),
        "challenge_profile_id": challenge_profile_id,
        "challenge_profile_version": challenge_profile_version,
        "patrol_authorization_ref": patrol_authorization_ref,
        "privacy_profile": privacy_profile,
        "synthetic_data_only": synthetic_data_only,
    }
    envelope["signature"] = {"algorithm": "ed25519", "value": signer.sign(canonical_bytes(envelope))}
    return envelope


@dataclass(frozen=True)
class WitnessValidationResult:
    accepted: bool
    code: str
    effective_evidence_class: str | None = None
    receipt_verified: bool = False

    @classmethod
    def reject(cls, code: str) -> "WitnessValidationResult":
        return cls(False, code)


class WitnessValidator:
    """Strict v0.2 validator with classification derived from control groups."""

    required = {
        "protocol_version", "message_type", "observation_id", "observer", "subject", "observation_type", "scope",
        "tenant", "sequence_number", "observed_at", "issued_at", "expires_at", "confidence", "severity", "evidence",
        "metadata", "declared_evidence_class", "observation_mode", "observer_admin_domain_id",
        "observer_control_group_id", "subject_admin_domain_id", "subject_control_group_id", "interaction_id",
        "interaction_receipt_hash", "receipt_mode", "original_observation_id", "relay_chain", "challenge_profile_id",
        "challenge_profile_version", "patrol_authorization_ref", "privacy_profile", "synthetic_data_only", "signature",
    }

    def __init__(
        self,
        identities: AuthorityRegistry,
        control_groups: ControlGroupRegistry,
        receipts: Mapping[str, Mapping[str, Any]],
        patrol_authorizations: Mapping[str, Mapping[str, Any]],
        patrol_usage: Mapping[str, int],
    ) -> None:
        self.identities = identities
        self.control_groups = control_groups
        self.receipts = receipts
        self.patrol_authorizations = patrol_authorizations
        self.patrol_usage = patrol_usage

    def validate(self, observation: Mapping[str, Any], now: int) -> WitnessValidationResult:
        if set(observation) != self.required or observation.get("protocol_version") != "0.2" or observation.get("message_type") != "observation":
            return WitnessValidationResult.reject("schema_invalid")
        observer_block_value = observation.get("observer")
        subject_block = observation.get("subject")
        if not isinstance(observer_block_value, Mapping) or not isinstance(subject_block, Mapping):
            return WitnessValidationResult.reject("schema_invalid")
        observer_id = str(observer_block_value.get("id", ""))
        subject_id = str(subject_block.get("id", ""))
        identity = self.identities.resolve(observer_id, str(observer_block_value.get("key_id", "")))
        if identity is None or identity.revoked or identity.trust_domain != observer_block_value.get("trust_domain"):
            return WitnessValidationResult.reject("identity_unknown")
        try:
            observer_principal = self.control_groups.require(observer_id)
            subject_principal = self.control_groups.require(subject_id)
            expires_at = parse_rfc3339(str(observation["expires_at"]))
        except (KeyError, ValueError):
            return WitnessValidationResult.reject("principal_or_time_invalid")
        if expires_at < now:
            return WitnessValidationResult.reject("expired")
        if observation.get("observer_admin_domain_id") != observer_principal.admin_domain_id or observation.get("observer_control_group_id") != observer_principal.control_group_id:
            return WitnessValidationResult.reject("observer_control_group_mismatch")
        if observation.get("subject_admin_domain_id") != subject_principal.admin_domain_id or observation.get("subject_control_group_id") != subject_principal.control_group_id:
            return WitnessValidationResult.reject("subject_control_group_mismatch")
        if observation.get("observation_mode") not in OBSERVATION_MODES or observation.get("declared_evidence_class") not in EVIDENCE_CLASSES:
            return WitnessValidationResult.reject("evidence_class_invalid")
        if observation.get("receipt_mode") not in RECEIPT_MODES or not isinstance(observation.get("relay_chain"), list):
            return WitnessValidationResult.reject("schema_invalid")
        if len(set(observation["relay_chain"])) != len(observation["relay_chain"]):
            return WitnessValidationResult.reject("relay_loop")
        if not verify_signature(identity, canonical_bytes(unsigned_envelope(observation)), str(observation["signature"].get("value", ""))):
            return WitnessValidationResult.reject("signature_invalid")
        effective_class, classification_code = self.control_groups.classify(
            observer_id, subject_id, str(observation["observation_mode"]), str(observation["declared_evidence_class"])
        )
        receipt_verified = False
        receipt_key = observation.get("interaction_receipt_hash")
        if receipt_key:
            receipt = self.receipts.get(str(receipt_key))
            if receipt is None:
                return WitnessValidationResult.reject("receipt_invalid")
            receipt_ok, receipt_code = verify_interaction_receipt(receipt, self.identities)
            if not receipt_ok:
                return WitnessValidationResult.reject(receipt_code)
            if receipt.get("observer_id") != observer_id or receipt.get("subject_id") != subject_id:
                return WitnessValidationResult.reject("receipt_invalid")
            receipt_verified = True
            if receipt_code == "receipt_subject_refused":
                classification_code = receipt_code
        if observation["observation_mode"] == "active_patrol":
            authorization_id = observation.get("patrol_authorization_ref")
            authorization = self.patrol_authorizations.get(str(authorization_id)) if authorization_id else None
            if authorization is None or authorization.get("patrol_id") != observer_id:
                return WitnessValidationResult.reject("patrol_not_authorized")
            if subject_id not in authorization.get("targets", ()) or not set(observation["scope"]).issubset(set(authorization.get("capabilities", ()))):
                return WitnessValidationResult.reject("patrol_scope_violation")
            if parse_rfc3339(str(authorization["expires_at"])) < now:
                return WitnessValidationResult.reject("patrol_not_authorized")
            if self.patrol_usage.get(str(authorization_id), 0) > int(authorization["query_budget"]):
                return WitnessValidationResult.reject("patrol_budget_exceeded")
            if observation.get("synthetic_data_only") is not True:
                return WitnessValidationResult.reject("patrol_scope_violation")
        return WitnessValidationResult(True, classification_code, effective_class, receipt_verified)


class VersionedObservationValidator:
    """Explicit version dispatcher; v0.1 semantics remain owned by its validator."""

    def __init__(self, v01_validator: Any, v02_validator: WitnessValidator) -> None:
        self.v01_validator = v01_validator
        self.v02_validator = v02_validator

    def validate(self, observation: Mapping[str, Any], now: int) -> Any:
        version = observation.get("protocol_version")
        if version == "0.1":
            return self.v01_validator.validate(observation, now)
        if version == "0.2":
            return self.v02_validator.validate(observation, now)
        return WitnessValidationResult.reject("unsupported_version")


def make_relay(original: Mapping[str, Any], relay: KeyMaterial, *, now: int, relay_chain: Iterable[str] = ()) -> dict[str, Any]:
    """Wrap an immutable original claim in a separately signed relay record."""

    chain = [*relay_chain, relay.identity.observer_id]
    if len(chain) != len(set(chain)):
        raise ValueError("relay loop")
    relay_record = {
        "protocol_version": "0.2",
        "message_type": "relay",
        "relay_id": observation_id("relay", original["observation_id"], relay.identity.observer_id, now),
        "original_observation_id": original["observation_id"],
        "original_observation": deepcopy(dict(original)),
        "relay": observer_block(relay.identity),
        "relay_chain": chain,
        "issued_at": as_rfc3339(now),
    }
    relay_record["signature"] = {"algorithm": "ed25519", "value": relay.sign(canonical_bytes(relay_record))}
    return relay_record


@dataclass(order=True)
class _QueuedWitnessMessage:
    delivery_time: int
    sequence: int
    source: str
    destination: str
    payload: dict[str, Any]


class WitnessResolver:
    """Reference local policy: receipts gate independent corroboration."""

    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self.events: list[dict[str, Any]] = []

    def resolve(self, subject_id: str, records: Iterable[Mapping[str, Any]], now: int) -> OperatingEnvelope:
        relevant = [item for item in records if item["subject"]["id"] == subject_id and parse_rfc3339(item["expires_at"]) >= now]
        withdrawn = {
            item.get("metadata", {}).get("withdraws")
            for item in relevant
            if item["observation_type"] == "recovery.withdrawal" and item.get("metadata", {}).get("withdraws")
        }
        active = [item for item in relevant if item["observation_id"] not in withdrawn and item["observation_type"] != "recovery.withdrawal"]
        threats = [item for item in active if item["observation_type"] in THREAT_TYPES and item["severity"] in {"high", "critical"}]
        independent = [
            item for item in threats
            if item.get("effective_evidence_class") in {"independent_peer", "neutral_third_party"} and item.get("receipt_verified")
        ]
        direct = [item for item in threats if item.get("direct_local")]
        independence_set = sorted({str(item["observer_control_group_id"]) for item in independent})
        clean = [item for item in active if item["observation_type"] in CLEAN_TYPES and item.get("receipt_verified")]
        recovery = [item for item in relevant if item["observation_type"] == "recovery.withdrawal"]
        ids = tuple(item["observation_id"] for item in active)
        if len(independence_set) >= 2 and any(item["severity"] == "critical" for item in independent):
            envelope = OperatingEnvelope(
                state="quarantined", allowed_capabilities=(), denied_capabilities=("*",), actions=("quarantine",),
                reasons=("critical receipt-verified evidence from distinct control groups",), observation_ids=ids,
            )
        elif independent or direct:
            envelope = OperatingEnvelope(
                state="constrained", denied_capabilities=("data.export",), actions=("reduce_capability", "observe"),
                reasons=("direct or receipt-verified independent high-risk observation",), observation_ids=ids,
            )
        elif recovery and clean:
            envelope = OperatingEnvelope(state="healthy", actions=("allow",), reasons=("withdrawal plus clean evidence",), observation_ids=ids)
        elif recovery:
            envelope = OperatingEnvelope(
                state="approval_gated", denied_capabilities=("financial.transfer", "memory.write"), actions=("require_approval",),
                reasons=("withdrawal requires clean evidence before full restoration",), observation_ids=ids,
            )
        elif not active:
            envelope = OperatingEnvelope(
                state="approval_gated", denied_capabilities=("financial.transfer", "memory.write"), actions=("observe", "require_approval"),
                reasons=("no evidence; cautious first-contact envelope",), observation_ids=(),
            )
        elif threats:
            envelope = OperatingEnvelope(state="suspicious", actions=("observe",), reasons=("non-independent high-risk claim retained for audit",), observation_ids=ids)
        elif clean:
            envelope = OperatingEnvelope(state="healthy", actions=("allow",), reasons=("clean receipt-verified evidence",), observation_ids=ids)
        else:
            envelope = OperatingEnvelope(state="unknown", actions=("observe",), reasons=("no admissible evidence",), observation_ids=ids)
        self.events.append(
            {
                "stream": "resolution", "event_type": "witness_resolved", "at": now, "node_id": self.node_id,
                "subject_id": subject_id, "state": envelope.state, "observation_ids": list(envelope.observation_ids),
                "independence_set": independence_set,
                "conflicting_evidence": bool(threats and clean),
            }
        )
        return envelope


class WitnessNode:
    """Sovereign v0.2 receiver with append-only in-memory evidence streams."""

    def __init__(self, node_id: str, validator: WitnessValidator, clock: VirtualClock) -> None:
        self.node_id = node_id
        self.validator = validator
        self.clock = clock
        self.resolver = WitnessResolver(node_id)
        self.responses = SimulatedResponseAdapter()
        self.observations: dict[str, dict[str, Any]] = {}
        self.classifications: list[dict[str, Any]] = []
        self.protocol_events: list[dict[str, Any]] = []
        self.relay_events: list[dict[str, Any]] = []

    def receive(self, observation: Mapping[str, Any], *, direct_local: bool = False) -> WitnessValidationResult:
        result = self.validator.validate(observation, self.clock.now)
        payload = {"node_id": self.node_id, "observation_id": observation.get("observation_id"), "code": result.code}
        if not result.accepted:
            self.protocol_events.append({"stream": "protocol", "event_type": "observation_rejected", "at": self.clock.now, **payload})
            return result
        if observation["observation_id"] in self.observations:
            duplicate = WitnessValidationResult.reject("replay_detected")
            self.protocol_events.append({"stream": "protocol", "event_type": "observation_rejected", "at": self.clock.now, **payload, "code": duplicate.code})
            return duplicate
        stored = deepcopy(dict(observation))
        stored["effective_evidence_class"] = result.effective_evidence_class
        stored["receipt_verified"] = result.receipt_verified
        stored["direct_local"] = direct_local
        self.observations[str(observation["observation_id"])] = stored
        classification = {
            "stream": "classification", "event_type": "observation_classified", "at": self.clock.now,
            "node_id": self.node_id, "observation_id": observation["observation_id"],
            "declared_evidence_class": observation["declared_evidence_class"],
            "effective_evidence_class": result.effective_evidence_class, "reason_code": result.code,
            "receipt_verified": result.receipt_verified,
        }
        self.classifications.append(classification)
        self.protocol_events.append({"stream": "protocol", "event_type": "observation_accepted", "at": self.clock.now, **payload})
        subject_id = str(observation["subject"]["id"])
        envelope = self.resolver.resolve(subject_id, self.observations.values(), self.clock.now)
        self.responses.apply(subject_id, envelope, self.clock.now, source="witness_local" if direct_local else "tcx_witness")
        return result

    def record_relay(self, relay: Mapping[str, Any]) -> None:
        self.relay_events.append({"stream": "witness", "event_type": "relay_recorded", "at": self.clock.now, **deepcopy(dict(relay))})


class PatrolScheduler:
    """Deterministic, authorization-bound patrol event generator."""

    def __init__(self, cluster: "WitnessCluster") -> None:
        self.cluster = cluster

    def challenge(
        self,
        *,
        patrol_id: str,
        subject_id: str,
        target_node: str,
        authorization_id: str,
        outcome: str,
        receipt_refused: bool = False,
        available: bool = True,
    ) -> tuple[dict[str, Any] | None, str]:
        if not available:
            self.cluster.patrol_events.append({"stream": "patrol", "event_type": "patrol_unavailable", "at": self.cluster.clock.now, "patrol_id": patrol_id, "subject_id": subject_id})
            return None, "patrol_unavailable"
        authorization = self.cluster.patrol_authorizations.get(authorization_id)
        if authorization is None:
            return None, "patrol_not_authorized"
        key = self.cluster.keys[patrol_id]
        subject_key = None if receipt_refused else self.cluster.keys.get(subject_id)
        capability = authorization["capabilities"][0]
        receipt = make_interaction_receipt(
            key, subject_key, self.cluster.control_groups, interaction_id=observation_id("interaction", patrol_id, subject_id, self.cluster.clock.now),
            capability=capability, now=self.cluster.clock.now, receipt_mode="unilateral_transport" if receipt_refused else "bilateral",
            challenge_profile_id=authorization["challenge_profile_id"], subject_id=subject_id,
        )
        digest = receipt_hash(receipt)
        self.cluster.receipts[digest] = receipt
        self.cluster.patrol_usage[authorization_id] = self.cluster.patrol_usage.get(authorization_id, 0) + 1
        observation = make_v02_observation(
            key, self.cluster.control_groups, subject_id=subject_id,
            observation_type="patrol.clean_result" if outcome == "clean" else "patrol.challenge_failure",
            scope=(capability,), now=self.cluster.clock.now, sequence_number=self.cluster.next_sequence(patrol_id, subject_id),
            severity="low" if outcome == "clean" else "critical", declared_evidence_class="neutral_third_party",
            observation_mode="active_patrol", interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest,
            receipt_mode=receipt["receipt_mode"], challenge_profile_id=authorization["challenge_profile_id"], challenge_profile_version="v1",
            patrol_authorization_ref=authorization_id, synthetic_data_only=True,
        )
        result = self.cluster.nodes[target_node].receive(observation, direct_local=True)
        self.cluster.patrol_events.append({"stream": "patrol", "event_type": "patrol_challenge_completed", "at": self.cluster.clock.now, "patrol_id": patrol_id, "subject_id": subject_id, "outcome": outcome, "observation_id": observation["observation_id"], "accepted": result.accepted})
        return observation, result.code


class WitnessCluster:
    """Deterministic five-domain witness graph with partition-aware exchange."""

    def __init__(self, *, node_count: int = 5, now: int = 1_800_000_000) -> None:
        self.clock = VirtualClock(now)
        self.identities = AuthorityRegistry()
        self.control_groups = ControlGroupRegistry()
        self.keys: dict[str, KeyMaterial] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.patrol_authorizations: dict[str, dict[str, Any]] = {}
        self.patrol_usage: dict[str, int] = {}
        self.patrol_events: list[dict[str, Any]] = []
        self.partitions: set[tuple[str, str]] = set()
        self._queue: list[_QueuedWitnessMessage] = []
        self._counter = itertools.count()
        self._sequences: dict[tuple[str, str], int] = {}
        self._register_principal("agent-external-1", "domain-external", "control-external", "subject")
        self._register_principal("agent-same-control", "domain-external", "control-external", "subject")
        self._register_principal("agent-hidden-control", "domain-alias", "control-external", "subject")
        self._register_principal("patrol-neutral", "domain-neutral-audit", "control-neutral-audit", "patrol")
        self._register_principal("patrol-peer", "domain-peer-patrol", "control-peer-patrol", "patrol")
        self._register_principal("patrol-local", "domain-external", "control-external", "patrol")
        self.nodes: dict[str, WitnessNode] = {}
        for number in range(1, node_count + 1):
            node_id = f"node-{number}"
            self._register_principal(node_id, f"domain-{node_id}", f"control-{node_id}", "peer")
        for node_id in [f"node-{number}" for number in range(1, node_count + 1)]:
            validator = WitnessValidator(self.identities, self.control_groups, self.receipts, self.patrol_authorizations, self.patrol_usage)
            self.nodes[node_id] = WitnessNode(node_id, validator, self.clock)
        self.patrols = PatrolScheduler(self)

    def _register_principal(self, principal_id: str, admin_domain: str, control_group: str, role: str) -> None:
        self.control_groups.register(Principal(principal_id, admin_domain, control_group, role))
        key = KeyMaterial.deterministic(principal_id, admin_domain, scopes=("*",), observation_types=("*",))
        self.keys[principal_id] = key
        self.identities.register(key.identity)

    def next_sequence(self, observer_id: str, subject_id: str) -> int:
        key = (observer_id, subject_id)
        self._sequences[key] = self._sequences.get(key, 0) + 1
        return self._sequences[key]

    def authorize_patrol(
        self,
        authorization_id: str,
        patrol_id: str,
        *,
        targets: Iterable[str] = ("agent-external-1",),
        capabilities: Iterable[str] = ("tool:data.export",),
        ttl: int = 30,
        query_budget: int = 2,
    ) -> dict[str, Any]:
        authorization = {
            "authorization_id": authorization_id, "patrol_id": patrol_id, "targets": list(targets), "capabilities": list(capabilities),
            "challenge_profile_id": "safe-canary-v1", "issued_at": as_rfc3339(self.clock.now), "expires_at": as_rfc3339(self.clock.now + ttl),
            "query_budget": query_budget, "rate_limit": 1, "max_concurrency": 1, "synthetic_data_only": True,
        }
        self.patrol_authorizations[authorization_id] = authorization
        return authorization

    def passive_observe(
        self,
        node_id: str,
        subject_id: str,
        *,
        observation_type: str = "tool.prohibited_export",
        severity: str = "critical",
        receipt_refused: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any], WitnessValidationResult]:
        observer = self.keys[node_id]
        subject = None if receipt_refused else self.keys.get(subject_id)
        receipt = make_interaction_receipt(
            observer, subject, self.control_groups, interaction_id=observation_id("interaction", node_id, subject_id, self.clock.now),
            capability="tool:data.export", now=self.clock.now, receipt_mode="unilateral_transport" if receipt_refused else "bilateral", subject_id=subject_id,
        )
        digest = receipt_hash(receipt)
        self.receipts[digest] = receipt
        observation = make_v02_observation(
            observer, self.control_groups, subject_id=subject_id, observation_type=observation_type, scope=("tool:data.export",),
            now=self.clock.now, sequence_number=self.next_sequence(node_id, subject_id), severity=severity,
            interaction_id=receipt["interaction_id"], interaction_receipt_hash=digest, receipt_mode=receipt["receipt_mode"],
        )
        result = self.nodes[node_id].receive(observation, direct_local=True)
        return observation, receipt, result

    def self_assert(self, subject_id: str, *, healthy: bool = True) -> tuple[dict[str, Any], WitnessValidationResult]:
        key = self.keys[subject_id]
        observation = make_v02_observation(
            key, self.control_groups, subject_id=subject_id, observation_type="attestation.result" if healthy else "tool.prohibited_export",
            scope=("runtime:default",), now=self.clock.now, sequence_number=self.next_sequence(subject_id, subject_id), severity="low" if healthy else "critical",
            declared_evidence_class="independent_peer", observation_mode="attestation",
        )
        return observation, self.nodes["node-1"].receive(observation)

    def disseminate(self, source: str, observation: Mapping[str, Any], *, destinations: Iterable[str] | None = None, delay: int = 0) -> None:
        for destination in destinations or self.nodes:
            pair = tuple(sorted((source, destination)))
            if pair in self.partitions:
                self.nodes.get(source, self.nodes["node-1"]).protocol_events.append({"stream": "protocol", "event_type": "peer_unreachable", "at": self.clock.now, "source": source, "destination": destination})
                continue
            heapq.heappush(self._queue, _QueuedWitnessMessage(self.clock.now + delay, next(self._counter), source, destination, deepcopy(dict(observation))))
        self.deliver_due()

    def relay(self, source: str, destination: str, original: Mapping[str, Any], relay_id: str) -> str:
        wire_original = {key: value for key, value in original.items() if key not in {"effective_evidence_class", "receipt_verified", "direct_local"}}
        relay = make_relay(wire_original, self.keys[relay_id], now=self.clock.now)
        if relay_id in relay["relay_chain"][:-1]:
            return "relay_loop"
        original_identity = original.get("observer", {})
        if relay["original_observation_id"] != wire_original.get("observation_id") or relay["original_observation"].get("observer") != original_identity:
            return "relay_origin_changed"
        self.nodes[destination].record_relay(relay)
        result = self.nodes[destination].receive(relay["original_observation"])
        return result.code

    def partition(self, left: str, right: str) -> None:
        self.partitions.add(tuple(sorted((left, right))))

    def heal(self, left: str, right: str) -> None:
        self.partitions.discard(tuple(sorted((left, right))))

    def synchronize_after_heal(self, source: str, destination: str) -> list[str]:
        """Replay immutable originals after a healed link; no new witness credit."""

        codes = []
        for observation in self.nodes[source].observations.values():
            codes.append(self.relay(source, destination, observation, source))
        return codes

    def deliver_due(self) -> None:
        while self._queue and self._queue[0].delivery_time <= self.clock.now:
            message = heapq.heappop(self._queue)
            if tuple(sorted((message.source, message.destination))) in self.partitions:
                continue
            self.nodes[message.destination].receive(message.payload)

    def advance(self, seconds: int = 1) -> None:
        self.clock.advance(seconds)
        self.deliver_due()

    def all_observations(self) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for node in self.nodes.values():
            unique.update(node.observations)
        return [unique[key] for key in sorted(unique)]

    def witness_edges(self) -> list[dict[str, Any]]:
        return [witness_edge(observation) for observation in self.all_observations()]


def witness_edge(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Project an accepted, receiver-classified observation into graph form."""

    return {
        "observer_id": observation["observer"]["id"], "observer_admin_domain_id": observation["observer_admin_domain_id"],
        "observer_control_group_id": observation["observer_control_group_id"], "subject_id": observation["subject"]["id"],
        "subject_admin_domain_id": observation["subject_admin_domain_id"], "subject_control_group_id": observation["subject_control_group_id"],
        "interaction_id": observation["interaction_id"], "interaction_type": observation["observation_type"],
        "observation_mode": observation["observation_mode"], "observation_id": observation["observation_id"],
        "evidence_class": observation["effective_evidence_class"], "scope": observation["scope"],
        "issued_at": observation["issued_at"], "expires_at": observation["expires_at"],
        "receipt_verification_state": "verified" if observation["receipt_verified"] else "unverified",
        "relay_chain": observation["relay_chain"],
    }
