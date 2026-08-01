"""Stable study-only records for v0.6 agent validation.

These types describe the executable evaluation and its artifacts.  They are
not TCX wire records and must never be accepted by a TCOP protocol validator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from time import monotonic_ns, time
from typing import Any, Mapping

from ..canonical import canonical_bytes


STUDY_VERSION = "tcop.agent-validation/0.1"
HARMFUL_CAPABILITIES = frozenset({"repository.write", "credential.use", "dataset.export", "workload.spawn"})
BENIGN_CAPABILITIES = frozenset({"public.read", "repository.read", "incident.response"})


def digest(value: Any) -> str:
    """Return the canonical content digest used by all study records."""

    return sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class ToolCall:
    """A canonical MCP tool request retained for strict counterfactual replay."""

    trace_id: str
    ordinal: int
    tool: str
    capability: str
    resource: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def canonical_request(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "ordinal": self.ordinal,
            "method": "tools/call",
            "tool": self.tool,
            "capability": self.capability,
            "resource": self.resource,
            "arguments": dict(self.arguments),
        }

    @property
    def request_digest(self) -> str:
        return digest(self.canonical_request())


@dataclass(frozen=True)
class AuthorizationRequest:
    """Gateway-to-local-evaluator request; it contains no remote decision."""

    domain_id: str
    principal_id: str
    session_id: str
    workload_id: str
    capability: str
    tool: str
    resource: str
    receipt_ref: str | None
    campaign_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "subject": {"principal_id": self.principal_id, "session_id": self.session_id, "workload_id": self.workload_id},
            "action": {"protocol": "mcp", "method": "tools/call", "tool": self.tool, "capability": self.capability, "resource": self.resource},
            "interaction": {"receipt_ref": self.receipt_ref, "campaign_ref": self.campaign_ref},
        }


@dataclass(frozen=True)
class AuthorizationDecision:
    """A decision made in Domain B and consumable by a generic gateway hook."""

    decision: str
    decision_id: str
    disposition: str
    capability_scope: tuple[str, ...]
    strategy: str
    valid_until: int
    reason_code: str
    domain_id: str
    policy_id: str
    evidence_ids: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        """The only data a gateway is allowed to receive from the evaluator."""

        return {
            "decision": self.decision,
            "decision_id": self.decision_id,
            "disposition": self.disposition,
            "capability_scope": list(self.capability_scope),
            "strategy": self.strategy,
            "valid_until": self.valid_until,
            "reason_code": self.reason_code,
            "decision_authority": self.domain_id,
            "policy_id": self.policy_id,
        }

    def audit(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EventRecorder:
    """Captures host-comparable monotonic and readable wall-clock timestamps."""

    events: list[dict[str, Any]] = field(default_factory=list)
    _sequence: int = 0

    def record(self, event_type: str, **values: Any) -> dict[str, Any]:
        self._sequence += 1
        item = {
            "event_type": event_type,
            "sequence": self._sequence,
            "monotonic_ns": monotonic_ns(),
            "wall_time_unix_ms": int(time() * 1000),
            **values,
        }
        self.events.append(item)
        return item


def trace_digest(calls: list[ToolCall]) -> str:
    return digest([call.canonical_request() for call in calls])
