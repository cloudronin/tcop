"""Generic MCP authorization hook and synthetic stateful tool service.

The hook has no TCOP-specific branches: it turns an MCP call into the small
local authorization-evaluator contract and acts only on the returned local
decision. A product-specific gateway patch should call this same contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .models import AuthorizationDecision, AuthorizationRequest, EventRecorder, HARMFUL_CAPABILITIES, ToolCall


class LocalAuthorizationClient(Protocol):
    """The sole interface required by the reference gateway integration."""

    def authorize(self, request: AuthorizationRequest, *, now: int) -> AuthorizationDecision: ...


@dataclass(frozen=True)
class GatewayResult:
    request_id: str
    forwarded: bool
    state_changed: bool
    decision: dict[str, Any]
    mcp_error: dict[str, Any] | None = None


class SyntheticToolService:
    """Sandbox-only MCP tool semantics. No method performs network I/O."""

    TOOL_CAPABILITIES = {
        "public_search": "public.read",
        "repository_read": "repository.read",
        "repository_write": "repository.write",
        "credential_use": "credential.use",
        "dataset_export": "dataset.export",
        "workload_spawn": "workload.spawn",
        "incident_status": "incident.response",
    }

    def __init__(self) -> None:
        self.events = EventRecorder()
        self.state: dict[str, Any] = {
            "repository_revision": 0,
            "privileged_sessions": 0,
            "exports": 0,
            "child_workloads": 0,
        }

    def execute(self, call: ToolCall, *, request_id: str, session_id: str) -> tuple[bool, dict[str, Any]]:
        if self.TOOL_CAPABILITIES.get(call.tool) != call.capability:
            raise ValueError("tool_capability_mismatch")
        before = dict(self.state)
        if call.tool == "repository_write":
            self.state["repository_revision"] += 1
        elif call.tool == "credential_use":
            self.state["privileged_sessions"] += 1
        elif call.tool == "dataset_export":
            self.state["exports"] += 1
        elif call.tool == "workload_spawn":
            self.state["child_workloads"] += 1
        changed = before != self.state
        event = self.events.record(
            "tool_execution_completed",
            request_id=request_id,
            session_id=session_id,
            tool=call.tool,
            capability=call.capability,
            resource=call.resource,
            arguments_digest=call.request_digest,
            state_changed=changed,
            protected_resources_affected=(1 if call.capability in HARMFUL_CAPABILITIES and changed else 0),
        )
        return changed, event


class GenericMcpAuthorizationAdapter:
    """A cache-free reference adapter usable by a real MCP gateway patch."""

    def __init__(self, evaluator: LocalAuthorizationClient, tools: SyntheticToolService, *, domain_id: str) -> None:
        self.evaluator = evaluator
        self.tools = tools
        self.domain_id = domain_id
        self.events = EventRecorder()

    def invoke(
        self,
        call: ToolCall,
        *,
        request_id: str,
        principal_id: str,
        session_id: str,
        workload_id: str,
        receipt_ref: str | None,
        now: int,
    ) -> GatewayResult:
        request = AuthorizationRequest(
            domain_id=self.domain_id,
            principal_id=principal_id,
            session_id=session_id,
            workload_id=workload_id,
            capability=call.capability,
            tool=call.tool,
            resource=call.resource,
            receipt_ref=receipt_ref,
        )
        self.events.record("gateway_authorization_requested", request_id=request_id, request=request.as_dict(), cache="disabled")
        try:
            decision = self.evaluator.authorize(request, now=now)
        except Exception as exc:  # evaluator-unavailable is deliberately a local gateway policy decision
            high_risk = call.capability in HARMFUL_CAPABILITIES
            fallback = "deny" if high_risk else "allow"
            self.events.record("gateway_authorization_unavailable", request_id=request_id, fallback=fallback, error=type(exc).__name__)
            if high_risk:
                return GatewayResult(
                    request_id=request_id,
                    forwarded=False,
                    state_changed=False,
                    decision={"decision": "deny", "decision_id": "local-timeout", "reason_code": "local_authorization_timeout"},
                    mcp_error={"code": -32001, "message": "tool call denied by local policy", "data": {"decision_id": "local-timeout", "policy_id": "gateway-local-timeout-policy", "decision_authority": self.domain_id}},
                )
            return GatewayResult(request_id=request_id, forwarded=True, state_changed=self.tools.execute(call, request_id=request_id, session_id=session_id)[0], decision={"decision": "allow", "decision_id": "local-timeout-allow", "reason_code": "local_authorization_timeout_allow"})
        public = decision.public()
        self.events.record("gateway_authorization_received", request_id=request_id, decision=public)
        if decision.decision != "allow":
            self.events.record("gateway_call_blocked", request_id=request_id, decision_id=decision.decision_id, local_policy_id=decision.policy_id)
            return GatewayResult(
                request_id=request_id,
                forwarded=False,
                state_changed=False,
                decision=public,
                mcp_error={"code": -32001, "message": "tool call denied by local policy", "data": {"decision_id": decision.decision_id, "policy_id": decision.policy_id, "decision_authority": decision.domain_id}},
            )
        self.events.record("gateway_call_forwarded", request_id=request_id, decision_id=decision.decision_id, local_policy_id=decision.policy_id)
        changed, _ = self.tools.execute(call, request_id=request_id, session_id=session_id)
        return GatewayResult(request_id=request_id, forwarded=True, state_changed=changed, decision=public)
