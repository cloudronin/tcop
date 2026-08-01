"""Receiver-local HTTP bridge for the generic reference-gateway hook.

The HTTP surface deliberately accepts only local invocation facts.  Context
admission is not exposed here: signed contexts and B-private receipt bindings
are admitted by the receiver process before a gateway call is evaluated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import time
from typing import Any, Mapping

from .authorization import LocalAuthorizationEvaluator
from .correlation import CorrelationError
from .models import AuthorizationRequest


DEFAULT_TOOL_CAPABILITIES = {
    "public_search": "public.read",
    "repository_read": "repository.read",
    "repository_write": "repository.write",
    "credential_use": "credential.use",
    "dataset_export": "dataset.export",
    "workload_spawn": "workload.spawn",
    "incident_status": "incident.response",
}
_REQUEST_KEYS = frozenset({"session_id", "client_name", "server", "tool"})
_RESERVE_KEYS = frozenset({"session_id", "principal_id", "capability", "ttl"})
_CONTEXT_KEYS = frozenset({"context", "receipt", "session_id", "principal_id"})


class LocalAuthorizationRequestError(ValueError):
    """Malformed gateway-local request; it never becomes an action."""


@dataclass
class LocalAuthorizationEndpoint:
    """Small cache-free B-local evaluator adapter for a patched gateway."""

    evaluator: LocalAuthorizationEvaluator
    tool_capabilities: Mapping[str, str]
    workload_id: str = "reference-mcp-gateway"

    def __init__(
        self,
        evaluator: LocalAuthorizationEvaluator,
        tool_capabilities: Mapping[str, str] | None = None,
        workload_id: str = "reference-mcp-gateway",
    ) -> None:
        self.evaluator = evaluator
        self.tool_capabilities = dict(tool_capabilities or DEFAULT_TOOL_CAPABILITIES)
        self.workload_id = workload_id

    def evaluate(self, payload: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Return a B-local decision for one gateway call, never from a cache."""

        if set(payload) != _REQUEST_KEYS:
            raise LocalAuthorizationRequestError("gateway_local_request_shape_invalid")
        values = {key: payload.get(key) for key in _REQUEST_KEYS}
        if not all(isinstance(value, str) and value for value in values.values()):
            raise LocalAuthorizationRequestError("gateway_local_request_value_invalid")
        tool = str(values["tool"])
        capability = self.tool_capabilities.get(tool, f"unmapped.{tool}")
        request = AuthorizationRequest(
            domain_id=self.evaluator.domain_id,
            principal_id=str(values["client_name"]),
            session_id=str(values["session_id"]),
            workload_id=self.workload_id,
            capability=capability,
            tool=tool,
            resource=f"gateway-server:{values['server']}",
            receipt_ref=None,
        )
        decision = self.evaluator.authorize(request, now=int(time()) if now is None else now)
        return {
            "allowed": decision.decision == "allow",
            "decision_id": decision.decision_id,
            "policy_id": decision.policy_id,
            "authority_domain": decision.domain_id,
            "reason_code": decision.reason_code,
            "cache": "disabled",
        }

    def reserve_correlation(self, payload: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Reserve one opaque B handle before the origin signs a receipt."""

        if set(payload) != _RESERVE_KEYS:
            raise LocalAuthorizationRequestError("correlation_reservation_shape_invalid")
        if not all(isinstance(payload.get(key), str) and payload.get(key) for key in ("session_id", "principal_id", "capability")):
            raise LocalAuthorizationRequestError("correlation_reservation_value_invalid")
        ttl = payload.get("ttl")
        if not isinstance(ttl, int) or ttl <= 0 or ttl > 3600:
            raise LocalAuthorizationRequestError("correlation_reservation_ttl_invalid")
        pending = self.evaluator.correlations.reserve(
            session_id=str(payload["session_id"]),
            principal_id=str(payload["principal_id"]),
            capability=str(payload["capability"]),
            now=int(time()) if now is None else now,
            ttl=ttl,
        )
        return {
            "interaction_handle": pending.interaction_handle,
            "expires_at": pending.expires_at,
            "generation": pending.generation,
        }

    def admit_context(self, payload: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Bind and validate a signed context only against its B reservation."""

        if set(payload) != _CONTEXT_KEYS:
            raise LocalAuthorizationRequestError("context_admission_shape_invalid")
        context, receipt = payload.get("context"), payload.get("receipt")
        if not isinstance(context, Mapping) or not isinstance(receipt, Mapping):
            raise LocalAuthorizationRequestError("context_admission_value_invalid")
        session_id, principal_id = payload.get("session_id"), payload.get("principal_id")
        if not isinstance(session_id, str) or not session_id or not isinstance(principal_id, str) or not principal_id:
            raise LocalAuthorizationRequestError("context_admission_subject_invalid")
        current = int(time()) if now is None else now
        receipt_ref = context.get("interaction_receipt_hash")
        if not isinstance(receipt_ref, str):
            raise LocalAuthorizationRequestError("context_admission_receipt_missing")
        try:
            if not self.evaluator.correlations.has_binding(receipt_ref):
                self.evaluator.correlations.bind(receipt_ref, receipt, now=current)
            return self.evaluator.accept_imported_context(
                context,
                receipt,
                session_id=session_id,
                principal_id=principal_id,
                now=current,
            )
        except CorrelationError as exc:
            return {"accepted": False, "code": str(exc), "restriction_created": False}


class _LocalAuthorizationHTTPServer(ThreadingHTTPServer):
    endpoint: LocalAuthorizationEndpoint


class _Handler(BaseHTTPRequestHandler):
    server: _LocalAuthorizationHTTPServer

    def log_message(self, _format: str, *_args: Any) -> None:
        # Requests are represented by the evaluator's append-only audit log.
        return

    def _reply(self, status: HTTPStatus, body: Mapping[str, Any]) -> None:
        rendered = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(rendered)))
        self.end_headers()
        self.wfile.write(rendered)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path not in {"/v1/authorize", "/v1/correlation/reserve", "/v1/context"}:
            self._reply(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16_384:
                raise LocalAuthorizationRequestError("gateway_local_request_length_invalid")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise LocalAuthorizationRequestError("gateway_local_request_shape_invalid")
            if self.path == "/v1/authorize":
                result = self.server.endpoint.evaluate(payload)
            elif self.path == "/v1/correlation/reserve":
                result = self.server.endpoint.reserve_correlation(payload)
            else:
                result = self.server.endpoint.admit_context(payload)
            self._reply(HTTPStatus.OK, result)
        except (UnicodeDecodeError, ValueError, LocalAuthorizationRequestError) as exc:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


def serve_local_authorization(
    endpoint: LocalAuthorizationEndpoint,
    *,
    host: str = "127.0.0.1",
    port: int = 8091,
) -> None:
    """Serve the adapter until the process is stopped by the study harness."""

    server = _LocalAuthorizationHTTPServer((host, port), _Handler)
    server.endpoint = endpoint
    server.serve_forever()
