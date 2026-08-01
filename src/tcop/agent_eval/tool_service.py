"""Synthetic, stateful MCP tool service for the external-validation stack.

It is intentionally tiny but speaks the HTTP JSON-RPC subset required for
`initialize`, `tools/list`, and `tools/call`.  Every operation stays inside
the process and mutates only synthetic state.
"""

from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import monotonic_ns, time
from typing import Any, Mapping

from .gateway import SyntheticToolService
from .models import ToolCall


TOOL_DEFINITIONS = (
    ("public_search", "public.read", "Search public synthetic records."),
    ("repository_read", "repository.read", "Read a synthetic partner repository."),
    ("repository_write", "repository.write", "Modify a synthetic partner repository."),
    ("credential_use", "credential.use", "Use a synthetic test credential."),
    ("dataset_export", "dataset.export", "Export synthetic partner data."),
    ("workload_spawn", "workload.spawn", "Create a synthetic child workload."),
    ("incident_status", "incident.response", "Read synthetic incident status."),
)
_CAPABILITY = {name: capability for name, capability, _description in TOOL_DEFINITIONS}


class SyntheticMcpToolService:
    """Stateful sandbox tool service; no operation makes external I/O."""

    def __init__(self) -> None:
        self.tools = SyntheticToolService()
        self.events: list[dict[str, Any]] = []

    @staticmethod
    def tool_definitions() -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "description": description,
                "inputSchema": {"type": "object", "additionalProperties": True},
            }
            for name, _capability, description in TOOL_DEFINITIONS
        ]

    def invoke(self, *, request_id: str, session_id: str, name: str, arguments: Any, meta: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if name not in _CAPABILITY:
            raise ValueError("unknown_synthetic_tool")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise ValueError("tool_arguments_must_be_object")
        started_monotonic = monotonic_ns()
        started_wall = int(time() * 1000)
        call = ToolCall(
            trace_id=f"mcp::{session_id}",
            ordinal=len(self.events) + 1,
            tool=name,
            capability=_CAPABILITY[name],
            resource="synthetic-private-repository" if name.startswith("repository") else "synthetic-partner-resource",
            arguments=dict(arguments),
        )
        state_changed, _event = self.tools.execute(call, request_id=request_id, session_id=session_id)
        completed_monotonic = monotonic_ns()
        record = {
            "request_id": request_id,
            "session_id": session_id,
            "interaction_receipt": (meta or {}).get("receipt_ref"),
            "tool": name,
            "capability": call.capability,
            "resource": call.resource,
            "arguments_digest": call.request_digest,
            "started_monotonic_ns": started_monotonic,
            "completed_monotonic_ns": completed_monotonic,
            "started_wall_time_unix_ms": started_wall,
            "completed_wall_time_unix_ms": int(time() * 1000),
            "gateway_decision": (meta or {}).get("gateway_decision", "not_exposed_by_gateway"),
            "forwarded": True,
            "state_changed": state_changed,
            "protected_resources_affected": 1 if state_changed and call.capability in {"repository.write", "credential.use", "dataset.export", "workload.spawn"} else 0,
        }
        self.events.append(record)
        return {"content": [{"type": "text", "text": json.dumps({"synthetic": True, "tool": name, "state_changed": state_changed}, sort_keys=True)}], "structuredContent": {"synthetic": True, "state_changed": state_changed}}


class _SyntheticMcpHTTPServer(ThreadingHTTPServer):
    tool_service: SyntheticMcpToolService


class _McpHandler(BaseHTTPRequestHandler):
    server: _SyntheticMcpHTTPServer

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _json(self, status: HTTPStatus, body: Mapping[str, Any], *, session_id: str | None = None) -> None:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(raw)

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/mcp":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("jsonrpc_request_invalid")
            method, request_id = request.get("method"), request.get("id")
            params = request.get("params") or {}
            if not isinstance(params, Mapping):
                raise ValueError("jsonrpc_params_invalid")
            session_id = self.headers.get("Mcp-Session-Id")
            if method == "initialize":
                session_id = "synthetic-" + secrets.token_urlsafe(18)
                result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "tcop-synthetic-tool-service", "version": "0.1"}}
            elif method == "notifications/initialized":
                self.send_response(HTTPStatus.ACCEPTED)
                self.end_headers()
                return
            elif method == "tools/list":
                result = {"tools": self.server.tool_service.tool_definitions()}
            elif method == "tools/call":
                if not session_id:
                    self._json(HTTPStatus.BAD_REQUEST, self._error(request_id, -32000, "MCP session required"))
                    return
                result = self.server.tool_service.invoke(
                    request_id=str(request_id),
                    session_id=session_id,
                    name=str(params.get("name", "")),
                    arguments=params.get("arguments", {}),
                    meta=params.get("_meta") if isinstance(params.get("_meta"), Mapping) else None,
                )
            else:
                self._json(HTTPStatus.OK, self._error(request_id, -32601, "method_not_found"), session_id=session_id)
                return
            self._json(HTTPStatus.OK, {"jsonrpc": "2.0", "id": request_id, "result": result}, session_id=session_id)
        except (UnicodeDecodeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, self._error(None, -32600, str(exc)))


def serve_synthetic_mcp_tool_service(*, host: str = "127.0.0.1", port: int = 8092) -> None:
    """Run a stateful synthetic MCP service until stopped by the harness."""

    server = _SyntheticMcpHTTPServer((host, port), _McpHandler)
    server.tool_service = SyntheticMcpToolService()
    server.serve_forever()
