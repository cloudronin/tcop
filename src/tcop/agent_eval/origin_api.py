"""Origin-domain signing and federation relay for the live agent study.

This reference endpoint has no authorization or enforcement surface.  It only
creates an origin-signed observation/receipt pair from an already B-minted
opaque correlation handle, then forwards it to Domain B's context-admission
endpoint over the isolated compose network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..witness import make_interaction_receipt, make_v02_observation, receipt_hash
from .trace_replay import LOCAL_MONITOR_HARMFUL, _universe


REQUIRED = frozenset({"scenario", "capability", "interaction_handle", "session_id", "principal_id", "trial_id", "receiver_endpoint"})


class OriginFederationError(ValueError):
    """Malformed origin relay input; it cannot induce an enforcement action."""


class OriginFederationEndpoint:
    """Domain A reference relay, intentionally separated from Domain B policy."""

    def federate(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if set(payload) != REQUIRED or not all(isinstance(payload.get(key), str) and payload.get(key) for key in REQUIRED):
            raise OriginFederationError("origin_federation_request_invalid")
        scenario, capability = str(payload["scenario"]), str(payload["capability"])
        if scenario not in LOCAL_MONITOR_HARMFUL or capability not in LOCAL_MONITOR_HARMFUL[scenario]:
            raise OriginFederationError("origin_federation_scope_invalid")
        identities, groups, keys = _universe()
        now = int(datetime.now(UTC).timestamp())
        handle = str(payload["interaction_handle"])
        receipt = make_interaction_receipt(
            keys["origin-monitor-a"], keys["origin-agent-a"], groups,
            interaction_id=handle, capability=capability, now=now, request=handle,
            response="accepted-synthetic-cross-domain-interaction", receipt_mode="bilateral",
            transport_evidence="tcopd-a-origin-federation-relay",
        )
        context = make_v02_observation(
            keys["origin-monitor-a"], groups, subject_id="origin-agent-a",
            observation_type="tool.prohibited_export", scope=tuple(sorted(LOCAL_MONITOR_HARMFUL[scenario])),
            now=now, sequence_number=1, ttl=60, severity="high", declared_evidence_class="independent_peer",
            observation_mode="passive", interaction_id=handle, interaction_receipt_hash=receipt_hash(receipt),
            receipt_mode=receipt["receipt_mode"], metadata={"scenario": scenario, "trial_id": str(payload["trial_id"]), "action": "deny"},
        )
        request = Request(
            str(payload["receiver_endpoint"]).rstrip("/") + "/v1/context",
            data=json.dumps({"context": context, "receipt": receipt, "session_id": payload["session_id"], "principal_id": payload["principal_id"]}, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - compose-internal endpoint supplied by fixed study runtime
                admission = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError) as exc:
            raise OriginFederationError(f"origin_federation_delivery_failed:{type(exc).__name__}") from exc
        if not isinstance(admission, dict):
            raise OriginFederationError("origin_federation_delivery_malformed")
        return {
            "origin_service": "tcopd-a", "signed_by": "origin-monitor-a", "receipt_ref": receipt_hash(receipt),
            "context_id": context.get("observation_id"), "admission": admission,
            "remote_enforcement_successes": 0,
        }


class _Server(ThreadingHTTPServer):
    endpoint: OriginFederationEndpoint


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/federate-context":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16_384:
                raise OriginFederationError("origin_federation_length_invalid")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise OriginFederationError("origin_federation_shape_invalid")
            result = self.server.endpoint.federate(payload)
            rendered = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(HTTPStatus.OK)
        except (UnicodeDecodeError, ValueError, OriginFederationError) as exc:
            rendered = json.dumps({"error": str(exc)}, sort_keys=True).encode("utf-8")
            self.send_response(HTTPStatus.BAD_REQUEST)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(rendered)))
        self.end_headers()
        self.wfile.write(rendered)


def serve_origin_federation(*, host: str = "127.0.0.1", port: int = 8090) -> None:
    server = _Server((host, port), _Handler)
    server.endpoint = OriginFederationEndpoint()
    server.serve_forever()
