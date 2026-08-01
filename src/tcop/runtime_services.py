"""Small safe network runtime used by ``tcop service`` and ``tcop admin``.

The listener deliberately exposes only context exchange and observational
endpoints. It cannot accept a remote enforcement request: a received context
is validated, persisted, and resolved locally only.
"""

from __future__ import annotations

import json
import sys
from threading import Thread
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import time
from typing import Any, Mapping
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .cli_context import _registry_for_context
from .cli_support import EXIT_SERVICE, TCOPCommandError, load_config, require_domain_config
from .responses import SimulatedResponseAdapter
from .trust import ReferenceResolver
from .validation import ObservationValidator
from .witness import WitnessValidator, receipt_hash


@dataclass
class LocalServiceState:
    domain_id: str
    service_kind: str
    state_dir: Path
    trust_store: Path | None = None
    accepted: int = 0
    rejected: int = 0

    def __post_init__(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.observations: list[dict[str, Any]] = []
        self.resolver = ReferenceResolver()
        self.responses = SimulatedResponseAdapter()

    def validate_and_store(self, payload: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
        context = payload.get("context", payload)
        if not isinstance(context, Mapping):
            return False, {"accepted": False, "code": "schema_invalid"}
        try:
            # Services use the system clock. The deterministic harness invokes
            # the same validators with its injected virtual tick instead.
            now = int(time())
            registry, groups, _ = _registry_for_context(context, self.trust_store)
            version = str(context.get("protocol_version"))
            if version == "0.1":
                result = ObservationValidator(registry).validate(context, now)
                accepted, code = result.accepted, result.code or "accepted"
            elif version == "0.2":
                receipt = payload.get("receipt")
                receipts = {receipt_hash(receipt): receipt} if isinstance(receipt, Mapping) else {}
                result = WitnessValidator(registry, groups, receipts, {}, {}).validate(context, now)
                accepted, code = result.accepted, result.code
            else:
                accepted, code = False, "unsupported_version"
        except (KeyError, ValueError, TypeError):
            accepted, code = False, "schema_invalid"
        record: dict[str, Any] = {
            "stream": "gateway", "event_type": "context_received", "domain_id": self.domain_id,
            "at": int(time()), "accepted": accepted, "code": code,
            "observation_id": context.get("observation_id") if isinstance(context, Mapping) else None,
        }
        if accepted:
            stored = dict(context)
            self.observations.append(stored)
            self.accepted += 1
            envelope = self.resolver.resolve(str(stored["subject"]["id"]), self.observations, now)
            record["local_resolution"] = envelope.to_dict()
            event_count = len(self.responses.events)
            self.responses.apply(str(stored["subject"]["id"]), envelope, now, source="local-runtime")
            record["local_enforcement"] = self.responses.events[-1] if len(self.responses.events) > event_count else {"event_type": "operating_envelope_unchanged", "local_only": True}
        else:
            self.rejected += 1
        with (self.state_dir / "gateway-events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return accepted, record

    def status(self) -> dict[str, Any]:
        return {
            "service_version": "tcop.runtime-service/0.1",
            "domain_id": self.domain_id,
            "service_kind": self.service_kind,
            "accepted_contexts": self.accepted,
            "rejected_contexts": self.rejected,
            "network_operations": ["publish_context", "receive_context", "acknowledge_receipt", "query_capabilities", "health", "peer_status"],
            "remote_enforcement_available": False,
            "verification_mode": "configured_public_keys" if self.trust_store else "deterministic_development_fixture",
        }


def _parse_listen(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise TCOPCommandError("--listen must be HOST:PORT", EXIT_SERVICE)
    host, port = value.rsplit(":", 1)
    try:
        return host, int(port)
    except ValueError as exc:
        raise TCOPCommandError("--listen port must be an integer", EXIT_SERVICE) from exc


def _handler(state: LocalServiceState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TCOPGateway/0.6"

        def _json(self, status: int, value: Mapping[str, Any]) -> None:
            encoded = json.dumps(dict(value), sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            path = urlparse(self.path).path
            if path in {"/health", "/v1/health"}:
                self._json(200, {"healthy": True, **state.status()})
            elif path in {"/v1/capabilities", "/v1/peers", "/v1/status", "/metrics"}:
                self._json(200, state.status())
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            if urlparse(self.path).path not in {"/v1/context", "/v1/context/publish", "/v1/context/receive"}:
                self._json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, Mapping):
                    raise ValueError("request body must be an object")
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"accepted": False, "code": "schema_invalid"})
                return
            accepted, record = state.validate_and_store(payload)
            self._json(202 if accepted else 400, record)

        def log_message(self, fmt: str, *args: object) -> None:
            print(f"tcop-service: {fmt % args}", file=sys.stderr)

    return Handler


def _configured_trust_store(config_path: Path, spec: Mapping[str, Any]) -> Path | None:
    gateway = spec.get("gateway", {}) if isinstance(spec.get("gateway"), Mapping) else {}
    value = spec.get("trustStore") or gateway.get("trustStore")
    if not value:
        return None
    path = Path(str(value).removeprefix("file://"))
    return path if path.is_absolute() else config_path.parent / path


def service_description(
    config_path: Path, *, component: str, listen: str | None, state_dir: Path | None, transport: str | None,
    metrics_listen: str | None = None, health_listen: str | None = None,
) -> dict[str, Any]:
    loaded = require_domain_config(load_config(config_path))
    spec = loaded["spec"]
    configured_listen = (spec.get("gateway", {}) if isinstance(spec.get("gateway"), Mapping) else {}).get("listen")
    final_listen = listen or configured_listen or "127.0.0.1:8443"
    final_state = state_dir or Path(str((spec.get("resolver", {}) if isinstance(spec.get("resolver"), Mapping) else {}).get("stateDirectory") or ".tcop-state"))
    final_transport = transport or str((spec.get("gateway", {}) if isinstance(spec.get("gateway"), Mapping) else {}).get("transport") or "https")
    trust_store = _configured_trust_store(config_path, spec)
    if final_transport in {"http", "https"} and trust_store is None:
        raise TCOPCommandError("network transport requires spec.trustStore or spec.gateway.trustStore", EXIT_SERVICE)
    if trust_store is not None and not trust_store.is_file():
        raise TCOPCommandError(f"configured trust store not found: {trust_store}", EXIT_SERVICE)
    return {
        "component": component,
        "domain_id": loaded["domain_id"],
        "config_kind": loaded["kind"],
        "listen": final_listen,
        "metrics_listen": metrics_listen,
        "health_listen": health_listen,
        "state_dir": str(final_state),
        "transport": final_transport,
        "trust_store": str(trust_store) if trust_store else None,
        "verification_mode": "configured_public_keys" if trust_store else "deterministic_development_fixture",
        "remote_enforcement_available": False,
        "network_operations": ["publish_context", "receive_context", "acknowledge_receipt", "query_capabilities", "health", "peer_status"],
    }


def run_service(
    config_path: Path, *, component: str, listen: str | None = None, state_dir: Path | None = None,
    transport: str | None = None, metrics_listen: str | None = None, health_listen: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    description = service_description(
        config_path, component=component, listen=listen, state_dir=state_dir, transport=transport,
        metrics_listen=metrics_listen, health_listen=health_listen,
    )
    if dry_run:
        return {"dry_run": True, **description}
    host, port = _parse_listen(str(description["listen"]))
    trust_store = Path(str(description["trust_store"])) if description.get("trust_store") else None
    state = LocalServiceState(str(description["domain_id"]), component, Path(str(description["state_dir"])), trust_store)
    server = ThreadingHTTPServer((host, port), _handler(state))
    auxiliary: list[ThreadingHTTPServer] = []
    for value in (metrics_listen, health_listen):
        if value and value != description["listen"]:
            extra_host, extra_port = _parse_listen(value)
            extra = ThreadingHTTPServer((extra_host, extra_port), _handler(state))
            Thread(target=extra.serve_forever, name=f"tcop-{extra_port}", daemon=True).start()
            auxiliary.append(extra)
    print(json.dumps({"started": True, **description}, sort_keys=True), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        raise TCOPCommandError(f"runtime service failed: {exc}", EXIT_SERVICE) from exc
    finally:
        server.server_close()
        for extra in auxiliary:
            extra.shutdown()
            extra.server_close()
    return {"stopped": True, **description}


def admin_query(
    endpoint: str, resource: str, *, domain: str | None = None, since: str | None = None, scope: str | None = None,
) -> dict[str, Any]:
    mapping = {
        "status": "/v1/status", "health": "/health", "peers": "/v1/peers", "metrics": "/metrics",
        "strategy": "/v1/capabilities", "contexts": "/v1/status", "decisions": "/v1/status",
    }
    if resource not in mapping:
        raise TCOPCommandError(f"unsupported admin resource: {resource}")
    query = {key: value for key, value in {"domain": domain, "since": since, "scope": scope}.items() if value is not None}
    target = endpoint.rstrip("/") + mapping[resource] + (f"?{urlencode(query)}" if query else "")
    try:
        with urlopen(Request(target, method="GET"), timeout=5) as response:  # noqa: S310 - explicit user-supplied local admin endpoint
            value = json.loads(response.read())
    except (URLError, OSError, ValueError) as exc:
        raise TCOPCommandError(f"admin endpoint unavailable: {exc}", EXIT_SERVICE) from exc
    if not isinstance(value, dict):
        raise TCOPCommandError("admin endpoint returned a non-object response", EXIT_SERVICE)
    return {"resource": resource, "endpoint": endpoint, "filters": query, "result": value}
