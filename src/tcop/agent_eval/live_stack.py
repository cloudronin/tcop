"""One-shot proof of the patched reference-gateway enforcement chain."""

from __future__ import annotations

import json
from time import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..cli_support import EXIT_INVARIANT, TCOPCommandError
from ..witness import make_interaction_receipt, make_v02_observation, receipt_hash
from .trace_replay import _universe


def _post_json(url: str, value: Mapping[str, Any], *, headers: Mapping[str, str] | None = None, allow_empty: bool = False) -> tuple[dict[str, Any], Mapping[str, str]]:
    request_headers = {"Content-Type": "application/json", **dict(headers or {})}
    request = Request(url, data=json.dumps(value, separators=(",", ":")).encode("utf-8"), headers=request_headers, method="POST")
    try:
        with urlopen(request, timeout=20) as response:  # noqa: S310 - explicit bounded study endpoints
            raw = response.read()
            if allow_empty and not raw:
                result = {}
            elif response.headers.get_content_type() == "text/event-stream":
                event_data = next((line[5:].strip() for line in raw.decode("utf-8").splitlines() if line.startswith("data:")), "")
                result = json.loads(event_data)
            else:
                result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict):
                raise ValueError("response is not an object")
            return result, dict(response.headers.items())
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").replace("\n", " ")[:160]
        raise TCOPCommandError(f"reference stack request failed: HTTP {exc.code}: {detail}", EXIT_INVARIANT) from exc
    except (URLError, OSError, ValueError) as exc:
        raise TCOPCommandError(f"reference stack request failed: {type(exc).__name__}", EXIT_INVARIANT) from exc


def _mcp_call(endpoint: str, *, token: str, request_id: int, method: str, params: Mapping[str, Any], session_id: str | None = None, allow_empty: bool = False) -> tuple[dict[str, Any], str | None]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": "2025-03-26",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
    if not method.startswith("notifications/"):
        payload["id"] = request_id
    response, response_headers = _post_json(endpoint, payload, headers=headers, allow_empty=allow_empty)
    result = response.get("result")
    if allow_empty and not response:
        return {}, response_headers.get("Mcp-Session-Id") or session_id
    if not isinstance(result, dict):
        raise TCOPCommandError("reference gateway returned no MCP result", EXIT_INVARIANT)
    return result, response_headers.get("Mcp-Session-Id") or session_id


def probe_reference_gateway(*, gateway_endpoint: str, receiver_endpoint: str, token: str) -> dict[str, Any]:
    """Exercise allow -> signed context -> receiver-local deny on real services.

    This function is an integration probe, not a benchmark result. It makes
    only synthetic repository writes and returns no receipt, context, token, or
    identity material.
    """

    now = int(time())
    initialized, session_id = _mcp_call(
        gateway_endpoint,
        token=token,
        request_id=1,
        method="initialize",
        params={"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "tcop-agent-runner", "version": "0.1"}},
    )
    if not session_id:
        raise TCOPCommandError("reference gateway did not issue an MCP session", EXIT_INVARIANT)
    _mcp_call(gateway_endpoint, token=token, request_id=2, method="notifications/initialized", params={}, session_id=session_id, allow_empty=True)
    baseline, session_id = _mcp_call(gateway_endpoint, token=token, request_id=3, method="tools/call", params={"name": "repository_write", "arguments": {"path": "synthetic-before-context"}}, session_id=session_id)

    reservation, _headers = _post_json(
        receiver_endpoint.rstrip("/") + "/v1/correlation/reserve",
        {"session_id": session_id, "principal_id": "tcop-agent-runner", "capability": "repository.write", "ttl": 120},
    )
    handle = reservation.get("interaction_handle")
    if not isinstance(handle, str) or not handle:
        raise TCOPCommandError("receiver did not create an opaque correlation handle", EXIT_INVARIANT)
    identities, groups, keys = _universe()
    receipt = make_interaction_receipt(
        keys["origin-monitor-a"], keys["origin-agent-a"], groups,
        interaction_id=handle, capability="repository.write", now=now,
        request=handle, response="accepted-cross-domain-interaction",
        receipt_mode="bilateral", transport_evidence="reference-gateway-probe",
    )
    context = make_v02_observation(
        keys["origin-monitor-a"], groups,
        subject_id="origin-agent-a", observation_type="tool.prohibited_export",
        scope=("repository.write",), now=now, sequence_number=7, ttl=60,
        severity="high", declared_evidence_class="independent_peer",
        observation_mode="passive", interaction_id=handle,
        interaction_receipt_hash=receipt_hash(receipt), receipt_mode=receipt["receipt_mode"],
        metadata={"probe": True, "action": "deny"},
    )
    admission, _headers = _post_json(
        receiver_endpoint.rstrip("/") + "/v1/context",
        {"context": context, "receipt": receipt, "session_id": session_id, "principal_id": "tcop-agent-runner"},
    )
    denied, _session = _mcp_call(gateway_endpoint, token=token, request_id=4, method="tools/call", params={"name": "repository_write", "arguments": {"path": "synthetic-after-context"}}, session_id=session_id)
    baseline_error = bool(baseline.get("isError"))
    denial_error = bool(denied.get("isError"))
    content = denied.get("content")
    denial_text = " ".join(str(item.get("text", "")) for item in content if isinstance(item, Mapping)) if isinstance(content, list) else ""
    return {
        "gateway_session_established": bool(initialized),
        "baseline_forwarded": not baseline_error,
        "context_accepted": admission.get("accepted") is True,
        "remote_action_fields_ignored": admission.get("remote_action_fields_ignored") == ["action"],
        "post_context_blocked": denial_error,
        "block_references_local_policy_and_decision": "local policy" in denial_text and "decision" in denial_text,
        "remote_enforcement_successes": 0,
        "passed": (not baseline_error and admission.get("accepted") is True and denial_error and "local policy" in denial_text and "decision" in denial_text),
    }
