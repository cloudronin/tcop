"""Focused external-validation contracts; frozen artifacts are inputs only."""

from __future__ import annotations

from copy import deepcopy
import json
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from pathlib import Path

from tcop.agent_eval.models import AuthorizationRequest
from tcop.agent_eval.local_api import LocalAuthorizationEndpoint, LocalAuthorizationRequestError
from tcop.agent_eval.plan import SOURCE_EVIDENCE_ROOT, verify_agent_source
from tcop.agent_eval.runner import AgentStudy
from tcop.agent_eval.trace_replay import CausalTraceReplay, create_fixture, receiver_for_fixture, scripted_trace
from tcop.agent_eval.tool_service import SyntheticMcpToolService, _McpHandler, _SyntheticMcpHTTPServer


class AgentValidationTests(unittest.TestCase):
    def fixture(self, *, metadata: dict[str, object] | None = None):
        return create_fixture("RA-01", scripted_trace("RA-01"), metadata=metadata)

    def test_receipt_reference_is_opaque_and_inside_boundary_blocks_locally(self) -> None:
        fixture = self.fixture()
        rendered = str(fixture.receipt)
        self.assertNotIn("session-719", rendered)
        self.assertNotIn("agent-account-19", rendered)
        self.assertTrue(fixture.receipt_ref.isalnum())
        self.assertEqual(len(fixture.receipt_ref), 64)
        baseline = CausalTraceReplay(fixture).run("NO_CONTEXT")
        inside = CausalTraceReplay(fixture).run("INSIDE_WINDOW_BOUNDARY")
        self.assertEqual(baseline["action_trace_digest"], inside["action_trace_digest"])
        self.assertEqual(baseline["local_configuration"]["policy_digest"], inside["local_configuration"]["policy_digest"])
        self.assertGreater(baseline["harmful_actions_forwarded"], inside["harmful_actions_forwarded"])
        self.assertEqual(inside["invariants"]["remote_enforcement_successes"], 0)

    def test_invalid_wrong_expired_and_replayed_contexts_cannot_restrict(self) -> None:
        fixture = self.fixture()
        evaluator = receiver_for_fixture(fixture)
        invalid = deepcopy(fixture.context)
        invalid["severity"] = "critical"
        rejected = evaluator.accept_imported_context(invalid, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertEqual(rejected["code"], "signature_invalid")
        wrong = deepcopy(fixture.context)
        wrong["interaction_receipt_hash"] = "0" * 64
        rejected = evaluator.accept_imported_context(wrong, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertEqual(rejected["code"], "receipt_unknown")
        expired = evaluator.accept_imported_context(fixture.context, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_061)
        self.assertEqual(expired["code"], "expired")
        accepted = evaluator.accept_imported_context(fixture.context, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertTrue(accepted["accepted"])
        replay = evaluator.accept_imported_context(fixture.context, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertEqual(replay["code"], "context_replayed")

    def test_remote_action_metadata_is_ignored_and_monitor_only_control_starts_after_forward(self) -> None:
        fixture = self.fixture(metadata={"action": "deny", "enforcement": "quarantine", "decision": "remote-block"})
        evaluator = receiver_for_fixture(fixture)
        accepted = evaluator.accept_imported_context(fixture.context, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertEqual(accepted["remote_action_fields_ignored"], ["action", "decision", "enforcement"])
        self.assertFalse(evaluator.invariant_snapshot()["remote_tcx_action_interpreted"])
        baseline = CausalTraceReplay(create_fixture("RA-01", scripted_trace("RA-01"))).run("NO_CONTEXT")
        first_harmful = next(row for row in baseline["results"] if row["capability"] == "repository.write")
        self.assertTrue(first_harmful["forwarded"])
        self.assertTrue(any(event["event_type"] == "receiver_local_detection" for event in baseline["events"]))

    def test_agent_prepare_fails_closed_without_admitted_source(self) -> None:
        if not (SOURCE_EVIDENCE_ROOT / "manifest.json").is_file():
            self.skipTest("requires generated v0.6 source artifacts")
        source = verify_agent_source()
        self.assertTrue(source["passed"])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "agent-smoke"
            result = AgentStudy().replay(output, selection="smoke")
            self.assertTrue(result["source_verified"])
            self.assertTrue((output / "reports" / "invariant-report.json").is_file())

    def test_local_gateway_endpoint_uses_only_local_request_and_local_decision(self) -> None:
        fixture = self.fixture()
        endpoint = LocalAuthorizationEndpoint(receiver_for_fixture(fixture))
        with self.assertRaises(LocalAuthorizationRequestError):
            endpoint.evaluate({"session_id": "session-719", "client_name": "agent-account-19", "server": "partner", "tool": "repository_write", "enforcement": "deny"}, now=2_300_000_000)
        admitted = endpoint.admit_context({"context": fixture.context, "receipt": fixture.receipt, "session_id": "session-719", "principal_id": "agent-account-19"}, now=2_300_000_000)
        self.assertTrue(admitted["accepted"])
        decision = endpoint.evaluate({"session_id": "session-719", "client_name": "agent-account-19", "server": "partner", "tool": "repository_write"}, now=2_300_000_000)
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["authority_domain"], "partner-platform")
        self.assertEqual(decision["cache"], "disabled")
        self.assertTrue(decision["policy_id"])

    def test_new_correlation_generation_invalidates_an_older_binding(self) -> None:
        fixture = self.fixture()
        evaluator = receiver_for_fixture(fixture)
        evaluator.correlations.reserve(session_id="session-719", principal_id="agent-account-19", capability="repository.write", now=2_300_000_000, ttl=30)
        rejected = evaluator.accept_imported_context(fixture.context, fixture.receipt, session_id="session-719", principal_id="agent-account-19", now=2_300_000_000)
        self.assertEqual(rejected["code"], "receipt_generation_stale")

    def test_synthetic_mcp_tool_service_records_only_synthetic_effects(self) -> None:
        service = SyntheticMcpToolService()
        result = service.invoke(request_id="request-1", session_id="session-1", name="repository_write", arguments={"path": "README.md"}, meta={"receipt_ref": "opaque-ref"})
        self.assertEqual(result["structuredContent"], {"synthetic": True, "state_changed": True})
        record = service.events[0]
        self.assertEqual(record["interaction_receipt"], "opaque-ref")
        self.assertTrue(record["state_changed"])
        self.assertEqual(record["protected_resources_affected"], 1)

    def test_synthetic_tool_service_supports_minimal_mcp_http_sequence(self) -> None:
        try:
            server = _SyntheticMcpHTTPServer(("127.0.0.1", 0), _McpHandler)
        except PermissionError:
            self.skipTest("local loopback listeners are disabled by this execution sandbox")
        server.tool_service = SyntheticMcpToolService()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            def invoke(request_id: int, method: str, params: dict[str, object], session_id: str | None = None):
                headers = {"Content-Type": "application/json"}
                if session_id:
                    headers["Mcp-Session-Id"] = session_id
                request = Request(endpoint, data=json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode(), headers=headers, method="POST")
                with urlopen(request, timeout=5) as response:  # noqa: S310 - loopback test server
                    return json.loads(response.read()), response.headers.get("Mcp-Session-Id")
            initialized, session_id = invoke(1, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
            self.assertTrue(session_id)
            self.assertEqual(initialized["result"]["serverInfo"]["name"], "tcop-synthetic-tool-service")
            called, _ = invoke(2, "tools/call", {"name": "repository_write", "arguments": {"path": "README.md"}}, session_id)
            self.assertTrue(called["result"]["structuredContent"]["state_changed"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
