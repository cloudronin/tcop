"""Context-value comparator v2: negative controls executed, not asserted.

Comparator v1 wrote its receiver-validation controls as ``passed: True``
without running them. v2 keeps the v1 policy and normalized rows unchanged
and replaces only the controls. Each one submits the unchanged RA-01 fixture
pair, tampered as the control requires, through the Domain-B receiver intake
(``LocalAuthorizationEvaluator.accept_imported_context``) used by the live
agent-study negative controls. The comparator policy receives a token only
for context that intake accepted. Every control records the outcome it
observed, and ``passed`` is computed only from that observation.

Environment metadata is written to a sidecar that the v2 root digest does
not cover, so the root matches on any Python version.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from .agent_eval.trace_replay import ReplayFixture, create_fixture, receiver_for_fixture, scripted_trace
from .cli_support import EXIT_FROZEN_INPUT, EXIT_INVARIANT, TCOPCommandError
from .context_comparator import (
    CONDITIONS,
    FEDERATED_ROOT,
    LIVE_ROOT,
    ArrivalToken,
    ValidatedContext,
    _decision,
    _digest,
    _file_digest,
    _fixture_actions,
    _read,
    _root_digest,
    _seal,
)


VERSION = "tcop.context-value-comparator/2.0"
EVIDENCE_ROOT = Path("artifacts/context-value-comparator-v2")
V1_ROOT = Path("artifacts/context-value-comparator-v1")
V1_DIGEST = "2a7c267f69aa736122de7366359983e838ba29316e142957c7e8049d63cbf421"
ENVIRONMENT_SIDECAR = "environment.sidecar.json"
DIGEST_EXCLUDES = frozenset({"artifact-root-digest.json", ".DS_Store", ENVIRONMENT_SIDECAR})
SESSION_ID, PRINCIPAL_ID, FIXTURE_NOW = "session-719", "agent-account-19", 2_300_000_000
# Conditions whose policy reads imported context; C0 and C3 never do.
CONTEXT_CONDITIONS = frozenset({"C1", "C2"})


def _root_digest_v2(root: Path) -> str:
    """v1's root digest, except that the environment sidecar is outside it."""
    files = {str(path.relative_to(root)): _file_digest(path) for path in sorted(root.rglob("*")) if path.is_file() and path.name not in DIGEST_EXCLUDES}
    return _digest(files)


# Same shape as the planned repo-wide observed-result helpers: a control
# passes only when every expected key was observed and matches.
def _require_observation(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> None:
    missing = sorted(set(expected) - set(observed))
    if missing:
        raise TCOPCommandError(f"control has no observation for: {', '.join(missing)}", EXIT_INVARIANT)


def _observed_pass(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool:
    _require_observation(expected, observed)
    return all(observed[key] == value for key, value in expected.items())


def _control(name: str, condition: str, expected: dict[str, Any], observed: dict[str, Any], **detail: Any) -> dict[str, Any]:
    return {"control": name, "condition": condition, "executed": True, "expected": expected, "observed": observed, "passed": _observed_pass(expected, observed), **detail}


def _unchanged(context: dict[str, Any]) -> None:
    return None


def _break_signature(context: dict[str, Any]) -> None:
    context["severity"] = "critical"


def _unknown_receipt(context: dict[str, Any]) -> None:
    context["interaction_receipt_hash"] = "0" * 64


@dataclass(frozen=True)
class IntakeControl:
    """One submission of the fixture pair through the receiver intake."""

    name: str
    expected_code: str
    tamper: Callable[[dict[str, Any]], None] = _unchanged
    offset: int = 0
    replay: bool = False
    expect_accepted: bool = False

    def expected(self, condition: str) -> dict[str, Any]:
        if self.expect_accepted:
            return {"code": self.expected_code, "accepted": True, "token_dispatched": True, "intake_restriction_created": True, "policy_restriction_created": condition in CONTEXT_CONDITIONS}
        expected = {"code": self.expected_code, "accepted": False, "token_dispatched": False, "restriction_created": False}
        if self.replay:
            expected["first_submission_accepted"] = True
        return expected


REJECTION_CONTROLS = (
    IntakeControl("invalid_signature", "signature_invalid", _break_signature),
    IntakeControl("unknown_receipt", "receipt_unknown", _unknown_receipt),
    IntakeControl("expired_context", "expired", offset=61),
    IntakeControl("replayed_context", "context_replayed", replay=True),
)
# Positive control: without it, a broken dispatcher that never hands context
# to the policy would make every rejection control pass.
ACCEPTED_CONTROL = IntakeControl("accepted_context", "accepted_independent_peer", expect_accepted=True)


def _fixture() -> ReplayFixture:
    return create_fixture("RA-01", scripted_trace("RA-01"))


def _probes() -> tuple[dict[str, Any], dict[str, Any]]:
    """The v1 selectivity fixture's matching harmful and nonmatching benign actions."""
    harmful, benign = _fixture_actions()
    return harmful[2], benign[2]


def _submit(control: IntakeControl, fixture: ReplayFixture) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Return the submitted context, the final intake record, and any earlier submission."""
    receiver = receiver_for_fixture(fixture)
    context = deepcopy(fixture.context)
    control.tamper(context)

    def submit() -> dict[str, Any]:
        return receiver.accept_imported_context(context, fixture.receipt, session_id=SESSION_ID, principal_id=PRINCIPAL_ID, now=FIXTURE_NOW + control.offset)

    first = submit() if control.replay else None
    return context, submit(), first


def _dispatch(record: Mapping[str, Any], context: Mapping[str, Any]) -> tuple[ArrivalToken | None, ValidatedContext | None]:
    """Hand the comparator policy a token only for context the receiver accepted."""
    if not record.get("accepted"):
        return None, None
    _, _, _, token, template, _ = _fixture_actions()[0]
    return token, replace(template, issuer=str(context["observer"]["id"]), observation_id=str(record["observation_id"]), receipt_ref=str(context["interaction_receipt_hash"]))


def _execute(control: IntakeControl, fixture: ReplayFixture) -> tuple[list[dict[str, Any]], ArrivalToken | None, ValidatedContext | None]:
    """Run one intake control and dispatch its outcome to every condition.

    Intake does not depend on the condition, so one submission feeds all four
    rows. A policy restriction counts only when the dispatched context changes
    the decision relative to no context at all.
    """
    context, record, first = _submit(control, fixture)
    token, validated = _dispatch(record, context)
    harmful, _ = _probes()
    intake_restricted = bool(record.get("restriction_created"))
    rows = []
    for condition in CONDITIONS:
        without_context, _, _ = _decision(condition, harmful, token=None, context=None, baseline_forwarded=True)
        forwarded, reason, _ = _decision(condition, harmful, token=token, context=validated, baseline_forwarded=True)
        policy_restricted = without_context and not forwarded
        observed = {
            "code": record.get("code"), "accepted": bool(record.get("accepted")), "token_dispatched": token is not None,
            "intake_restriction_created": intake_restricted, "policy_restriction_created": policy_restricted,
            "restriction_created": intake_restricted or policy_restricted, "policy_reason": reason,
        }
        if first is not None:
            observed["first_submission_accepted"] = bool(first.get("accepted"))
        rows.append(_control(control.name, condition, control.expected(condition), observed, intake=record, first_submission=first))
    return rows, token, validated


def _policy_controls(token: ArrivalToken | None, validated: ValidatedContext | None) -> list[dict[str, Any]]:
    """Execute v1's policy-interface controls against the accepted, dispatched context."""
    if token is None or validated is None:
        names = (("context_target_mismatch", "C2"), ("context_target_mismatch", "C1"), ("C1_opaque_interface", "C1"), ("C3_no_tcop_message", "C3"))
        return [_control(name, condition, {"token_dispatched": True}, {"token_dispatched": False}) for name, condition in names]
    harmful, benign = _probes()
    c2_forwarded, c2_reason, _ = _decision("C2", benign, token=token, context=validated, baseline_forwarded=True)
    c1_forwarded, c1_reason, c1_fields = _decision("C1", benign, token=token, context=validated, baseline_forwarded=True)
    try:
        _ = token.subject
        refused = False
    except AssertionError:
        refused = True
    c3_with = _decision("C3", harmful, token=token, context=validated, baseline_forwarded=True)
    c3_without = _decision("C3", harmful, token=None, context=None, baseline_forwarded=True)
    return [
        _control("context_target_mismatch", "C2", {"policy_reason": "context_binding_mismatch", "restriction_created": False}, {"policy_reason": c2_reason, "restriction_created": not c2_forwarded}),
        # C1 is expected to over-restrict the nonmatching benign action.
        _control("context_target_mismatch", "C1", {"policy_reason": "arrival_only_blanket", "restriction_created": True}, {"policy_reason": c1_reason, "restriction_created": not c1_forwarded}),
        _control("C1_opaque_interface", "C1", {"context_field_access_refused": True, "fields_outside_arrival_or_local": []}, {"context_field_access_refused": refused, "fields_outside_arrival_or_local": [field for field in c1_fields if not field.startswith(("arrival.", "receiver_local_"))]}),
        _control("C3_no_tcop_message", "C3", {"context_changed_decision": False, "tcop_fields_used": []}, {"context_changed_decision": c3_with != c3_without, "tcop_fields_used": [field for field in c3_with[2] if not field.startswith("receiver_local_")], "policy_reason": c3_with[1]}),
    ]


def _controls(fixture: ReplayFixture | None = None) -> list[dict[str, Any]]:
    fixture = fixture or _fixture()
    rows = [row for control in REJECTION_CONTROLS for row in _execute(control, fixture)[0]]
    accepted_rows, token, validated = _execute(ACCEPTED_CONTROL, fixture)
    # JSON round-trip so the in-memory result compares equal to the sealed file.
    return json.loads(json.dumps(rows + accepted_rows + _policy_controls(token, validated)))


def run_context_comparator_v2(output: Path = EVIDENCE_ROOT, *, federated_root: Path = FEDERATED_ROOT, live_root: Path = LIVE_ROOT, v1_root: Path = V1_ROOT) -> dict[str, Any]:
    """Seal v2 under its own root; rows must equal sealed v1's, controls are executed."""
    if _root_digest(v1_root) != V1_DIGEST:
        raise TCOPCommandError("superseded comparator v1 digest mismatch", EXIT_FROZEN_INPUT)
    v1_result = _read(v1_root / "manifest.json")["result_digest"]
    supersedes = {"artifact": str(v1_root), "artifact_root_digest": V1_DIGEST, "result_digest": v1_result, "normalized_rows_identical": True, "change": "v1 controls were asserted without execution; v2 executes each control through the receiver intake and computes passed from the observed outcome"}
    return _seal(
        output, federated_root=federated_root, live_root=live_root, version=VERSION, controls=_controls, command="tcop study comparator-v2 run",
        expected_result_digest=v1_result, manifest_extra={"controls_executed": True, "root_digest_excludes": sorted(DIGEST_EXCLUDES), "supersedes": supersedes},
        digest_root=_root_digest_v2, environment_file=ENVIRONMENT_SIDECAR,
    )


def verify_context_comparator_v2(root: Path = EVIDENCE_ROOT) -> dict[str, Any]:
    """Check the root digest and that every sealed pass was earned, then re-execute the controls."""
    manifest = _read(root / "manifest.json")
    digest = _read(root / "artifact-root-digest.json")["artifact_root_digest"]
    actual = _root_digest_v2(root)
    sealed, replayed = _read(root / "controls" / "control-results.json"), _controls()
    earned = all(row["passed"] == _observed_pass(row["expected"], row["observed"]) for row in sealed)
    passed = all(row["passed"] for row in replayed)
    if digest != actual or not manifest.get("complete") or manifest.get("version") != VERSION or not manifest.get("controls_executed"):
        raise TCOPCommandError("context comparator v2 artifact verification failed", EXIT_INVARIANT)
    if not earned or sealed != replayed or manifest.get("controls_passed") != passed:
        raise TCOPCommandError("context comparator v2 controls did not replay", EXIT_INVARIANT)
    return {"valid": True, "artifact_root_digest": actual, "normalized_row_count": manifest["normalized_row_count"], "controls_replayed": len(replayed), "controls_passed": passed}
