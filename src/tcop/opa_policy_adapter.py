"""Versioned receiver-local policy contract for the STIX/TCOP comparator.

This is a deterministic fixture adapter, not a substitute for the pinned OPA
runtime required for the cross-host experiment.  It makes the exact policy
input and every field read explicit before an external runtime is admitted.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from .canonical import canonical_bytes


VERSION = "tcop.opa-policy-adapter/1.0"
_TOP_LEVEL = frozenset({"local_action", "local_state", "message_state", "time"})
_LOCAL_ACTION = frozenset({"subject", "resource_namespace", "capability_class", "gateway_request_id", "session_id"})
_FORBIDDEN = frozenset({"remote_action", "remote_enforcement", "enforcement_action", "benchmark_label", "detector_ground_truth", "future_action", "hidden_policy_branch", "scenario", "harm"})
_POLICY_SOURCE = """package tcop.comparator
default allow := true
# The production study evaluates this fixed normalized contract in pinned OPA.
"""


class PolicyInputError(ValueError):
    """The comparator's receiver-local policy boundary was violated."""


def policy_digest() -> str:
    return sha256(_POLICY_SOURCE.encode("utf-8")).hexdigest()


def _forbidden_keys(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for key, item in value.items():
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            if name in _FORBIDDEN:
                result.append(path)
            result.extend(_forbidden_keys(item, path))
        return result
    if isinstance(value, list):
        return [item for index, child in enumerate(value) for item in _forbidden_keys(child, f"{prefix}[{index}]")]
    return []


def validate_normalized_input(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reject any input that is not exclusively receiver-local and declared."""

    if set(value) != _TOP_LEVEL:
        raise PolicyInputError("normalized_policy_input_shape_invalid")
    action = value.get("local_action")
    if not isinstance(action, Mapping) or set(action) != _LOCAL_ACTION or not all(isinstance(action[key], str) and action[key] for key in _LOCAL_ACTION):
        raise PolicyInputError("normalized_local_action_invalid")
    if not isinstance(value.get("local_state"), Mapping) or not isinstance(value.get("message_state"), Mapping) or not isinstance(value.get("time"), Mapping):
        raise PolicyInputError("normalized_policy_value_invalid")
    forbidden = _forbidden_keys(value)
    if forbidden:
        raise PolicyInputError("forbidden_policy_input:" + ",".join(sorted(forbidden)))
    return {key: dict(item) if isinstance(item, Mapping) else item for key, item in value.items()}


def _t2_or_s2(input_value: Mapping[str, Any], condition: str) -> tuple[bool, str, list[str]]:
    action, state, message = input_value["local_action"], input_value["local_state"], input_value["message_state"]
    used = [
        "local_action.subject", "local_action.resource_namespace", "local_action.capability_class",
        "local_state.receipt_session_valid", "message_state.accepted", "message_state.subject",
        "message_state.resource_namespace", "message_state.capability_class", "message_state.scope",
    ]
    exact = bool(
        state.get("receipt_session_valid")
        and message.get("accepted")
        and message.get("subject") == action["subject"]
        and message.get("resource_namespace") == action["resource_namespace"]
        and message.get("capability_class") == action["capability_class"]
        and message.get("scope") == "guarded-capability"
    )
    return (not exact, "local_binding_match" if exact else "local_binding_no_match", used)


def decide(condition: str, input_value: Mapping[str, Any]) -> dict[str, Any]:
    """Return an allow/block result plus the complete, declared field-use trace."""

    normalized = validate_normalized_input(input_value)
    if condition == "S1":
        message, action = normalized["message_state"], normalized["local_action"]
        used = ["message_state.stix_risk_signal", "message_state.confidence", "local_action.capability_class", "local_state.local_authorization"]
        block = bool(message.get("stix_risk_signal") and int(message.get("confidence", 0)) >= 70 and action["capability_class"] == "repository.write" and normalized["local_state"].get("local_authorization"))
        reason = "native_standard_risk_local_policy" if block else "native_standard_risk_not_actionable"
    elif condition in {"T2", "S2"}:
        allow, reason, used = _t2_or_s2(normalized, condition)
        block = not allow
    else:
        raise PolicyInputError("unknown_composition_condition")
    trace = {
        "adapter_version": VERSION,
        "condition": condition,
        "policy_digest": policy_digest(),
        "fields_used": used,
        "forbidden_fields_present": [],
        "remote_enforcement": False,
        "result": "block" if block else "allow",
        "reason": reason,
        "input_digest": sha256(canonical_bytes(normalized)).hexdigest(),
    }
    return {"allow": not block, "trace": trace}
