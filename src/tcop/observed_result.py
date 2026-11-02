"""Outcome-bearing check records, independent of any study or validator."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


def _has_outcome(value: Any) -> bool:
    """False and zero are outcomes; absent or recursively empty data are not."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return any(_has_outcome(child) for child in value.values())
    if isinstance(value, (list, tuple, set, frozenset, bytes, bytearray)):
        return bool(value) and any(_has_outcome(child) for child in value)
    return True


def require_observation(record: Mapping[str, Any]) -> None:
    """Reject any ``passed`` record without an outcome in observed or detail.

    This applies to failed checks too. A reason, expected value, or label alone
    is not an observation. This structural check cannot establish that supplied
    evidence was actually measured; the producer must preserve that provenance.
    """
    if "passed" in record and not any(
        _has_outcome(record.get(field)) for field in ("observed", "detail")
    ):
        raise ValueError("pass-bearing record requires a non-empty observed or detail outcome")


def observed_pass(
    expected: Any,
    observed: Any,
    *,
    predicate: Callable[[Any, Any], bool] | None = None,
) -> dict[str, Any]:
    """Compare expected with observed, or call predicate(expected, observed).

    Retain both inputs even when the comparison fails. Empty observations are
    rejected rather than treated as evidence that an empty expectation passed.
    """
    record = {
        "expected": expected,
        "observed": observed,
        "passed": bool(expected == observed if predicate is None else predicate(expected, observed)),
    }
    require_observation(record)
    return record
