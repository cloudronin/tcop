"""Deterministic v0.5 Pareto and equivalence calculations.

An equal point is not a dominator.  Earlier study output left equal points on
the frontier, but did not state that they were aliases for the purpose of the
selected dimensions.  The validation pass consumes the explicit status and
equivalence-class fields below; the original v0.5 artifacts remain frozen.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes


DIMENSION_SETS = {
    "security_vs_utility": ("security_loss", "utility_loss"),
    "security_vs_operational": ("security_loss", "operational_cost"),
    "security_vs_static_complexity": ("security_loss", "static_complexity"),
    "harm_vs_complexity": ("severity_weighted_harm", "static_complexity", "dynamic_complexity", "operator_complexity"),
    "safety_critical": ("C2_safety_critical",),
    "utility_sensitive": ("C3_utility_sensitive",),
}


def dominates(left: Mapping[str, Any], right: Mapping[str, Any], dimensions: Iterable[str]) -> bool:
    values = tuple(dimensions)
    return all(float(left.get(key, 0)) <= float(right.get(key, 0)) for key in values) and any(float(left.get(key, 0)) < float(right.get(key, 0)) for key in values)


def equivalent(left: Mapping[str, Any], right: Mapping[str, Any], dimensions: Iterable[str]) -> bool:
    """Return whether two records have the same values in every dimension."""

    return all(float(left.get(key, 0)) == float(right.get(key, 0)) for key in dimensions)


def equivalence_class_id(record: Mapping[str, Any], dimensions: Iterable[str]) -> str:
    """Stable, content-addressed label for a point in a declared frontier."""

    values = {key: record.get(key, 0) for key in dimensions}
    return "EQ-" + sha256(canonical_bytes(values)).hexdigest()[:16]


def pareto_records(records: list[dict[str, Any]], *, dimensions: Iterable[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dimensions = tuple(dimensions)
    frontier: list[dict[str, Any]] = []
    dominated: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda item: item["profile_id"]):
        dominators = [candidate["profile_id"] for candidate in records if candidate["profile_id"] != record["profile_id"] and dominates(candidate, record, dimensions)]
        equivalents = sorted(
            candidate["profile_id"]
            for candidate in records
            if candidate["profile_id"] != record["profile_id"] and equivalent(candidate, record, dimensions)
        )
        incomparable = sorted(
            candidate["profile_id"]
            for candidate in records
            if candidate["profile_id"] != record["profile_id"]
            and not dominates(candidate, record, dimensions)
            and not dominates(record, candidate, dimensions)
            and not equivalent(candidate, record, dimensions)
        )
        value = {
            "profile_id": record["profile_id"],
            "dimensions": list(dimensions),
            "pareto_status": "dominated" if dominators else "equivalent" if equivalents else "non_dominated",
            "equivalence_class_id": equivalence_class_id(record, dimensions),
            "equivalent_to": equivalents,
            "incomparable_with": incomparable,
            "dominated_by": sorted(dominators),
            "raw": {key: record.get(key, 0) for key in dimensions},
        }
        (dominated if dominators else frontier).append(value)
    return frontier, dominated
