"""Select only pre-registered, executed nested v0.5 deployment profiles."""

from __future__ import annotations

from typing import Any, Mapping

from .profile_composer import PROFILE_BY_ID


def select_profiles(executed_ids: set[str], dominated: set[str], costs: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, Any]]:
    targets = (("minimal", "P2"), ("standard", "P5"), ("high_assurance", "P7"))
    selected: dict[str, dict[str, Any]] = {}
    prior: str | None = None
    for role, profile_id in targets:
        status = "selected"
        explanation = "pre-registered coherent profile executed and retained"
        if profile_id not in executed_ids:
            status, explanation = "deferred", "pre-registered profile was not executed"
        elif profile_id in dominated:
            status, explanation = "policy_dependent", "executed profile is dominated under the declared balanced frontier"
        if prior and status == "selected" and set(PROFILE_BY_ID[prior].enabled_features) == set(PROFILE_BY_ID[profile_id].enabled_features):
            status, explanation = "not_distinct", "no additional tested mechanism set beyond the preceding tier"
        selected[role] = {
            "deployment_profile_version": "tcop.deployment-profile/0.1",
            "role": role,
            "selection_status": status,
            "profile_id": profile_id if status != "deferred" else None,
            "profile_manifest": PROFILE_BY_ID[profile_id].as_dict(),
            "cost_model_scores": {name: costs.get(profile_id, {}).get(name, 0) for name in ("C1_balanced", "C2_safety_critical", "C3_utility_sensitive")},
            "explanation": explanation,
        }
        if status == "selected":
            prior = profile_id
    return selected
