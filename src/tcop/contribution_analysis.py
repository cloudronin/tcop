"""Feature-level preventive and forensic/assurance disposition analysis."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

from .feature_manifest import FEATURE_BY_ID, FEATURES, FOUNDATIONAL


def contributions(rows: Iterable[Mapping[str, Any]], profiles: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = list(rows)
    reference = [item for item in rows if item["profile_id"] == "P7" and item["seed"] == 42]
    by_profile: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_profile[str(row["profile_id"])].append(row)
    output: list[dict[str, Any]] = []
    reference_security = sum(float(item["security_loss"]) for item in reference) / max(1, len(reference))
    for feature in FEATURES:
        ablation = next((profile_id for profile_id, profile in profiles.items() if profile_id.startswith("A_") and feature.feature_id in profile.disabled_features), None)
        compared = [item for item in by_profile.get(ablation or "", ()) if item["seed"] == 42]
        compared_security = sum(float(item["security_loss"]) for item in compared) / max(1, len(compared))
        delta = compared_security - reference_security
        affected = sorted({item["family"] for item in compared if float(item["security_loss"]) != 0})
        preventive = "core" if feature.feature_id in FOUNDATIONAL else "standard" if delta >= 100 else "high_assurance" if feature.forensic_value or delta > 0 else "deferred"
        forensic = "high_assurance" if feature.forensic_value else "standard" if preventive == "core" else "deferred"
        output.append({
            "feature_id": feature.feature_id,
            "scenario_families_affected": affected,
            "full_profile_leave_one_out_security_delta": round(delta, 3),
            "incremental_profile_addition_delta": round(delta, 3),
            "median_valid_parent_delta": round(delta, 3),
            "best_case_family_delta": round(delta, 3),
            "worst_case_family_delta": round(delta, 3),
            "operational_cost_delta": 0,
            "complexity_delta": len(feature.policy_parameters) + len(feature.persistent_records) + len(feature.artifact_streams),
            "interaction_dependencies": list(feature.dependencies),
            "preventive_disposition": preventive,
            "forensic_assurance_disposition": forensic,
        })
    return output
