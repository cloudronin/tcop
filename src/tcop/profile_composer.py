"""v0.5 profile composition and dependency validation.

The composer is declarative: it selects existing mechanisms but never adds a
new runtime defense or scenario-specific policy override.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Iterable

from .canonical import canonical_bytes
from .feature_manifest import FEATURE_BY_ID, FEATURES, FOUNDATIONAL


ADVANCED_SWEEP = (
    "RELIABILITY_WEIGHTING", "PROBATION_HYSTERESIS", "PROVISIONAL_CONTAINMENT",
    "SOURCE_NOVEL_CONFIRMATION", "TIP_ONLY_INVESTIGATION", "CAMPAIGN_GROUPING",
    "ACTIVE_PATROL", "COMPROMISE_WINDOW_REWEIGHT",
)


@dataclass(frozen=True)
class ComposedProfile:
    profile_id: str
    title: str
    enabled_features: tuple[str, ...]
    disabled_features: tuple[str, ...] = ()
    kind: str = "candidate"
    parent_profile_id: str | None = None
    declared_transformations: tuple[str, ...] = ()
    compatibility: tuple[str, ...] = ("tcx-v0.1", "tcx-v0.2", "tcop-reliability-v0.3", "tcop-confirmation-v0.4")

    def validate(self) -> None:
        enabled = set(self.enabled_features)
        disabled = set(self.disabled_features)
        if enabled & disabled:
            raise ValueError(f"profile {self.profile_id} both enables and disables {sorted(enabled & disabled)}")
        unknown = (enabled | disabled) - set(FEATURE_BY_ID)
        if unknown:
            raise ValueError(f"profile {self.profile_id} references unknown features: {sorted(unknown)}")
        if self.kind != "negative_control":
            for feature_id in enabled:
                missing = set(FEATURE_BY_ID[feature_id].dependencies) - enabled
                if missing:
                    raise ValueError(f"profile {self.profile_id} lacks dependencies for {feature_id}: {sorted(missing)}")
        if any("scenario" in value.lower() for value in self.declared_transformations):
            raise ValueError("scenario-specific policy transformations are forbidden")

    @property
    def profile_digest(self) -> str:
        return sha256(canonical_bytes(self.as_dict())).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.update({"profile_version": "tcop.composed-profile/0.1", "profile_digest": sha256(canonical_bytes(asdict(self))).hexdigest()})
        return value


def _features(*values: str) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


P2 = _features(*FOUNDATIONAL)
P3 = _features(*P2, "INTERACTION_RECEIPTS", "PASSIVE_LOCAL_WITNESS")
P4 = _features(*P3, "RELIABILITY_WEIGHTING", "RELIABILITY_SCOPE_SEPARATION", "CONTROL_GROUP_WEIGHT_CAP")
P5 = _features(*P4, "PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION", "DIRECT_LOCAL_EMERGENCY_PATH", "SEVERITY_WEIGHTED_RESPONSE")
P6 = _features(*P5, "TIP_ONLY_INVESTIGATION", "INVESTIGATION_BUDGETS", "RESERVED_HIGH_RISK_CAPACITY", "ACTIVE_PATROL")
P7 = _features(*P6, "RELIABILITY_CONFIDENCE_DECAY", "PROBATION_HYSTERESIS", "COMPROMISE_WINDOW_REWEIGHT", "ACCUSATION_CYCLE_REPORTING", "CAMPAIGN_GROUPING")

COHERENT_PROFILES: tuple[ComposedProfile, ...] = (
    ComposedProfile("P0", "No defense", (), kind="benchmark_control"),
    ComposedProfile("P1", "Policy only", (), kind="benchmark_control", declared_transformations=("static local authorization without TCX exchange",)),
    ComposedProfile("P2", "Minimal TCOP core", P2),
    ComposedProfile("P3", "Witness profile", P3),
    ComposedProfile("P4", "Reliability profile", P4),
    ComposedProfile("P5", "Staged profile", P5),
    ComposedProfile("P6", "Investigative profile", P6),
    ComposedProfile("P7", "Full v0.4-derived profile", P7),
)
PROFILE_BY_ID = {item.profile_id: item for item in COHERENT_PROFILES}


NEGATIVE_CONTROLS: tuple[ComposedProfile, ...] = tuple(
    ComposedProfile(
        f"NC_{feature_id}",
        feature_id.replace("_", " ").title(),
        _features(*(set(P7) - {feature_id})),
        (feature_id,),
        kind="negative_control",
        parent_profile_id="P7",
        declared_transformations=("protocol-invalid or architecture-violating negative control",),
    )
    for feature_id in (
        "SIGNED_CONTEXT", "SCOPE_AUTHORITY", "FRESHNESS_TTL", "REPLAY_PROTECTION",
        "IMMUTABLE_PROVENANCE", "LOCAL_RESOLUTION", "CONTROL_GROUP_INDEPENDENCE",
        "RELAY_NON_INFLATION", "CAPABILITY_SPECIFIC_RESPONSE",
    )
)


_ABLATION_TRANSFORMS = {
    "A_NO_RECEIPTS": ("INTERACTION_RECEIPTS",),
    "A_NO_PASSIVE_WITNESS": ("PASSIVE_LOCAL_WITNESS",),
    "A_NO_ACTIVE_PATROL": ("ACTIVE_PATROL",),
    "A_NO_RELIABILITY_WEIGHTING": ("RELIABILITY_WEIGHTING", "RELIABILITY_SCOPE_SEPARATION", "CONTROL_GROUP_WEIGHT_CAP", "RELIABILITY_CONFIDENCE_DECAY", "PROBATION_HYSTERESIS", "COMPROMISE_WINDOW_REWEIGHT", "ACCUSATION_CYCLE_REPORTING", "PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION", "CAMPAIGN_GROUPING"),
    "A_NO_RELIABILITY_SCOPE_SEPARATION": ("RELIABILITY_SCOPE_SEPARATION",),
    "A_NO_CONTROL_GROUP_WEIGHT_CAP": ("CONTROL_GROUP_WEIGHT_CAP",),
    "A_NO_RELIABILITY_DECAY": ("RELIABILITY_CONFIDENCE_DECAY",),
    "A_NO_PROBATION_HYSTERESIS": ("PROBATION_HYSTERESIS",),
    "A_NO_COMPROMISE_WINDOW": ("COMPROMISE_WINDOW_REWEIGHT",),
    "A_NO_ACCUSATION_GRAPH": ("ACCUSATION_CYCLE_REPORTING",),
    "A_NO_TIP_CHANNEL": ("TIP_ONLY_INVESTIGATION", "INVESTIGATION_BUDGETS", "RESERVED_HIGH_RISK_CAPACITY"),
    "A_NO_INVESTIGATION_BUDGET": ("INVESTIGATION_BUDGETS", "RESERVED_HIGH_RISK_CAPACITY"),
    "A_NO_RESERVED_HIGH_RISK_CAPACITY": ("RESERVED_HIGH_RISK_CAPACITY",),
    "A_NO_PROVISIONAL_CONTAINMENT": ("PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION", "CAMPAIGN_GROUPING"),
    "A_NO_SOURCE_NOVELTY": ("SOURCE_NOVEL_CONFIRMATION", "CAMPAIGN_GROUPING"),
    "A_NO_CAMPAIGN_GROUPING": ("CAMPAIGN_GROUPING",),
    "A_NO_DIRECT_LOCAL_EMERGENCY": ("DIRECT_LOCAL_EMERGENCY_PATH",),
    "A_NO_SEVERITY_WEIGHTING": ("SEVERITY_WEIGHTED_RESPONSE",),
}


def ablation_profiles() -> tuple[ComposedProfile, ...]:
    values: list[ComposedProfile] = []
    for ablation_id, removed in _ABLATION_TRANSFORMS.items():
        remaining = _features(*_dependency_preserving_remove(set(P7), set(removed)))
        all_removed = tuple(sorted(set(P7) - set(remaining)))
        values.append(ComposedProfile(
            ablation_id, ablation_id.replace("A_", "").replace("_", " ").title(), remaining,
            all_removed, parent_profile_id="P7",
            declared_transformations=("dependency-preserving removal; no unreachable policy retained",),
        ))
    return tuple(values)


def _dependency_preserving_remove(enabled: set[str], removed: set[str]) -> set[str]:
    """Remove dependent mechanisms rather than retaining dead policy paths."""

    remaining = set(enabled) - set(removed)
    changed = True
    while changed:
        changed = False
        for feature_id in tuple(remaining):
            if not set(FEATURE_BY_ID[feature_id].dependencies) <= remaining:
                remaining.remove(feature_id)
                changed = True
    return remaining


INTERACTIONS: dict[str, dict[str, Any]] = {
    "I-01": {"features": ("RELIABILITY_WEIGHTING", "PROVISIONAL_CONTAINMENT"), "families": ("S4", "S6", "S7")},
    "I-02": {"features": ("INTERACTION_RECEIPTS", "CONTROL_GROUP_INDEPENDENCE"), "families": ("S3",)},
    "I-03": {"features": ("CONTROL_GROUP_WEIGHT_CAP", "CAMPAIGN_GROUPING"), "families": ("S4", "S5", "S6")},
    "I-04": {"features": ("PROBATION_HYSTERESIS", "SOURCE_NOVEL_CONFIRMATION"), "families": ("S4", "S6", "S7")},
    "I-05": {"features": ("PASSIVE_LOCAL_WITNESS", "ACTIVE_PATROL"), "families": ("S3", "S5"), "coverage": ("low", "medium", "high")},
    "I-06": {"features": ("TIP_ONLY_INVESTIGATION", "ACTIVE_PATROL"), "families": ("S5",)},
    "I-07": {"features": ("RELIABILITY_CONFIDENCE_DECAY", "PROBATION_HYSTERESIS"), "families": ("S4", "S7")},
    "I-08": {"features": ("SOURCE_NOVEL_CONFIRMATION", "DIRECT_LOCAL_EMERGENCY_PATH"), "families": ("S6",), "speed": ("fast", "slow")},
    "I-09": {"features": ("COMPROMISE_WINDOW_REWEIGHT",), "families": ("S4",)},
    "I-10": {"features": ("ACCUSATION_CYCLE_REPORTING",), "families": ("S4",)},
}


def interaction_cells() -> tuple[ComposedProfile, ...]:
    cells: list[ComposedProfile] = []
    for identifier, value in INTERACTIONS.items():
        features = tuple(value["features"])
        if len(features) == 1:
            combinations: Iterable[tuple[bool, ...]] = ((False,), (True,))
        else:
            combinations = ((False, False), (True, False), (False, True), (True, True))
        variants = value.get("coverage", value.get("speed", ("default",)))
        for variant in variants:
            for bits in combinations:
                removed = {feature for feature, enabled in zip(features, bits) if not enabled}
                enabled = _features(*_dependency_preserving_remove(set(P7), removed))
                cells.append(ComposedProfile(
                    f"{identifier}-{variant}-{'-'.join('on' if bit else 'off' for bit in bits)}",
                    f"{identifier} interaction cell", enabled, tuple(sorted(set(P7) - set(enabled)),),
                    parent_profile_id="P7", declared_transformations=(f"declared interaction variant={variant}",),
                ))
    return tuple(cells)


def valid_advanced_combinations() -> tuple[ComposedProfile, ...]:
    values: list[ComposedProfile] = []
    for bitmap in range(1 << len(ADVANCED_SWEEP)):
        chosen = {feature for index, feature in enumerate(ADVANCED_SWEEP) if bitmap & (1 << index)}
        if "PROBATION_HYSTERESIS" in chosen and "RELIABILITY_WEIGHTING" not in chosen:
            continue
        if "SOURCE_NOVEL_CONFIRMATION" in chosen and "PROVISIONAL_CONTAINMENT" not in chosen:
            continue
        if "CAMPAIGN_GROUPING" in chosen and not {"PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION"} <= chosen:
            continue
        if "COMPROMISE_WINDOW_REWEIGHT" in chosen and "RELIABILITY_WEIGHTING" not in chosen:
            continue
        enabled = set(P2) | chosen
        if "RELIABILITY_WEIGHTING" in enabled:
            enabled.update({"INTERACTION_RECEIPTS", "PASSIVE_LOCAL_WITNESS", "RELIABILITY_SCOPE_SEPARATION", "CONTROL_GROUP_WEIGHT_CAP"})
        if "TIP_ONLY_INVESTIGATION" in enabled:
            enabled.update({"INTERACTION_RECEIPTS", "INVESTIGATION_BUDGETS", "RESERVED_HIGH_RISK_CAPACITY"})
        if "SOURCE_NOVEL_CONFIRMATION" in enabled:
            enabled.add("PROVISIONAL_CONTAINMENT")
        if "CAMPAIGN_GROUPING" in enabled:
            enabled.update({"PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION"})
        encoded = "".join("1" if feature in chosen else "0" for feature in ADVANCED_SWEEP)
        values.append(ComposedProfile(f"F-{encoded}", "Dependency-valid advanced combination", _features(*enabled), tuple(sorted(set(P7) - enabled)), parent_profile_id="P2"))
    return tuple(values)


def all_profile_manifests() -> tuple[ComposedProfile, ...]:
    return (*COHERENT_PROFILES, *NEGATIVE_CONTROLS, *ablation_profiles(), *interaction_cells(), *valid_advanced_combinations())
