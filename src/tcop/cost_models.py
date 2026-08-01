"""Pre-registered v0.5 integer cost models."""

from __future__ import annotations

from typing import Any


COST_MODELS: dict[str, dict[str, int]] = {
    "C1_balanced": {"security_loss": 4, "utility_loss": 4, "operational_cost": 3, "static_complexity": 3, "dynamic_complexity": 2, "operator_complexity": 2},
    "C2_safety_critical": {"security_loss": 9, "utility_loss": 2, "operational_cost": 2, "static_complexity": 1, "dynamic_complexity": 1, "operator_complexity": 1},
    "C3_utility_sensitive": {"security_loss": 3, "utility_loss": 8, "operational_cost": 5, "static_complexity": 5, "dynamic_complexity": 4, "operator_complexity": 4},
}


def cost_model_manifest() -> dict[str, Any]:
    return {"cost_model_version": "tcop.cost-model/0.1", "models": COST_MODELS}


def score(record: dict[str, Any], model_id: str) -> int:
    weights = COST_MODELS[model_id]
    return sum(int(record.get(dimension, 0)) * weight for dimension, weight in weights.items())
