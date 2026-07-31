"""Deterministic tool-using workload adapter for the v0.1 benchmark.

This module is intentionally not an LLM integration. It accepts explicit,
replayable runtime facts and translates them into scoped TCX observations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .simulation import Cluster


@dataclass(frozen=True)
class RuntimeFact:
    observer: str
    observation_type: str
    scope: str
    severity: str
    sequence_number: int = 1
    metadata: Mapping[str, Any] | None = None


class DeterministicAgentWorkload:
    """Turns explicit tool/runtime/memory facts into signed observations.

    It makes the benchmark integration seam visible without introducing a model
    provider, stochastic planning, or a production tool gateway.
    """

    def __init__(self, cluster: Cluster, subject_id: str) -> None:
        self.cluster = cluster
        self.subject_id = subject_id

    def observation(self, fact: RuntimeFact) -> dict[str, Any]:
        return self.cluster.observe(
            fact.observer,
            self.subject_id,
            fact.observation_type,
            fact.scope,
            severity=fact.severity,
            sequence_number=fact.sequence_number,
            metadata=fact.metadata,
        )

    def benign_email_triage(self) -> dict[str, Any]:
        return self.observation(
            RuntimeFact(
                observer="runtime",
                observation_type="runtime.lifecycle",
                scope="runtime:default",
                severity="low",
                metadata={"workload": "email_triage", "outcome": "completed"},
            )
        )

    def prohibited_export(self, *, sequence_number: int = 1) -> dict[str, Any]:
        return self.observation(
            RuntimeFact(
                observer="tool",
                observation_type="tool.prohibited_export",
                scope="tool:data.export",
                severity="high",
                sequence_number=sequence_number,
                metadata={"workload": "cross_domain_procurement", "tool": "export"},
            )
        )

    def memory_contamination(self) -> dict[str, Any]:
        return self.observation(
            RuntimeFact(
                observer="memory",
                observation_type="memory.contamination",
                scope="memory:shared",
                severity="high",
                metadata={"workload": "retrieval_assistant", "lineage": "untrusted"},
            )
        )

