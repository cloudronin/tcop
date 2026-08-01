"""Faultable deterministic central monitor for fair v0.2 architecture controls.

It consumes the same signed observations, receipt registry, patrol outputs, and
``SimulatedResponseAdapter`` used by the distributed witness nodes. Only where
resolution occurs differs from TCX.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .witness import WitnessCluster, WitnessNode, WitnessValidator


@dataclass(frozen=True)
class CentralFaultProfile:
    available: bool = True
    processing_delay: int = 0
    compromised: bool = False
    malicious_global_quarantine: bool = False
    observation_reachable_nodes: frozenset[str] | None = None
    enforcement_reachable_nodes: frozenset[str] | None = None


class FaultableCentralMonitor:
    """A monitor with explicit input and enforcement reachability constraints."""

    def __init__(self, cluster: WitnessCluster, profile: CentralFaultProfile = CentralFaultProfile()) -> None:
        self.cluster = cluster
        self.profile = profile
        validator = WitnessValidator(
            cluster.identities, cluster.control_groups, cluster.receipts, cluster.patrol_authorizations, cluster.patrol_usage
        )
        self.node = WitnessNode("central", validator, cluster.clock)
        self.events: list[dict[str, Any]] = []
        # Benchmark artifact assembly includes this receiver's immutable input
        # and classification streams, while enforcement still uses the same
        # adapters attached to the sovereign cluster nodes.
        cluster.central_monitor = self

    def ingest(self, observation: Mapping[str, Any], *, source_node: str, targets: Iterable[str] | None = None) -> str:
        if not self.profile.available:
            self.events.append({"stream": "central", "event_type": "central_unavailable", "at": self.cluster.clock.now})
            return "central_unavailable"
        allowed_inputs = self.profile.observation_reachable_nodes
        if allowed_inputs is not None and source_node not in allowed_inputs:
            self.events.append({"stream": "central", "event_type": "central_observation_unreachable", "at": self.cluster.clock.now, "source_node": source_node})
            return "central_observation_unreachable"
        result = self.node.receive(observation)
        if not result.accepted:
            return result.code
        if self.profile.processing_delay:
            self.cluster.advance(self.profile.processing_delay)
        subject_id = str(observation["subject"]["id"])
        envelope = self.node.responses.envelopes[subject_id]
        if self.profile.compromised and self.profile.malicious_global_quarantine:
            from .responses import OperatingEnvelope

            envelope = OperatingEnvelope(
                state="quarantined", allowed_capabilities=(), denied_capabilities=("*",), actions=("quarantine",),
                reasons=("malicious central authority",), observation_ids=envelope.observation_ids,
            )
        allowed_targets = self.profile.enforcement_reachable_nodes
        applied = []
        for node_id in targets or self.cluster.nodes:
            if allowed_targets is not None and node_id not in allowed_targets:
                continue
            self.cluster.nodes[node_id].responses.apply(subject_id, envelope, self.cluster.clock.now, source="central_monitor")
            applied.append(node_id)
        self.events.append(
            {
                "stream": "central", "event_type": "central_envelope_applied", "at": self.cluster.clock.now,
                "subject_id": subject_id, "state": envelope.state, "applied_nodes": applied,
                "input_observation_id": observation["observation_id"],
            }
        )
        return result.code
