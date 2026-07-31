"""Deterministic multi-node simulation and faultable in-process transport."""

from __future__ import annotations

import heapq
import itertools
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .identity import AuthorityRegistry, KeyMaterial
from .protocol import make_observation
from .responses import OperatingEnvelope, SimulatedResponseAdapter
from .store import EvidenceStore
from .time import VirtualClock
from .trust import ReferenceResolver
from .validation import ObservationValidator, ValidationResult


class TrustNode:
    """One local sovereign receiver in a deterministic topology."""

    def __init__(self, node_id: str, registry: AuthorityRegistry, clock: VirtualClock, *, tenant: str = "shared") -> None:
        self.node_id = node_id
        self.clock = clock
        self.validator = ObservationValidator(registry, tenant=tenant)
        self.store = EvidenceStore()
        self.resolver = ReferenceResolver()
        self.responses = SimulatedResponseAdapter()
        self.protocol_events: list[dict[str, Any]] = []

    def receive(self, observation: Mapping[str, Any]) -> ValidationResult:
        result = self.validator.validate(observation, self.clock.now)
        payload = {
            "node_id": self.node_id,
            "observation_id": observation.get("observation_id"),
            "observer_id": observation.get("observer", {}).get("id"),
            "code": result.code,
        }
        if not result.accepted:
            event_type = "observation_rejected"
            self.protocol_events.append({"stream": "protocol", "event_type": event_type, "at": self.clock.now, **payload})
            self.store.append_protocol_event(event_type, self.clock.now, payload)
            return result
        if not self.store.append_observation(observation, self.clock.now):
            # Database uniqueness is an additional fail-closed guard. The
            # replay window should already have caught this condition.
            result = ValidationResult.reject("replay_detected")
            self.protocol_events.append(
                {"stream": "protocol", "event_type": "observation_rejected", "at": self.clock.now, **payload, "code": result.code}
            )
            return result
        self.validator.commit(observation)
        self.protocol_events.append({"stream": "protocol", "event_type": "observation_accepted", "at": self.clock.now, **payload})
        self.store.append_protocol_event("observation_accepted", self.clock.now, payload)
        subject_id = observation["subject"]["id"]
        envelope = self.resolver.resolve(subject_id, self.store.observations_for(subject_id), self.clock.now)
        self.responses.apply(subject_id, envelope, self.clock.now)
        return result

    def heartbeat_missing(self, subject_id: str) -> OperatingEnvelope:
        envelope = OperatingEnvelope(state="unknown", actions=("observe",), reasons=("heartbeat missing",))
        self.responses.apply(subject_id, envelope, self.clock.now)
        self.protocol_events.append(
            {"stream": "protocol", "event_type": "peer_unreachable", "at": self.clock.now, "node_id": self.node_id, "subject_id": subject_id}
        )
        return envelope

    def close(self) -> None:
        self.store.close()


@dataclass(order=True)
class _ScheduledMessage:
    delivery_time: int
    sequence: int
    source: str
    destination: str
    observation: dict[str, Any]


class FaultingTransport:
    """A deterministic in-process transport supporting named fault injections."""

    def __init__(self, clock: VirtualClock, nodes: Mapping[str, TrustNode]) -> None:
        self.clock = clock
        self.nodes = nodes
        self._queue: list[_ScheduledMessage] = []
        self._counter = itertools.count()
        self.partitions: set[tuple[str, str]] = set()
        self.events: list[dict[str, Any]] = []

    def partition(self, left: str, right: str) -> None:
        self.partitions.add(tuple(sorted((left, right))))

    def heal(self, left: str, right: str) -> None:
        self.partitions.discard(tuple(sorted((left, right))))

    def send(
        self,
        source: str,
        destination: str,
        observation: Mapping[str, Any],
        *,
        delay: int = 0,
        duplicate: bool = False,
    ) -> None:
        if tuple(sorted((source, destination))) in self.partitions:
            self.events.append(
                {"stream": "protocol", "event_type": "peer_unreachable", "at": self.clock.now, "source": source, "destination": destination}
            )
            return
        message = _ScheduledMessage(self.clock.now + delay, next(self._counter), source, destination, deepcopy(dict(observation)))
        heapq.heappush(self._queue, message)
        if duplicate:
            heapq.heappush(
                self._queue,
                _ScheduledMessage(self.clock.now + delay + 1, next(self._counter), source, destination, deepcopy(dict(observation))),
            )

    def deliver_due(self) -> list[ValidationResult]:
        outcomes: list[ValidationResult] = []
        while self._queue and self._queue[0].delivery_time <= self.clock.now:
            message = heapq.heappop(self._queue)
            if tuple(sorted((message.source, message.destination))) in self.partitions:
                self.events.append(
                    {"stream": "protocol", "event_type": "peer_unreachable", "at": self.clock.now, "source": message.source, "destination": message.destination}
                )
                continue
            outcomes.append(self.nodes[message.destination].receive(message.observation))
        return outcomes

    def pending(self) -> int:
        return len(self._queue)


class Cluster:
    """Five sovereign trust nodes plus independently scoped test observers."""

    def __init__(self, *, now: int = 1_800_000_000) -> None:
        self.clock = VirtualClock(now)
        self.registry = AuthorityRegistry()
        self.observers: dict[str, KeyMaterial] = {}
        observer_specs = {
            "runtime": ("domain-runtime", ("runtime:*",), ("runtime.*",)),
            "tool": ("domain-tool", ("tool:*",), ("tool.*",)),
            "memory": ("domain-memory", ("memory:*",), ("memory.*",)),
            "identity": ("domain-identity", ("identity:*",), ("identity.*",)),
            "recovery": ("domain-recovery", ("recovery:*", "attestation:*"), ("recovery.*", "attestation.*")),
        }
        for name, (domain, scopes, types) in observer_specs.items():
            key = KeyMaterial.deterministic(name, domain, scopes=scopes, observation_types=types)
            self.observers[name] = key
            self.registry.register(key.identity)
        self.nodes = {f"node-{number}": TrustNode(f"node-{number}", self.registry, self.clock) for number in range(1, 6)}
        self.transport = FaultingTransport(self.clock, self.nodes)

    def observe(
        self,
        observer: str,
        subject_id: str,
        observation_type: str,
        scope: str,
        *,
        severity: str = "high",
        sequence_number: int = 1,
        ttl: int = 60,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return make_observation(
            self.observers[observer],
            subject_id=subject_id,
            observation_type=observation_type,
            scope=(scope,),
            sequence_number=sequence_number,
            now=self.clock.now,
            ttl=ttl,
            severity=severity,
            metadata=metadata,
        )

    def disseminate(
        self,
        source: str,
        observation: Mapping[str, Any],
        *,
        delay: int = 0,
        duplicate: bool = False,
        destinations: Iterable[str] | None = None,
    ) -> list[ValidationResult]:
        target_ids = list(destinations or self.nodes.keys())
        for destination in target_ids:
            self.transport.send(source, destination, observation, delay=delay, duplicate=duplicate)
        return self.transport.deliver_due()

    def advance(self, seconds: int = 1) -> list[ValidationResult]:
        self.clock.advance(seconds)
        return self.transport.deliver_due()

    def all_protocol_events(self) -> list[dict[str, Any]]:
        events = list(self.transport.events)
        for node in self.nodes.values():
            events.extend(node.protocol_events)
        return sorted(events, key=lambda item: (item["at"], item.get("node_id", ""), item["event_type"]))

    def all_resolution_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for node in self.nodes.values():
            events.extend(node.resolver.events)
            events.extend(node.responses.events)
        return sorted(events, key=lambda item: (item["at"], item.get("subject_id", ""), item["event_type"]))

    def accepted_observations(self) -> list[dict[str, Any]]:
        """Return the deduplicated records that passed receiver validation."""

        accepted: dict[str, dict[str, Any]] = {}
        for node in self.nodes.values():
            for observation in node.store.all_observations():
                accepted.setdefault(observation["observation_id"], observation)
        return [accepted[key] for key in sorted(accepted)]

    def close(self) -> None:
        for node in self.nodes.values():
            node.close()
