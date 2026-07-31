"""Transparent local TCRS reference resolver; not a universal trust score."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

from .responses import OperatingEnvelope
from .time import parse_rfc3339


HIGH_RISK_TYPES = {"tool.prohibited_export", "memory.contamination", "runtime.behavior_deviation"}
RECOVERY_TYPES = {"recovery.clean_checkpoint", "attestation.result"}
WITHDRAWAL_TYPES = {"recovery.withdrawal"}


class ReferenceResolver:
    """Deterministic capability-specific rules with explainable contributions.

    It intentionally values trust-domain diversity over observer count. A single
    signed accusation can constrain local capabilities but cannot, on its own,
    cause mandatory quarantine.
    """

    def __init__(
        self,
        *,
        enforce_expiration: bool = True,
        require_domain_diversity: bool = True,
        capability_specific: bool = True,
    ) -> None:
        self.events: list[dict[str, Any]] = []
        self.enforce_expiration = enforce_expiration
        self.require_domain_diversity = require_domain_diversity
        self.capability_specific = capability_specific

    def resolve(self, subject_id: str, observations: Iterable[Mapping[str, Any]], now: int) -> OperatingEnvelope:
        relevant = [
            observation
            for observation in observations
            if (not self.enforce_expiration or parse_rfc3339(observation["expires_at"]) >= now)
            and observation["subject"]["id"] == subject_id
        ]
        if not relevant:
            return OperatingEnvelope(state="unknown", actions=("observe",), reasons=("no current evidence",))

        withdrawn_ids = {
            observation.get("metadata", {}).get("withdraws")
            for observation in relevant
            if observation["observation_type"] in WITHDRAWAL_TYPES
            and observation.get("metadata", {}).get("withdraws")
        }
        active = [
            observation
            for observation in relevant
            if observation["observation_id"] not in withdrawn_ids
            and observation["observation_type"] not in WITHDRAWAL_TYPES
        ]
        recovery = [
            item for item in relevant if item["observation_type"] in RECOVERY_TYPES | WITHDRAWAL_TYPES
        ]
        threats = [
            item
            for item in active
            if item["observation_type"] in HIGH_RISK_TYPES and item["severity"] in {"high", "critical"}
        ]
        domains = {item["observer"]["trust_domain"] for item in threats}
        ids = tuple(item["observation_id"] for item in threats + recovery)

        if recovery and not threats:
            envelope = OperatingEnvelope(
                state="recovered",
                actions=("recover",),
                reasons=("fresh recovery evidence",),
                observation_ids=ids,
            )
        elif any(item["severity"] == "critical" for item in threats) and (
            len(domains) >= 2 if self.require_domain_diversity else len(threats) >= 2
        ):
            envelope = OperatingEnvelope(
                state="quarantined",
                allowed_capabilities=(),
                denied_capabilities=("*",),
                actions=("quarantine", "isolate_memory"),
                reasons=("critical evidence from independent trust domains",),
                observation_ids=ids,
            )
        elif threats:
            denied = ("data.export", "memory.write") if any(
                item["observation_type"] == "memory.contamination" for item in threats
            ) else ("data.export",)
            if not self.capability_specific:
                envelope = OperatingEnvelope(
                    state="quarantined",
                    allowed_capabilities=(),
                    denied_capabilities=("*",),
                    actions=("quarantine",),
                    reasons=("capability-specific restriction disabled",),
                    observation_ids=ids,
                )
                self.events.append(
                    {
                        "stream": "resolution",
                        "event_type": "trust_resolved",
                        "at": now,
                        "subject_id": subject_id,
                        "state": envelope.state,
                        "trust_domains": sorted(domains),
                        "observation_ids": list(envelope.observation_ids),
                        "reasons": list(envelope.reasons),
                    }
                )
                return envelope
            envelope = OperatingEnvelope(
                state="constrained",
                denied_capabilities=denied,
                actions=("reduce_capability", "observe"),
                reasons=("high-impact direct observation; corroboration incomplete",),
                observation_ids=ids,
            )
        elif any(item["severity"] == "medium" for item in active):
            envelope = OperatingEnvelope(
                state="suspicious",
                actions=("observe", "challenge"),
                reasons=("medium-severity context",),
                observation_ids=tuple(item["observation_id"] for item in active),
            )
        else:
            envelope = OperatingEnvelope(
                state="healthy",
                actions=("allow",),
                reasons=("current evidence consistent",),
                observation_ids=tuple(item["observation_id"] for item in active),
            )
        self.events.append(
            {
                "stream": "resolution",
                "event_type": "trust_resolved",
                "at": now,
                "subject_id": subject_id,
                "state": envelope.state,
                "trust_domains": sorted(domains),
                "observation_ids": list(envelope.observation_ids),
                "reasons": list(envelope.reasons),
            }
        )
        return envelope
