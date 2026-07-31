"""No-op/simulated local response adapters for the first milestone."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


@dataclass(frozen=True)
class OperatingEnvelope:
    state: str
    allowed_capabilities: tuple[str, ...] = ("*",)
    denied_capabilities: tuple[str, ...] = ()
    actions: tuple[str, ...] = ("allow",)
    reevaluate_after: int = 30
    reasons: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ConnectivityPosture(StrEnum):
    """Local behavior when fresh remote trust context is unavailable."""

    FAIL_OPEN = "fail_open"
    FAIL_CONSTRAINED = "fail_constrained"
    FAIL_CLOSED = "fail_closed"
    RISK_SENSITIVE = "risk_sensitive"


def connectivity_loss_envelope(posture: ConnectivityPosture) -> OperatingEnvelope:
    if posture is ConnectivityPosture.FAIL_OPEN:
        return OperatingEnvelope(state="unknown", actions=("observe",), reasons=("trust context unavailable; fail open",))
    if posture is ConnectivityPosture.FAIL_CONSTRAINED:
        return OperatingEnvelope(
            state="constrained",
            denied_capabilities=("data.export", "memory.write", "financial.transfer"),
            actions=("reduce_capability", "observe"),
            reasons=("trust context unavailable; fail constrained",),
        )
    if posture is ConnectivityPosture.FAIL_CLOSED:
        return OperatingEnvelope(
            state="quarantined",
            allowed_capabilities=(),
            denied_capabilities=("*",),
            actions=("quarantine",),
            reasons=("trust context unavailable; fail closed",),
        )
    return OperatingEnvelope(
        state="constrained",
        denied_capabilities=("memory.write", "financial.transfer", "data.export"),
        actions=("reduce_capability", "observe"),
        reasons=("trust context unavailable; risk-sensitive restriction",),
    )


class SimulatedResponseAdapter:
    """Records intended local action; it never changes a real system."""

    def __init__(self) -> None:
        self.envelopes: dict[str, OperatingEnvelope] = {}
        self.events: list[dict[str, object]] = []

    def apply(self, subject_id: str, envelope: OperatingEnvelope, at: int, *, source: str = "local") -> None:
        previous = self.envelopes.get(subject_id)
        self.envelopes[subject_id] = envelope
        if previous != envelope:
            self.events.append(
                {
                    "stream": "resolution",
                    "event_type": "operating_envelope_changed",
                    "at": at,
                    "subject_id": subject_id,
                    "source": source,
                    "envelope": envelope.to_dict(),
                }
            )
