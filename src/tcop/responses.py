"""No-op/simulated local response adapters for the first milestone."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


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


class SimulatedResponseAdapter:
    """Records intended local action; it never changes a real system."""

    def __init__(self) -> None:
        self.envelopes: dict[str, OperatingEnvelope] = {}
        self.events: list[dict[str, object]] = []

    def apply(self, subject_id: str, envelope: OperatingEnvelope, at: int) -> None:
        previous = self.envelopes.get(subject_id)
        self.envelopes[subject_id] = envelope
        if previous != envelope:
            self.events.append(
                {
                    "stream": "resolution",
                    "event_type": "operating_envelope_changed",
                    "at": at,
                    "subject_id": subject_id,
                    "envelope": envelope.to_dict(),
                }
            )

