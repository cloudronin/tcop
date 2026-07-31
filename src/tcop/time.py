"""RFC3339 and deterministic-clock utilities."""

from __future__ import annotations

from datetime import datetime, timezone


def as_rfc3339(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(value: str) -> int:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("timestamp must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return int(parsed.timestamp())


class VirtualClock:
    """A manually advanced clock; simulations never consult wall time."""

    def __init__(self, now: int = 1_800_000_000) -> None:
        self._now = now

    @property
    def now(self) -> int:
        return self._now

    def advance(self, seconds: int = 1) -> int:
        if seconds < 0:
            raise ValueError("virtual time cannot move backwards")
        self._now += seconds
        return self._now

