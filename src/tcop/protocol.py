"""Construction and signing of TCX v0.1 observation envelopes."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Mapping

from .canonical import canonical_bytes, unsigned_envelope
from .identity import KeyMaterial, observer_block
from .time import as_rfc3339


def observation_id(*parts: object) -> str:
    """Stable IDs make repeated deterministic scenarios reproducible."""

    material = "|".join(str(part) for part in parts).encode("utf-8")
    return sha256(material).hexdigest()[:32]


def make_observation(
    signer: KeyMaterial,
    *,
    subject_id: str,
    subject_type: str = "agent",
    observation_type: str = "runtime.lifecycle",
    scope: tuple[str, ...] | list[str] = ("runtime:default",),
    tenant: str = "shared",
    sequence_number: int = 1,
    now: int = 1_800_000_000,
    ttl: int = 60,
    confidence: float = 0.9,
    severity: str = "medium",
    evidence: list[dict[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
    extensions: list[dict[str, Any]] | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create a signed direct observation for a simulation or integration."""

    envelope: dict[str, Any] = {
        "protocol_version": "0.1",
        "message_type": "observation",
        "observation_id": observation_id(
            signer.identity.observer_id, subject_id, sequence_number, now, observation_type
        ),
        "observer": observer_block(signer.identity),
        "subject": {"id": subject_id, "type": subject_type},
        "observation_type": observation_type,
        "scope": list(scope),
        "tenant": tenant,
        "sequence_number": sequence_number,
        "observed_at": as_rfc3339(now),
        "issued_at": as_rfc3339(now),
        "expires_at": as_rfc3339(now + ttl),
        "confidence": confidence,
        "severity": severity,
        "evidence": evidence
        or [{"type": "trace_hash", "digest": sha256(f"{subject_id}:{now}".encode()).hexdigest()}],
        "metadata": dict(metadata or {}),
    }
    if extensions:
        envelope["extensions"] = deepcopy(extensions)
    if nonce:
        envelope["nonce"] = nonce
    envelope["signature"] = {"algorithm": "ed25519", "value": signer.sign(canonical_bytes(envelope))}
    return envelope


def resign(envelope: Mapping[str, Any], signer: KeyMaterial) -> dict[str, Any]:
    """Return a copy signed by a signer, useful when varying test fixtures."""

    result = deepcopy(dict(envelope))
    result["observer"] = observer_block(signer.identity)
    result["signature"] = {"algorithm": "ed25519", "value": signer.sign(canonical_bytes(unsigned_envelope(result)))}
    return result

