"""Strict TCX v0.1 validation, preserving the specified validation order."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_bytes, unsigned_envelope
from .identity import AuthorityRegistry, verify_signature
from .time import parse_rfc3339


ERROR_UNSUPPORTED_VERSION = "unsupported_version"
ERROR_SCHEMA_INVALID = "schema_invalid"
ERROR_SIGNATURE_INVALID = "signature_invalid"
ERROR_IDENTITY_UNKNOWN = "identity_unknown"
ERROR_SCOPE_VIOLATION = "scope_violation"
ERROR_EXPIRED = "expired"
ERROR_FUTURE_TIMESTAMP = "future_timestamp"
ERROR_REPLAY = "replay_detected"
ERROR_TENANT = "tenant_violation"
ERROR_EVIDENCE = "evidence_unavailable"
ERROR_RATE_LIMITED = "rate_limited"
ERROR_EXTENSION = "mandatory_extension_unknown"

REQUIRED_FIELDS = {
    "protocol_version", "message_type", "observation_id", "observer", "subject",
    "observation_type", "scope", "tenant", "sequence_number", "observed_at",
    "issued_at", "expires_at", "confidence", "severity", "evidence", "metadata",
    "signature",
}
OPTIONAL_FIELDS = {"extensions", "correlation_id", "workflow_id", "parent_observations", "nonce"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
SUBJECT_TYPES = {"agent", "memory", "tool", "credential", "workflow", "observer", "resource"}


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    code: str | None = None
    detail: str = ""

    @classmethod
    def ok(cls) -> "ValidationResult":
        return cls(True)

    @classmethod
    def reject(cls, code: str, detail: str = "") -> "ValidationResult":
        return cls(False, code, detail)


class ReplayWindow:
    """Bounded replay/sequence/nonce state for one trust node."""

    def __init__(self) -> None:
        self.observation_ids: set[str] = set()
        self.highest_sequence: dict[tuple[str, str], int] = {}
        self.nonces: set[str] = set()

    def duplicate_or_stale(self, observation: Mapping[str, Any]) -> bool:
        if observation["observation_id"] in self.observation_ids:
            return True
        observer_id = observation["observer"]["id"]
        subject_id = observation["subject"]["id"]
        highest = self.highest_sequence.get((observer_id, subject_id), -1)
        return int(observation["sequence_number"]) <= highest

    def commit(self, observation: Mapping[str, Any]) -> None:
        self.observation_ids.add(str(observation["observation_id"]))
        key = (str(observation["observer"]["id"]), str(observation["subject"]["id"]))
        self.highest_sequence[key] = int(observation["sequence_number"])

    def use_challenge_nonce(self, nonce: str) -> bool:
        if nonce in self.nonces:
            return False
        self.nonces.add(nonce)
        return True


class ObservationValidator:
    """Stateful receiver-side validator. It does not calculate trust."""

    def __init__(
        self,
        registry: AuthorityRegistry,
        *,
        tenant: str = "shared",
        accepted_tenants: set[str] | None = None,
        clock_skew: int = 5,
        max_message_bytes: int = 32_768,
        max_rate_per_tick: int = 100,
        enforce_scope: bool = True,
        enforce_expiration: bool = True,
    ) -> None:
        self.registry = registry
        self.tenant = tenant
        self.accepted_tenants = accepted_tenants or {tenant}
        self.clock_skew = clock_skew
        self.max_message_bytes = max_message_bytes
        self.max_rate_per_tick = max_rate_per_tick
        self.enforce_scope = enforce_scope
        self.enforce_expiration = enforce_expiration
        self.replay = ReplayWindow()
        self._rate: dict[tuple[int, str], int] = defaultdict(int)

    def validate(self, observation: Mapping[str, Any], now: int) -> ValidationResult:
        # 1. Strict parsing and limits.
        try:
            encoded = canonical_bytes(dict(observation))
        except (TypeError, ValueError):
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "not canonicalizable")
        if len(encoded) > self.max_message_bytes:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "message exceeds byte limit")
        if not isinstance(observation, Mapping) or len(observation) > 32:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid envelope shape")

        # 2. Version and mandatory schema.
        schema = self._schema_error(observation)
        if schema:
            return schema
        if observation["protocol_version"] != "0.1" or observation["message_type"] != "observation":
            return ValidationResult.reject(ERROR_UNSUPPORTED_VERSION)

        # 3. Resolve identity and authorized scope.
        observer = observation["observer"]
        identity = self.registry.resolve(observer["id"], observer["key_id"])
        if identity is None or identity.revoked or identity.trust_domain != observer["trust_domain"]:
            return ValidationResult.reject(ERROR_IDENTITY_UNKNOWN)
        if not self.registry.validate_authority_chain(identity.observer_id):
            return ValidationResult.reject(ERROR_SCOPE_VIOLATION, "invalid delegation chain")
        if self.enforce_scope and not all(identity.allows(scope, observation["observation_type"]) for scope in observation["scope"]):
            return ValidationResult.reject(ERROR_SCOPE_VIOLATION)

        # 4. Verify signature over exact canonical unsigned bytes.
        signature = observation["signature"]
        if signature.get("algorithm") != "ed25519" or not verify_signature(
            identity, canonical_bytes(unsigned_envelope(observation)), signature.get("value", "")
        ):
            return ValidationResult.reject(ERROR_SIGNATURE_INVALID)

        # 5. Freshness and expiration.
        try:
            observed_at = parse_rfc3339(observation["observed_at"])
            issued_at = parse_rfc3339(observation["issued_at"])
            expires_at = parse_rfc3339(observation["expires_at"])
        except ValueError as exc:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, str(exc))
        if self.enforce_expiration and (expires_at <= issued_at or expires_at < now):
            return ValidationResult.reject(ERROR_EXPIRED)
        if observed_at > now + self.clock_skew or issued_at > now + self.clock_skew:
            return ValidationResult.reject(ERROR_FUTURE_TIMESTAMP)

        # 6. Sequence and replay status.
        if self.replay.duplicate_or_stale(observation):
            return ValidationResult.reject(ERROR_REPLAY)

        # 7. Tenant boundary.
        if observation["tenant"] not in self.accepted_tenants:
            return ValidationResult.reject(ERROR_TENANT)

        # 8. Negotiated extension and observation type checks.
        for extension in observation.get("extensions", []):
            if extension.get("mandatory") and extension.get("id") not in {"tcop.v0.1"}:
                return ValidationResult.reject(ERROR_EXTENSION)

        # 9. Evidence availability / safe reference shape.
        if not observation["evidence"] or any(not entry.get("digest") for entry in observation["evidence"]):
            return ValidationResult.reject(ERROR_EVIDENCE)

        # 10. Bounded per-observer rate.
        rate_key = (now, identity.observer_id)
        self._rate[rate_key] += 1
        if self._rate[rate_key] > self.max_rate_per_tick:
            return ValidationResult.reject(ERROR_RATE_LIMITED)
        return ValidationResult.ok()

    def commit(self, observation: Mapping[str, Any]) -> None:
        self.replay.commit(observation)

    def _schema_error(self, observation: Mapping[str, Any]) -> ValidationResult | None:
        missing = REQUIRED_FIELDS - set(observation)
        if missing:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, f"missing: {','.join(sorted(missing))}")
        unknown = set(observation) - REQUIRED_FIELDS - OPTIONAL_FIELDS
        if unknown:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, f"unknown top fields: {','.join(sorted(unknown))}")
        if not isinstance(observation["observer"], Mapping) or not {"id", "trust_domain", "key_id"} <= set(observation["observer"]):
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid observer")
        if not isinstance(observation["subject"], Mapping) or not {"id", "type"} <= set(observation["subject"]):
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid subject")
        if observation["subject"]["type"] not in SUBJECT_TYPES:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid subject type")
        if not isinstance(observation["scope"], list) or not observation["scope"]:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "scope required")
        if not isinstance(observation["sequence_number"], int) or observation["sequence_number"] < 0:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid sequence")
        if observation["severity"] not in SEVERITIES:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid severity")
        if not isinstance(observation["confidence"], (float, int)) or not 0 <= observation["confidence"] <= 1:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid confidence")
        if not isinstance(observation["metadata"], Mapping) or len(observation["metadata"]) > 32:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid metadata")
        if not isinstance(observation["evidence"], list) or len(observation["evidence"]) > 16:
            return ValidationResult.reject(ERROR_SCHEMA_INVALID, "invalid evidence")
        return None
