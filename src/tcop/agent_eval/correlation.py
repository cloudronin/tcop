"""Domain-B-private, receipt-backed cross-domain correlation.

The public TCX reference remains the existing interaction receipt digest.  The
receiver mints an opaque interaction handle before the receipt is obtained;
the handle is only entropy plus a keyed MAC and contains no B-local session or
principal identifier.  Domain B alone maintains the resulting binding.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Mapping

from ..canonical import canonical_bytes
from ..identity import KeyMaterial
from ..time import parse_rfc3339
from ..witness import ControlGroupRegistry, make_interaction_receipt, receipt_hash, verify_interaction_receipt


class CorrelationError(ValueError):
    """A precise local failure that must not cause broad enforcement."""


@dataclass
class CorrelationBinding:
    receipt_ref: str
    interaction_handle: str
    session_id: str
    principal_id: str
    capability: str
    expires_at: int
    generation: int
    revoked: bool = False
    accepted_observation_ids: set[str] | None = None

    def __post_init__(self) -> None:
        if self.accepted_observation_ids is None:
            self.accepted_observation_ids = set()

    def audit(self) -> dict[str, Any]:
        item = asdict(self)
        item["accepted_observation_ids"] = sorted(self.accepted_observation_ids or ())
        # The private map is never exported in a study artifact.  This method
        # is used only by local negative-control tests.
        return item


@dataclass(frozen=True)
class PendingCorrelation:
    """A B-private reservation before the origin signs the standard receipt."""

    interaction_handle: str
    session_id: str
    principal_id: str
    capability: str
    expires_at: int
    generation: int


class CorrelationRegistry:
    """One-to-one, expiring, revocable, generation-bound B-local bindings."""

    def __init__(self, domain_id: str, secret: bytes | None = None) -> None:
        self.domain_id = domain_id
        self._secret = secret or secrets.token_bytes(32)
        self._bindings: dict[str, CorrelationBinding] = {}
        self._generations: dict[tuple[str, str], int] = {}
        self._pending_by_handle: dict[str, PendingCorrelation] = {}
        self._counter = 0

    def _handle(self, session_id: str, principal_id: str, generation: int) -> str:
        self._counter += 1
        # The MAC binds a receiver-secret nonce to this B-local generation
        # without making either local identifier observable in the handle.
        payload = generation.to_bytes(8, "big") + self._counter.to_bytes(8, "big")
        token = hmac.new(self._secret, payload, sha256).digest() + payload
        return "corr_" + base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")

    @staticmethod
    def _assert_opaque(receipt: Mapping[str, Any], handle: str, session_id: str, principal_id: str) -> None:
        rendered = canonical_bytes(dict(receipt)).decode("utf-8")
        if session_id in rendered or principal_id in rendered:
            raise CorrelationError("receipt_discloses_b_local_identifier")
        if len(handle) < 48 or session_id in handle or principal_id in handle:
            raise CorrelationError("correlation_handle_not_opaque")

    def reserve(
        self,
        *,
        session_id: str,
        principal_id: str,
        capability: str,
        now: int,
        ttl: int,
    ) -> PendingCorrelation:
        """Create a B-minted opaque handle before any remote receipt exists."""

        if ttl <= 0:
            raise CorrelationError("correlation_ttl_invalid")
        key = (session_id, principal_id)
        generation = self._generations.get(key, 0) + 1
        self._generations[key] = generation
        pending = PendingCorrelation(
            interaction_handle=self._handle(session_id, principal_id, generation),
            session_id=session_id,
            principal_id=principal_id,
            capability=capability,
            expires_at=now + ttl,
            generation=generation,
        )
        self._pending_by_handle[pending.interaction_handle] = pending
        return pending

    def bind(
        self,
        receipt_ref: str,
        receipt: Mapping[str, Any],
        *,
        now: int,
    ) -> None:
        """Bind one origin-signed receipt to one unexpired B reservation."""

        handle = str(receipt.get("interaction_id", ""))
        pending = self._pending_by_handle.get(handle)
        if pending is None:
            raise CorrelationError("receipt_handle_unknown")
        if now > pending.expires_at:
            raise CorrelationError("receipt_handle_expired")
        if receipt_hash(receipt) != receipt_ref:
            raise CorrelationError("receipt_digest_mismatch")
        if receipt_ref in self._bindings:
            raise CorrelationError("receipt_binding_collision")
        self._assert_opaque(receipt, handle, pending.session_id, pending.principal_id)
        self._bindings[receipt_ref] = CorrelationBinding(
            receipt_ref=receipt_ref,
            interaction_handle=handle,
            session_id=pending.session_id,
            principal_id=pending.principal_id,
            capability=pending.capability,
            expires_at=pending.expires_at,
            generation=pending.generation,
        )
        del self._pending_by_handle[handle]

    def issue(
        self,
        *,
        observer: KeyMaterial,
        subject: KeyMaterial,
        control_groups: ControlGroupRegistry,
        session_id: str,
        principal_id: str,
        capability: str,
        now: int,
        ttl: int,
    ) -> tuple[str, dict[str, Any]]:
        """Mint B's opaque handle and obtain a standard existing TCOP receipt.

        The context observer must match the existing receipt observer rule.
        Therefore B mints the opaque correlation handle, while the origin
        monitor signs the receipt and the agent acknowledges it.  B validates
        and stores the receipt digest as its private local-session key.
        """

        pending = self.reserve(
            session_id=session_id,
            principal_id=principal_id,
            capability=capability,
            now=now,
            ttl=ttl,
        )
        receipt = make_interaction_receipt(
            observer,
            subject,
            control_groups,
            interaction_id=pending.interaction_handle,
            capability=capability,
            now=now,
            request=pending.interaction_handle,
            response="accepted-cross-domain-interaction",
            receipt_mode="bilateral",
            transport_evidence="agent-validation-private-network",
        )
        receipt_ref = receipt_hash(receipt)
        self.bind(receipt_ref, receipt, now=now)
        return receipt_ref, receipt

    def admit(
        self,
        receipt_ref: str,
        receipt: Mapping[str, Any],
        *,
        session_id: str,
        principal_id: str,
        capability: str,
        expires_at: int,
        generation: int,
    ) -> None:
        """Restore a B-private binding for a strict replay treatment."""

        handle = str(receipt.get("interaction_id", ""))
        self._assert_opaque(receipt, handle, session_id, principal_id)
        if receipt_hash(receipt) != receipt_ref or receipt_ref in self._bindings:
            raise CorrelationError("receipt_binding_mismatch")
        self._bindings[receipt_ref] = CorrelationBinding(
            receipt_ref=receipt_ref,
            interaction_handle=handle,
            session_id=session_id,
            principal_id=principal_id,
            capability=capability,
            expires_at=expires_at,
            generation=generation,
        )
        key = (session_id, principal_id)
        self._generations[key] = max(self._generations.get(key, 0), generation)

    def resolve(
        self,
        receipt_ref: str | None,
        *,
        session_id: str,
        principal_id: str,
        now: int,
        observation_id: str | None = None,
    ) -> CorrelationBinding:
        if not receipt_ref or receipt_ref not in self._bindings:
            raise CorrelationError("receipt_unknown")
        binding = self._bindings[receipt_ref]
        if binding.revoked:
            raise CorrelationError("receipt_revoked")
        if now > binding.expires_at:
            raise CorrelationError("receipt_expired")
        if binding.session_id != session_id or binding.principal_id != principal_id:
            raise CorrelationError("receipt_session_mismatch")
        if binding.generation != self._generations.get((session_id, principal_id)):
            raise CorrelationError("receipt_generation_stale")
        if observation_id and observation_id in (binding.accepted_observation_ids or set()):
            raise CorrelationError("context_replayed")
        if observation_id:
            assert binding.accepted_observation_ids is not None
            binding.accepted_observation_ids.add(observation_id)
        return binding

    def revoke(self, receipt_ref: str) -> None:
        if receipt_ref in self._bindings:
            self._bindings[receipt_ref].revoked = True

    def has_binding(self, receipt_ref: str) -> bool:
        """Return whether this receiver has already bound the receipt digest."""

        return receipt_ref in self._bindings

    def mark_context(self, receipt_ref: str, observation_id: str) -> None:
        """Atomically reserve an accepted observation after signature checks."""

        binding = self._bindings.get(receipt_ref)
        if binding is None:
            raise CorrelationError("receipt_unknown")
        assert binding.accepted_observation_ids is not None
        if observation_id in binding.accepted_observation_ids:
            raise CorrelationError("context_replayed")
        binding.accepted_observation_ids.add(observation_id)

    def verify_receipt(self, receipt_ref: str, receipt: Mapping[str, Any], identities: Any) -> None:
        if receipt_hash(receipt) != receipt_ref:
            raise CorrelationError("receipt_digest_mismatch")
        accepted, code = verify_interaction_receipt(receipt, identities)
        if not accepted or code != "receipt_verified":
            raise CorrelationError(code if not accepted else "receipt_not_bilateral")
        binding = self._bindings.get(receipt_ref)
        if binding is None or receipt.get("interaction_id") != binding.interaction_handle:
            raise CorrelationError("receipt_binding_mismatch")
        try:
            completed = parse_rfc3339(str(receipt["completed_at"]))
        except (KeyError, ValueError) as exc:
            raise CorrelationError("receipt_time_invalid") from exc
        if completed > binding.expires_at:
            raise CorrelationError("receipt_after_binding_expiry")

    def public_snapshot(self) -> list[dict[str, Any]]:
        """Export only safe handles, expiry, and generation for audit artifacts."""

        return [
            {
                "receipt_ref": binding.receipt_ref,
                "interaction_handle": binding.interaction_handle,
                "capability": binding.capability,
                "expires_at": binding.expires_at,
                "generation": binding.generation,
                "revoked": binding.revoked,
                "accepted_context_count": len(binding.accepted_observation_ids or ()),
            }
            for binding in sorted(self._bindings.values(), key=lambda item: item.receipt_ref)
        ]
