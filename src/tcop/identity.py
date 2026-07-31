"""Identity, static authority, and Ed25519 helpers for the v0.1 profile."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from hashlib import sha256
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class ObserverIdentity:
    observer_id: str
    trust_domain: str
    key_id: str
    scopes: tuple[str, ...]
    observation_types: tuple[str, ...]
    public_key: bytes
    revoked: bool = False

    def allows(self, scope: str, observation_type: str) -> bool:
        return (
            any(fnmatchcase(scope, pattern) for pattern in self.scopes)
            and any(fnmatchcase(observation_type, pattern) for pattern in self.observation_types)
        )


class AuthorityRegistry:
    """Static discovery and authority model used by the deterministic profile.

    A registry verifies the source and scope of a message. It deliberately does
    not assign trust conclusions or voting power.
    """

    def __init__(self) -> None:
        self._identities: dict[tuple[str, str], ObserverIdentity] = {}
        self._delegations: dict[str, str | None] = {}

    def register(
        self,
        identity: ObserverIdentity,
        *,
        delegated_by: str | None = None,
    ) -> None:
        key = (identity.observer_id, identity.key_id)
        self._identities[key] = identity
        self._delegations[identity.observer_id] = delegated_by

    def rotate(self, old_observer_id: str, old_key_id: str, replacement: ObserverIdentity) -> None:
        old = self._identities[(old_observer_id, old_key_id)]
        self._identities[(old_observer_id, old_key_id)] = ObserverIdentity(
            observer_id=old.observer_id,
            trust_domain=old.trust_domain,
            key_id=old.key_id,
            scopes=old.scopes,
            observation_types=old.observation_types,
            public_key=old.public_key,
            revoked=True,
        )
        self.register(replacement, delegated_by=self._delegations.get(old_observer_id))

    def resolve(self, observer_id: str, key_id: str) -> ObserverIdentity | None:
        return self._identities.get((observer_id, key_id))

    def validate_authority_chain(self, observer_id: str) -> bool:
        """Return false if the optional delegation chain is cyclic or broken."""

        seen: set[str] = set()
        current: str | None = observer_id
        while current is not None:
            if current in seen:
                return False
            seen.add(current)
            if current not in self._delegations:
                return False
            current = self._delegations[current]
        return True

    def domain_for(self, observer_id: str, key_id: str) -> str | None:
        identity = self.resolve(observer_id, key_id)
        return identity.trust_domain if identity else None


class KeyMaterial:
    """Private key material used only by observers in reference simulations."""

    def __init__(self, private_key: Ed25519PrivateKey, identity: ObserverIdentity) -> None:
        self._private_key = private_key
        self.identity = identity

    @classmethod
    def deterministic(
        cls,
        observer_id: str,
        trust_domain: str,
        *,
        key_id: str | None = None,
        scopes: Iterable[str] = ("*",),
        observation_types: Iterable[str] = ("*",),
    ) -> "KeyMaterial":
        # Reproducible fixtures require deterministic test keys. Production
        # profiles must use a secure keystore and random private keys.
        seed = sha256(f"tcop-test-key:{observer_id}:{trust_domain}:{key_id or 'v1'}".encode()).digest()
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        identity = ObserverIdentity(
            observer_id=observer_id,
            trust_domain=trust_domain,
            key_id=key_id or "v1",
            scopes=tuple(scopes),
            observation_types=tuple(observation_types),
            public_key=public_key,
        )
        return cls(private_key, identity)

    def sign(self, payload: bytes) -> str:
        return self._private_key.sign(payload).hex()


def verify_signature(identity: ObserverIdentity, payload: bytes, signature_hex: str) -> bool:
    try:
        signature = bytes.fromhex(signature_hex)
        Ed25519PublicKey.from_public_bytes(identity.public_key).verify(signature, payload)
    except (ValueError, InvalidSignature):
        return False
    return True


def observer_block(identity: ObserverIdentity) -> dict[str, str]:
    return {
        "id": identity.observer_id,
        "trust_domain": identity.trust_domain,
        "key_id": identity.key_id,
    }

