"""Protocol-object commands backed by the same TCX validators as the harness."""

from __future__ import annotations

import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_bytes, unsigned_envelope
from .cli_support import EXIT_PROTOCOL, TCOPCommandError
from .identity import AuthorityRegistry, KeyMaterial, ObserverIdentity
from .protocol import make_observation
from .time import parse_rfc3339
from .validation import ObservationValidator
from .witness import (
    ControlGroupRegistry,
    Principal,
    WitnessValidator,
    make_interaction_receipt,
    make_relay,
    make_v02_observation,
    receipt_hash,
    verify_interaction_receipt,
)


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TCOPCommandError(f"invalid protocol object: {exc}", EXIT_PROTOCOL) from exc
    if not isinstance(value, dict):
        raise TCOPCommandError("protocol object root must be a JSON object", EXIT_PROTOCOL)
    return value


def _write_if_requested(value: Mapping[str, Any], destination: Path | None) -> None:
    if destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(dict(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _registry_for_context(
    context: Mapping[str, Any], trust_store: Path | None = None,
) -> tuple[AuthorityRegistry, ControlGroupRegistry, dict[str, KeyMaterial]]:
    """Build the deterministic developer trust store used by CLI-created TCX.

    Production gateways receive their trust store from declarative config. The
    command's deterministic identities are intentionally limited to local
    protocol inspection and test/interop fixtures.
    """

    if trust_store is not None:
        return _registry_from_trust_store(trust_store)

    observer = context.get("observer", {})
    subject = context.get("subject", {})
    observer_id = str(observer.get("id", ""))
    trust_domain = str(observer.get("trust_domain", ""))
    subject_id = str(subject.get("id", ""))
    if not observer_id or not trust_domain or not subject_id:
        raise TCOPCommandError("context omits observer identity or subject", EXIT_PROTOCOL)
    registry, groups = AuthorityRegistry(), ControlGroupRegistry()
    observer_key = KeyMaterial.deterministic(observer_id, trust_domain, key_id=str(observer.get("key_id") or "v1"))
    subject_domain = str(context.get("subject_admin_domain_id") or "subject-local")
    subject_key = KeyMaterial.deterministic(subject_id, subject_domain)
    registry.register(observer_key.identity)
    registry.register(subject_key.identity)
    groups.register(Principal(observer_id, str(context.get("observer_admin_domain_id") or trust_domain), str(context.get("observer_control_group_id") or f"control::{observer_id}"), "peer"))
    groups.register(Principal(subject_id, subject_domain, str(context.get("subject_control_group_id") or f"control::{subject_id}"), "subject"))
    return registry, groups, {observer_id: observer_key, subject_id: subject_key}


def _registry_from_trust_store(path: Path) -> tuple[AuthorityRegistry, ControlGroupRegistry, dict[str, KeyMaterial]]:
    """Load explicit public identities and control groups for protocol review.

    This deliberately accepts public verification material only.  It neither
    reads a private key nor silently falls back to the deterministic fixture
    identities when an operator supplied a trust store.
    """

    value = _read_object(path)
    identities = value.get("identities")
    groups_value = value.get("control_groups")
    if value.get("trust_store_version") != "tcop.trust-store/0.1" or not isinstance(identities, list) or not isinstance(groups_value, list):
        raise TCOPCommandError("trust store requires trust_store_version, identities, and control_groups", EXIT_PROTOCOL)
    registry, groups = AuthorityRegistry(), ControlGroupRegistry()
    try:
        for item in identities:
            if not isinstance(item, Mapping):
                raise ValueError("identity must be an object")
            identity = ObserverIdentity(
                observer_id=str(item["id"]),
                trust_domain=str(item["trust_domain"]),
                key_id=str(item["key_id"]),
                scopes=tuple(str(scope) for scope in item.get("scopes", ["*"])),
                observation_types=tuple(str(kind) for kind in item.get("observation_types", ["*"])),
                public_key=bytes.fromhex(str(item["public_key"])),
                revoked=bool(item.get("revoked", False)),
            )
            registry.register(identity, delegated_by=(str(item["delegated_by"]) if item.get("delegated_by") is not None else None))
        for item in groups_value:
            if not isinstance(item, Mapping):
                raise ValueError("control group must be an object")
            groups.register(Principal(str(item["id"]), str(item["admin_domain_id"]), str(item["control_group_id"]), str(item.get("role", "subject"))))
    except (KeyError, TypeError, ValueError) as exc:
        raise TCOPCommandError(f"invalid trust store: {exc}", EXIT_PROTOCOL) from exc
    return registry, groups, {}


def create_context(
    *,
    version: str,
    observer_id: str,
    trust_domain: str,
    subject_id: str,
    scope: str,
    observation_type: str,
    now: int,
    ttl: int,
    severity: str,
    write: Path | None = None,
    receipt_write: Path | None = None,
) -> dict[str, Any]:
    signer = KeyMaterial.deterministic(observer_id, trust_domain)
    if version == "0.1":
        context = make_observation(
            signer,
            subject_id=subject_id,
            observation_type=observation_type,
            scope=(scope,),
            now=now,
            ttl=ttl,
            severity=severity,
        )
        _write_if_requested(context, write)
        if receipt_write is not None:
            raise TCOPCommandError("v0.1 observations do not have interaction receipts", EXIT_PROTOCOL)
        return {"context": context, "receipt": None, "written_to": str(write) if write else None}
    if version != "0.2":
        raise TCOPCommandError(f"unsupported context version: {version}", EXIT_PROTOCOL)
    groups = ControlGroupRegistry()
    groups.register(Principal(observer_id, trust_domain, f"control::{observer_id}", "peer"))
    groups.register(Principal(subject_id, "subject-local", f"control::{subject_id}", "subject"))
    subject_key = KeyMaterial.deterministic(subject_id, "subject-local")
    receipt = make_interaction_receipt(
        signer,
        subject_key,
        groups,
        interaction_id=f"cli-interaction::{observer_id}::{subject_id}::{now}",
        capability=scope,
        now=now,
    )
    context = make_v02_observation(
        signer,
        groups,
        subject_id=subject_id,
        observation_type=observation_type,
        scope=(scope,),
        now=now,
        severity=severity,
        interaction_id=receipt["interaction_id"],
        interaction_receipt_hash=receipt_hash(receipt),
        receipt_mode=receipt["receipt_mode"],
    )
    _write_if_requested(context, write)
    _write_if_requested(receipt, receipt_write)
    return {
        "context": context,
        "receipt": receipt,
        "receipt_digest": receipt_hash(receipt),
        "written_to": str(write) if write else None,
        "receipt_written_to": str(receipt_write) if receipt_write else None,
    }


def verify_context(
    path: Path, *, now: int | None = None, receipt: Path | None = None, trust_store: Path | None = None,
) -> dict[str, Any]:
    context = _read_object(path)
    try:
        verification_time = int(now) if now is not None else parse_rfc3339(str(context["issued_at"]))
    except (KeyError, ValueError) as exc:
        raise TCOPCommandError(f"context has invalid issue time: {exc}", EXIT_PROTOCOL) from exc
    registry, groups, _ = _registry_for_context(context, trust_store)
    version = str(context.get("protocol_version"))
    if version == "0.1":
        result = ObservationValidator(registry).validate(context, verification_time)
        accepted, code = result.accepted, result.code or "accepted"
    elif version == "0.2":
        receipts: dict[str, Mapping[str, Any]] = {}
        if receipt is not None:
            item = _read_object(receipt)
            receipts[receipt_hash(item)] = item
        validator = WitnessValidator(registry, groups, receipts, {}, {})
        result = validator.validate(context, verification_time)
        accepted, code = result.accepted, result.code
    else:
        raise TCOPCommandError(f"unsupported context version: {version}", EXIT_PROTOCOL)
    value = {
        "context_path": str(path), "protocol_version": version, "accepted": accepted, "code": code,
        "verified_at": verification_time, "trust_store": str(trust_store) if trust_store else "deterministic-development",
    }
    if not accepted:
        raise TCOPCommandError(json.dumps(value, sort_keys=True), EXIT_PROTOCOL)
    return value


def inspect_context(path: Path) -> dict[str, Any]:
    context = _read_object(path)
    return {
        "context_path": str(path),
        "protocol_version": context.get("protocol_version"),
        "message_type": context.get("message_type"),
        "observation_id": context.get("observation_id"),
        "observer": context.get("observer"),
        "subject": context.get("subject"),
        "scope": context.get("scope"),
        "observation_type": context.get("observation_type"),
        "expires_at": context.get("expires_at"),
        "context_digest": sha256(canonical_bytes(context)).hexdigest(),
        "receipt_reference": context.get("interaction_receipt_hash"),
        "context": context,
    }


def sign_context(path: Path, *, observer_id: str, trust_domain: str, write: Path | None = None) -> dict[str, Any]:
    context = _read_object(path)
    signer = KeyMaterial.deterministic(observer_id, trust_domain)
    signed = deepcopy(context)
    signed["observer"] = {"id": observer_id, "trust_domain": trust_domain, "key_id": signer.identity.key_id}
    signed["signature"] = {"algorithm": "ed25519", "value": signer.sign(canonical_bytes(unsigned_envelope(signed)))}
    _write_if_requested(signed, write)
    return {"context": signed, "written_to": str(write) if write else None}


def relay_context(path: Path, *, relay_id: str, trust_domain: str, now: int, write: Path | None = None) -> dict[str, Any]:
    context = _read_object(path)
    if context.get("protocol_version") != "0.2":
        raise TCOPCommandError("relay requires a v0.2 signed observation", EXIT_PROTOCOL)
    relay = KeyMaterial.deterministic(relay_id, trust_domain)
    record = make_relay(context, relay, now=now)
    _write_if_requested(record, write)
    return {"relay": record, "written_to": str(write) if write else None}


def verify_receipt(path: Path, *, context: Path | None = None, trust_store: Path | None = None) -> dict[str, Any]:
    receipt = _read_object(path)
    observer_id, subject_id = str(receipt.get("observer_id", "")), str(receipt.get("subject_id", ""))
    if not observer_id or not subject_id:
        raise TCOPCommandError("receipt omits observer_id or subject_id", EXIT_PROTOCOL)
    if trust_store is not None:
        registry, _, _ = _registry_from_trust_store(trust_store)
    else:
        registry = AuthorityRegistry()
        observer = KeyMaterial.deterministic(observer_id, str(receipt.get("observer_admin_domain_id") or "observer-local"), key_id=str(receipt.get("observer_key_id") or "v1"))
        subject = KeyMaterial.deterministic(subject_id, str(receipt.get("subject_admin_domain_id") or "subject-local"), key_id=str(receipt.get("subject_ack_key_id") or "v1"))
        registry.register(observer.identity)
        registry.register(subject.identity)
    accepted, code = verify_interaction_receipt(receipt, registry)
    context_match: bool | None = None
    if context is not None:
        item = _read_object(context)
        context_match = item.get("interaction_receipt_hash") == receipt_hash(receipt)
        accepted = accepted and context_match
        if not context_match:
            code = "context_receipt_hash_mismatch"
    value = {
        "receipt_path": str(path), "receipt_digest": receipt_hash(receipt), "accepted": accepted, "code": code,
        "context_match": context_match, "trust_store": str(trust_store) if trust_store else "deterministic-development",
    }
    if not accepted:
        raise TCOPCommandError(json.dumps(value, sort_keys=True), EXIT_PROTOCOL)
    return value
