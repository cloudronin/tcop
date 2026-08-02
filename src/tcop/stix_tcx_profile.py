"""Declared TCX-over-STIX extension fixture for S2 transport equivalence."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Mapping

from .canonical import canonical_bytes


EXTENSION_ID = "extension-definition--66666666-6666-4666-8666-666666666666"


def extension_definition() -> dict[str, Any]:
    return {
        "type": "extension-definition", "spec_version": "2.1", "id": EXTENSION_ID,
        "name": "TCOP TCX context profile", "version": "1.0", "created": "2026-08-01T00:00:00Z", "modified": "2026-08-01T00:00:00Z",
        "schema": "https://tcop.io/schema/stix/tcx-profile/v1",
        "extension_types": ["property-extension"],
        "description": "Carries a signed TCX message without making a remote enforcement instruction actionable.",
    }


def encode_tcx(context: Mapping[str, Any]) -> dict[str, Any]:
    """Place the signed context in a declared STIX extension envelope."""

    return {
        "type": "observed-data", "spec_version": "2.1", "id": "observed-data--77777777-7777-4777-8777-777777777777",
        "created": "2026-08-01T00:00:00Z", "modified": "2026-08-01T00:00:00Z", "first_observed": "2026-08-01T00:00:00Z", "last_observed": "2026-08-01T00:00:00Z", "number_observed": 1,
        "extensions": {EXTENSION_ID: {"extension_type": "property-extension", "x_tcop_context": deepcopy(dict(context))}},
    }


def decode_tcx(profile_object: Mapping[str, Any]) -> dict[str, Any]:
    try:
        extension = profile_object["extensions"][EXTENSION_ID]
        if extension["extension_type"] != "property-extension":
            raise ValueError("tcx_extension_type_invalid")
        context = extension["x_tcop_context"]
    except (KeyError, TypeError) as exc:
        raise ValueError("tcx_extension_missing") from exc
    if not isinstance(context, Mapping):
        raise ValueError("tcx_extension_context_invalid")
    return deepcopy(dict(context))


def semantic_equivalence(context: Mapping[str, Any]) -> dict[str, Any]:
    encoded = encode_tcx(context)
    decoded = decode_tcx(encoded)
    return {"equivalent": canonical_bytes(dict(context)) == canonical_bytes(decoded), "direct_digest": sha256(canonical_bytes(dict(context))).hexdigest(), "stix_profile_digest": sha256(canonical_bytes(decoded)).hexdigest(), "extension_id": EXTENSION_ID}
