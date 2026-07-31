"""Canonical JSON helpers for the TCX v0.1 reference profile."""

from __future__ import annotations

import json
from typing import Any, Mapping


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the exact UTF-8 bytes covered by a v0.1 signature.

    The reference profile intentionally rejects NaN and Infinity, uses sorted
    keys, compact separators, and UTF-8 rather than an implementation-specific
    pretty JSON representation.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def unsigned_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Copy an envelope excluding the only field outside the signature."""

    return {key: value for key, value in envelope.items() if key != "signature"}

