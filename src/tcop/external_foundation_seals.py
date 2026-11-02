"""Content seals for amendment 003 records. These are integrity seals, not signatures."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .cli_support import TCOPCommandError
from .context_comparator import _root_digest


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TCOPCommandError(message)


def obj(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()) and value == value.strip(), f"{label} is required")
    return value


def hash256(value: Any, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"{label} must be SHA-256")
    return value


def timestamp(value: Any, label: str) -> str:
    text(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.utcoffset() is not None, f"{label} requires timezone")
    except ValueError as exc:
        raise TCOPCommandError(f"{label} must be an ISO timestamp") from exc
    return value


def digest(value: Any) -> str:
    try:
        return sha256(canonical_bytes(value)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise TCOPCommandError("record is not canonical JSON") from exc


def _parse_json(data: str | bytes, label: str) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda value: require(False, "non-finite JSON number"))
        return obj(value, label)
    except (ValueError, UnicodeError) as exc:
        raise TCOPCommandError(f"unreadable JSON record: {label}") from exc


def read_json(path: Path) -> dict[str, Any]:
    try:
        return _parse_json(path.read_bytes(), str(path))
    except OSError as exc:
        raise TCOPCommandError(f"unreadable JSON record: {path}") from exc


def ensure_unsealed_output(root: Path) -> None:
    for ancestor in root.resolve().parents:
        require(not (ancestor / 'artifact-root-digest.json').exists(), f"cannot write inside a sealed artifact: {ancestor}")


def write_seal(root: Path, kind: str, documents: dict[str, Any]) -> dict[str, Any]:
    ensure_unsealed_output(root)
    require(not root.exists(), f"seal output already exists: {root}")
    encoded = {}
    for name, value in documents.items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and name not in {'seal.json', 'artifact-root-digest.json'}, "invalid seal member")
        if isinstance(value, bytes):
            _parse_json(value, name)
            encoded[name] = value
        else:
            digest(value)
            encoded[name] = canonical_bytes(value) + b'\n'
    root.mkdir(parents=True)
    for name, payload in encoded.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    seal = {"schema": "tcop.external-foundation-seal/1.0", "kind": kind,
            "sealed_at": datetime.now(timezone.utc).isoformat(),
            "files": {name: sha256(data).hexdigest() for name, data in encoded.items()}}
    (root / 'seal.json').write_bytes(canonical_bytes(seal) + b'\n')
    root_hash = _root_digest(root)
    (root / 'artifact-root-digest.json').write_bytes(canonical_bytes({'artifact_root_digest': root_hash}) + b'\n')
    return {"artifact_dir": str(root), "artifact_root_digest": root_hash}


def read_seal(root: Path, kind: str) -> dict[str, Any]:
    require(root.is_dir() and not root.is_symlink(), f"unsealed {kind} record")
    require(not any(p.is_symlink() for p in root.rglob('*')), "seal contains symlinks")
    seal = read_json(root / 'seal.json')
    require(seal.get('schema') == 'tcop.external-foundation-seal/1.0' and seal.get('kind') == kind, "wrong seal schema or kind")
    timestamp(seal.get('sealed_at'), 'sealed_at')
    files = obj(seal.get('files'), 'seal files')
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual == set(files) | {'seal.json', 'artifact-root-digest.json'}, "seal file census mismatch")
    for name, expected in files.items():
        member = Path(name)
        require(not member.is_absolute() and '..' not in member.parts, "invalid seal path")
        hash256(expected, 'member hash')
        require(sha256((root / name).read_bytes()).hexdigest() == expected, f"changed sealed member: {name}")
    expected = read_json(root / 'artifact-root-digest.json').get('artifact_root_digest')
    require(_root_digest(root) == expected, "foundation seal root changed")
    return {'documents': {name: read_json(root / name) for name in files}, 'seal': seal,
            'artifact_root_digest': expected}
