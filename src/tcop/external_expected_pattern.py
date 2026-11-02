"""Sealed predictions for amendment 003. The real draft remains unsealed."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from .external_foundation_seals import digest, hash256, obj, read_seal, require, text, write_seal
from .external_role_scripts import FAMILIES


def validate_expected_pattern(record: dict[str, Any]) -> None:
    r = obj(record, 'expected pattern')
    if r.get('schema') == 'tcop.external-expected-pattern/1.1':
        from .external_enforcement_validation import validate_expected_pattern_v14
        validate_expected_pattern_v14(r)
        return
    require(r.get('schema') == 'tcop.external-expected-pattern/1.0', 'unknown expected-pattern schema')
    require(r.get('status') == 'preregistered' and r.get('open_owner_issues') == [],
            'expected pattern is unsealed-pending-owner; issues must be resolved before sealing')
    families = obj(r.get('families'), 'predicted families')
    require(set(families) == set(FAMILIES), 'all three predicted frontier families required')
    for family, prediction in families.items():
        text(prediction, f'{family} prediction')
    require(r.get('pool_e2_modes') is False, 'E2a/E2b predictions must never be pooled')
    bindings = obj(r.get('bindings'), 'prediction bindings')
    require(set(bindings) == {'plan_sha256', 'census_sha256', 'admission_sha256'}, 'prediction must bind plan, census, admission')
    for name, value in bindings.items():
        hash256(value, name)
    digest(r)


def seal_expected_pattern(record: dict[str, Any], output: Path) -> dict[str, Any]:
    validate_expected_pattern(record)
    return {**write_seal(output, 'expected-pattern', {'record.json': record}), 'record_sha256': digest(record)}


def verify_expected_pattern(root: Path, *, bindings: dict[str, str] | None = None) -> dict[str, Any]:
    sealed = read_seal(root, 'expected-pattern')
    require(set(sealed['documents']) == {'record.json'}, 'invalid expected-pattern member set')
    record = sealed['documents']['record.json']; validate_expected_pattern(record)
    for key, value in (bindings or {}).items():
        require(record['bindings'].get(key) == value, f'expected-pattern {key} mismatch')
    return {'valid': True, 'record': record, 'record_sha256': digest(record),
            'sealed_at': sealed['seal']['sealed_at'], 'artifact_root_digest': sealed['artifact_root_digest']}
