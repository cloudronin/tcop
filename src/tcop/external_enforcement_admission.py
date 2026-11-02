"""Three-machine admission record for amendment 003; no runtime operations."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .external_foundation_seals import digest, hash256, obj, read_seal, require, text, timestamp, write_seal

PINS = {
    'openclaw': {'release': '2026.9.2', 'commit': '3928bad9badfcb6c7d140530435e806fb8092190',
                 'npm_integrity': 'sha512-M6C7UsnX815nv26qBJFYGe6aGzv+ftZLRzV6S9oRXUtXg2Yn67eVntpssT94kgkquKVSeUxerUg0j1ONp4WYQg=='},
    'nemoclaw': {'commit': '88fe14f3fb9a0bf72997cce19ec88b5b2ee08391'},
    'openshell': {'version': '0.0.116', 'commit': 'd1155aa70042d3e2ee49dbfa15346b108b7c1d92'},
}
HOST_FIELDS = {'identity', 'hardware_id_sha256', 'os_admin_account', 'administration_statement', 'nemoclaw_notice'}


def validate_admission(record: dict[str, Any]) -> None:
    r = obj(record, 'admission')
    require(r.get('schema') == 'tcop.external-enforcement-admission/1.0', 'unknown admission schema')
    require(set(r) <= {'schema', 'synthetic_fixture', 'pins', 'hosts', 'clock_offset', 'policy', 'arms', 'sandbox'}, 'unknown admission field')
    require(obj(r.get('pins'), 'pins') == PINS, 'missing or mismatched immutable pin')
    hosts = obj(r.get('hosts'), 'hosts')
    require(set(hosts) == {'runner', 'host_a', 'host_b'}, 'three machine identities required')
    for role, host in hosts.items():
        h = obj(host, role)
        require(set(h) <= HOST_FIELDS, 'unknown host field; raw hardware identifiers are forbidden')
        for key in ('identity', 'os_admin_account', 'administration_statement'):
            text(h.get(key), f'{role}.{key}')
        hash256(h.get('hardware_id_sha256'), f'{role}.hardware_id_sha256')
        if role != 'runner':
            notice = obj(h.get('nemoclaw_notice'), f'{role}.nemoclaw_notice')
            require(notice == {'version': '2026-04-01b', 'accepted': True} and notice.get('accepted') is True, f'{role} pinned notice acceptance required')
    require(len({h['identity'] for h in hosts.values()}) == 3, 'runner/A/B identities must differ')
    require(len({h['hardware_id_sha256'] for h in hosts.values()}) == 3, 'runner/A/B must be distinct physical machines')
    clock = obj(r.get('clock_offset'), 'clock_offset')
    offset = clock.get('a_to_b_ms')
    require(type(offset) in (float, int) and math.isfinite(offset), 'finite measured A-to-B clock offset required')
    text(clock.get('method'), 'clock method'); timestamp(clock.get('measured_at'), 'clock measured_at')
    policy = obj(r.get('policy'), 'policy')
    text(policy.get('tier'), 'policy tier')
    baseline = hash256(policy.get('installed_effective_baseline_sha256'), 'installed effective baseline')
    presets = policy.get('presets')
    require(isinstance(presets, list), 'complete preset list required (may be empty for base-only)')
    names = []
    for preset in presets:
        p = obj(preset, 'preset')
        require(set(p) == {'name', 'sha256'}, 'preset requires name and hash only')
        names.append(text(p.get('name'), 'preset name')); hash256(p.get('sha256'), 'preset hash')
    require(len(set(names)) == len(names), 'duplicate preset name')
    arms = obj(r.get('arms'), 'arms')
    require(set(arms) == {'E0', 'E1', 'E2'}, 'all three arm baselines required')
    for arm in arms:
        a = obj(arms[arm], arm)
        require(a.get('agent_release') == PINS['openclaw']['release'], 'E0/E1/E2 agent release mismatch')
        if arm != 'E0':
            require(a.get('baseline_policy_sha256') == baseline, 'E1/E2 effective baseline mismatch')
    sandbox = obj(r.get('sandbox'), 'sandbox')
    require(set(sandbox) == {'id', 'name', 'workspace', 'gateway', 'host_identity'}, 'one complete bound sandbox required')
    for key in sandbox:
        text(sandbox[key], f'sandbox.{key}')
    require(sandbox['host_identity'] == hosts['host_b']['identity'], 'bound sandbox must be on Domain B')
    digest(r)


def seal_admission(record: dict[str, Any], output: Path) -> dict[str, Any]:
    validate_admission(record)
    return {**write_seal(output, 'admission', {'record.json': record}), 'record_sha256': digest(record)}


def verify_admission(root: Path, *, host_a: str | None = None, host_b: str | None = None,
                     runner: str | None = None) -> dict[str, Any]:
    sealed = read_seal(root, 'admission')
    require(set(sealed['documents']) == {'record.json'}, 'invalid admission member set')
    record = sealed['documents']['record.json']
    validate_admission(record)
    for role, expected in (('host_a', host_a), ('host_b', host_b), ('runner', runner)):
        if expected is not None:
            require(record['hosts'][role]['identity'] == expected, f'{role} identity differs from execution environment')
    return {'valid': True, 'record': record, 'record_sha256': digest(record),
            'artifact_root_digest': sealed['artifact_root_digest']}
