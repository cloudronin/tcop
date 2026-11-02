"""Draft role-script census and immutable content sealing. No agent execution."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .external_foundation_seals import digest, hash256, obj, read_json, read_seal, require, text, write_seal

FAMILIES = {'S-A': 'hugging-face-technical-timeline-stage-1',
            'S-B': 'hugging-face-technical-timeline-stage-2-vector-1',
            'S-C': 'metr-investigation-july-10'}
DISPOSITIONS = {'executed', 'not_triggered', 'not_representable', 'environment_failure',
                'policy_failure', 'excluded_before_execution'}
DEFAULT_SCRIPTS = Path('benchmark/role-scripts/amendment-003')


def validate_script(record: dict[str, Any], *, non_smoke: bool = False) -> None:
    r = obj(record, 'role script')
    require(r.get('schema') == 'tcop.external-role-script/1.0', 'unknown role-script schema')
    family = r.get('family')
    require(isinstance(family, str) and family in FAMILIES, 'unknown role family')
    require(r.get('script_id') == family, 'script ID must name its draft family')
    require(r.get('public_source_tag') == FAMILIES[family], 'public-source tag missing or mismatched')
    text(r.get('harmful_intent'), 'harmful intent'); text(r.get('A0'), 'A0 action')
    roles = obj(r.get('roles'), 'roles')
    text(roles.get('A'), 'adversarial A role'); text(roles.get('B'), 'benign B role')
    targets = r.get('targets')
    require(isinstance(targets, list) and bool(targets), 'synthetic targets required')
    for target in targets:
        text(target, 'target')
        try:
            parsed = urlsplit(target)
            require(parsed.scheme in {'https', 'http'} and parsed.hostname is not None
                    and parsed.hostname.endswith('.invalid') and not parsed.username and not parsed.password,
                    'targets must use synthetic .invalid hosts without credentials')
        except ValueError as exc:
            from .cli_support import TCOPCommandError
            raise TCOPCommandError('invalid synthetic target') from exc
    branches = obj(r.get('branches'), 'branches')
    require(set(branches) == {'A1', 'A2', 'A3', 'A4'}, 'A1-A4 must all be censused')
    for name, branch in branches.items():
        b = obj(branch, name)
        require(type(b.get('representable')) is bool, f'{name} representability required')
        require(isinstance(b.get('disposition'), str) and b['disposition'] in DISPOSITIONS, f'{name} must have a closing disposition')
        require(b['representable'] or b['disposition'] == 'not_representable', f'{name} not-representable disposition required')
        text(b.get('action'), f'{name} action'); text(b.get('reason'), f'{name} reason')
    a4 = branches['A4']
    # Unrepresentable legacy drafts may remain undeclared. Every representable
    # A4 must declare independence; even a draft cannot explicitly deny it.
    if a4['representable'] or 'independent_of_harmful_side_effects' in a4:
        require(a4.get('independent_of_harmful_side_effects') is True,
                'A4 independence from harmful side effects must be declared true')
    require(isinstance(r.get('status'), str) and r['status'] in {'draft-pending-mapping', 'mapped'}, 'role status required')
    if family == 'S-C':
        origin = obj(r.get('replay_origin'), 'S-C replay origin')
        require(origin == {'domain': 'B', 'boundary': 'bound_domain_b_sandbox',
                           'actor': 'domain_b_agent', 'egress': 'domain_b_proxy'},
                'S-C replay must originate inside the bound Domain-B sandbox through its proxy')
        capability = obj(r.get('runtime_capability'), 'provider detach capability')
        require(capability.get('action') == 'detach_one_named_provider'
                and capability.get('native_path') == 'DetachSandboxProvider'
                and capability.get('credential_unit') == 'whole_provider'
                and capability.get('openshell_version') == '0.0.116',
                'S-C native action is whole-provider detach at the pinned OpenShell')
    if non_smoke:
        require(r['status'] != 'draft-pending-mapping', 'draft role scripts cannot be admitted for non-smoke execution')
        mapping = obj(r.get('source_mapping'), 'public-source mapping')
        require(mapping.get('path') == 'docs/case-hugging-face.md', 'public-source mapping document required')
        path = Path(mapping['path'])
        expected = hash256(mapping.get('sha256'), 'public-source mapping hash')
        require(path.is_file() and sha256(path.read_bytes()).hexdigest() == expected, 'public-source mapping missing or changed')
    digest(r)


def census_roles(scripts_dir: Path = DEFAULT_SCRIPTS) -> dict[str, Any]:
    require(scripts_dir.is_dir() and not scripts_dir.is_symlink(), 'role-script directory required')
    require(not any(p.is_symlink() for p in scripts_dir.rglob('*')), 'role scripts cannot be symlinks')
    scripts = []
    for path in sorted(scripts_dir.glob('*.json')):
        record = read_json(path); validate_script(record)
        require(path.name == record['script_id'] + '.json', 'script filename must match script ID')
        scripts.append({'script_id': record['script_id'], 'family': record['family'], 'status': record['status'],
                        'path': f"scripts/{path.name}", 'sha256': sha256(path.read_bytes()).hexdigest()})
    require(len(scripts) == 3 and {s['family'] for s in scripts} == set(FAMILIES), 'all three role families required exactly once')
    return {'schema': 'tcop.external-role-census/1.0', 'scripts': scripts}


def seal_roles(scripts_dir: Path, output: Path) -> dict[str, Any]:
    census = census_roles(scripts_dir)
    documents = {'census.json': census}
    for row in census['scripts']:
        record = read_json(scripts_dir / Path(row['path']).name)
        payload = (scripts_dir / Path(row['path']).name).read_bytes()
        require(sha256(payload).hexdigest() == row['sha256'], 'script changed during census')
        documents[row['path']] = payload
    return {**write_seal(output, 'role-census', documents), 'census_sha256': digest(census)}


def verify_roles(root: Path, *, non_smoke: bool = False, scripts_dir: Path | None = None,
                 script_id: str | None = None) -> dict[str, Any]:
    sealed = read_seal(root, 'role-census')
    documents = sealed['documents']; census = obj(documents.get('census.json'), 'sealed census')
    require(census.get('schema') == 'tcop.external-role-census/1.0', 'unknown census schema')
    rows = census.get('scripts')
    require(isinstance(rows, list) and len(rows) == 3, 'complete role census required')
    expected_paths = {'census.json'}; ids = set()
    for row in rows:
        row = obj(row, 'census row'); sid = text(row.get('script_id'), 'census script ID')
        require(sid in FAMILIES and sid not in ids, 'unknown or duplicate census script')
        ids.add(sid); name = f'scripts/{sid}.json'; expected_paths.add(name)
        require(row.get('path') == name and name in documents, 'uncensused or missing role script')
        record = documents[name]; validate_script(record, non_smoke=non_smoke)
        require(row == {'script_id': sid, 'family': record['family'], 'status': record['status'],
                        'path': name, 'sha256': sha256((root / name).read_bytes()).hexdigest()}, 'role census/script mismatch')
    require(ids == set(FAMILIES) and set(documents) == expected_paths, 'role seal census mismatch')
    if scripts_dir is not None:
        require(census_roles(scripts_dir) == census, 'role scripts changed after seal')
    if script_id is not None:
        require(script_id in ids, 'script is not in the sealed census')
    return {'valid': True, 'census': census, 'census_sha256': digest(census),
            'artifact_root_digest': sealed['artifact_root_digest']}
