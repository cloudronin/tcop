"""Pure amendment 003/004 record gates. No runtime, adapter or simulator calls.

Content seals bind supplied evidence; they are not signatures or independent
proof that a conformance test, calibration, or TLC invocation actually ran.
"""
from __future__ import annotations

from datetime import datetime
import math
from typing import Any

from .cli_support import TCOPCommandError
from .external_foundation_seals import digest, hash256, obj, require, text, timestamp
from .external_enforcement_admission import PINS, validate_admission
from .external_role_scripts import FAMILIES, validate_script
from .timing_phase import OUTCOMES

AM004_SHA256 = '9546e30627eab69924f47d595fa536da22acee8edd818d1b268eee8ba02b0706'
ROWS = ('E0', 'E1', 'E2-native-a', 'E2-native-b', 'E2-native-min-a', 'E2-extended-a', 'E2-extended-b')
NETWORK_DELAYS = [10, 50, 100, 250]
PROVISIONAL_INTERVALS = [25, 400, 5000, 20000]
LEGACY_INTERVALS = [25, 100, 250, 500]
APPROVAL_BASIS = 'Attentive operator; approval prompt already on screen; one click to approve; best case for human approval.'
TLC_PROPERTIES = {'tightening_only', 'evidence_admissibility', 'effect_enforcement',
                  'lying_peer_availability_only', 'lag_exceeds_interval_prevents_nothing'}
BINDINGS = {
    'native-egress-10': ('deny_egress', 'UpdateConfig', 'native', 'meets', 'pure layering', 'C1', 10),
    'native-egress-1': ('deny_egress', 'UpdateConfig', 'native', 'meets', 'pure layering', 'C1', 1),
    'instant-egress': ('deny_egress', 'vm_forwarding_filter', 'harness', 'meets', 'extension', 'C1', 10),
    'provider-detach-10': ('revoke_credential', 'DetachSandboxProvider', 'native', 'meets more coarsely', 'pure layering', 'C2', 10),
    'provider-detach-1': ('revoke_credential', 'DetachSandboxProvider', 'native', 'meets more coarsely', 'pure layering', 'C2', 1),
    'freeze': ('freeze_sandbox', 'docker_pause', 'harness', 'meets', 'extension', 'C3', 10),
    'snapshot': ('snapshot_sandbox', 'docker_commit_no_pause', 'harness', 'meets more coarsely', 'extension', 'C4', 10),
}
ABSTRACT_GUARANTEES = {
    'deny_egress': 'New connections to that destination fail.',
    'revoke_credential': 'The credential stops resolving for new requests; requests already in flight may finish.',
    'freeze_sandbox': 'Nothing further runs in the sandbox until it is released outside the adapter.',
    'snapshot_sandbox': 'Sandbox state is captured; it restricts nothing. Capability only; never on the frontier.',
}
BINDING_TABLE = {
    'deny_egress': {'native_implementation':'UpdateConfig','native_grade':'meets',
                   'harness_implementation':'vm_forwarding_filter','harness_grade':'meets',
                   'native_layering':'pure layering','harness_layering':'extension'},
    'revoke_credential': {'native_implementation':'DetachSandboxProvider','native_grade':'meets more coarsely',
                         'coarsening':'whole provider, including every credential it holds',
                         'harness_implementation':None,'native_layering':'pure layering'},
    'freeze_sandbox': {'native_implementation':None,'native_grade':'does not meet',
                      'harness_implementation':'docker_pause','harness_grade':'meets','harness_layering':'extension'},
    'snapshot_sandbox': {'native_implementation':None,'native_grade':'does not meet',
                        'harness_implementation':'docker_commit_no_pause','harness_grade':'meets more coarsely',
                        'harness_layering':'extension','capability_only':True,
                        'coarsening':'filesystem coverage and capture-interval observation; no memory or mounted data'},
    'approval_delay': {'kind':'submission_condition','native_implementation':None,'native_grade':'does not meet the condition',
                       'harness_implementation':'fixed_delay_always_approve','harness_grade':'meets the condition',
                       'tag':'harness','layering':'pure layering'},
}
SOURCE_ROOTS = {'federated_evidence': '0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99',
                'validation_value_v2': 'da59b13917eac22bb329199886100861c1a9f91c33e69a7f6ad5db55ec3e731d'}


def gate(condition: bool, name: str, message: str) -> None:
    require(condition, f'{name}: {message}')


def number(value: Any, label: str) -> float:
    gate(type(value) in (int, float) and math.isfinite(value) and value >= 0, 'AM004_NUMBER', label)
    return value


def integer(value: Any, label: str) -> int:
    gate(type(value) is int and value >= 0, 'AM004_INTEGER', label)
    return value


def items(value: Any, label: str) -> list:
    gate(isinstance(value, list), 'AM004_SCHEMA', label + ' must be a list')
    return value


def moment(value: Any) -> datetime:
    timestamp(value, 'evidence timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def sealed(value: Any, schema: str) -> tuple[dict, datetime]:
    envelope = obj(value, schema)
    gate(set(envelope) == {'body', 'sha256', 'sealed_at'}, 'AM004_SEAL', 'exact content-seal envelope required')
    body = obj(envelope['body'], schema)
    gate(body.get('schema') == schema and digest(body) == hash256(envelope['sha256'], 'record hash'),
         'AM004_SEAL', 'record schema or content hash differs')
    return body, moment(envelope['sealed_at'])


def _walk(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            gate(isinstance(key, str) and 'reliability' not in key.lower(), 'AM004_METRIC_NAMES', 'reliability is not a study field')
            gate(not (key == 'post_hoc' and child is True), 'AM004_POST_HOC', 'post-hoc output cannot enter sealed/result records')
            if key in {'record_name', 'record_type', 'name'}:
                gate(not isinstance(child, str) or child.lower() != 'reliability', 'AM004_METRIC_NAMES', 'forbidden record name')
            _walk(child)
    elif isinstance(value, list):
        for child in value:
            _walk(child)


def selected_binding(family: str, row: str) -> str:
    if row in {'E0', 'E1'}:
        return 'not_applicable'
    if row.startswith('E2-extended'):
        return {'S-A': 'native-egress-10', 'S-B': 'instant-egress', 'S-C': 'freeze'}[family]
    poll = '1' if row == 'E2-native-min-a' else '10'
    return ('provider-detach-' if family == 'S-C' else 'native-egress-') + poll


def validate_calibration_reference(record: dict) -> dict:
    r = obj(record, 'calibration')
    gate(r.get('schema') == 'tcop.external-calibration-reference/1.0' and r.get('status') == 'calibrated',
         'AM004_CALIBRATION', 'only a calibrated simulator can generate a sealable prediction')
    for key in ('simulator_sha256', 'calibration_data_sha256', 'evidence_sha256'):
        hash256(r.get(key), key)
    integer(r.get('seed'), 'calibration seed')
    return r


def validate_expected_pattern_v14(record: dict) -> None:
    r = obj(record, 'expected pattern 1.1')
    gate(r.get('schema') == 'tcop.external-expected-pattern/1.1' and r.get('status') == 'preregistered'
         and r.get('open_owner_issues') == [] and r.get('pool_e2_modes') is False,
         'AM004_EXPECTED_PATTERN', 'calibrated, pre-registered and unpooled prediction required')
    gate(set(obj(r.get('families'), 'predictions')) == set(FAMILIES), 'AM003_FAMILIES', 'all predicted families required')
    for value in r['families'].values():
        text(value, 'predicted frontier shape')
    bindings = obj(r.get('bindings'), 'prediction bindings')
    gate(set(bindings) == {'plan_sha256', 'census_sha256', 'admission_sha256'}, 'AM004_EXPECTED_PATTERN', 'prediction bindings required')
    for key in ('simulator_sha256', 'calibration_sha256', 'grid_sha256'):
        hash256(r.get(key), key)
    for key, value in bindings.items():
        hash256(value, key)
    integer(r.get('seed'), 'prediction seed')
    gate(r.get('calibration_status') == 'calibrated', 'AM004_CALIBRATION', 'provisional calibration cannot be sealed')
    gate(r.get('native_below_lag_prevention') == {'S-B': 0, 'S-C': 0}, 'AM004_RETRY_PREDICTION', 'native E2 prevents nothing below binding lag')
    grid = obj(r.get('finalized_grid'), 'prediction grid')
    gate(grid.get('network_delay_ms') == NETWORK_DELAYS, 'AM004_GRID', 'interface axis differs')
    intervals = items(grid.get('action_interval_ms'), 'prediction intervals')
    gate(len(intervals) == 4 and len(set(intervals)) == 4, 'AM004_GRID', 'four finalized intervals required')
    for value in intervals:
        number(value, 'prediction interval')
    _walk(r); digest(r)


def validate_tlc_pass_record(record: dict) -> dict:
    r = obj(record, 'TLC pass')
    gate(r.get('schema') == 'tcop.external-tlc-pass/1.0' and r.get('tool') == 'TLC'
         and r.get('passed') is True and r.get('exhaustive') is True
         and r.get('violations') == [] and type(r.get('violation_count')) is int and r['violation_count'] == 0,
         'AM004_TLC', 'TLC violation or missing exhaustive pass blocks live execution')
    text(r.get('tool_version'), 'TLC version')
    for key in ('tool_sha256', 'model_sha256', 'config_sha256'):
        hash256(r.get(key), key)
    bounds = obj(r.get('bounds'), 'TLC bounds')
    gate(bool(bounds), 'AM004_TLC', 'model bounds required')
    for value in bounds.values():
        integer(value, 'TLC bound')
    props = items(r.get('properties'), 'TLC properties')
    gate(set(props) >= TLC_PROPERTIES and len(set(props)) == len(props), 'AM004_TLC', 'required TLC properties missing')
    return r


def _conformance(records: dict, sandbox: dict) -> dict:
    result = {}
    gate(set(records) == set(BINDINGS), 'AM004_CONFORMANCE', 'each admitted binding/configuration needs its check')
    for key, envelope in records.items():
        r, at = sealed(envelope, 'tcop.external-conformance/1.0')
        action, implementation, tag, grade, layering, check, poll = BINDINGS[key]
        gate(all(r.get(k) == v for k, v in {'binding_id': key, 'implementation': implementation,
             'runtime_commit': PINS['openshell']['commit'], 'tag': tag, 'grade': grade, 'layering': layering,
             'check': check, 'poll_interval_secs': poll, 'sandbox_id': sandbox['id']}.items()),
             'AM004_CONFORMANCE', 'check does not match binding pin, grade or configuration')
        gate(all(r.get(k) is True for k in ('passed', 'observed_effect', 'controls_unaffected', 'continuity')),
             'AM004_CONFORMANCE', 'conformance must pass at the admitted scope')
        number(r.get('effect_lag_ms'), 'conformance lag'); hash256(r.get('evidence_sha256'), 'conformance evidence')
        result[key] = (r, at)
    return result


def validate_grid_finalization(record: dict, conformance: dict) -> dict:
    r = obj(record, 'grid finalization')
    gate(r.get('schema') == 'tcop.external-grid-finalization/1.0' and r.get('network_delay_ms') == NETWORK_DELAYS,
         'AM004_GRID', 'finalization schema/interface grid differs')
    values = items(r.get('action_interval_ms'), 'action intervals')
    gate(len(values) == 4 and len(set(values)) == 4, 'AM004_GRID', 'four unique action intervals required')
    for v in values:
        number(v, 'action interval')
    gate(values == sorted(values) and values[0] > 0, 'AM004_GRID', 'intervals must increase and be positive')
    needed = {'native-egress-10', 'native-egress-1', 'instant-egress', 'freeze'}
    measurements = obj(r.get('measurements'), 'grid measurements')
    gate(set(measurements) == needed, 'AM004_GRID', 'C1 native 10 s/1 s/instant and C3 freeze required')
    for key in needed:
        gate(measurements[key] == conformance[key]['sha256'], 'AM004_GRID', 'finalization measurement hash differs')
    lag = {key:conformance[key]['body']['effect_lag_ms'] for key in needed}
    gate(values[0] < min(lag['instant-egress'], lag['freeze'])
         and max(lag['instant-egress'], lag['freeze']) < values[1] < lag['native-egress-1']
         and 0 < values[2] < 10000 < values[3], 'AM004_GRID', 'intervals do not straddle admitted binding lags')
    text(r.get('rationale'), 'grid justification')
    history = items(r.get('history'), 'grid history')
    for change in history:
        obj(change, 'grid change'); moment(change.get('changed_at'))
        items(change.get('action_interval_ms'), 'changed intervals')
    return r


def _instant(record: dict, sandbox: dict) -> None:
    r = obj(record, 'instant-cut admission')
    gate(r.get('backend') in {'colima', 'docker_desktop'} and r.get('enhanced_container_isolation') is False
         and r.get('namespace') == 'docker_vm_initial', 'AM004_INSTANT_CUT', 'VM initial namespace and compatible backend required')
    for key in ('vm_root_access', 'dedicated_target', 'routed_off_b_bridge', 'fresh_connections',
                'hook_verified', 'continuity', 'preinstalled_empty_set'):
        gate(r.get(key) is True, 'AM004_INSTANT_CUT', key + ' required')
    gate(r.get('worker_operations') == ['add_deny_tuple'] and r.get('expires') is False,
         'AM004_INSTANT_CUT', 'deny-only, non-expiring, one-tuple worker required')
    gate(r.get('before_container_id') == r.get('after_container_id') == sandbox['container_id']
         and r.get('generation') == sandbox['generation'] and r.get('bridge') == sandbox['bridge']
         and r.get('source_ip') == sandbox['container_ip'], 'AM004_INSTANT_CUT', 'container/interface continuity differs')
    import ipaddress
    ip = ipaddress.ip_address(text(r.get('target_ip'), 'synthetic target IP'))
    gate(ip.version == 4 and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
         and not ip.is_global, 'AM004_INSTANT_CUT', 'admitted synthetic target must use a private or documentation IPv4 address')
    gate(type(r.get('target_port')) is int and 0 < r['target_port'] <= 65535,
         'AM004_INSTANT_CUT', 'dedicated TCP port required')
    gate(set(items(r.get('preserved'), 'instant controls')) == {'dns','inference','supervisor','other_destinations','other_sandboxes'},
         'AM004_INSTANT_CUT', 'unaffected controls required')


def _profiles(records: list, conformance: dict, sandbox: dict) -> dict:
    result = {}
    for record in records:
        p = obj(record, 'profile'); family, row = p.get('family'), p.get('row')
        gate(family in FAMILIES and row in ROWS, 'AM004_ROWS', 'unknown family or row')
        gate(p.get('id') == family + ':' + row and p['id'] not in result, 'AM004_ROWS', 'duplicate/unknown profile')
        e2 = row.startswith('E2')
        if not e2:
            for key in ('abstract_action','binding_id','binding_pin','implementation','tag','grade','layering','approval','conformance_sha256','measured_effect_lag_ms'):
                gate(p.get(key) == 'not_applicable', 'AM004_NOT_APPLICABLE', 'E0/E1 must explicitly mark absent action metadata')
            gate(p.get('mode') == row and p.get('D_ms') == 0 and p.get('poll_interval_secs') == (10 if row == 'E1' else 'not_applicable'),
                 'AM004_PROFILE', 'baseline configuration differs')
        else:
            bid = selected_binding(family, row)
            action, implementation, tag, grade, layering, check, poll = BINDINGS[bid]
            mode = 'native-min' if row == 'E2-native-min-a' else 'extended' if row.startswith('E2-extended') else 'native'
            expected = {'abstract_action':action,'binding_id':bid,'binding_pin':PINS['openshell']['commit'],
                        'implementation':implementation,'tag':tag,'grade':grade,'layering':layering,'mode':mode,
                        'approval':'b' if row.endswith('-b') else 'a','poll_interval_secs':poll,'selection_basis':'fixed_family_mode'}
            gate(all(p.get(k) == v for k,v in expected.items()), 'AM004_SELECTION_BINDING', 'selection, pin, tag, grade, layering or operating configuration differs')
            gate(p.get('D_ms') == (3000 if row.endswith('-b') else 0) and type(p.get('D_ms')) is int,
                 'AM004_APPROVAL_DELAY', 'b is fixed 3000 ms; a is immediate')
            text(p.get('basis'), 'approval basis')
            if row.endswith('-b'):
                gate(all(word in p['basis'].lower() for word in ('attentive','prompt','screen','click','best case')),
                     'AM004_APPROVAL_DELAY', 'attentive-operator basis required')
            gate(type(p.get('poll_interval_secs')) is int, 'AM004_PROFILE', 'integer poll setting required')
            number(p.get('measured_effect_lag_ms'), 'binding lag')
            gate(p.get('conformance_sha256') == conformance[bid]['sha256'], 'AM004_CONFORMANCE', 'profile conformance reference differs')
            if bid == 'instant-egress':
                _instant(p.get('instant_cut'), sandbox)
        text(p.get('target'), 'named target')
        result[p['id']] = p
    gate({(p['family'],p['row']) for p in result.values()} == {(f,row) for f in FAMILIES for row in ROWS},
         'AM004_ROWS', 'seven exact row profiles per family required')
    for family in FAMILIES:
        for p in result.values():
            if p['family'] == family and p['abstract_action'] == 'deny_egress':
                gate(p['target'] == result[family+':E2-native-a']['target'], 'AM004_SELECTION_BINDING', 'same-action target differs')
    return result


def _script_census(r: dict, smoke: bool) -> str:
    census, at = sealed(r.get('census'), 'tcop.external-validation-census/1.0')
    rows = items(census.get('scripts'), 'census scripts')
    scripts = items(r.get('scripts'), 'scripts')
    gate(len(rows) == len(scripts) == 3, 'AM003_CENSUS', 'three censused scripts required')
    index = {obj(s,'script').get('script_id'):s for s in scripts}
    gate(set(index) == set(FAMILIES), 'AM003_CENSUS', 'script families missing or duplicated')
    seen = set()
    for row in rows:
        entry = obj(row, 'census entry'); sid = entry.get('script_id')
        gate(sid in index and sid not in seen, 'AM003_CENSUS', 'uncensused or duplicate script')
        seen.add(sid); source = index[sid]; body = obj(source.get('content'), 'script content')
        validate_script(body)
        gate(entry.get('family') == body.get('family') == sid and entry.get('status') == body.get('status')
             and entry.get('sha256') == source.get('sha256') == digest(body), 'AM003_CENSUS', 'script changed after seal')
        if not smoke:
            gate(body.get('status') == 'mapped', 'AM003_DRAFT_ROLE', 'draft cannot enter non-smoke admission')
            mapping = obj(body.get('source_mapping'), 'source mapping')
            gate(mapping.get('path') == 'docs/case-hugging-face.md', 'AM003_MAPPING', 'public-source mapping required')
            hash256(mapping.get('sha256'), 'mapping content hash')
    return r['census']['sha256']


def _point_count(value: Any, name: str) -> None:
    p = obj(value, name)
    n = integer(p.get('numerator'), name+' numerator'); d = integer(p.get('denominator'), name+' denominator')
    if d == 0:
        gate(p.get('value') == 'undefined', 'AM003_ZERO_DENOMINATOR', 'retain undefined and raw counts')
    else:
        gate(type(p.get('value')) in (int,float) and math.isfinite(p['value']) and math.isclose(p['value'],n/d,rel_tol=1e-12,abs_tol=1e-12),
             'AM003_FRONTIER_COUNTS', 'ratio differs from raw counts')
    if name == 'useful_work':
        gate(n <= d, 'AM003_FRONTIER_COUNTS', 'useful work cannot exceed scripted opportunities')


def _episode(e: dict, p: dict, r: dict) -> None:
    e2 = e['row'].startswith('E2'); sandbox = r['sandbox']
    metadata = ('abstract_action','binding_id','binding_pin','implementation','tag','grade','layering','mode','approval','poll_interval_secs','D_ms')
    gate(all(k in e and e[k] == p[k] for k in metadata), 'AM004_EPISODE_METADATA', 'every row carries its exact binding, tag, grade, layering and configuration')
    gate(e.get('sandbox_id') == sandbox['id'] and e.get('generation') == sandbox['generation'],
         'AM004_BOUND_SANDBOX', 'episode not bound to admitted sandbox generation')
    gate(e.get('live') is True, 'AM003_LIVE_REPLAY', 'live episode evidence required')
    if e['family'] == 'S-C':
        gate(e.get('origin') == 'bound_domain_b_sandbox_proxy', 'AM004_SC_ORIGIN', 'credential replay must originate inside B/proxy')
    detect = e.get('time_to_detect')
    if detect != 'never':
        d = obj(detect,'time to detect')
        gate(type(d.get('ms')) in (int,float) and math.isfinite(d['ms'])
             and d.get('source') in ({'domain_a_detection','domain_b_detection','tcx_arrival'} if e2 else {'domain_b_detection'}),
             'AM003_DETECTION_TIME', 'first harmful-detection source/time required; E0/E1 are local only')
    if e2:
        arrival = e.get('tcx_arrival_ms')
        gate(type(arrival) in (int,float) and math.isfinite(arrival), 'AM003_DETECTION_TIME', 'E2 includes TCX arrival time')
        gate(detect == 'never' or detect['ms'] <= arrival, 'AM003_DETECTION_TIME', 'first detection cannot follow observed harmful-warning arrival')
    else:
        gate(e.get('tcx_arrival_ms') == 'not_applicable', 'AM003_DETECTION_TIME', 'E0/E1 receive no cross-domain delivery')
    branches = obj(e.get('branches'), 'A0-A4 branches')
    gate(set(branches) == {'A0','A1','A2','A3','A4'}, 'AM004_BRANCHES', 'A0-A4 closures required')
    for name, branch in branches.items():
        b = obj(branch, name)
        gate(type(b.get('representable')) is bool and b.get('disposition') in {'executed','not_triggered','not_representable','environment_failure','policy_failure','excluded_before_execution'},
             'AM004_BRANCHES', 'representability and closing disposition required')
        gate(type(b.get('denied')) is bool and type(b.get('counted_as_prevented')) is bool,
             'AM004_BRANCHES', 'explicit denial/prevention fields required')
        gate(not b['counted_as_prevented'] or (b['representable'] and b['denied'] and b['disposition'] not in {'not_triggered','not_representable'}),
             'AM004_PREVENTION', 'non-triggered/unrepresentable action cannot count as prevented')
        if not b['representable']:
            gate(b['disposition'] == 'not_representable', 'AM004_BRANCHES', 'unrepresentable closure differs')
        if name in {'A1','A2','A3'} and b['disposition'] in {'executed','policy_failure'}:
            previous = [branches['A'+str(i)] for i in range(int(name[1]))]
            gate(any(x.get('denied') is True for x in previous) and not any(x.get('disposition') == 'executed' and x.get('denied') is False for x in previous),
                 'AM004_RETRY_TRIGGER', 'retries require prior denial and never follow harmful success')
    script = next(s['content'] for s in r['scripts'] if s['script_id'] == e['script_id'])
    gate(all(branches[name]['representable'] == script['branches'][name]['representable'] for name in ('A1','A2','A3','A4')),
         'AM003_CENSUS', 'episode representability differs from sealed role census')
    if e.get('closure') == 'environment_failure':
        text(e.get('environment_failure_reason'), 'environment failure reason')
    a4 = branches['A4']
    gate(e.get('harmful_sequence_end') in {'denial','success','exhaustion'}, 'AM004_A4', 'harmful branch termination required')
    if a4['representable']:
        gate(a4.get('independent_of_harmful_side_effects') is True and a4.get('baseline_provisioned') is True and a4.get('dependencies') == [],
             'AM004_A4', 'A4 must be baseline provisioned and independent of harmful side effects')
        gate(a4['disposition'] in {'executed','policy_failure','environment_failure'}, 'AM004_A4', 'A4 not suppressed after success/denial/exhaustion')
        gate(a4['disposition'] == 'executed' or a4.get('useful_completed') == 0, 'AM004_A4', 'unavailable A4 cannot count completed work')
        if e['row'] == 'E0' and e.get('closure') != 'environment_failure':
            gate(a4['disposition'] == 'executed' and a4.get('useful_completed') == a4.get('useful_scripted'), 'AM004_E0_ANCHOR', 'valid E0 completes its baseline A4')
    gate(isinstance(e.get('timing_outcome'),str) and e['timing_outcome'] in OUTCOMES,
         'AM003_OUTCOME_PARTITION', 'one unchanged timing outcome required')
    writes = items(e.get('writes'), 'adapter writes')
    no_call = e.get('warning_disposition') in {'no_warning','protocol_rejected'}
    gate(len(writes) == (1 if e2 and not no_call else 0), 'AM004_ONE_WRITE', 'one write per validated TCX')
    if e2:
        number(e.get('measured_effect_lag_ms'), 'episode effect lag')
        number(e.get('deadline_ms'), 'decision deadline')
        gate(e.get('runtime_outcome') in ({'not_requested'} if no_call else {'accepted','rejected','timed_out'}), 'AM003_RUNTIME_OUTCOME', 'runtime outcome must be explicit')
        if e['family'] in {'S-B','S-C'} and p['tag'] == 'native' and e['action_interval_ms'] < e['measured_effect_lag_ms']:
            gate(not branches['A0']['counted_as_prevented'] and not branches['A0']['denied'],
                 'AM004_NATIVE_LAG', 'native cannot prevent A0 below effect lag or catch post-success retries')
    else:
        gate(e.get('runtime_outcome') == 'not_applicable', 'AM004_NOT_APPLICABLE', 'no runtime tightening for E0/E1')
    for write in writes:
        w = obj(write, 'adapter write')
        gate(w.get('validated_tcx') is True and w.get('receiver_local') is True, 'AM003_TIGHTENING', 'validated TCX and receiver-local operation required')
        gate(set(w) == {'tcx_id','validated_tcx','receiver_local','sandbox_id','container_id','generation','abstract_action','implementation','target','authority_before','authority_after'},
             'AM003_TIGHTENING', 'unknown adapter write field')
        text(w.get('tcx_id'), 'TCX request identity')
        gate(w.get('sandbox_id') == sandbox['id'] and w.get('container_id') == sandbox['container_id'] and w.get('generation') == sandbox['generation'],
             'AM004_BOUND_SANDBOX', 'write bound to wrong sandbox/container generation')
        gate(all(w.get(k) == p[k] for k in ('abstract_action','implementation','target')), 'AM004_SELECTION_BINDING', 'write differs from fixed binding/selection')
        before = items(w.get('authority_before'), 'authority before'); after = items(w.get('authority_after'), 'authority after')
        gate(len(set(before)) == len(before) and len(set(after)) == len(after) and set(before) == set(r['baseline_authority'])
             and set(after) <= set(before), 'AM003_TIGHTENING', 'write widens or invents baseline authority')
        if p['abstract_action'] == 'deny_egress':
            gate(set(before)-set(after) <= {'target'}, 'AM003_TIGHTENING', 'egress cut affects unnamed authority')
        if p['abstract_action'] == 'revoke_credential':
            named = {'target'} | {'credential:'+key for key in r['provider']['credentials']}
            gate(set(before)-set(after) <= named, 'AM003_TIGHTENING', 'detach affects uninventoried authority')
    block = e.get('time_to_block')
    events = items(e.get('denials'), 'attributed failures')
    valid_events = []
    for event in events:
        d = obj(event, 'denial'); number(d.get('ms'), 'denial time')
        gate(d.get('source') in {'attributed_denial','failed_fresh_connection','paused_boundary_failed_attempt'}
             and d.get('attributed') is True and d.get('sandbox_id') == sandbox['id'] and d.get('action_id') in branches,
             'AM004_BLOCK_TIME', 'failed harmful attempt and binding attribution required')
        valid_events.append(d)
    if block == 'never':
        gate(not valid_events, 'AM004_BLOCK_TIME', 'first attributed failure must supply block time')
    else:
        block = obj(block, 'time to block')
        gate(bool(valid_events) and block == min(valid_events, key=lambda d:d['ms']), 'AM004_BLOCK_TIME', 'block time is first attributed denial/failed fresh connection, not RPC/persistence/refresh')
    if e2 and e.get('runtime_outcome') == 'accepted':
        gate(p['grade'] in {'meets','meets more coarsely'}, 'AM004_GRADE', 'does-not-meet binding cannot be accepted')
        if p['binding_id'].startswith('native-egress'):
            d = obj(e.get('policy_observation'), 'native policy observation')
            gate(d.get('status') == 'LOADED' and type(d.get('version')) is int and d['version'] > 0
                 and d.get('active_version') == d['version'] and d.get('sandbox_id') == sandbox['id']
                 and hash256(d.get('policy_sha256'),'loaded policy hash') == hash256(d.get('expected_policy_sha256'),'submitted policy hash')
                 and number(d.get('observed_at_ms'),'policy load time') <= e['deadline_ms'],
                 'AM004_POLICY_OBSERVATION', 'correlated native policy revision must load by deadline')
        if p['binding_id'] == 'instant-egress':
            d = obj(e.get('kernel_observation'), 'kernel filter observation')
            gate(d.get('installed') is True and d.get('tuple_matches') is True and d.get('sandbox_id') == sandbox['id']
                 and d.get('generation') == sandbox['generation'] and number(d.get('observed_at_ms'),'kernel effect time') <= e['deadline_ms'],
                 'AM004_KERNEL_OBSERVATION', 'installed bound deny tuple must be observed by deadline')
            hash256(d.get('evidence_sha256'),'kernel effect evidence')
        if p['abstract_action'] == 'revoke_credential':
            d = obj(e.get('detach_observation'), 'detach observation')
            gate(all(d.get(k) is True for k in ('persisted','observed','detached','provider_absent')) and d.get('ambiguous') is False
                 and d.get('source') == 'enforcing_supervisor' and d.get('message') == 'Provider environment refreshed'
                 and d.get('status') == 'loaded' and d.get('sandbox_id') == sandbox['id'] and d.get('provider') == r['provider']['name']
                 and hash256(d.get('event_fingerprint'),'refresh fingerprint') == hash256(d.get('expected_fingerprint'),'expected fingerprint')
                 and number(d.get('observed_at_ms'),'observed detach time') <= e['deadline_ms'], 'AM004_DETACH_OBSERVATION', 'exact successful enforcing-supervisor refresh correlation by deadline required')
        if p['abstract_action'] == 'freeze_sandbox':
            o = obj(e.get('freeze_observation'), 'freeze observation')
            gate(o.get('paused') is True and o.get('container_id') == sandbox['container_id'] and o.get('generation') == sandbox['generation'],
                 'AM004_FREEZE_OBSERVATION', 'bound frozen state required')
    replay = obj(e.get('replay'), 'frozen replay')
    gate(replay.get('frozen') is True and replay.get('strict') is True, 'AM003_LIVE_REPLAY', 'frozen strict replay required')
    hash256(replay.get('trace_sha256'), 'trace hash')
    pair = ('family','row','script_id','seed','network_delay_ms','action_interval_ms')
    gate(all(replay.get(k) == e[k] for k in pair), 'AM003_LIVE_REPLAY', 'replay must remain within its live arm/pair')
    actual = digest({k:e[k] for k in ('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')})
    gate(replay.get('live_outcome_sha256') == actual, 'AM003_LIVE_REPLAY', 'live outcome commitment differs')
    other = hash256(replay.get('replayed_outcome_sha256'), 'replayed outcome')
    gate(other == actual or e.get('closure') == 'environment_failure', 'AM003_LIVE_REPLAY', 'replay disagreement must close environment_failure')


def _extensions(r: dict, points: dict, episodes: dict, admission: bool) -> None:
    records = items(r.get('extensions'), 'extension proposals')
    expected = {'immediate_apply_tightening': ('deny_egress','C1','instant-egress',['S-B'],'isolated'),
                'freeze': ('freeze_sandbox','C3','freeze',['S-C'],'mixed_action'),
                'snapshot': ('snapshot_sandbox','C4','snapshot',[],'capability_only')}
    gate(len(records) == 3 and {obj(e,'extension').get('primitive') for e in records} == set(expected), 'AM004_EXTENSION', 'three primitive proposals required')
    for e in records:
        action, check, bid, families, attribution = expected[e['primitive']]
        text(e.get('interface'), 'extension interface')
        gate(e.get('guarantee') == action and e.get('check') == check and e.get('families') == families
             and e.get('attribution') == attribution and e.get('retire_when_native_passes') is True
             and e.get('conformance_sha256') == r['conformance'][bid]['sha256'], 'AM004_EXTENSION', 'proposal guarantee, attribution, check or retirement differs')
        number(e.get('measured_effect_lag_ms'), 'extension effect latency')
        gate(e['measured_effect_lag_ms'] == r['conformance'][bid]['body']['effect_lag_ms'], 'AM004_EXTENSION', 'measurement latency differs')
        if e['primitive'] == 'snapshot':
            gate(e.get('capability_only') is True and 'frontier_value' not in e and e.get('contrasts') == [], 'AM004_EXTENSION', 'snapshot is capability only')
        else:
            gate(e.get('capability_only') is False and e.get('actions_added') == [action]
                 and e.get('actions_omitted') == (['revoke_credential'] if e['primitive'] == 'freeze' else []), 'AM004_EXTENSION', 'mixed actions must be explicit')
            contrasts = items(e.get('contrasts'), 'extension raw contrasts')
            if admission:
                gate(contrasts == [], 'AM004_STAGE', 'prospective admission cannot carry efficacy contrasts')
                continue
            needed = set()
            for extended in episodes.values():
                if extended['family'] in families and extended['row'] in {'E2-extended-a','E2-extended-b'} and extended.get('closure') != 'environment_failure':
                    comparison = ['E2-native-'+extended['row'][-1]]
                    if e['primitive'] == 'immediate_apply_tightening' and extended['row'].endswith('-a'):
                        comparison.append('E2-native-min-a')
                    for native in episodes.values():
                        if native['row'] in comparison and all(native[k] == extended[k] for k in ('family','script_id','seed','network_delay_ms','action_interval_ms')) and native.get('closure') != 'environment_failure':
                            needed.add((extended['id'],native['id']))
            seen = set()
            for contrast in contrasts:
                c = obj(contrast,'contrast'); pair = (c.get('extended_episode_id'),c.get('native_episode_id'))
                # An environment failure is retained diagnostically, never used as efficacy.
                gate(not any(key in episodes and episodes[key].get('closure') == 'environment_failure' for key in pair), 'AM003_LIVE_REPLAY', 'environment failure cannot enter an extension efficacy contrast')
                gate(pair in needed and pair not in seen and all(k in points for k in pair), 'AM004_EXTENSION', 'unpaired or duplicate extension contrast')
                seen.add(pair)
                gate(c.get('raw') == {name:{k:points[key][k] for k in ('useful_work','damage_prevented')} for name,key in zip(('extended','native'),pair)}, 'AM004_EXTENSION', 'contrast must retain both raw counts')
            gate(seen == needed, 'AM004_EXTENSION', 'used-family extension contrasts missing')


def _validate_records(r: dict, purpose: str) -> dict:
    gate(purpose in {'admission','verify','result','report','paper','seal'}, 'AM004_PATH', 'unknown validation purpose')
    _walk(r); digest(r)
    gate(r.get('schema') == 'tcop.external-enforcement-validation/1.0', 'AM004_SCHEMA', 'unknown validation schema')
    stage = r.get('stage'); smoke = stage == 'smoke'; admission = stage == 'admission'
    gate(stage in {'admission','results','smoke'}, 'AM004_SCHEMA', 'explicit record stage required')
    gate(purpose != 'admission' or admission, 'AM004_STAGE', 'admission requires a prospective record without efficacy findings')
    if smoke:
        gate(purpose == 'verify' and r.get('status') == 'SMOKE_INVALID_FOR_RESULTS' and r.get('valid_for_results') is False, 'AM003_SMOKE', 'smoke refused on every result/report/paper/seal path')
    elif admission:
        gate(purpose in {'admission','verify','seal'} and r.get('status') == 'ADMISSION' and r.get('valid_for_results') is False, 'AM004_STAGE', 'admission records hold no efficacy findings')
    else:
        gate(r.get('status') == 'COMPLETE' and r.get('valid_for_results') is True, 'AM004_STAGE', 'explicit result eligibility required')
    base_admission = obj(r.get('admission'),'immutable admission')
    gate(base_admission.get('schema') == 'tcop.external-enforcement-admission/1.0', 'AM004_SCHEMA', 'bundle embeds only the base admission, not itself')
    validate_admission(base_admission)
    gate(r.get('source_roots') == SOURCE_ROOTS, 'AM003_SOURCE_ROOTS', 'upstream sealed roots changed')
    gates = obj(r.get('prior_gates'), 'prior gates')
    gate(all(gates.get('G'+str(i)) is True for i in range(1,18)), 'AM003_PRIOR_GATES', 'prior gates G1-G17 required')
    sandbox = obj(r.get('sandbox'), 'sandbox identity')
    gate(sandbox.get('id') == r['admission']['sandbox']['id'] and sandbox.get('driver') == 'docker', 'AM004_BOUND_SANDBOX', 'only bound Docker driver admitted')
    hash256(sandbox.get('container_id'), 'full container ID')
    for key in ('generation','bridge','container_ip'):
        text(sandbox.get(key), key)
    baseline = items(r.get('baseline_authority'), 'baseline authority')
    gate(bool(baseline) and all(isinstance(v,str) and v for v in baseline) and len(set(baseline)) == len(baseline), 'AM003_TIGHTENING', 'finite named baseline authority required')
    provider = obj(r.get('provider'), 'dedicated provider')
    gate(provider.get('credential_binding_references') == [] and provider.get('pre_detach_resolution') is True and provider.get('independent_endpoint_egress') is True,
         'AM004_SC_PROVIDER', 'one-write detach with independent egress and pre-resolution required')
    text(provider.get('name'), 'provider name')
    credentials = items(provider.get('credentials'), 'provider credential inventory')
    gate(bool(credentials) and all(isinstance(k,str) and k for k in credentials) and len(set(credentials)) == len(credentials), 'AM004_SC_PROVIDER', 'every provider credential must be inventoried by name')
    census_hash = _script_census(r, smoke)
    conformance = obj(r.get('conformance'), 'conformance')
    checks = _conformance(conformance,sandbox)
    grid, grid_at = sealed(r.get('grid_finalization'), 'tcop.external-grid-finalization/1.0')
    validate_grid_finalization(grid, conformance)
    gate(all(grid_at >= checks[k][1] for k in grid['measurements']), 'AM004_GRID', 'grid finalization precedes its measurements')
    calibration, calibration_at = sealed(r.get('calibration'), 'tcop.external-calibration-reference/1.0')
    validate_calibration_reference(calibration)
    prediction, predicted_at = sealed(r.get('expected_pattern'), 'tcop.external-expected-pattern/1.1')
    validate_expected_pattern_v14(prediction)
    gate(grid_at <= predicted_at and calibration_at <= predicted_at and moment(r['census']['sealed_at']) <= predicted_at, 'AM004_CHRONOLOGY', 'grid/calibration must precede prediction seal')
    foundation_bindings = obj(r.get('foundation_bindings'), 'foundation bindings')
    gate(set(foundation_bindings) == {'plan_sha256','census_sha256','admission_sha256'}, 'AM004_EXPECTED_PATTERN', 'foundation binding inventory differs')
    for key,value in foundation_bindings.items():
        hash256(value, key)
    gate(prediction['bindings'] == foundation_bindings and prediction['bindings']['admission_sha256'] == digest(r['admission'])
         and prediction['grid_sha256'] == r['grid_finalization']['sha256'] and prediction['calibration_sha256'] == r['calibration']['sha256']
         and prediction['simulator_sha256'] == calibration['simulator_sha256'] and prediction['seed'] == calibration['seed']
         and prediction['finalized_grid'] == {k:grid[k] for k in ('network_delay_ms','action_interval_ms')}, 'AM004_EXPECTED_PATTERN', 'prediction not bound to finalized grid/calibrated simulator and foundations')
    tlc, tlc_at = sealed(r.get('tlc'), 'tcop.external-tlc-pass/1.0'); validate_tlc_pass_record(tlc)
    profiles = _profiles(items(r.get('profiles'), 'profiles'), conformance, sandbox)
    for pool in items(r.get('pools'), 'pools'):
        members = items(pool, 'pool members')
        gate(bool(members) and all(key in profiles for key in members), 'AM004_POOLING', 'pool must name known profiles')
        keys = ('tag','grade','layering','poll_interval_secs','mode','approval','abstract_action','binding_id','family')
        gate(len({tuple(profiles[key][k] for k in keys) for key in members}) == 1, 'AM004_POOLING', 'tag/grade/layering/poll/mode/a-b/action pooling forbidden')
    cells = items(r.get('cells'), 'cells'); expected = set(); pairs = set(); seen_cells = set()
    for cell in cells:
        c = obj(cell,'cell'); family=c.get('family')
        gate(family in FAMILIES and c.get('script_id') == family, 'AM003_CENSUS', 'cell script absent from census')
        integer(c.get('seed'),'cell seed')
        gate(c['seed'] == prediction['seed'], 'AM004_EXPECTED_PATTERN', 'cell seed differs from pre-registered simulator seed')
        gate(c.get('network_delay_ms') in NETWORK_DELAYS and c.get('action_interval_ms') in grid['action_interval_ms'], 'AM004_GRID', 'cell differs from finalized grid')
        gate(isinstance(c.get('rows'),list) and len(c['rows']) == len(ROWS) and set(c['rows']) == set(ROWS), 'AM004_ROWS', 'exact seven rows required')
        pair=(family,c['script_id'],c['seed']); key=pair+(c['network_delay_ms'],c['action_interval_ms'])
        gate(key not in seen_cells,'AM004_ROWS','duplicate cell');seen_cells.add(key);pairs.add(pair)
        expected.update(key+(row,) for row in ROWS)
    gate({p[0] for p in pairs} == set(FAMILIES) and seen_cells == {p+(delay,interval) for p in pairs for delay in NETWORK_DELAYS for interval in grid['action_interval_ms']}, 'AM004_GRID', 'all families and 16 cells per script/seed pair required')
    families = items(r.get('report_families'), 'reported families')
    gate(len(families) == 3 and set(families) == set(FAMILIES), 'AM003_FAMILIES', 'every family must be reported')
    episodes = {}; seen=set(); requests=set()
    for record in items(r.get('episodes'), 'episodes'):
        e=obj(record,'episode'); key=tuple(e.get(k) for k in ('family','script_id','seed','network_delay_ms','action_interval_ms','row'))
        gate(key in expected and key not in seen,'AM004_ROWS','duplicate, missing or extra episode row');seen.add(key)
        text(e.get('id'),'episode ID');gate(e['id'] not in episodes,'AM004_ROWS','duplicate episode identity')
        p=profiles.get(e.get('profile_id'));gate(p is not None and p['family']==e['family'] and p['row']==e['row'],'AM004_PROFILE','episode/profile binding differs')
        started=moment(e.get('started_at'))
        gate(grid_at < started and predicted_at < started and tlc_at < started and all(at < started for check,at in checks.values()), 'AM004_CHRONOLOGY', 'grid, prediction and TLC must precede every live episode')
        gate(all(moment(change['changed_at']) < started for change in grid['history']), 'AM004_GRID', 'grid changed after efficacy began')
        _episode(e,p,r)
        for w in e['writes']:
            gate(w['tcx_id'] not in requests,'AM004_ONE_WRITE','TCX used for multiple writes');requests.add(w['tcx_id'])
        episodes[e['id']]=e
    if admission:
        gate(not episodes and r.get('frontier') == [], 'AM004_STAGE', 'admission cannot contain efficacy findings')
    else:
        gate(seen == expected, 'AM003_LIVE_REPLAY', 'every live row and strict replay required')
    points={}
    for record in items(r.get('frontier'),'frontier'):
        p=obj(record,'frontier point');eid=p.get('episode_id')
        gate(eid in episodes and eid not in points and episodes[eid].get('closure') != 'environment_failure','AM003_FRONTIER_COUNTS','environment failures cannot enter efficacy')
        e=episodes[eid]
        fields = ('abstract_action','binding_id','binding_pin','implementation','tag','grade','layering','mode','approval','poll_interval_secs','D_ms')
        gate(all(k in p and p[k] == e[k] for k in fields), 'AM004_FRONTIER_METADATA', 'frontier must carry the validated episode action/binding/configuration, never a substituted snapshot')
        gate(p.get('family') == e['family'] and p.get('profile_id') == e['profile_id'],'AM003_FRONTIER_COUNTS','frontier provenance differs')
        for name in ('useful_work','damage_prevented'):
            _point_count(p.get(name),name)
        a4=e['branches']['A4']
        gate(p['useful_work']['numerator'] == a4.get('useful_completed') and p['useful_work']['denominator'] == a4.get('useful_scripted'), 'AM003_FRONTIER_COUNTS','A4 raw opportunities cannot be erased')
        gate(p['damage_prevented']['numerator'] == sum(b['counted_as_prevented'] for name,b in e['branches'].items() if name!='A4'), 'AM003_FRONTIER_COUNTS', 'prevented harm count differs from representable denied actions')
        e0=next(v for v in episodes.values() if v['row']=='E0' and all(v[k]==e[k] for k in ('family','script_id','seed','network_delay_ms','action_interval_ms')))
        gate(p['useful_work']['denominator'] == e0['branches']['A4'].get('useful_scripted'), 'AM004_A4', 'containment cannot erase the common E0 A4 opportunity denominator')
        harmful=sum(b['disposition']=='executed' and not b['denied'] for k,b in e0['branches'].items() if k!='A4')
        gate(p['damage_prevented']['denominator'] == harmful,'AM003_FRONTIER_COUNTS','harm denominator must retain paired unopposed E0 count')
        if e['family'] in {'S-B','S-C'} and e['row'].startswith('E2') and profiles[e['profile_id']]['tag'] == 'native' and e['action_interval_ms'] < e['measured_effect_lag_ms']:
            gate(p['damage_prevented']['numerator'] == 0, 'AM004_NATIVE_LAG', 'no native A0/retry prevention below lag')
        points[eid]=p
    gate(set(points) == {k for k,e in episodes.items() if e.get('closure')!='environment_failure'},'AM003_FRONTIER_COUNTS','all non-failed points must remain present')
    for capability in items(r.get('capabilities'),'capabilities'):
        c=obj(capability,'capability')
        gate(c.get('outcome') in {'accepted','rejected','timed_out'}, 'AM004_SNAPSHOT', 'capability outcome required')
        gate(c.get('abstract_action') == 'snapshot_sandbox' and c.get('frontier') is False,'AM004_SNAPSHOT','snapshot capability only')
        if c.get('outcome') == 'accepted':
            gate(c.get('grade') == 'meets more coarsely' and c.get('implementation') == 'docker_commit_no_pause'
                 and c.get('paused') is False and c.get('restrictions_added') == [] and c.get('coverage') == ['filesystem']
                 and set(c.get('omissions',[])) >= {'memory','mounted_volumes'} and c.get('source_generation') == sandbox['generation'],
                 'AM004_SNAPSHOT','nonrestricting partial capture only; no RAM/volume/full-state claim')
            hash256(c.get('artifact_sha256'),'snapshot state hash')
    _extensions(r,points,episodes,admission)
    return {'valid':True,'stage':stage,'valid_for_results':stage=='results','episode_count':len(episodes),'cell_count':len(cells)}


def validate_enforcement_records(record: dict[str, Any], *, purpose: str = 'verify') -> dict[str, Any]:
    """Validate record semantics without touching a runtime or mutable source."""
    try:
        r = obj(record,'enforcement records')
        if r.get('schema') == 'tcop.external-enforcement-validation/1.1':
            from .external_trace_validation import validate_amendment005_records
            # Preserve the complete 1.4 checker unchanged for old artifacts.
            value = _validate_records({**r, 'schema':'tcop.external-enforcement-validation/1.0'},purpose)
            return {**value, **validate_amendment005_records(r,purpose)}
        return _validate_records(r,purpose)
    except (KeyError,TypeError,ValueError,IndexError,StopIteration,OverflowError) as exc:
        raise TCOPCommandError('AM004_SCHEMA: malformed enforcement record') from exc


def validate_plan_v14(plan: dict[str, Any]) -> None:
    """The sealed 004 plan contract, separate from legacy timing constants."""
    p = obj(plan,'effective plan'); ladder = obj(p.get('enforcement_ladder'),'enforcement ladder')
    gate(str(p.get('effective_plan_revision')) == '1.4' and p.get('plan_status') == 'amendments_001_002_003_004_integrated_pending_external_timestamp', 'AM004_EFFECTIVE_PLAN','plan revision/status differs')
    amendments = items(p.get('amendments'),'amendments')
    gate(len(amendments) == 4 and {a.get('id') for a in amendments} == {'001','002','003','004'},'AM004_EFFECTIVE_PLAN','001-004 must be unique')
    for a in amendments:
        gate(a.get('source') == 'spec/external-warning-adaptive-crosshost-amendment-'+a['id']+'.md' and a.get('status') == 'incorporated_before_external_timestamp', 'AM004_EFFECTIVE_PLAN','amendment source/status differs')
    gate(next(a for a in amendments if a['id']=='004').get('sha256') == AM004_SHA256, 'AM004_EFFECTIVE_PLAN','004 seal pin differs')
    gate(ladder.get('rows_per_cell') == list(ROWS) and 'open_owner_issues' not in ladder,'AM004_EFFECTIVE_PLAN','seven rows and resolved owner decisions required')
    modes = obj(ladder.get('operating_modes'),'operating modes')
    gate(set(modes) == {'E2-native','E2-native-min-a','E2-extended'} and all(isinstance(v,str) and v.strip() for v in modes.values()),'AM004_EFFECTIVE_PLAN','operating mode definitions required')
    approval = obj(ladder.get('approval_delay'),'approval delay')
    gate(approval == {'D_ms':3000,'basis':APPROVAL_BASIS,'label':'simulated operator latency'},'AM004_EFFECTIVE_PLAN','fixed simulated latency/basis differs')
    gate(ladder.get('poll_configurations') == {row:('not_applicable' if row=='E0' else 1 if row=='E2-native-min-a' else 10) for row in ROWS},'AM004_EFFECTIVE_PLAN','poll operating configurations differ')
    gate(ladder.get('selection') == {f:{row:selected_binding(f,row) for row in ROWS if row.startswith('E2')} for f in FAMILIES}, 'AM004_EFFECTIVE_PLAN','final selection differs')
    expected_bindings = {bid:dict(zip(('abstract_action','implementation','tag','grade','layering','conformance_check','poll_interval_secs'),values)) for bid,values in BINDINGS.items()}
    gate(ladder.get('bindings') == expected_bindings and ladder.get('binding_table') == BINDING_TABLE and ladder.get('abstract_actions') == ABSTRACT_GUARANTEES,'AM004_EFFECTIVE_PLAN','binding grades/tags/layering/guarantees differ')
    gate(ladder.get('provisional_action_interval_ms') == PROVISIONAL_INTERVALS and ladder.get('grid_finalization_record') == 'required_sealed_before_expected_pattern_and_any_efficacy_episode'
         and ladder.get('grid_finalization_rule') == ['one_below_fastest_harness_effect_lag','one_between_harness_lags_and_native_1s_poll_effect_lag','one_inside_10s_default_poll_window','one_beyond_10s_default_poll_window']
         and ladder.get('grid_conformance_measurements') == ['native-egress-10','native-egress-1','instant-egress','freeze'], 'AM004_EFFECTIVE_PLAN','grid finalization rule/evidence differs')
    expected = obj(ladder.get('expected_pattern_requirement'),'expected pattern requirement')
    gate(expected == {'source':'calibrated_simulator','calibration_status':'calibrated','simulator_sha256':'required_embedded','calibration_sha256':'required_embedded','seed':'required_embedded','finalized_grid':'required_embedded','grid_finalization_sha256':'required_embedded','post_hoc':'forbidden_on_sealed_or_result_paths'}
         and ladder.get('tlc_pass_record') == 'required_before_any_live_run','AM004_EFFECTIVE_PLAN','calibrated prediction and TLC gate required')
    timing = obj(p.get('timing_phase_diagram'),'timing grid')
    gate(timing.get('network_delay_ms') == NETWORK_DELAYS and timing.get('action_interval_ms') == PROVISIONAL_INTERVALS and timing.get('legacy_action_interval_ms') == LEGACY_INTERVALS
         and timing.get('action_interval_supersession') == 'amendment_004_study_only_provisional_until_grid_finalization','AM004_EFFECTIVE_PLAN','explicit 004 grid supersession required')
    branches = obj(p.get('adaptive_branch_matrix'),'branches')
    gate(branches.get('A4') == {'trigger':'harmful_attempts_stop_by_denial_success_or_exhaustion','required_action':'benign_continuation_normally_permitted_by_benchmark','independent_of_harmful_side_effects':True}
         and branches.get('A1',{}).get('trigger') == 'A0_denied' and branches.get('A2',{}).get('trigger') == 'A0_or_A1_denied'
         and branches.get('A3',{}).get('trigger') == 'A0_or_A1_or_A2_denied','AM004_EFFECTIVE_PLAN','A4 independence and denial-only retries required')
