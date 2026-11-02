#!/usr/bin/env python3
"""Convert and exhaustively check complete frozen receiver traces (stdlib only)."""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
import hashlib
import json
import re
import subprocess
import time
from tooling import FORMAL, JAVA, checked_tools, sha256, tlc_stats

KINDS = ('deny_egress', 'revoke_credential', 'freeze')


class Malformed(ValueError):
    def __init__(self, message, index=None):
        super().__init__(message)
        self.index = index


def schema_check(value, schema, root, path='$'):
    """Validate every keyword used by our closed, local JSON schema."""
    if '$ref' in schema:
        ref = root
        for key in schema['$ref'][2:].split('/'):
            ref = ref[key]
        return schema_check(value, ref, root, path)
    if 'oneOf' in schema:
        count = 0
        for variant in schema['oneOf']:
            try:
                schema_check(value, variant, root, path)
                count += 1
            except Malformed:
                pass
        if count != 1:
            raise Malformed(f'{path}: expected exactly one schema variant')
    tests = {'object': lambda v: type(v) is dict, 'array': lambda v: type(v) is list,
             'string': lambda v: type(v) is str, 'integer': lambda v: type(v) is int,
             'boolean': lambda v: type(v) is bool, 'null': lambda v: v is None}
    if 'type' in schema and not tests[schema['type']](value):
        raise Malformed(f'{path}: expected {schema["type"]}')
    if 'const' in schema and value != schema['const']:
        raise Malformed(f'{path}: incorrect constant')
    if 'enum' in schema and value not in schema['enum']:
        raise Malformed(f'{path}: unknown enum value')
    if type(value) is int and 'minimum' in schema and value < schema['minimum']:
        raise Malformed(f'{path}: below minimum')
    if type(value) is str and 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
        raise Malformed(f'{path}: invalid identifier')
    if type(value) is dict:
        for key in schema.get('required', []):
            if key not in value:
                raise Malformed(f'{path}: missing {key}')
        props = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(props):
            raise Malformed(f'{path}: unknown fields {sorted(set(value)-set(props))}')
        for key, child in value.items():
            if key in props:
                schema_check(child, props[key], root, f'{path}.{key}')
    if type(value) is list:
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', sys.maxsize):
            raise Malformed(f'{path}: wrong array length')
        if schema.get('uniqueItems') and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            raise Malformed(f'{path}: duplicate array entries')
        prefix = schema.get('prefixItems', [])
        for i, child in enumerate(value):
            if i < len(prefix):
                schema_check(child, prefix[i], root, f'{path}[{i}]')
            elif schema.get('items') is False:
                raise Malformed(f'{path}: extra array entry')
            elif isinstance(schema.get('items'), dict):
                schema_check(child, schema['items'], root, f'{path}[{i}]')


def closed_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Malformed(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load_trace(path):
    data = json.loads(path.read_text(), object_pairs_hook=closed_json,
                      parse_constant=lambda x: (_ for _ in ()).throw(Malformed(f'nonfinite JSON: {x}')))
    schema = json.loads((FORMAL / 'trace-v1.schema.json').read_text())
    schema_check(data, schema, schema)
    p = data['parameters']
    caps = {('egress', x) for x in p['destinations']} | {('credential', x) for x in p['credentials']} | {('work', 'benign')}
    choices = {('deny_egress', x) for x in p['destinations']} | {('revoke_credential', x) for x in p['credentials']} | {('freeze', 'sandbox')}
    if p['primary_destination'] not in p['destinations'] or p['primary_credential'] not in p['credentials']:
        raise Malformed('primary target absent from declared domain')
    if any(p['min_lag'][k] > p['max_lag'][k] for k in KINDS):
        raise Malformed('minimum lag exceeds maximum lag')
    if not {tuple(x) for x in data['initial_authority']} <= caps:
        raise Malformed('unmappable initial authority capability')
    messages, envelopes = {}, []
    previous = 0
    for i, event in enumerate(data['events']):
        if event['t'] < previous:
            raise Malformed('timestamps must be nondecreasing; list order resolves ties', i)
        previous = event['t']
        if not {tuple(x) for x in event['authority']} <= caps:
            raise Malformed('unmappable authority capability', i)
        if event['type'] == 'receive':
            if event['message'] in messages:
                raise Malformed('delivery key must be unique; replay the observation ID/nonce instead', i)
            messages[event['message']] = len(messages) + 1
            correlated = (event['receipt_verified'] and event['receipt_receiver_local']
                          and event['interaction_id'] is not None
                          and event['interaction_id'] == event['receipt_interaction_id'])
            envelopes.append(dict(id=event['observation_id'], nonce=event['nonce'],
                                  signed=event['signature_valid'], authorized=event['peer_authorized'],
                                  correlated=correlated, expires=event['expires_at'], lie=False))
            if event['selected'] is not None and tuple(event['selected']) not in choices:
                raise Malformed('unmappable selected tightening', i)
        elif event['type'] in ('submit', 'effect') and event['message'] not in messages:
            raise Malformed('submission/effect has no preceding delivery key', i)
        if event['type'] == 'attempt' and tuple(event['capability']) not in caps:
            raise Malformed('unmappable attempt capability', i)
        if event['type'] == 'end' and i != len(data['events']) - 1:
            raise Malformed('end must be the last event', i)
    if data['events'][-1]['type'] != 'end':
        raise Malformed('complete episode must have a final end event', len(data['events'])-1)
    if len(messages) > 7:
        raise Malformed('this model instance supports at most 7 evidence deliveries')
    horizon = 4*p['action_interval'] + p['receive_until'] + p['approval_delay'] + max(p['max_lag'].values()) + 1
    if previous > horizon:
        raise Malformed('event beyond this model instance horizon', len(data['events'])-1)
    return data, messages, envelopes, horizon


def tla(value):
    if value is True: return 'TRUE'
    if value is False: return 'FALSE'
    if type(value) is int: return str(value)
    if type(value) is str: return json.dumps(value, ensure_ascii=True)
    if type(value) is list: return '<<' + ', '.join(tla(v) for v in value) + '>>'
    if type(value) is dict: return '[' + ', '.join(f'{k} |-> {tla(v)}' for k,v in value.items()) + ']'
    raise TypeError(type(value))


def tla_set(values):
    return '{' + ', '.join(tla(x) for x in values) + '}'


def generate(data, messages, envelopes, directory):
    records = []
    for e in data['events']:
        r = dict(kind=e['type'], t=e['t'], m=messages.get(e.get('message'), 0),
                 decision=e.get('decision', ''), selected=e.get('selected') or ['none','none'],
                 action=int(e['action'][1]) if 'action' in e else 0,
                 cap=e.get('capability', ['none','none']), authorized=e.get('authorized', False),
                 denied=e.get('denied', False), executed=e.get('executed', False))
        # Sets are represented directly rather than as sequences.
        records.append(tla(r)[:-1] + ', authority |-> ' + tla_set(e['authority']) + ']')
    module = ('---------------- MODULE FrozenTrace ----------------\nEXTENDS TCOPTrace\n'
              + 'InputEvents == <<\n' + ',\n'.join(records) + '\n>>\n'
              + 'InputEnvelopes == ' + tla(envelopes) + '\n'
              + 'InputInitialAuthority == ' + tla_set(data['initial_authority']) + '\n'
              + '====================================================\n')
    p = data['parameters']
    constants = dict(Destinations=tla_set(p['destinations']), Credentials=tla_set(p['credentials']),
                     PrimaryDest=tla(p['primary_destination']), PrimaryCredential=tla(p['primary_credential']),
                     MinLag=tla(p['min_lag']), MaxLag=tla(p['max_lag']), ActionInterval=str(p['action_interval']),
                     ApprovalDelay=str(p['approval_delay']), BaselineDeniesA0=tla(p['baseline_denies_a0']),
                     A0Kind=tla(p['a0_kind']), ReadyAtEmission='FALSE', MaxMessages=str(max(1, len(messages))),
                     ReceiveUntil=str(p['receive_until']))
    # Function-valued constants need function syntax, not record syntax.
    for field, source in [('MinLag','min_lag'), ('MaxLag','max_lag')]:
        constants[field] = '(' + ' @@ '.join(f'({tla(k)} :> {p[source][k]})' for k in KINDS) + ')'
    # :> and @@ are defined by TLC (already extended in the base module).
    cfg = 'SPECIFICATION TraceSpec\nCONSTANTS\n' + ''.join(f'  {k} = {v}\n' for k,v in constants.items())
    cfg += '''  LocalChoices <- Tightenings
  TraceEvents <- InputEvents
  TraceEnvelopes <- InputEnvelopes
  TraceInitialAuthority <- InputInitialAuthority
  Messages <- TraceMessageSet
  Msg <- TraceMsg
INVARIANT TypeOK
INVARIANT AcceptOnlyValid
INVARIANT LadderOrder
INVARIANT A4Independent
INVARIANT EffectInstalled
INVARIANT TimingClaim
INVARIANT TraceReport
PROPERTY NoWidening
PROPERTY EffectHolds
PROPERTY LyingPeerOnlyCostsAvailability
'''
    # TLC config values do not accept expressions; define every value in TLA.
    defs = []
    cfg_lines = []
    for line in cfg.splitlines():
        match = re.match(r'  (\w+) = (.*)', line)
        if match:
            key, val = match.groups()
            defs.append(f'Input{key} == {val}')
            cfg_lines.append(f'  {key} <- Input{key}')
        else:
            cfg_lines.append(line)
    module = module.replace('====================================================', '\n'.join(defs)+'\n====================================================')
    (directory / 'FrozenTrace.tla').write_text(module)
    (directory / 'FrozenTrace.cfg').write_text('\n'.join(cfg_lines)+'\n')


def validate_one(path, out_root, bfs=False, timeout=120, fixture=False):
    raw_hash = sha256(path)
    directory = out_root / (path.stem + '-' + raw_hash[:12])
    directory.mkdir(parents=True, exist_ok=True)
    record = dict(schema_version='tcop.trace-result/1', input_kind='fixture' if fixture else 'frozen_trace', trace_file=str(path.resolve()),
                  trace_sha256=raw_hash, spec_sha256=sha256(FORMAL/'tla/TCOPReceiver.tla'),
                  trace_spec_sha256=sha256(FORMAL/'tla/TCOPTrace.tla'),
                  converter_sha256=sha256(Path(__file__)), trace_schema_sha256=sha256(FORMAL/'trace-v1.schema.json'),
                  pinned_tools_record_sha256=sha256(FORMAL/'pinned-tools.json'),
                  mode='bfs' if bfs else 'dfid', first_rejected_step_index=None,
                  first_rejected_record=None, tlc_stats=None)
    data = None
    try:
        data, messages, envelopes, horizon = load_trace(path)
        generate(data, messages, envelopes, directory)
        record['generated_module_sha256'] = sha256(directory/'FrozenTrace.tla')
        record['generated_config_sha256'] = sha256(directory/'FrozenTrace.cfg')
        record['pinned_tools_record_sha256'] = checked_tools()
        command = [JAVA, '-XX:+UseParallelGC', '-DTLA-Library='+str(FORMAL/'tla'),
                   '-cp', str(FORMAL/'tools/tla2tools.jar'), 'tlc2.TLC',
                   '-workers', 'auto' if bfs else '1', '-fp', '0']
        if not bfs:
            command += ['-dfid', str(horizon + len(data['events']) + 4)]
        command += ['-metadir', str(directory/'states'), '-config', str(directory/'FrozenTrace.cfg'), str(directory/'FrozenTrace.tla')]
        record['command'] = command
        start = time.monotonic()
        run = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout)
        record['seconds'] = round(time.monotonic()-start, 3)
        record['exit_code'] = run.returncode
        (directory/'tlc.log').write_text(run.stdout)
        record['tlc_stats'] = tlc_stats(run.stdout)
        reached = [int(x) for x in re.findall(r'<<"TCOP_TRACE_REACHED", (\d+)>>', run.stdout)]
        complete = run.returncode == 0 and 'Model checking completed. No error has been found.' in run.stdout
        if not complete:
            # A contradictory initial projection is a rejected initial record.
            if 'No states satisfying init predicate' in run.stdout:
                record.update(outcome='rejected', first_rejected_step_index=-1,
                              first_rejected_record={'initial_authority':data['initial_authority']},
                              reason='Initial authority does not match the admitted baseline')
            else:
                record.update(outcome='tool_error', reason='TLC did not complete an exhaustive check; see tlc.log')
        elif reached and max(reached) == len(data['events']):
            record.update(outcome='accepted', reached_events=max(reached))
        else:
            index = max(reached) if reached else -1
            rejected = data['events'][index] if index >= 0 else {'initial_authority':data['initial_authority']}
            record.update(outcome='rejected', reached_events=max(reached) if reached else 0,
                          first_rejected_step_index=index, first_rejected_record=rejected,
                          reason='No TCOPReceiver behavior extends this prefix through the next record')
    except (Malformed, json.JSONDecodeError, UnicodeError) as exc:
        index = getattr(exc, 'index', None)
        # Keep the raw input immutable. For schema errors, recover the event path if available.
        if index is None:
            match = re.search(r'events\[(\d+)\]', str(exc))
            if match: index = int(match.group(1))
        if data is None:
            try:
                data = json.loads(path.read_text(), object_pairs_hook=closed_json)
            except (ValueError, UnicodeError):
                data = None
        rejected = data['events'][index] if isinstance(data, dict) and index is not None and isinstance(data.get('events'), list) and 0 <= index < len(data['events']) else None
        record.update(outcome='malformed', reason=str(exc), first_rejected_step_index=index,
                      first_rejected_record=rejected)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        record.update(outcome='tool_error', reason=str(exc))
    if record['outcome'] == 'rejected' and not fixture:
        (directory/'FINDING.md').write_text(
            '# Frozen trace rejected by the receiver contract\n\n'
            + f"Trace: `{path.resolve()}`\nTrace SHA-256: `{raw_hash}`\n\n"
            + f"First rejected event index (zero-based): {record['first_rejected_step_index']}\n\n"
            + record['reason'] + '\n\n```json\n'
            + json.dumps(record['first_rejected_record'], indent=2) + '\n```\n\n'
            + 'Preserve this trace and the result. Investigate the receiver, binding, '
              'exporter, or model-code assumption; do not repair the trace or weaken a property.\n')
    (directory/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='one trace JSON file or a directory (recursive *.json)')
    parser.add_argument('--output-dir', type=Path, default=FORMAL/'traces/results')
    parser.add_argument('--bfs', action='store_true', help='use BFS outside the sandbox; default DFID')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if not out.is_relative_to(FORMAL.resolve()):
        parser.error('output directory must be under formal/')
    paths = sorted(args.input.rglob('*.json')) if args.input.is_dir() else [args.input]
    if args.input.is_dir() and out.is_relative_to(args.input.resolve()):
        parser.error('output directory must not be inside the input directory')
    if not paths:
        parser.error('no frozen trace JSON files found')
    results = []
    for path in paths:
        record = validate_one(path, out, args.bfs, args.timeout)
        results.append(record)
        print(json.dumps(record), flush=True)
    out.mkdir(parents=True, exist_ok=True)
    (out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
    return 0 if all(r['outcome']=='accepted' for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
