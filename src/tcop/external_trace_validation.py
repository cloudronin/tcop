"""Pure amendment 005 admission/trace record gates. Never invokes TLC or a runtime."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import base64
import math

from .external_foundation_seals import digest, hash256, obj, require, text, _parse_json
from .external_enforcement_validation import gate, moment, sealed, number, integer

AM005_SHA256 = '3b45fef22a9b00cff1a3e001db07404a10a396445620d7c8298459e672cdd22b'
PINNED_TOOLS_SHA256 = '9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e'
GRID_RULE = 'half-fastest-harness; midpoint-slowest-harness/min-native; midpoint-min-native/default-window; twice-beyond-default'
CONVENTIONS = {
    'time_origin':'domain_a_warning_stimulus', 'a0_at':'action_interval_after_origin',
    'ties':'against_e2_computed_only_preserve_observed_outcomes',
    'decision_deadline':'validated_request_ready_ms + D_ms + 20000',
    'no_change':{'family':'S-A','decision':'rejected','reason':'no_change','e2_prevention':0},
    'grid':{'rule':GRID_RULE,'sample_count':1024,'reference_interface_delay_ms':10,
            'families':['S-B','S-C'],'transition':'smallest_representable_interval_with_probability_a0_denied_at_least_half',
            'inseparable':'owner_decides_before_efficacy_never_silently_move'},
    'trace_validation':'every_frozen_trace_smoke_and_live_every_row',
    'pinned_tools_record_sha256':PINNED_TOOLS_SHA256,
    'frozen_inputs':'sealed_before_first_live_episode_immutable_after',
    'smoke_rejection':'blocks_live_until_owner_resolution',
}


def plan_v14_projection(plan):
    p=deepcopy(plan)
    p['effective_plan_revision']='1.4';p['plan_status']='amendments_001_002_003_004_integrated_pending_external_timestamp'
    p['amendments']=[a for a in p.get('amendments',[]) if isinstance(a,dict) and a.get('id')!='005']
    return p


def validate_plan_v15(plan):
    from .external_enforcement_validation import validate_plan_v14
    p=deepcopy(obj(plan,'plan 1.5'))
    gate(str(p.get('effective_plan_revision'))=='1.5' and p.get('plan_status')=='amendments_001_002_003_004_005_integrated_pending_external_timestamp', 'AM005_EFFECTIVE_PLAN','plan revision/status differs')
    entries=p.get('amendments',[])
    gate(isinstance(entries,list) and len(entries)==5 and all(isinstance(a,dict) for a in entries) and {a.get('id') for a in entries}=={'001','002','003','004','005'},'AM005_EFFECTIVE_PLAN','001-005 required exactly once')
    a=next(a for a in entries if a['id']=='005')
    gate(a=={'id':'005','source':'spec/external-warning-adaptive-crosshost-amendment-005.md','status':'incorporated_before_external_timestamp','sha256':AM005_SHA256},'AM005_EFFECTIVE_PLAN','005 source/status/seal pin differs')
    gate(obj(p.get('enforcement_ladder'),'enforcement ladder').get('amendment_005')==CONVENTIONS,'AM005_EFFECTIVE_PLAN','005 intake/trace/timing/grid conventions required')
    validate_plan_v14(plan_v14_projection(p))


def validate_intake_events(events, *, seen_ids=None, seen_nonces=None):
    """Reconstruct replay state, never trust an exported freshness verdict."""
    ids=set() if seen_ids is None else seen_ids; nonces=set() if seen_nonces is None else seen_nonces; deliveries=set()
    required={'type','t','authority','message','observation_id','nonce','signature_valid','peer_authorized','expires_at','interaction_id','receipt_interaction_id','receipt_verified','receipt_receiver_local','decision','selected'}
    last=-math.inf
    for e in events:
        gate(isinstance(e,dict) and set(e)==required and e['type']=='receive','AM005_INTAKE','closed receive event required')
        gate(type(e['t']) is int and e['t']>=last and e['t']>=0,'AM005_INTAKE','ordered exact tick timestamps required');last=e['t']
        gate(e['message'] not in deliveries,'AM005_INTAKE','unique delivery key required');deliveries.add(e['message'])
        for k in ('signature_valid','peer_authorized','receipt_verified','receipt_receiver_local'):
            gate(type(e[k]) is bool,'AM005_INTAKE','actual boolean check results required')
        gate(e['decision'] in {'accepted','rejected'},'AM005_INTAKE','intake decision required')
        if e['decision']=='accepted':
            gate(isinstance(e['observation_id'],str) and bool(e['observation_id']) and e['observation_id'] not in ids
                 and isinstance(e['nonce'],str) and bool(e['nonce']) and e['nonce'] not in nonces
                 and e['signature_valid'] and e['peer_authorized'] and e['receipt_verified'] and e['receipt_receiver_local']
                 and e['interaction_id'] is not None and e['interaction_id']==e['receipt_interaction_id']
                 and type(e['expires_at']) is int and e['expires_at']>=e['t']
                 and isinstance(e['selected'],list) and len(e['selected'])==2
                 and e['selected'][0] in {'deny_egress','revoke_credential','freeze'},'AM005_INTAKE','acceptance violates atomic freshness/correlation/validation contract')
            ids.add(e['observation_id']);nonces.add(e['nonce'])
        else:
            gate(e['selected'] is None,'AM005_INTAKE','rejected evidence must not select an action')


def validate_placement(p, grid, calibration):
    gate(p.get('schema')=='tcop.crosshost-grid-placement/1.0' and p.get('rule')==GRID_RULE
         and p.get('sample_count')==1024 and p.get('reference_network_delay_ms')==10
         and p.get('post_hoc') is False and p.get('sealed_eligible') is True,'AM005_GRID','fixed 005 placement rule and calibrated input required')
    gate(p.get('simulator_sha256')==calibration['simulator_sha256'] and p.get('calibration_sha256')==calibration['calibration_data_sha256'] and p.get('seed')==calibration['seed'],'AM005_GRID','placement calibration/version/seed mismatch')
    expected={(f,row) for f in ('S-B','S-C') for row in ('E2-native-a','E2-native-b','E2-native-min-a','E2-extended-a','E2-extended-b')}
    ts=p.get('transitions');gate(isinstance(ts,list) and len(ts)==10 and {(t['family'],t['row']) for t in ts}==expected,'AM005_GRID','both families and every E2 transition required')
    for t in ts:
        samples=t.get('effect_samples_ms')
        gate(t.get('sample_count')==1024 and isinstance(samples,list) and len(samples)==1024,'AM005_GRID','1024 seeded effect samples per transition required')
        for v in samples:number(v,'sample effect time')
        crossing=math.nextafter(sorted(samples)[511],math.inf)
        gate(t.get('transition_ms')==crossing,'AM005_GRID','transition must reach probability one half; ties deny E2 credit')
    h=[t['transition_ms'] for t in ts if t['row']=='E2-extended-a'];m=min(t['transition_ms'] for t in ts if t['row']=='E2-native-min-a');d=max(t['transition_ms'] for t in ts if t['row']=='E2-native-a')
    gate(0<min(h) and max(h)<m<10000,'AM005_GRID','calibration cannot separate the four values; owner decision required')
    values=[min(h)/2,(max(h)+m)/2,(m+10000)/2,2*max(10000,d)]
    gate(all(a<b for a,b in zip(values,values[1:])) and grid['action_interval_ms']==values
         and p.get('grid')=={'network_delays_ms':[10,50,100,250],'action_intervals_ms':values},'AM005_GRID','grid differs from deterministic placement')


def _tools(r):
    p=obj(r.get('pinned_tools'),'pinned tools');raw=p.get('raw')
    gate(isinstance(raw,str) and bool(raw),'AM005_TOOLS','pinned tools original bytes required')
    gate(p.get('sha256')==PINNED_TOOLS_SHA256==sha256(raw.encode()).hexdigest(),'AM005_TOOLS','pinned-tools bytes differ from sealed 005 pin')
    return json.loads(raw)


def _result(result, frozen, tools):
    gate(result.get('pinned_tools_record_sha256')==PINNED_TOOLS_SHA256,'AM005_TOOLS','pinned tools reference differs')
    if result.get('outcome')=='malformed':
        gate(result.get('tlc_used') is False and result.get('executed_tools') is None,'AM005_TOOLS','malformed input must not claim TLC executed')
    else:
        gate(result.get('executed_tools')==tools,'AM005_TOOLS','TLC jar/JDK/architecture/package source must match the pinned record')
    mapping={'spec_sha256':'spec_modules','trace_spec_sha256':'trace_checker','converter_sha256':'converter','trace_schema_sha256':'trace_schema'}
    for field,category in mapping.items():
        gate(hash256(result.get(field),field) in frozen['inputs'][category].values(),'AM005_TRACE_HASH','TLC result input differs from frozen set')
    hash256(result.get('trace_sha256'),'TLC trace hash')
    gate(result.get('post_hoc') is not True,'AM005_POST_HOC','post-hoc result cannot replace frozen result')


def _validate(r, purpose):
    tools=_tools(r)
    frozen,at=sealed(r.get('frozen_inputs'),'tcop.external-frozen-inputs/1.0')
    categories={'spec_modules','trace_checker','converter','trace_schema','tlc_configs'}
    gate(set(frozen)=={'schema','inputs','bounds','pinned_tools_record_sha256'} and set(frozen['inputs'])==categories
         and frozen['pinned_tools_record_sha256']==PINNED_TOOLS_SHA256,'AM005_FROZEN_INPUTS','complete frozen-input inventory required')
    for category, files in frozen['inputs'].items():
        gate(isinstance(files,dict) and bool(files),'AM005_FROZEN_INPUTS','nonempty input categories required')
        for path,h in files.items():text(path,'input path');hash256(h,'input hash')
    gate(bool(frozen['bounds']) and all(type(v) is int and v>=0 for v in frozen['bounds'].values()),'AM005_FROZEN_INPUTS','TLC bounds required')
    tlc=r['tlc']['body']
    gate(tlc.get('pinned_tools_record_sha256')==PINNED_TOOLS_SHA256 and tlc.get('executed_tools')==tools,'AM005_TOOLS','property run must embed pinned jar/JDK')
    gate(tlc.get('spec_sha256') in frozen['inputs']['spec_modules'].values(),'AM005_TRACE_HASH','property spec differs from frozen set')
    gate(tlc.get('tool_sha256')==tools['tla_plus']['sha256'] and tlc.get('tool_version')==tools['tla_plus']['version'],'AM005_TOOLS','property top-level jar/version differs')
    gate(tlc.get('config_sha256') in frozen['inputs']['tlc_configs'].values() and tlc.get('bounds')==frozen['bounds'],'AM005_TRACE_HASH','property config/bounds differ from frozen set')
    gate(isinstance(tlc.get('property_trace_raw'),str) and sha256(tlc['property_trace_raw'].encode()).hexdigest()==hash256(tlc.get('trace_sha256'),'property trace hash'),'AM005_TRACE_HASH','property witness bytes differ from committed hash')
    findings=r.get('smoke_trace_findings')
    gate(isinstance(findings,list),'AM005_SMOKE','smoke trace dispositions required')
    for finding in findings:
        gate(finding.get('outcome') in {'accepted','rejected','malformed'},'AM005_SMOKE','smoke outcome required')
        if finding['outcome']!='accepted' and r['stage']!='smoke':
            gate(finding.get('resolved_by_owner') is True and bool(finding.get('owner_resolution')) and (not r['episodes'] or moment(finding['resolved_at'])<min(moment(e['started_at']) for e in r['episodes'])),'AM005_SMOKE','unresolved rejected/malformed smoke trace blocks live admission')
    validations=r.get('trace_validations');gate(isinstance(validations,list),'AM005_TRACE_RECORD','trace validation inventory required')
    byid={};counts={};safety_stops=[]
    episodes={e['id']:e for e in r['episodes']}
    for v in validations:
        eid=v.get('episode_id');gate(eid in episodes and eid not in byid,'AM005_TRACE_RECORD','duplicate/unmatched trace result')
        e=episodes[eid];result=obj(v.get('result'),'trace validation')
        _result(result,frozen,tools)
        gate(('frozen_trace_raw' in v) != ('frozen_trace_base64' in v),'AM005_TRACE_HASH','exactly one original byte representation required')
        if 'frozen_trace_raw' in v:
            gate(isinstance(v['frozen_trace_raw'],str),'AM005_TRACE_HASH','original UTF8 text required')
            raw=v['frozen_trace_raw'].encode('utf-8')
        else:
            raw=base64.b64decode(v['frozen_trace_base64'],validate=True)
        h=sha256(raw).hexdigest()
        gate(h==result['trace_sha256']==e['replay']['trace_sha256'],'AM005_TRACE_HASH','original bytes/result/frozen replay hashes differ')
        outcome=result.get('outcome')
        gate(outcome in {'accepted','rejected','malformed'},'AM005_TRACE_RECORD','tool errors cannot close as trace outcomes')
        gate(result.get('schema_version')=='tcop.trace-result/1' and result.get('input_kind')=='frozen_trace','AM005_TRACE_RECORD','real frozen-trace result required')
        gate(result.get('counted_as_accepted',outcome=='accepted') is (outcome=='accepted'),'AM005_TRACE_RECORD','malformed/rejected never counted accepted')
        if outcome=='accepted':
            gate(result.get('exhaustive') is True and type(result.get('event_count')) is int and result.get('reached_events')==result['event_count'],'AM005_TRACE_RECORD','exhaustive end-of-trace reach required')
            trace=_parse_json(raw,"frozen trace")
            gate(trace.get('schema_version')=='tcop.trace/1' and trace.get('trace_id')==eid
                 and trace.get('sandbox_id')==r['sandbox']['id'] and trace.get('sandbox_generation')==r['sandbox']['generation']
                 and isinstance(trace.get('events'),list) and bool(trace['events']) and trace['events'][-1].get('type')=='end'
                 and any(ev.get('type')=='attempt' and ev.get('action')=='A4' for ev in trace['events'])
                 and result['event_count']==len(trace['events']),'AM005_TRACE_RECORD','trace identity/generation/end/A4/count differs')
            gate(e.get('intake_events')==[ev for ev in trace['events'] if ev['type']=='receive'],'AM005_INTAKE','episode intake differs from its frozen trace')
        else:
            f=obj(v.get('finding'),'preserved trace finding')
            gate(f.get('classification') in ({'model_gap','implementation_deviation','mapping_error'} if r['stage']=='results' else {'model_gap','implementation_deviation','mapping_error','pending'}) and bool(f.get('evidence')),'AM005_TRACE_FINDING','every rejection/malformed result remains a finding')
            if outcome=='rejected':
                gate(type(result.get('first_rejected_step_index')) is int and result.get('first_rejected_record') is not None,'AM005_TRACE_FINDING','preserve first rejected step and record')
            widened=False
            if outcome=='rejected':
                trace=_parse_json(raw,'rejected frozen trace');index=result['first_rejected_step_index']
                gate(-1<=index<len(trace['events']),'AM005_TRACE_FINDING','rejected prefix index outside trace')
                gate(e.get('intake_events')==[ev for ev in trace['events'] if ev['type']=='receive'],'AM005_INTAKE','episode intake differs from rejected frozen trace')
                expected={'initial_authority':trace['initial_authority']} if index==-1 else trace['events'][index]
                gate(result['first_rejected_record']==expected,'AM005_TRACE_FINDING','first rejected record differs from the frozen trace')
                if index>=0:
                    before=trace['initial_authority'] if index==0 else trace['events'][index-1]['authority']
                    widened=not set(map(tuple,expected['authority']))<=set(map(tuple,before))
            if widened or f.get('authority_widening') is True or f.get('evidence_command_path') is True:
                gate(f.get('safety_stop') is True,'AM005_SAFETY_STOP','guarantee failure must stop the run');safety_stops.append(moment(e['started_at']))
        counts.setdefault((e['family'],e['row']),{'accepted':0,'rejected':0,'malformed':0})[outcome]+=1
        byid[eid]=v
    gate(set(byid)==set(episodes),'AM005_TRACE_RECORD','every frozen episode needs its own trace validation')
    seen_ids=set();seen_nonces=set()
    for e in episodes.values():
        gate(at<moment(e['started_at']),'AM005_FROZEN_INPUTS','inputs must freeze before the first live episode')
        gate(not safety_stops or moment(e['started_at'])<=min(safety_stops),'AM005_SAFETY_STOP','live run continued after widening/command finding')
        validate_intake_events(e.get('intake_events',[]),seen_ids=seen_ids,seen_nonces=seen_nonces)
        if e['row'].startswith('E2'):
            ready=number(e.get('validated_request_ready_ms'),'validated request ready')
            gate(e['deadline_ms']==ready+e['D_ms']+20000,'AM005_DEADLINE','decision deadline must equal ready + D + 20000 ms')
            if e['family']=='S-A' and e.get('binding_result')=='no_change':
                gate(e['runtime_outcome']=='rejected' and e.get('runtime_reason')=='no_change' and e.get('e2_prevention_credit')==0 and all(not b['counted_as_prevented'] or b.get('prevention_attribution')=='E1_baseline' for b in e['branches'].values()),'AM005_NO_CHANGE','S-A no_change never earns E2 prevention')
            gate(e.get('outcome_basis') in {'observed','computed'},'AM005_TIES','observed/computed outcome provenance required')
            if e['outcome_basis']=='computed':
                gate('effect_at_ms' in e and e.get('a0_at_ms')==e['action_interval_ms'] and type(e.get('a0_prevented')) is bool,'AM005_TIES','computed outcome requires effect/A0 times on the warning-origin clock')
                if e['effect_at_ms'] is not None:number(e['effect_at_ms'],'computed effect time')
            if e['outcome_basis']=='computed' and e.get('effect_at_ms')==e.get('a0_at_ms') and e.get('effect_at_ms') is not None:
                gate(e.get('a0_prevented') is False and not e['branches']['A0']['counted_as_prevented'] and e['timing_outcome']!='prospective_prevention','AM005_TIES','computed tie cannot credit E2')
            if e['outcome_basis']=='computed' and e.get('abstract_action')=='freeze_sandbox' and e.get('effect_at_ms')==e.get('a4_completion_at_ms') and e.get('effect_at_ms') is not None:
                gate(e['branches']['A4']['useful_completed']==0,'AM005_TIES','freeze/completion tie stops computed benign completion')
    validate_placement(r['grid_finalization']['body'].get('placement',{}),r['grid_finalization']['body'],r['calibration']['body'])
    return {'trace_counts':[{'family':f,'row':row,**c} for (f,row),c in sorted(counts.items())]}


def validate_amendment005_records(record,purpose='verify'):
    from .cli_support import TCOPCommandError
    try:return _validate(record,purpose)
    except (KeyError,TypeError,ValueError,AttributeError,IndexError,OverflowError) as exc:
        raise TCOPCommandError('AM005_SCHEMA: malformed trace/frozen-input record') from exc
