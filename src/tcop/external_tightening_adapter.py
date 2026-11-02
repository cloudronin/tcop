"""Finite, receiver-local tightening selection and single-write transport boundary.

Transport implementations receive only canonical, revalidated closed writes.
No command, policy replacement, TCX-supplied target, or reversal API exists here.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
import ipaddress
import json
import re
from pathlib import Path
from hashlib import sha256
from typing import Protocol

from .canonical import canonical_bytes
from .cli_support import TCOPCommandError
from .external_foundation_seals import require, hash256, digest
from .external_enforcement_admission import PINS
from .external_enforcement_validation import BINDINGS, ROWS, selected_binding, APPROVAL_BASIS

SELECTION_FIELDS={'family','row','abstract_action','binding_id','target','sandbox_id','generation'}


class Transport(Protocol):
    def identity(self) -> dict: ...
    def write(self,wire: bytes) -> dict: ...
    def observations(self,wire: bytes,ack: dict,until_ms: float): ...


class Clock(Protocol):
    def now_ms(self) -> float: ...
    def wait_until(self,at_ms: float) -> None: ...


def validate_bound(b):
    require(b.get('driver')=='docker','only the admitted Docker driver is implemented')
    require(b.get('binding_pin')==PINS['openshell']['commit'],'runtime pin differs')
    hash256(b.get('container_id'),'exact full container ID')
    for key in ('sandbox_id','name','workspace','generation'):
        require(isinstance(b.get(key),str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',b[key]) is not None,'invalid bound identity')
    require(type(b.get('resource_version')) is int and b['resource_version']>0,'optimistic concurrency resource version required')
    require(isinstance(b.get('destinations'),dict) and bool(b['destinations']) and isinstance(b.get('providers'),dict),'finite admitted inventory required')
    baseline=b.get('baseline_authority')
    require(isinstance(baseline,list) and all(isinstance(x,list) and len(x)==2 and all(isinstance(y,str) for y in x) for x in baseline),'finite authority required')
    for name,d in b['destinations'].items():
        require(d.get('rule_name') and d.get('host') and type(d.get('port')) is int and 0<d['port']<65536,'named destination rule/host/port required')
        require(type(d.get('initially_allowed')) is bool and (['egress',name] in baseline)==d['initially_allowed'],'destination baseline disposition differs from admitted authority')
    require(isinstance(b.get('family_targets'),dict) and set(b['family_targets'])=={'S-A','S-B','S-C'},'fixed named target per family required')
    for name,p in b['providers'].items():
        require(p.get('name') and p.get('credential_bindings')==[] and isinstance(p.get('credentials'),list) and name in p['credentials'],'dedicated, unreferenced provider inventory required')
        require(all(['credential',c] in baseline for c in p['credentials']),'provider credential outside baseline')


def _selection(b,c, *, capability=False):
    validate_bound(b)
    require(isinstance(c,dict) and set(c)==SELECTION_FIELDS and all(isinstance(v,str) for v in c.values()),'closed receiver-local selection with string identifiers required')
    require(c['sandbox_id']==b['sandbox_id'] and c['generation']==b['generation'],'selection outside bound sandbox generation')
    if capability:
        require(c['family']=='capability' and c['row']=='capability' and c['abstract_action']=='snapshot_sandbox' and c['binding_id']=='snapshot' and c['target']=='sandbox','snapshot is capability only')
        return
    require(c['family'] in {'S-A','S-B','S-C'} and c['row'] in ROWS and c['row'].startswith('E2'),'no binding writes in E0/E1')
    bid=selected_binding(c['family'],c['row'])
    require(c['binding_id']==bid and bid in BINDINGS and c['abstract_action']==BINDINGS[bid][0],'action differs from the fixed family/row selection')
    action=c['abstract_action'];target=c['target']
    require((action=='deny_egress' and target in b['destinations']) or (action=='revoke_credential' and target in b['providers']) or (action=='freeze_sandbox' and target=='sandbox'),'target outside finite admitted inventory')
    # Exactly one target/group is selected per family before execution. A larger
    # admitted inventory does not give the evidence a target-selection channel.
    if action=='deny_egress':require(target==b['family_targets'][c['family']],'not the pre-registered primary destination')
    if action=='revoke_credential':require(target==b['family_targets'][c['family']],'not the pre-registered leaked credential')


def serialize_write(b,c, *, capability=False):
    _selection(b,c,capability=capability)
    bid=c['binding_id'];target=c['target']
    if bid.startswith('native-egress'):
        d=b['destinations'][target]
        payload={'name':b['name'],'workspace':b['workspace'],'expected_resource_version':b['resource_version'],
                 'merge_operations':[{'remove_endpoint':{k:d[k] for k in ('rule_name','host','port')}}]}
    elif bid.startswith('provider-detach'):
        payload={'sandbox_name':b['name'],'workspace':b['workspace'],'provider_name':b['providers'][target]['name'],'expected_resource_version':b['resource_version']}
    elif bid=='instant-egress':
        require(b.get('instant_cut_admitted') is True,'instant cut unavailable')
        proof=b.get('instant_cut_evidence',{})
        require(all(proof.get(k) is True for k in ('vm_root_access','dedicated_routed_target','off_bridge','fresh_connections','continuity','initial_vm_namespace','preinstalled_empty_named_set')),'instant cut missing admission evidence')
        d=b['destinations'][target]
        require(isinstance(b.get('bridge'),str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',b['bridge']) is not None,'verified bridge interface required')
        for ip in (b.get('container_ip'),d.get('ip')):
            address=ipaddress.ip_address(ip);require(address.version==4 and not address.is_multicast and not address.is_loopback,'dedicated routed IPv4 target/source required')
        payload={'operation':'add_bound_tuple','tuple':{'bridge':b['bridge'],'source_ip':b['container_ip'],'destination_ip':d['ip'],'tcp_port':d['port']}}
    elif bid in {'freeze','snapshot'}:
        payload={'container_id':b['container_id'],'operation':'pause' if bid=='freeze' else 'commit_no_pause'}
    else:raise TCOPCommandError('unrepresentable binding')
    return canonical_bytes({'schema':'tcop.tightening-write/1','selection':deepcopy(c),
                            'container_id':b['container_id'],'binding_pin':b['binding_pin'],'payload':payload})


def validate_wire(b,wire, *, capability=False):
    try:
        def closed(pairs):
            d={}
            for k,v in pairs:
                require(k not in d,'duplicate wire key');d[k]=v
            return d
        w=json.loads(wire,object_pairs_hook=closed)
        require(isinstance(w,dict) and serialize_write(b,w.get('selection'),capability=capability)==wire,'serialized write differs from the allowlisted bound operation')
        return w
    except (ValueError,TypeError,KeyError,AttributeError) as exc:raise TCOPCommandError('malformed tightening wire') from exc


def authority_after(b,c):
    _selection(b,c,capability=c.get('abstract_action')=='snapshot_sandbox')
    before=deepcopy(b['baseline_authority']);action=c['abstract_action']
    if action=='deny_egress':return [v for v in before if v!=['egress',c['target']]]
    if action=='revoke_credential':return [v for v in before if not(v[0]=='credential' and v[1] in b['providers'][c['target']]['credentials'])]
    if action=='freeze_sandbox':return []
    return before


def effect_matches(b,c,ack,e):
    if any(e.get(k)!=b[k] for k in ('sandbox_id','generation','container_id')):return False
    bid=c['binding_id']
    if bid.startswith('native-egress'):
        return e.get('kind')=='policy' and e.get('status')=='LOADED' and type(ack.get('version')) is int and ack['version']>0 and e.get('version')==ack['version']==e.get('active_version') and bool(ack.get('policy_hash')) and e.get('policy_hash')==ack['policy_hash']
    if bid.startswith('provider-detach'):
        return e.get('kind')=='provider' and ack.get('detached') is True and bool(ack.get('provider_env_revision')) and e.get('fingerprint')==ack['provider_env_revision'] and e.get('provider_absent') is True and e.get('provider')==b['providers'][c['target']]['name'] and e.get('message')=='Provider environment refreshed' and e.get('status')=='loaded' and e.get('source')=='enforcing_supervisor' and e.get('ambiguous',False) is False
    if bid=='freeze':return e.get('kind')=='paused' and e.get('paused') is True
    if bid=='instant-egress':return e.get('kind')=='tuple' and e.get('installed') is True and e.get('tuple_matches') is True
    return False


class TighteningAdapter:
    def __init__(self,bound,intake,transport:Transport,clock:Clock):
        validate_bound(bound);self.bound=deepcopy(bound);self.intake=intake;self.transport=transport;self.clock=clock;self._issued_results={}

    def execute(self,ticket,candidate):
        b=self.bound;c=deepcopy(candidate)
        wire=serialize_write(b,c);validate_wire(b,wire)
        from .external_receiver_intake import ValidatedTCX
        require(isinstance(ticket,ValidatedTCX) and ticket.sandbox_id==b['sandbox_id'] and ticket.generation==b['generation'],'unvalidated or foreign TCX')
        expected_action='freeze' if c['abstract_action']=='freeze_sandbox' else c['abstract_action']
        require(ticket.selected==(expected_action,c['target']),'selection changed after atomic intake')
        identity=self.transport.identity()
        require(all(identity.get(k)==b[k] for k in ('sandbox_id','generation','container_id')),'sandbox replaced/recreated before write')
        bid=c['binding_id'];action,implementation,tag,grade,layering,check,poll=BINDINGS[bid]
        require(identity.get('poll_interval_secs')==poll,'binding poll configuration differs from admitted mode')
        D=3000 if c['row'].endswith('-b') else 0;ready=ticket.ready_at_ms;submitted=ready+D;deadline=submitted+20000
        require(self.clock.now_ms()<deadline,'validated request arrived too late to submit before its fixed deadline')
        self.intake.claim(ticket);self.clock.wait_until(submitted)
        actual_submitted=self.clock.now_ms()
        require(submitted<=actual_submitted<deadline,'invalid submission clock or scheduling overrun')
        result={'schema':'tcop.tightening-result/1','tcx_id':ticket.observation_id,**c,
            'binding_pin':b['binding_pin'],'implementation':implementation,'tag':tag,'grade':grade,'layering':layering,
            'binding_identity':{'id':bid,'runtime_commit':b['binding_pin'],
                'adapter_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
                'transport_sha256':sha256(Path(__file__).with_name('external_binding_transports.py').read_bytes()).hexdigest(),
                'admission_binding_sha256':digest(b)},
            'poll_interval_secs':poll,'D_ms':D,'basis':APPROVAL_BASIS if D else 'immediate submission',
            'ready_at_ms':ready,'scheduled_submission_at_ms':submitted,'submitted_at_ms':actual_submitted,
            'submission_deviation_ms':actual_submitted-submitted,'deadline_ms':deadline,'writes':1,
            'wire_sha256':digest(json.loads(wire)),'decision':'timed_out','reason':'effect_not_observed_by_deadline',
            'decision_at_ms':deadline,'binding_result':'pending','observations':[],'late_effects':[],'time_to_block':'never'}
        self._issued_results[result['tcx_id']]=result
        known_no_change=c['family']=='S-A' and action=='deny_egress' and not b['destinations'][c['target']]['initially_allowed']
        if known_no_change:
            result.update(binding_result='no_change',decision='rejected',reason='no_change',decision_at_ms=actual_submitted,e2_prevention_credit=0)
        try:
            ack=self.transport.write(wire);result['ack']=deepcopy(ack)
            ack_at=self.clock.now_ms();result['rpc_return_at_ms']=ack_at
        except (OSError,TimeoutError) as exc:
            result['transport_error']=type(exc).__name__
            if result['decision']=='timed_out':self.clock.wait_until(deadline)
            result['decision_closed']=True;return result
        if not known_no_change and ack_at>deadline and (ack.get('no_change') is True or ack.get('rejected') is True):
            result['late_rejection']=deepcopy(ack)
        elif not known_no_change and ack.get('no_change') is True:
            result.update(binding_result='no_change',decision='rejected',reason='no_change',decision_at_ms=ack_at,e2_prevention_credit=0)
        elif not known_no_change and ack.get('rejected') is True:
            result.update(binding_result='rejected',decision='rejected',reason=str(ack.get('reason','runtime_rejected')),decision_at_ms=ack_at)
        self._observe(result,c,ack,deadline+20000,closed=False)
        if result['decision']=='timed_out':self.clock.wait_until(deadline)
        result['decision_closed']=True
        return result

    def observe_until(self,result,until_ms):
        """Retain later episode observations without another write or relabeling."""
        require(self._issued_results.get(result.get('tcx_id')) is result,'foreign adapter result')
        require(type(until_ms) in (int,float) and until_ms>=result.get('observation_end_ms',result['deadline_ms']),'observation window cannot move backwards')
        c={k:result[k] for k in SELECTION_FIELDS}
        self._observe(result,c,result.get('ack',{}),until_ms,closed=True)
        return result

    def _observe(self,result,c,ack,until_ms,*,closed):
        b=self.bound;wire=serialize_write(b,c);deadline=result['deadline_ms']
        last=result['observations'][-1]['at_ms'] if result['observations'] else result['submitted_at_ms']
        try:
            for e in self.transport.observations(wire,ack,until_ms):
                e=deepcopy(e);at=e.get('at_ms');require(type(at) in (int,float) and at>=last,'unordered/nonfinite binding observation')
                import math
                require(math.isfinite(at),'nonfinite observation time')
                require(not closed or at>deadline,'late collection cannot backdate a decision observation')
                last=at;result['observations'].append(e)
                scoped=all(e.get(k)==b[k] for k in ('sandbox_id','generation','container_id'))
                if scoped and e.get('kind')=='denial' and e.get('attributed') is True and (e.get('source','attributed_denial')=='attributed_denial' or e.get('source')=='failed_fresh_connection' and e.get('fresh') is True) and result['binding_result']!='no_change' and e.get('target')==c['target'] and e.get('action_id') in {'A0','A1','A2','A3'} and result['time_to_block']=='never':result['time_to_block']=e
                observed=result['binding_result']!='no_change' and effect_matches(b,c,ack,e)
                if observed and 'effect_observation' not in result:
                    result['effect_observation']=e
                    if at>deadline:result['late_effects'].append(e)
                    elif not closed and result['decision']=='timed_out':result.update(binding_result='observed',decision='accepted',reason='observed_effect',decision_at_ms=at)
                explicit_rejection=scoped and e.get('kind')=='policy' and e.get('version')==ack.get('version') and e.get('status') in {'FAILED','SUPERSEDED'}
                if explicit_rejection and not closed and at<=deadline and result['decision']=='timed_out':result.update(binding_result='rejected',decision='rejected',reason=e['status'].lower(),decision_at_ms=at)
        except (OSError,TimeoutError) as exc:result['observation_error']=type(exc).__name__
        result['observation_end_ms']=until_ms
