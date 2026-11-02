"""C1-C4 procedures and measured calibration import. No automatic admission.

The fixture controller is separate from the tightening transport. Only that
controller can release a C3 test fixture after its fixed observation window.
"""
from __future__ import annotations
from copy import deepcopy
import math
from pathlib import Path

from .cli_support import TCOPCommandError
from .external_foundation_seals import digest, require, hash256
from .external_enforcement_admission import PINS
from .external_enforcement_validation import BINDINGS
from .external_tightening_adapter import serialize_write, validate_wire, effect_matches

REQUIRED={'native-egress-10','native-egress-1','instant-egress','provider-detach-10','provider-detach-1','freeze'}


def _selection(b,bid):
    action=BINDINGS[bid][0]
    family='capability' if bid=='snapshot' else 'S-C' if action in {'freeze_sandbox','revoke_credential'} else 'S-B'
    row='capability' if bid=='snapshot' else 'E2-native-min-a' if bid.endswith('-1') else 'E2-extended-a' if bid in {'freeze','instant-egress'} else 'E2-native-a'
    target='sandbox' if action in {'freeze_sandbox','snapshot_sandbox'} else b['family_targets'][family]
    return dict(family=family,row=row,abstract_action=action,binding_id=bid,target=target,sandbox_id=b['sandbox_id'],generation=b['generation'])


def evaluate_check(r):
    """Recompute pass from retained observations and controls, never a pass flag."""
    try:
        b=r['bound'];bid=r['binding_id'];check=r['check'];before=r['before'];after=r['after']
        require(bid in BINDINGS and check==BINDINGS[bid][5] and r['pins']==PINS and r['writes']==1,'check pin/action/write mismatch')
        require(all(r.get(key)==value for key,value in zip(('implementation','tag','grade','layering'),BINDINGS[bid][1:5])),'conformance binding metadata mismatch')
        wire=serialize_write(b,r['selection'],capability=check=='C4');require(digest(__import__('json').loads(wire))==r['write_sha256'],'write hash mismatch')
        keys=('sandbox_id','generation','container_id')
        require(all(r['identity_before'][k]==r['identity_after'][k]==b[k] for k in keys),'replacement/recreation during check')
        require(r['identity_before']['poll_interval_secs']==r['identity_after']['poll_interval_secs']==BINDINGS[bid][6],'check poll mismatch')
        events=r['observations']
        if check!='C4':
            require(any(effect_matches(b,r['selection'],r['ack'],e) for e in events),'no correlated installed effect')
        if check=='C1':
            require(all(before.get(k) is True for k in ('target','control','other_sandbox','inference','supervisor','fresh')),'baseline connectivity failed')
            require(after.get('target') is False and all(after.get(k) is True for k in ('control','other_sandbox','inference','supervisor','fresh')),'target/control guarantee failed')
        elif check=='C2':
            require(all(before.get(k) is True for k in ('target_resolves','group_peer_resolves','unrelated_resolves','in_flight_staged')),'baseline resolution/in-flight setup failed')
            require(after.get('target_resolves') is False and after.get('new_request_existing_connection_resolves') is False and after.get('unrelated_resolves') is True,'credential resolution granularity failed')
            require(after.get('in_flight_may_finish') is True,'in-flight completion was incorrectly required to fail')
        elif check=='C3':
            require(len(before['counters'])==2 and all(type(v) is int for v in before['counters']) and after['counters']==before['counters'] and after['outside_counter']>before['outside_counter'],'freeze progress guarantee failed')
            require(after['window_ms']==r['window_ms']>0 and after.get('restarted') is False,'fixed freeze continuity window required')
            require(r.get('release_controller')=='separate_fixture_controller' and all(a>b for a,b in zip(r['released']['counters'],before['counters'])),'fixture did not resume after external release')
        elif check=='C4':
            require(after['source_generation']==b['generation'] and after['source_container_id']==b['container_id'] and after['coverage']==['filesystem'] and set(after['omissions'])>={'memory','mounted_volumes'},'snapshot source/coverage mismatch')
            require(bool(before['markers']) and after['captured_markers']==before['markers'],'empty/unrelated/inaccurate capture')
            hash256(after['artifact_sha256'],'captured artifact hash')
            require(r['ack'].get('image_id')=='sha256:'+after['artifact_sha256'],'captured image differs from this commit result')
            require(after.get('paused') is False and all(after.get(k) is True for k in ('execution_continues','access_continues','other_sandbox')),'snapshot restricted execution/access')
        require(type(r['effect_lag_ms']) in (int,float) and math.isfinite(r['effect_lag_ms']) and r['effect_lag_ms']>=0,'measured lag required')
        return True
    except (KeyError,TypeError,ValueError,TCOPCommandError):return False


def run_check(check,binding_id,bound,transport,controller,clock,*,window_ms=20000):
    require(binding_id in BINDINGS and check==BINDINGS[binding_id][5],'check/binding mismatch')
    require(type(window_ms) is int and window_ms>0,'fixed positive observation window required')
    b=deepcopy(bound);c=_selection(b,binding_id);wire=serialize_write(b,c,capability=check=='C4');validate_wire(b,wire,capability=check=='C4')
    before=controller.measure('before');identity=transport.identity();submitted=clock.now_ms()
    require(all(identity.get(k)==b[k] for k in ('sandbox_id','generation','container_id')) and identity.get('poll_interval_secs')==BINDINGS[binding_id][6],'conformance bound generation/poll mismatch before write')
    errors={}
    try:
        ack=transport.write(wire);events=list(transport.observations(wire,ack,submitted+window_ms))
    except (OSError,TimeoutError,TCOPCommandError) as exc:
        ack={};events=[];errors['transport_error']=type(exc).__name__
    matched=[e for e in events if effect_matches(b,c,ack,e)]
    measured=[e for e in matched if type(e.get('effect_at_ms')) in (int,float)]
    effect=min(measured or matched,key=lambda e:e['at_ms']) if matched else next((e for e in events if check=='C4' and e.get('kind')=='snapshot' and e.get('container_id')==b['container_id'] and e.get('generation')==b['generation']),None)
    clock.wait_until(submitted+window_ms)
    try:after=controller.measure('after');after_id=transport.identity()
    except (OSError,TimeoutError,TCOPCommandError) as exc:
        after={};after_id={};errors['readback_error']=type(exc).__name__
    r={'schema':'tcop.binding-conformance/1','check':check,'binding_id':binding_id,'selection':c,
       'bound':b,'pins':deepcopy(PINS),'implementation':BINDINGS[binding_id][1],'tag':BINDINGS[binding_id][2],
       'grade':BINDINGS[binding_id][3],'layering':BINDINGS[binding_id][4],'poll_interval_secs':BINDINGS[binding_id][6],
       'writes':1,'write_sha256':digest(__import__('json').loads(wire)),'submitted_at_ms':submitted,
       'ack':ack,'observations':events,'identity_before':identity,'identity_after':after_id,
       'before':before,'after':after,'window_ms':window_ms,'post_hoc':False,
       'effect_lag_ms':(effect.get('effect_at_ms',effect['at_ms'])-submitted) if effect else (ack.get('persisted_at_ms',submitted)-submitted) if check=='C4' else None,
       **errors}
    if check=='C4':r['capture_interval_ms']=[submitted,ack.get('persisted_at_ms')]
    if check=='C3':
        try:
            controller.release();r['released']=controller.measure('released');r['release_controller']='separate_fixture_controller'
        except (OSError,TimeoutError,TCOPCommandError) as exc:r['release_error']=type(exc).__name__
    r['passed']=not errors and evaluate_check(r)
    r['evidence_sha256']=digest({k:v for k,v in r.items() if k not in {'passed','evidence_sha256'}})
    return r


def import_calibration(records,timings,*,seed):
    from .crosshost_sim import validate_calibration
    require(type(seed) is int,'calibration seed required')
    require(isinstance(records,list) and bool(records),'C1-C3 records required')
    byid={}
    for r in records:
        require(r.get('passed') is True and evaluate_check(r),'conformance failed, incomplete or substituted')
        require(r.get('evidence_sha256')==digest({k:v for k,v in r.items() if k not in {'passed','evidence_sha256'}}),'conformance evidence changed')
        bid=r['binding_id'];require(bid not in byid,'use one aggregate record per binding/configuration')
        byid[bid]=r
    require(set(byid)>=REQUIRED,'C1 10 s/1 s/cut, C2 both polls and C3 are all required')
    require(timings.get('status')=='measured','separately measured warning acquisition stages required')
    hash256(timings.get('evidence_sha256'),'acquisition timing evidence')
    def empirical(samples,source):
        require(isinstance(samples,list) and bool(samples) and all(type(v) in (int,float) and math.isfinite(v) and v>=0 for v in samples),'nonnegative measured samples required')
        return {'kind':'empirical','samples_ms':samples,'source':source}
    lags={name:empirical(timings['samples_ms'][name],'measured acquisition '+timings['evidence_sha256']) for name in ('detection','signing','validation')}
    binding_lags={}
    observation=[]
    for bid in sorted(REQUIRED):
        r=byid[bid];event=next((e for e in r['observations'] if effect_matches(r['bound'],r['selection'],r['ack'],e) and type(e.get('effect_at_ms')) in (int,float)),None)
        require(event is not None,'measured effect barrier required, not RPC/local readback time')
        effect=event.get('effect_at_ms');require(type(effect) in (int,float),'effect barrier time must be measured, not inferred from RPC/readback')
        observation.append(event['at_ms']-effect)
        if bid.startswith(('native-egress','provider-detach')):
            persisted=r['ack'].get('persisted_at_ms');polled=event.get('poll_at_ms')
            require(type(persisted) in (int,float) and type(polled) in (int,float) and r['submitted_at_ms']<=persisted<=polled<=effect<=event['at_ms'],'native persistence/poll/effect barriers required; do not double-count polling')
            processing='native_egress_processing' if bid.startswith('native-egress') else 'native_detach_processing'
            binding_lags[bid]={'native_persistence':empirical([persisted-r['submitted_at_ms']],digest(r)),processing:empirical([effect-polled],digest(r)),'effect_observation':empirical([event['at_ms']-effect],digest(r))}
        else:
            lags['harness_cut' if bid=='instant-egress' else 'harness_freeze']=empirical([effect-r['submitted_at_ms']],digest(r))
            binding_lags[bid]={'effect_observation':empirical([event['at_ms']-effect],digest(r))}
    # Keep per-binding/poll measurements distinct. Legacy simulator fields use
    # the default binding only; the simulator applies explicit overrides.
    lags['native_persistence']=binding_lags['native-egress-10']['native_persistence']
    lags['native_egress_processing']=binding_lags['native-egress-10']['native_egress_processing']
    lags['native_detach_processing']=binding_lags['provider-detach-10']['native_detach_processing']
    lags['effect_observation']=binding_lags['native-egress-10']['effect_observation']
    result={'schema':'tcop.crosshost-calibration/1.0','status':'calibrated','D_ms':3000,
        'poll_ms':{'default':10000,'minimum':1000},'poll_phase':'uniform_at_baseline',
        'decision_deadline_after_ready_ms':20000,'lags':lags,'binding_lags':binding_lags,
        'sources':{'poll':'004 operating configurations, verified in C1/C2','D':'004 fixed simulated operator latency','deadline':'005 ready + D + 20000'},
        'seed':seed,'conformance_sha256':{check:digest([byid[b] for b in sorted(REQUIRED) if BINDINGS[b][5]==check]) for check in ('C1','C2','C3')},
        'acquisition_timings_sha256':digest(timings)}
    validate_calibration(result);return result


class CommandController:
    """Trusted fixture-only controller, never exposed to receiver evidence."""
    def __init__(self,argv,binding_id,config_path,run):
        require(isinstance(argv,list) and bool(argv) and all(isinstance(v,str) and v for v in argv),'fixture controller argv required')
        self.argv=list(argv);self.binding_id=binding_id;self.config=str(config_path);self.run=run
    def _call(self,stage):
        import json
        return json.loads(self.run(self.argv+['--stage',stage,'--binding',self.binding_id,'--config',self.config]))
    def measure(self,stage):return self._call(stage)
    def release(self):self._call('release_fixture')
    def fingerprint(self):return self._call('provider_fingerprint')


def load_host_driver(config_path,binding_id):
    from .external_foundation_seals import read_json
    from .external_binding_transports import (CommonClock,DockerIdentity,Journal,OpenShellTransport,
        DockerTransport,VMWorkerTransport,UnixVMWorkerClient,GRPCurl,run_argv)
    from .external_enforcement_admission import verify_admission
    cfg=read_json(Path(config_path));require(cfg.get('synthetic_fixture') is False,'replace synthetic example with measured host admission before running')
    b=cfg['bound'];admission=verify_admission(Path(cfg['admission_seal']))['record']
    require(all(b[k]==admission['sandbox'][k if k!='sandbox_id' else 'id'] for k in ('sandbox_id','name','workspace')),'conformance sandbox differs from sealed admission')
    clock=CommonClock(cfg['clock_origin_unix_ms']);identity=DockerIdentity(b)
    journal=Journal(cfg['observation_journal'])
    controller=CommandController(cfg['fixture_controller_command'],binding_id,config_path,run_argv)
    kwargs={'identity_reader':identity,'clock':clock,'journal':journal}
    if binding_id.startswith(('native-egress','provider-detach')):
        transport=OpenShellTransport(b,GRPCurl(cfg['gateway_endpoint'],cfg['openshell_proto_directory']),provider_fingerprint_reader=controller.fingerprint,**kwargs)
    elif binding_id=='instant-egress':transport=VMWorkerTransport(b,UnixVMWorkerClient(cfg['vm_worker_socket']),**kwargs)
    else:transport=DockerTransport(b,**kwargs)
    return b,transport,controller,clock


def write_record(path,record):
    from .external_foundation_seals import ensure_unsealed_output
    from .canonical import canonical_bytes
    p=Path(path);ensure_unsealed_output(p)
    require(not p.resolve().is_relative_to(Path('formal').resolve()),'do not write into the formal tree')
    p.parent.mkdir(parents=True,exist_ok=True)
    try:
        with p.open('xb') as stream:stream.write(canonical_bytes(record)+b'\n')
    except FileExistsError as exc:raise TCOPCommandError('record output already exists') from exc


def main(argv=None):
    import argparse
    import json
    from .external_foundation_seals import read_json
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    run=subs.add_parser('run');run.add_argument('--config',type=Path,required=True);run.add_argument('--check',choices=['C1','C2','C3','C4'],required=True);run.add_argument('--binding',choices=list(BINDINGS),required=True);run.add_argument('--window-ms',type=int,default=20000);run.add_argument('--output',type=Path,required=True)
    imp=subs.add_parser('import-calibration');imp.add_argument('--record',type=Path,action='append',required=True);imp.add_argument('--timings',type=Path,required=True);imp.add_argument('--seed',type=int,required=True);imp.add_argument('--output',type=Path,required=True)
    freeze=subs.add_parser('freeze-inputs');freeze.add_argument('--output',type=Path,required=True)
    identity=subs.add_parser('identity');identity.add_argument('--config',type=Path,required=True)
    args=parser.parse_args(argv)
    if args.command=='run':
        require(not args.output.exists(),'record output already exists')
        b,t,p,c=load_host_driver(args.config,args.binding)
        record=run_check(args.check,args.binding,b,t,p,c,window_ms=args.window_ms);write_record(args.output,record)
        return 0 if record['passed'] else 1
    if args.command=='import-calibration':
        record=import_calibration([read_json(p) for p in args.record],read_json(args.timings),seed=args.seed);write_record(args.output,record);return 0
    if args.command=='freeze-inputs':
        from .external_frozen_inputs import freeze_inputs
        freeze_inputs(args.output);return 0
    if args.command=='identity':
        from .external_binding_transports import DockerIdentity
        print(json.dumps(DockerIdentity(read_json(args.config)['bound'])(),sort_keys=True));return 0
    return 2


if __name__=='__main__':
    try:raise SystemExit(main())
    except TCOPCommandError as exc:raise SystemExit(str(exc))
