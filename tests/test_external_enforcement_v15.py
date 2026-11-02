"""005 negative gates first. All TLC and runtime evidence here is authored test data."""
from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import tempfile
import unittest

from tcop.cli_support import TCOPCommandError, load_config
from tcop.external_foundation_seals import digest
from test_external_enforcement_validation import fixture as old_fixture

PIN = '3b45fef22a9b00cff1a3e001db07404a10a396445620d7c8298459e672cdd22b'
TOOLS = '9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e'


def seal(body, at='2026-11-02T00:04:30Z'):
    return {'body':body, 'sha256':digest(body), 'sealed_at':at}


def fixture():
    r = old_fixture(); r['schema'] = 'tcop.external-enforcement-validation/1.1'
    raw = Path('formal/pinned-tools.json').read_text()
    tools = json.loads(raw)
    r['pinned_tools'] = {'raw':raw, 'sha256':TOOLS}
    inputs = {'spec_modules':{'formal/tla/TCOPReceiver.tla':'a'*64},
              'trace_checker':{'formal/tla/TCOPTrace.tla':'b'*64},
              'converter':{'formal/trace_to_tla.py':'c'*64},
              'trace_schema':{'formal/trace-v1.schema.json':'d'*64},
              'tlc_configs':{'formal/tla/MC.cfg':'e'*64}}
    r['frozen_inputs'] = seal({'schema':'tcop.external-frozen-inputs/1.0','inputs':inputs,
        'bounds':r['tlc']['body']['bounds'],'pinned_tools_record_sha256':TOOLS})
    r['tlc']['body'].update(pinned_tools_record_sha256=TOOLS, spec_sha256='a'*64,
        trace_sha256=sha256(b'property witness').hexdigest(), property_trace_raw='property witness', executed_tools=tools,
        config_sha256='e'*64,tool_sha256=tools['tla_plus']['sha256'],tool_version=tools['tla_plus']['version'])
    r['tlc']['sha256'] = digest(r['tlc']['body'])
    ts=[]
    for family in ('S-B','S-C'):
        for row, value in [('E2-native-a',6000),('E2-native-b',9000),
                           ('E2-native-min-a',600),('E2-extended-a',16 if family=='S-B' else 24),('E2-extended-b',3024)]:
            ts.append({'family':family,'row':row,'sample_count':1024,
                       'effect_samples_ms':[value]*1024,'transition_ms':math.nextafter(value,math.inf)})
    h=[x['transition_ms'] for x in ts if x['row']=='E2-extended-a']
    m=min(x['transition_ms'] for x in ts if x['row']=='E2-native-min-a')
    d=max(x['transition_ms'] for x in ts if x['row']=='E2-native-a')
    vals=[min(h)/2,(max(h)+m)/2,(m+10000)/2,2*max(10000,d)]
    grid=r['grid_finalization']['body']; oldvals=grid['action_interval_ms']; remap=dict(zip(oldvals,vals))
    grid['action_interval_ms']=vals
    grid['placement']={'schema':'tcop.crosshost-grid-placement/1.0','sample_count':1024,
        'reference_network_delay_ms':10,'seed':r['calibration']['body']['seed'],
        'simulator_sha256':r['calibration']['body']['simulator_sha256'],
        'calibration_sha256':r['calibration']['body']['calibration_data_sha256'],
        'transitions':ts,'rule':'half-fastest-harness; midpoint-slowest-harness/min-native; midpoint-min-native/default-window; twice-beyond-default',
        'grid':{'network_delays_ms':[10,50,100,250],'action_intervals_ms':vals},'post_hoc':False,'sealed_eligible':True}
    grid['history']=[];r['grid_finalization']['sha256']=digest(grid)
    pred=r['expected_pattern']['body'];pred['grid_sha256']=r['grid_finalization']['sha256'];pred['finalized_grid']['action_interval_ms']=vals
    r['expected_pattern']['sha256']=digest(pred)
    r['smoke_trace_findings']=[];r['trace_validations']=[]
    for c in r['cells']:c['action_interval_ms']=remap[c['action_interval_ms']]
    for e in r['episodes']:
        e['action_interval_ms']=remap[e['action_interval_ms']];e['replay']['action_interval_ms']=e['action_interval_ms']
        e['validated_request_ready_ms']=10 if e['row'].startswith('E2') else 'not_applicable'
        e['deadline_ms']=10+e['D_ms']+20000 if e['row'].startswith('E2') else e['deadline_ms']
        e['outcome_basis']='observed';e['intake_events']=[]
        if e['family']=='S-A' and e['row'].startswith('E2'):
            e['runtime_outcome']='rejected';e['runtime_reason']='no_change';e['binding_result']='no_change';e['e2_prevention_credit']=0
        keys=('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')
        e['replay']['live_outcome_sha256']=digest({k:e[k] for k in keys});e['replay']['replayed_outcome_sha256']=e['replay']['live_outcome_sha256']
        data=json.loads(Path('formal/traces/fixtures/accepted-no-evidence.json').read_text())
        data.update(trace_id=e['id'],sandbox_id=r['sandbox']['id'],sandbox_generation=r['sandbox']['generation'])
        trace=json.dumps(data,sort_keys=True)
        th=sha256(trace.encode()).hexdigest();e['replay']['trace_sha256']=th
        result={'schema_version':'tcop.trace-result/1','input_kind':'frozen_trace','outcome':'accepted',
                'trace_sha256':th,'spec_sha256':'a'*64,'trace_spec_sha256':'b'*64,
                'converter_sha256':'c'*64,'trace_schema_sha256':'d'*64,'pinned_tools_record_sha256':TOOLS,
                'executed_tools':deepcopy(tools),'exhaustive':True,'reached_events':len(data['events']),'event_count':len(data['events']),
                'first_rejected_step_index':None,'first_rejected_record':None,'post_hoc':False}
        r['trace_validations'].append({'episode_id':e['id'],'frozen_trace_raw':trace,'result':result})
    return r


class Amendment005Gates(unittest.TestCase):
    def check(self,r):
        from tcop.external_enforcement_validation import validate_enforcement_records
        return validate_enforcement_records(r)

    def test_complete_v15_fixture(self):self.assertTrue(self.check(fixture())['valid'])

    def reject(self, mutate):
        r=fixture();mutate(r)
        with self.assertRaises(TCOPCommandError):self.check(r)

    def test_reject_missing_trace_validation(self):self.reject(lambda r:r['trace_validations'].pop())
    def test_reject_missing_spec_hash(self):self.reject(lambda r:r['trace_validations'][0]['result'].pop('spec_sha256'))
    def test_reject_wrong_frozen_spec_hash(self):self.reject(lambda r:r['trace_validations'][0]['result'].__setitem__('spec_sha256','f'*64))
    def test_reject_wrong_trace_hash(self):self.reject(lambda r:r['trace_validations'][0]['result'].__setitem__('trace_sha256','f'*64))
    def test_reject_changed_frozen_trace_bytes(self):self.reject(lambda r:r['trace_validations'][0].__setitem__('frozen_trace_raw','{}'))
    def test_reject_wrong_tools_hash(self):self.reject(lambda r:r['trace_validations'][0]['result'].__setitem__('pinned_tools_record_sha256','f'*64))
    def test_reject_wrong_jar(self):self.reject(lambda r:r['trace_validations'][0]['result']['executed_tools']['tla_plus'].__setitem__('sha256','f'*64))
    def test_reject_wrong_jdk(self):self.reject(lambda r:r['trace_validations'][0]['result']['executed_tools']['jdk']['observed_properties'].__setitem__('java.version','99'))
    def test_reject_malformed_counted_accepted(self):
        self.reject(lambda r:r['trace_validations'][0]['result'].update(outcome='malformed',counted_as_accepted=True))
    def test_reject_tool_error(self):self.reject(lambda r:r['trace_validations'][0]['result'].__setitem__('outcome','tool_error'))
    def test_reject_unresolved_smoke_rejection(self):self.reject(lambda r:r['smoke_trace_findings'].append({'outcome':'rejected','resolved_by_owner':False}))
    def test_reject_unresolved_smoke_malformed(self):self.reject(lambda r:r['smoke_trace_findings'].append({'outcome':'malformed','resolved_by_owner':False}))
    def test_reject_post_hoc_trace(self):self.reject(lambda r:r['trace_validations'][0]['result'].__setitem__('post_hoc',True))
    def test_reject_unsealed_frozen_inputs(self):self.reject(lambda r:r['frozen_inputs'].pop('sha256'))
    def test_reject_inputs_frozen_after_live(self):self.reject(lambda r:r['frozen_inputs'].__setitem__('sealed_at','2027-01-01T00:00:00Z'))
    def test_reject_inputs_changed_after_live(self):self.reject(lambda r:r['frozen_inputs']['body']['inputs']['converter'].__setitem__('formal/trace_to_tla.py','f'*64))
    def test_reject_property_tools_mismatch(self):
        def change(r):r['tlc']['body']['executed_tools']['tla_plus']['size_bytes']=1;r['tlc']['sha256']=digest(r['tlc']['body'])
        self.reject(change)
    def test_reject_deadline_missing_delay(self):
        self.reject(lambda r:next(e for e in r['episodes'] if e['row']=='E2-native-b').__setitem__('deadline_ms',20010))
    def test_reject_no_change_prevention(self):
        self.reject(lambda r:next(e for e in r['episodes'] if e['family']=='S-A' and e['row']=='E2-native-a').__setitem__('runtime_outcome','accepted'))
    def test_reject_tie_credited_computed(self):
        def change(r):
            e=next(e for e in r['episodes'] if e['row']=='E2-extended-a' and e['family']=='S-B')
            e.update(outcome_basis='computed',effect_at_ms=e['action_interval_ms'],a0_at_ms=e['action_interval_ms'],a0_prevented=True)
        self.reject(change)
    def test_reject_computed_outcome_without_timestamps(self):
        self.reject(lambda r:next(e for e in r['episodes'] if e['row']=='E2-extended-a' and e['family']=='S-B').update(outcome_basis='computed'))
    def test_reject_grid_rule(self):
        def change(r):r['grid_finalization']['body']['placement']['rule']='chosen by eye';r['grid_finalization']['sha256']=digest(r['grid_finalization']['body'])
        self.reject(change)
    def test_reject_grid_not_1024(self):
        def change(r):r['grid_finalization']['body']['placement']['sample_count']=32;r['grid_finalization']['sha256']=digest(r['grid_finalization']['body'])
        self.reject(change)
    def test_reject_intake_replay(self):
        def change(r):
            e=r['episodes'][2];event=dict(type='receive',t=1,authority=[],message='m1',observation_id='id',nonce='n',signature_valid=True,peer_authorized=True,expires_at=2,interaction_id='i',receipt_interaction_id='i',receipt_verified=True,receipt_receiver_local=True,decision='accepted',selected=['deny_egress','target'])
            e['intake_events']=[event,{**event,'message':'m2'}]
        self.reject(change)
    def test_reject_property_top_level_jar_pin(self):
        def change(r):r['tlc']['body']['tool_sha256']='f'*64;r['tlc']['sha256']=digest(r['tlc']['body'])
        self.reject(change)
    def test_reject_property_config_outside_frozen_set(self):
        def change(r):r['tlc']['body']['config_sha256']='f'*64;r['tlc']['sha256']=digest(r['tlc']['body'])
        self.reject(change)
    def test_reject_property_witness_hash_mismatch(self):
        def change(r):r['tlc']['body']['property_trace_raw']='changed';r['tlc']['sha256']=digest(r['tlc']['body'])
        self.reject(change)
    def test_reject_empty_accepted_trace(self):
        def change(r):
            v=r['trace_validations'][0];raw=json.dumps({'trace_id':r['episodes'][0]['id'],'events':[]});h=sha256(raw.encode()).hexdigest()
            v['frozen_trace_raw']=raw;v['result'].update(trace_sha256=h,event_count=0,reached_events=0);r['episodes'][0]['replay']['trace_sha256']=h
        self.reject(change)
    def test_reject_grid_effect_samples_replaced(self):
        def change(r):r['grid_finalization']['body']['placement']['transitions'][0]['effect_samples_ms']=[0]*1024;r['grid_finalization']['sha256']=digest(r['grid_finalization']['body'])
        self.reject(change)
    def test_reject_separation_failure(self):
        from tcop.external_trace_validation import validate_placement
        r=fixture();p=r['grid_finalization']['body']['placement']
        for t in p['transitions']:
            if t['row']=='E2-extended-a':t.update(effect_samples_ms=[2000]*1024,transition_ms=math.nextafter(2000,math.inf))
        with self.assertRaises(TCOPCommandError):validate_placement(p,r['grid_finalization']['body'],r['calibration']['body'])
    def test_live_malformed_is_preserved_without_claiming_tlc_ran(self):
        r=fixture();v=r['trace_validations'][0];v['frozen_trace_raw']='';h=sha256(b'').hexdigest()
        v['result'].update(outcome='malformed',trace_sha256=h,tlc_used=False,executed_tools=None,first_rejected_step_index=None,first_rejected_record=None)
        v['finding']={'classification':'mapping_error','evidence':'synthetic invalid JSON','safety_stop':False}
        r['episodes'][0]['replay']['trace_sha256']=h
        self.assertTrue(self.check(r)['valid'])
    def test_non_utf8_malformed_trace_keeps_original_bytes(self):
        import base64
        r=fixture();v=r['trace_validations'][0];v.pop('frozen_trace_raw');raw=b'\xff invalid UTF8'
        v['frozen_trace_base64']=base64.b64encode(raw).decode();h=sha256(raw).hexdigest()
        v['result'].update(outcome='malformed',trace_sha256=h,tlc_used=False,executed_tools=None,first_rejected_step_index=None,first_rejected_record=None)
        v['finding']={'classification':'mapping_error','evidence':'synthetic invalid UTF8','safety_stop':False}
        r['episodes'][0]['replay']['trace_sha256']=h
        self.assertTrue(self.check(r)['valid'])
    def test_actual_tie_outcome_not_overridden(self):
        r=fixture();e=next(e for e in r['episodes'] if e['row']=='E2-extended-a' and e['family']=='S-B')
        e.update(outcome_basis='observed',effect_at_ms=8,a0_at_ms=8,a0_prevented=True)
        self.assertTrue(self.check(r)['valid'])
    def test_sa_baseline_prevention_kept_without_e2_credit(self):
        r=fixture();e=next(e for e in r['episodes'] if e['family']=='S-A' and e['row']=='E2-native-a')
        e['branches']['A0'].update(denied=True,counted_as_prevented=True,prevention_attribution='E1_baseline')
        e['harmful_sequence_end']='denial'
        keys=('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')
        e['replay']['live_outcome_sha256']=digest({k:e[k] for k in keys});e['replay']['replayed_outcome_sha256']=e['replay']['live_outcome_sha256']
        next(p for p in r['frontier'] if p['episode_id']==e['id'])['damage_prevented'].update(numerator=1,value=1)
        self.assertTrue(self.check(r)['valid'])
    def test_pending_classification_cannot_be_final_result(self):
        r=fixture();v=r['trace_validations'][0];v['result'].update(outcome='rejected',first_rejected_step_index=-1,first_rejected_record={'initial_authority':json.loads(v['frozen_trace_raw'])['initial_authority']})
        v['finding']={'classification':'pending','evidence':'synthetic pending review','safety_stop':False}
        with self.assertRaises(TCOPCommandError):self.check(r)
    def test_safety_stop_derived_from_rejected_authority_step(self):
        r=fixture();v=r['trace_validations'][0];trace=json.loads(v['frozen_trace_raw'])
        trace['events'][0]['authority']=trace['events'][0]['authority'][1:]
        raw=json.dumps(trace);v['frozen_trace_raw']=raw;h=sha256(raw.encode()).hexdigest()
        v['result'].update(outcome='rejected',trace_sha256=h,first_rejected_step_index=1,first_rejected_record=trace['events'][1])
        r['episodes'][0]['replay']['trace_sha256']=h
        v['finding']={'classification':'implementation_deviation','evidence':'synthetic regrant','safety_stop':False}
        with self.assertRaises(TCOPCommandError):self.check(r)
    def test_safety_stop_requires_no_subsequent_episode(self):
        r=fixture();v=r['trace_validations'][0];v['result'].update(outcome='rejected',first_rejected_step_index=-1,first_rejected_record={'initial_authority':json.loads(v['frozen_trace_raw'])['initial_authority']})
        v['finding']={'classification':'implementation_deviation','evidence':'synthetic command path','evidence_command_path':True,'safety_stop':True}
        r['episodes'][1]['started_at']='2026-11-02T00:06:00Z'
        with self.assertRaises(TCOPCommandError):self.check(r)
    def test_smoke_owner_resolution_can_follow_input_freeze_before_live(self):
        r=fixture();r.update(stage='admission',status='ADMISSION',valid_for_results=False);r['episodes']=[];r['frontier']=[];r['trace_validations']=[]
        for x in r['extensions']:x['contrasts']=[]
        r['smoke_trace_findings']=[{'outcome':'rejected','resolved_by_owner':True,'owner_resolution':'synthetic mapping corrected before live','resolved_at':'2026-11-02T00:04:45Z'}]
        self.assertTrue(self.check(r)['valid'])
    def test_rejected_live_trace_preserved_as_finding(self):
        r=fixture();v=r['trace_validations'][0];v['result'].update(outcome='rejected',first_rejected_step_index=-1,first_rejected_record={'initial_authority':json.loads(v['frozen_trace_raw'])['initial_authority']},reason='synthetic gap')
        v['finding']={'classification':'model_gap','evidence':'synthetic fixture only','safety_stop':False}
        self.assertTrue(self.check(r)['valid'])


class Plan15Tests(unittest.TestCase):
    def test_plan15_and_manifest005(self):
        from tcop.external_adaptive_crosshost import PLAN,_effective_plan_contract,run_external_adaptive,verify_external_adaptive
        p=load_config(PLAN);self.assertEqual(str(p['effective_plan_revision']),'1.5')
        self.assertTrue(_effective_plan_contract(p)['amendment_005'])
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            m=json.loads((root/'manifest.json').read_text());self.assertEqual(m['version'],'1.5');self.assertEqual(m['amendment_hashes']['005'],PIN)
            self.assertTrue(verify_external_adaptive(root)['valid'])
    def test_missing005_named_blocker(self):
        from tcop.external_adaptive_crosshost import PLAN,_preflight
        p=load_config(PLAN);p['amendments']=[a for a in p['amendments'] if a['id']!='005']
        self.assertTrue(any(b.startswith('AM005_EFFECTIVE_PLAN:') for b in _preflight(p)['blockers']))


class Manifest15IntegrationTests(unittest.TestCase):
    def test_complete_15_foundations_results_and_smoke_round_trip(self):
        from unittest.mock import patch
        import test_external_enforcement_v14 as legacy
        from tcop.external_adaptive_crosshost import PLAN
        case=legacy.Manifest14Tests('test_verified_v14_foundations_and_result_gate_round_trip')
        with patch.object(legacy,'fixture',fixture),patch.object(legacy,'PLAN',PLAN):
            case.test_verified_v14_foundations_and_result_gate_round_trip()
    def test_005_contract_does_not_relabel_valid004_as_invalid(self):
        from tcop.external_adaptive_crosshost import PLAN,_effective_plan_contract
        p=load_config(PLAN);p['amendments'][-1]['sha256']='f'*64
        result=_effective_plan_contract(p)
        self.assertTrue(result['amendment_004']);self.assertFalse(result['amendment_005'])


class IntakeTraceStateTests(unittest.TestCase):
    def test_replay_state_shared_across_episode_checks(self):
        from tcop.external_trace_validation import validate_intake_events
        from test_external_receiver_intake import ReceiverIntakeTests
        case=ReceiverIntakeTests();case.setUp();result=case.receive(case.observation())
        self.assertTrue(result.accepted);e=result.event
        ids=set();nonces=set();validate_intake_events([e],seen_ids=ids,seen_nonces=nonces)
        with self.assertRaises(TCOPCommandError):validate_intake_events([{**e,'message':'m2'}],seen_ids=ids,seen_nonces=nonces)


class Malformed005Tests(unittest.TestCase):
    def test_malformed_amendment_entry_gets_named_contract_blocker(self):
        from tcop.external_adaptive_crosshost import PLAN,_preflight
        p=load_config(PLAN);p['amendments'][-1]=None
        self.assertTrue(any(b.startswith('AM005_EFFECTIVE_PLAN:') for b in _preflight(p)['blockers']))
    def test_malformed_trace_entry_is_a_command_error(self):
        from tcop.external_enforcement_validation import validate_enforcement_records
        r=fixture();r['trace_validations'][0]='not_a_record'
        with self.assertRaises(TCOPCommandError):validate_enforcement_records(r)
