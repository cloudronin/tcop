"""Finite adapter proof and effect-decision gates. Fake transports only."""
from copy import deepcopy
import itertools
import json
import unittest
from tcop.cli_support import TCOPCommandError
from tcop.external_enforcement_validation import ROWS,selected_binding
import test_external_receiver_intake as intake_tests


def bound():
    return {'sandbox_id':'sandbox-B','name':'B','workspace':'default','generation':'gen-1','container_id':'a'*64,
        'resource_version':7,'driver':'docker','bridge':'br-tcop','container_ip':'192.0.2.2',
        'destinations':{'target':{'rule_name':'synthetic','host':'synthetic.invalid','ip':'192.0.2.42','port':443,'initially_allowed':True},'relay':{'rule_name':'relay','host':'relay.invalid','ip':'192.0.2.43','port':443,'initially_allowed':False}},
        'family_targets':{'S-A':'relay','S-B':'target','S-C':'credential'},
        'providers':{'credential':{'name':'synthetic-provider','credentials':['credential','sibling'],'credential_bindings':[]}},
        'baseline_authority':[['egress','target'],['egress','control'],['credential','credential'],['credential','sibling'],['work','benign']],
        'instant_cut_admitted':True,'instant_cut_evidence':{'vm_root_access':True,'dedicated_routed_target':True,'off_bridge':True,'fresh_connections':True,'continuity':True,'initial_vm_namespace':True,'preinstalled_empty_named_set':True},
        'binding_pin':'d1155aa70042d3e2ee49dbfa15346b108b7c1d92'}


def candidate(family='S-B',row='E2-extended-a'):
    bid=selected_binding(family,row)
    action='freeze_sandbox' if bid=='freeze' else 'revoke_credential' if bid.startswith('provider') else 'deny_egress'
    return {'family':family,'row':row,'abstract_action':action,'binding_id':bid,'target':'sandbox' if action=='freeze_sandbox' else 'credential' if action=='revoke_credential' else 'relay' if family=='S-A' else 'target','sandbox_id':'sandbox-B','generation':'gen-1'}


class Clock:
    def __init__(self):self.ms=0;self.waits=[]
    def now_ms(self):return self.ms
    def wait_until(self,at):self.waits.append(at);self.ms=max(self.ms,at)


class FakeTransport:
    def __init__(self,b=None):self.bound=b or bound();self.calls=[];self.events=[];self.ack={'version':4,'policy_hash':'b'*64};self.poll=10
    def identity(self):return {**{k:self.bound[k] for k in ('sandbox_id','container_id','generation')},'poll_interval_secs':self.poll}
    def write(self,wire):self.calls.append(json.loads(wire));return deepcopy(self.ack)
    def observations(self,wire,ack,until_ms):return iter(deepcopy(self.events))


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.intake_case=intake_tests.ReceiverIntakeTests();self.intake_case.setUp();self.intake=self.intake_case.intake
        self.clock=Clock();self.transport=FakeTransport()
    def ticket(self,c=None):
        c=c or candidate();action='freeze' if c['abstract_action']=='freeze_sandbox' else c['abstract_action']
        return self.intake.receive(self.intake_case.observation(),now=self.intake_case.now,t=0,selected=[action,c['target']],authority=bound()['baseline_authority']).ticket
    def adapter(self):
        from tcop.external_tightening_adapter import TighteningAdapter
        return TighteningAdapter(bound(),self.intake,self.transport,self.clock)
    def run_action(self,c=None):return self.adapter().execute(self.ticket(c),c or candidate())
    def observed(self,kind='tuple',at=20,**extra):
        self.transport.events=[{'kind':kind,'at_ms':at,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,**extra}]
    def test_malformed_selection_types_reject_before_transport(self):
        c=candidate();c['target']=['target']
        with self.assertRaises(TCOPCommandError):self.adapter().execute(self.ticket(),c)
        self.assertEqual(self.transport.calls,[])
    def test_reject_widening_before_transport(self):
        c=candidate();c['abstract_action']='allow_egress'
        with self.assertRaises(TCOPCommandError):self.run_action(c)
        self.assertEqual(self.transport.calls,[])
    def test_reject_unvalidated_ticket(self):
        with self.assertRaises(TCOPCommandError):self.adapter().execute(None,candidate())
        self.assertEqual(self.transport.calls,[])
    def test_reject_wrong_generation_before_write(self):
        self.transport.bound={**bound(),'generation':'replacement'}
        with self.assertRaises(TCOPCommandError):self.run_action()
        self.assertEqual(self.transport.calls,[])
    def test_reject_more_than_one_write_per_tcx(self):
        a=self.adapter();t=self.ticket();a.execute(t,candidate())
        with self.assertRaises(TCOPCommandError):a.execute(t,candidate())
        self.assertEqual(len(self.transport.calls),1)
    def test_reject_accepted_on_rpc_only(self):self.assertEqual(self.run_action()['decision'],'timed_out')
    def test_tuple_readback_accepts(self):
        self.observed(installed=True,tuple_matches=True);self.assertEqual(self.run_action()['decision'],'accepted')
    def test_wrong_tuple_not_accepted(self):
        self.observed(installed=True,tuple_matches=False);self.assertEqual(self.run_action()['decision'],'timed_out')
    def test_late_effect_kept_after_timeout(self):
        self.observed(at=20001,installed=True,tuple_matches=True);r=self.run_action()
        self.assertEqual(r['decision'],'timed_out');self.assertEqual(r['late_effects'][0]['at_ms'],20001)
    def test_late_explicit_rejection_cannot_reopen_deadline(self):
        def write(w):self.transport.calls.append(json.loads(w));self.clock.ms=25000;return {'rejected':True,'reason':'late'}
        self.transport.write=write;r=self.run_action()
        self.assertEqual(r['decision'],'timed_out');self.assertEqual(r['late_rejection']['reason'],'late')
    def test_sa_absent_relay_is_a_valid_no_change_selection(self):
        from tcop.external_tightening_adapter import serialize_write,authority_after
        b=bound();b['destinations']['relay']={**b['destinations']['target'],'initially_allowed':False};b['family_targets']={'S-A':'relay','S-B':'target','S-C':'credential'}
        c=candidate('S-A','E2-native-a');c['target']='relay'
        self.assertTrue(serialize_write(b,c));self.assertEqual(authority_after(b,c),b['baseline_authority'])
    def test_readback_after_deadline_is_not_a_second_late_effect(self):
        base={'kind':'tuple','sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,'installed':True,'tuple_matches':True}
        self.transport.events=[{**base,'at_ms':20},{**base,'at_ms':30000}]
        r=self.run_action();self.assertEqual(r['decision'],'accepted');self.assertEqual(r['late_effects'],[])
    def test_late_observation_can_extend_beyond_default_window_without_write(self):
        a=self.adapter();r=a.execute(self.ticket(),candidate())
        self.observed(at=60000,installed=True,tuple_matches=True)
        a.observe_until(r,70000)
        self.assertEqual(r['decision'],'timed_out');self.assertEqual(r['late_effects'][0]['at_ms'],60000)
        self.assertEqual(len(self.transport.calls),1)
    def test_b_waits_3000_deadline_23000(self):
        r=self.run_action(candidate(row='E2-extended-b'));self.assertEqual(self.clock.waits[0],3000);self.assertEqual(r['deadline_ms'],23000)
    def test_policy_requires_exact_loaded_revision(self):
        self.observed('policy',status='LOADED',version=3,active_version=3,policy_hash='b'*64)
        self.assertEqual(self.run_action(candidate(row='E2-native-a'))['decision'],'timed_out')
    def test_policy_loaded_exact_accepts(self):
        self.observed('policy',status='LOADED',version=4,active_version=4,policy_hash='b'*64)
        self.assertEqual(self.run_action(candidate(row='E2-native-a'))['decision'],'accepted')
    def test_policy_superseded_rejected(self):
        self.observed('policy',status='SUPERSEDED',version=4)
        self.assertEqual(self.run_action(candidate(row='E2-native-a'))['decision'],'rejected')
    def test_no_change_rejected_no_credit(self):
        self.transport.ack={'no_change':True};r=self.run_action(candidate('S-A','E2-native-a'))
        self.assertEqual((r['binding_result'],r['decision'],r['reason']),('no_change','rejected','no_change'))
    def test_detach_refresh_requires_fingerprint_correlation(self):
        self.transport.ack={'detached':True,'provider_env_revision':'c'*64}
        self.observed('provider',message='Provider environment refreshed',fingerprint='d'*64,provider_absent=True,status='loaded',source='enforcing_supervisor',provider='synthetic-provider')
        self.assertEqual(self.run_action(candidate('S-C','E2-native-a'))['decision'],'timed_out')
    def test_detach_matched_refresh_accepts(self):
        self.transport.ack={'detached':True,'provider_env_revision':'c'*64}
        self.observed('provider',message='Provider environment refreshed',fingerprint='c'*64,provider_absent=True,status='loaded',source='enforcing_supervisor',provider='synthetic-provider')
        self.assertEqual(self.run_action(candidate('S-C','E2-native-a'))['decision'],'accepted')
    def test_freeze_paused_readback(self):
        self.observed('paused',paused=True);self.assertEqual(self.run_action(candidate('S-C','E2-extended-a'))['decision'],'accepted')
    def test_minimum_poll_verified(self):
        with self.assertRaises(TCOPCommandError):self.run_action(candidate(row='E2-native-min-a'))
        self.assertEqual(self.transport.calls,[])
    def test_rejection_is_explicit(self):
        self.transport.ack={'rejected':True,'reason':'binding referenced'};self.assertEqual(self.run_action()['decision'],'rejected')
    def test_time_to_block_never_refresh_rpc(self):
        self.observed(installed=True,tuple_matches=True);r=self.run_action();self.assertEqual(r['time_to_block'],'never')
    def test_credential_denial_on_existing_connection_is_block_event(self):
        self.transport.events=[{'kind':'denial','source':'attributed_denial','at_ms':40,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,'attributed':True,'fresh':False,'target':'credential','action_id':'A0'}]
        self.assertEqual(self.run_action(candidate('S-C','E2-native-a'))['time_to_block']['at_ms'],40)
    def test_no_change_denial_never_gets_adapter_block_credit(self):
        self.transport.ack={'no_change':True}
        self.transport.events=[{'kind':'denial','at_ms':40,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,'attributed':True,'fresh':True,'target':'target','action_id':'A0'}]
        self.assertEqual(self.run_action(candidate('S-A','E2-native-a'))['time_to_block'],'never')
    def test_first_attributed_failed_fresh_connection_only(self):
        self.transport.events=[{'kind':'denial','at_ms':40,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,'attributed':True,'fresh':True,'target':'target','action_id':'A0'}]
        self.assertEqual(self.run_action()['time_to_block']['at_ms'],40)
    def test_intake_selection_cannot_change_before_write(self):
        t=self.ticket()
        with self.assertRaises(TCOPCommandError):self.adapter().execute(t,candidate('S-C','E2-extended-a'))
        self.assertEqual(self.transport.calls,[])
    def test_dispatch_latency_recorded_without_moving_deadline(self):
        self.clock.ms=0.125
        r=self.run_action()
        self.assertEqual(r['submission_deviation_ms'],0.125)
        self.assertEqual(r['deadline_ms'],20000)
    def test_boundary_rejects_payload_tampering(self):
        from tcop.external_tightening_adapter import serialize_write,validate_wire
        wire=json.loads(serialize_write(bound(),candidate()));wire['payload']['operation']='accept'
        with self.assertRaises(TCOPCommandError):validate_wire(bound(),json.dumps(wire).encode())
    def test_instant_cut_missing_admission_rejected(self):
        from tcop.external_tightening_adapter import serialize_write
        b=bound();b['instant_cut_evidence']['vm_root_access']=False
        with self.assertRaises(TCOPCommandError):serialize_write(b,candidate())


class CannotWidenProof(unittest.TestCase):
    def test_exhaustive_representable_output_space_and_wire_boundary(self):
        from tcop.external_tightening_adapter import serialize_write,validate_wire,authority_after
        actions=['deny_egress','revoke_credential','freeze_sandbox','snapshot_sandbox','allow_egress','attach_provider','grant_credential','unfreeze','unpause','restore','exec']
        targets=['target','relay','credential','sibling','sandbox','control','unadmitted']
        identities=['sandbox-B','sandbox-A'];generations=['gen-1','gen-2']
        bindings=['native-egress-10','native-egress-1','instant-egress','provider-detach-10','provider-detach-1','freeze','snapshot','add-rule']
        accepted=0;count=0
        case=intake_tests.ReceiverIntakeTests();case.setUp();ticket=case.receive(case.observation()).ticket
        transport=FakeTransport()
        from tcop.external_tightening_adapter import TighteningAdapter
        adapter=TighteningAdapter(bound(),case.intake,transport,Clock())
        for family,row,action,target,sandbox,generation,binding in itertools.product(['S-A','S-B','S-C','capability'],[*ROWS,'capability'],actions,targets,identities,generations,bindings):
            count+=1;c=dict(family=family,row=row,abstract_action=action,target=target,sandbox_id=sandbox,generation=generation,binding_id=binding)
            try:wire=serialize_write(bound(),c,capability=row=='capability')
            except TCOPCommandError:
                with self.assertRaises(TCOPCommandError):adapter.execute(ticket,c)
                self.assertEqual(transport.calls,[])
                continue
            accepted+=1;validated=validate_wire(bound(),wire,capability=row=='capability');after=authority_after(bound(),validated['selection'])
            self.assertLessEqual(set(map(tuple,after)),set(map(tuple,bound()['baseline_authority'])))
            self.assertIn(action,['deny_egress','revoke_credential','freeze_sandbox','snapshot_sandbox'])
            if action=='snapshot_sandbox':self.assertEqual(row,'capability')
        self.assertEqual(count,78848);self.assertEqual(accepted,16)
