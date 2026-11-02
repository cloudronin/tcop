"""Runnable C1-C4 against deterministic fake controllers and transports."""
from copy import deepcopy
import unittest
from tcop.cli_support import TCOPCommandError
from tcop.external_foundation_seals import digest
from test_external_tightening_adapter import bound,candidate,FakeTransport,Clock


class Probe:
    def __init__(self,check,fail=False):self.check=check;self.fail=fail;self.released=False
    def measure(self,stage):
        if self.check=='C1':
            d={'target':stage=='before' or self.fail,'control':True,'other_sandbox':True,'inference':True,'supervisor':True,'fresh':True}
        elif self.check=='C2':
            d={'target_resolves':stage=='before' or self.fail,'group_peer_resolves':stage=='before',
               'unrelated_resolves':True,'new_request_existing_connection_resolves':stage=='before' or self.fail,'in_flight_staged':True,'in_flight_may_finish':True}
        elif self.check=='C3':
            d={'counters':[1,2] if stage=='before' else [2,3] if stage=='released' or self.fail else [1,2],
               'outside_counter':1 if stage=='before' else 2,'window_ms':1000,'restarted':False}
        else:
            d={'source_generation':'gen-1','markers':{'file':'known'},'execution_continues':True,'access_continues':True,'other_sandbox':True}
            if stage=='after':d.update(captured_markers={'file':'wrong' if self.fail else 'known'},coverage=['filesystem'],omissions=['memory','mounted_volumes'],artifact_sha256='d'*64,source_container_id='a'*64,paused=False)
        return d
    def release(self):self.released=True


def check_record(check,bid,fail=False):
    from tcop.external_conformance import run_check
    b=bound();t=FakeTransport(b);clock=Clock();p=Probe(check,fail)
    if bid.endswith('-1'):t.poll=1
    extra={};kind='tuple'
    if bid.startswith('native-egress'):kind='policy';extra=dict(status='LOADED',version=4,active_version=4,policy_hash='b'*64)
    elif bid.startswith('provider-detach'):
        kind='provider';t.ack={'detached':True,'provider_env_revision':'c'*64,'persisted_at_ms':2}
        extra=dict(message='Provider environment refreshed',fingerprint='c'*64,provider_absent=True,status='loaded',source='enforcing_supervisor',provider='synthetic-provider')
    elif bid=='freeze':kind='paused';extra={'paused':True}
    elif bid=='snapshot':kind='snapshot';extra={'artifact_sha256':'d'*64}
    else:extra={'installed':True,'tuple_matches':True}
    t.ack.update(persisted_at_ms=18 if check=='C4' else 2)
    if check=='C4':t.ack['image_id']='sha256:'+'d'*64
    t.events=[{'kind':kind,'at_ms':20,'effect_at_ms':18,'poll_at_ms':16,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,**extra}]
    return run_check(check,bid,b,t,p,clock,window_ms=1000)


class ConformanceTests(unittest.TestCase):
    def test_c1_failing_binding(self):self.assertFalse(check_record('C1','instant-egress',True)['passed'])
    def test_c2_failing_binding(self):self.assertFalse(check_record('C2','provider-detach-10',True)['passed'])
    def test_c3_failing_binding(self):self.assertFalse(check_record('C3','freeze',True)['passed'])
    def test_c4_failing_binding(self):self.assertFalse(check_record('C4','snapshot',True)['passed'])
    def test_all_checks_pass_at_required_configurations(self):
        for check,bid in [('C1','native-egress-10'),('C1','native-egress-1'),('C1','instant-egress'),('C2','provider-detach-10'),('C2','provider-detach-1'),('C3','freeze'),('C4','snapshot')]:
            with self.subTest(binding=bid):
                r=check_record(check,bid);self.assertTrue(r['passed'],r);self.assertEqual(r['writes'],1);self.assertEqual(r['effect_lag_ms'],18)
    def test_conformance_grade_tag_and_layering_are_not_asserted_by_caller(self):
        from tcop.external_conformance import evaluate_check
        for field,value in [('grade','does not meet'),('tag','native'),('layering','pure layering'),('implementation','arbitrary')]:
            r=check_record('C1','instant-egress');r[field]=value
            with self.subTest(field=field):self.assertFalse(evaluate_check(r))
    def test_freeze_replacement_fails(self):
        from tcop.external_conformance import evaluate_check
        r=check_record('C3','freeze');r['identity_after']['container_id']='f'*64
        self.assertFalse(evaluate_check(r))
    def test_no_claimed_pass_without_effect_evidence(self):
        from tcop.external_conformance import evaluate_check
        r=check_record('C1','instant-egress');r['observations']=[];self.assertFalse(evaluate_check(r))
    def test_snapshot_rejects_unrelated_image(self):
        from tcop.external_conformance import evaluate_check
        r=check_record('C4','snapshot');r['ack']['image_id']='sha256:'+'f'*64
        self.assertFalse(evaluate_check(r))
    def test_transport_failure_closes_failed_check_record(self):
        from tcop.external_conformance import run_check
        t=FakeTransport()
        def fail(w):raise OSError('synthetic disconnected driver')
        t.write=fail
        r=run_check('C1','instant-egress',bound(),t,Probe('C1'),Clock(),window_ms=1000)
        self.assertFalse(r['passed']);self.assertEqual(r['transport_error'],'OSError')
    def test_calibration_import_rejects_incomplete(self):
        from tcop.external_conformance import import_calibration
        with self.assertRaises(TCOPCommandError):import_calibration([],{},seed=42)
    def test_calibration_import_rejects_failed_input(self):
        from tcop.external_conformance import import_calibration
        with self.assertRaises(TCOPCommandError):import_calibration([check_record('C1','instant-egress',True)],{},seed=42)
    def test_calibration_import_complete_measured_input(self):
        from tcop.external_conformance import import_calibration
        from tcop.crosshost_sim import validate_calibration
        records=[check_record(c,b) for c,b in [('C1','native-egress-10'),('C1','native-egress-1'),('C1','instant-egress'),('C2','provider-detach-10'),('C2','provider-detach-1'),('C3','freeze')]]
        timings={'status':'measured','samples_ms':{'detection':[5],'signing':[2],'validation':[3]},'evidence_sha256':'e'*64}
        result=import_calibration(records,timings,seed=42);validate_calibration(result);self.assertEqual(result['status'],'calibrated')
    def test_calibration_import_does_not_trust_passing_boolean(self):
        from tcop.external_conformance import import_calibration
        r=check_record('C1','instant-egress',True);r['passed']=True
        with self.assertRaises(TCOPCommandError):import_calibration([r],{},seed=42)
