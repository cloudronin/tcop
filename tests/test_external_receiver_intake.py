"""Study intake acceptance uses real synthetic signatures, no network."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import unittest
from tcop.identity import AuthorityRegistry, KeyMaterial
from tcop.protocol import make_observation, resign
from tcop.validation import ObservationValidator
from tcop.witness import WitnessCluster,make_interaction_receipt,receipt_hash
from tcop.external_foundation_seals import digest


class ReceiverIntakeTests(unittest.TestCase):
    def setUp(self):
        from tcop.external_receiver_intake import ReceiverIntake
        self.cluster=WitnessCluster();self.signer=self.cluster.keys['node-2'];self.subject='agent-external-1';self.now=self.cluster.clock.now
        self.receipt=make_interaction_receipt(self.signer,self.cluster.keys[self.subject],self.cluster.control_groups,interaction_id='interaction-1',capability='tool:data.export',now=self.now)
        self.ref=receipt_hash(self.receipt)
        registry=AuthorityRegistry()
        for key in self.cluster.keys.values():registry.register(key.identity)
        self.validator=ObservationValidator(registry)
        self.intake=ReceiverIntake(self.validator,receiver_id='B',sandbox_id='sandbox-B',generation='gen-1',subject_id=self.subject,session_id='session-1',clock_origin_seconds=self.now)
        self.intake.register_receipt(self.receipt,receiver_id='B',sandbox_id='sandbox-B',generation='gen-1',session_id='session-1')
    def observation(self,seq=1,nonce='nonce-1',**kw):
        return make_observation(self.signer,subject_id=self.subject,observation_type='tool.prohibited_export',scope=['tool:data.export'],now=self.now,sequence_number=seq,nonce=nonce,metadata={'interaction_id':'interaction-1','interaction_receipt_hash':self.ref,'session_id':'session-1'},**kw)
    def receive(self,o):return self.intake.receive(o,now=self.now,t=0,selected=['deny_egress','target'],authority=[['egress','target'],['work','benign']])
    def test_replayed_id(self):
        o=self.observation();self.assertTrue(self.receive(o).accepted);self.assertFalse(self.receive(o).accepted)
    def test_replayed_nonce(self):
        self.assertTrue(self.receive(self.observation()).accepted);self.assertFalse(self.receive(self.observation(2)).accepted)
    def test_missing_nonce(self):self.assertFalse(self.receive(self.observation(nonce=None)).accepted)
    def test_absent_receipt(self):
        o=self.observation();o['metadata']['interaction_receipt_hash']='f'*64;self.assertFalse(self.receive(resign(o,self.signer)).accepted)
    def test_receipt_interaction_mismatch(self):
        o=self.observation();o['metadata']['interaction_id']='different';self.assertFalse(self.receive(resign(o,self.signer)).accepted)
    def test_unowned_receipt(self):
        self.intake.register_receipt(self.receipt,receiver_id='other',sandbox_id='sandbox-B',generation='gen-1',session_id='session-1')
        self.assertFalse(self.receive(self.observation()).accepted)
    def test_wrong_session(self):
        o=self.observation();o['metadata']['session_id']='wrong';self.assertFalse(self.receive(resign(o,self.signer)).accepted)
    def test_wrong_sandbox_generation(self):
        self.intake.register_receipt(self.receipt,receiver_id='B',sandbox_id='sandbox-B',generation='gen-2',session_id='session-1');self.assertFalse(self.receive(self.observation()).accepted)
    def test_expired(self):self.assertFalse(self.receive(self.observation(ttl=-1)).accepted)
    def test_unauthorized(self):
        o=self.observation();bad=KeyMaterial.deterministic('unknown','unadmitted');self.assertFalse(self.receive(resign(o,bad)).accepted)
    def test_invalid_signature(self):
        o=self.observation();o['severity']='critical';self.assertFalse(self.receive(o).accepted)
    def test_rejected_does_not_consume_replay_state(self):
        o=self.observation();bad=deepcopy(o);bad['signature']['value']='00'*64
        self.assertFalse(self.receive(bad).accepted);self.assertEqual(self.validator.replay.observation_ids,set());self.assertEqual(self.validator.replay.nonces,set())
        self.assertTrue(self.receive(o).accepted)
    def test_rejected_correlation_does_not_consume_nonce(self):
        o=self.observation();bad=deepcopy(o);bad['metadata']['interaction_id']='bad'
        self.assertFalse(self.receive(resign(bad,self.signer)).accepted);self.assertTrue(self.receive(o).accepted)
    def test_atomic_concurrent_acceptance(self):
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(self.receive,[self.observation() for _ in range(16)]))
        self.assertEqual(sum(r.accepted for r in results),1)
    def test_trace_shape_and_checks_are_actual(self):
        r=self.receive(self.observation());self.assertTrue(r.accepted)
        from tcop.external_trace_validation import validate_intake_events
        validate_intake_events([r.event]);self.assertEqual(r.event['interaction_id'],r.event['receipt_interaction_id'])
        self.assertTrue(r.event['signature_valid']);self.assertTrue(r.event['peer_authorized'])
    def test_rejected_bad_signature_not_logged_as_true(self):
        o=self.observation();o['signature']['value']='00'*64;r=self.receive(o)
        self.assertFalse(r.event['signature_valid']);self.assertTrue(r.event['peer_authorized']);self.assertIsNone(r.event['selected'])


class IntakeClockGates(unittest.TestCase):
    setUp=ReceiverIntakeTests.setUp
    observation=ReceiverIntakeTests.observation
    receive=ReceiverIntakeTests.receive
    def test_expiry_rechecked_at_actual_ready_event(self):
        self.intake.ready_clock=lambda:(self.now+61,61000)
        r=self.receive(self.observation())
        self.assertFalse(r.accepted);self.assertEqual(r.event['t'],61000)
        self.assertEqual(self.validator.replay.nonces,set())
    def test_nonce_outside_trace_identifier_domain_rejected(self):
        self.assertFalse(self.receive(self.observation(nonce='space nonce')).accepted)
    def test_expiry_is_not_rounded_into_trace_quantum(self):
        self.intake.tick_duration_ns=3
        r=self.receive(self.observation(ttl=61))
        self.assertFalse(r.accepted);self.assertIsNone(r.event['expires_at'])
        self.assertEqual(self.validator.replay.nonces,set())
    def test_nanosecond_trace_quantum_keeps_exact_receive_tick(self):
        from fractions import Fraction
        self.intake.tick_duration_ns=1
        r=self.intake.receive(self.observation(),now=Fraction(self.now)+Fraction(1234567,10**9),t=1234567,selected=['deny_egress','target'],authority=[])
        self.assertTrue(r.accepted);self.assertEqual(r.event['t'],1234567)
        self.assertEqual(r.ticket.ready_at_ms,1.234567)
