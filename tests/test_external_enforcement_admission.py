import copy
import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli_support import TCOPCommandError
from tcop.external_enforcement_admission import validate_admission, seal_admission, verify_admission

FIXTURE = Path('tests/fixtures/amendment-003-admission.json')

def example():
    return json.loads(FIXTURE.read_text())

class AdmissionTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)/'seal'
            seal_admission(example(), root)
            self.assertEqual(verify_admission(root)['record'], example())

    def test_each_missing_pin(self):
        for group, pins in example()['pins'].items():
            for key in pins:
                with self.subTest(group=group, key=key):
                    record = example(); del record['pins'][group][key]
                    with self.assertRaises(TCOPCommandError): validate_admission(record)

    def test_wrong_pin(self):
        r = example(); r['pins']['openshell']['commit'] = 'f'*40
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_missing_policy_hash(self):
        r=example(); del r['policy']['installed_effective_baseline_sha256']
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_preset_hash_missing_or_duplicate(self):
        for presets in ([{'name':'npm'}], [{'name':'npm','sha256':'a'*64}]*2):
            with self.subTest(presets=presets):
                r=example(); r['policy']['presets']=presets
                with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_each_machine_identity_collision(self):
        for left,right in (('host_a','host_b'),('runner','host_a'),('runner','host_b')):
            with self.subTest(left=left,right=right):
                r=example(); r['hosts'][left]['identity']=r['hosts'][right]['identity']
                with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_each_machine_attestation_collision(self):
        for left,right in (('host_a','host_b'),('runner','host_a'),('runner','host_b')):
            with self.subTest(left=left,right=right):
                r=example(); r['hosts'][left]['hardware_id_sha256']=r['hosts'][right]['hardware_id_sha256']
                with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_missing_attestation_fields(self):
        for role in example()['hosts']:
            for field in ('hardware_id_sha256','os_admin_account','administration_statement'):
                with self.subTest(role=role,field=field):
                    r=example(); del r['hosts'][role][field]
                    with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_notice_required_on_both_deployment_hosts(self):
        for role in ('host_a','host_b'):
            for value in (None, {'accepted':False,'version':'v0.0.140'}, {'accepted':True,'version':''}):
                with self.subTest(role=role,value=value):
                    r=example(); r['hosts'][role]['nemoclaw_notice']=value
                    with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_clock_measurement_required(self):
        for key,value in (('a_to_b_ms',float('nan')),('a_to_b_ms',True),('method',''),('measured_at','yesterday')):
            with self.subTest(key=key,value=value):
                r=example(); r['clock_offset'][key]=value
                with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_agent_release_mismatch(self):
        r=example(); r['arms']['E0']['agent_release']='2026.10.9'
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_baseline_mismatch(self):
        r=example(); r['arms']['E2']['baseline_policy_sha256']='b'*64
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_missing_sandbox_or_wrong_host(self):
        for key in ('id','name','workspace','gateway','host_identity'):
            with self.subTest(key=key):
                r=example(); r['sandbox'][key]=''
                with self.assertRaises(TCOPCommandError): validate_admission(r)
        r=example(); r['sandbox']['host_identity']='synthetic-host_a'
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_environment_binding(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'; seal_admission(example(),root)
            with self.assertRaises(TCOPCommandError):
                verify_admission(root, host_a='different',host_b='synthetic-host_b',runner='synthetic-runner')

    def test_unsealed_changed_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'
            with self.assertRaises(TCOPCommandError): verify_admission(root)
            seal_admission(example(),root)
            with self.assertRaises(TCOPCommandError): seal_admission(example(),root)
            (root/'record.json').write_text('{}')
            with self.assertRaises(TCOPCommandError): verify_admission(root)

    def test_resealed_invalid_record_rejected(self):
        from tcop.external_foundation_seals import write_seal
        with tempfile.TemporaryDirectory() as d:
            r=example(); r['arms']['E2']['baseline_policy_sha256']='b'*64
            root=Path(d)/'seal'; write_seal(root,'admission',{'record.json':r})
            with self.assertRaises(TCOPCommandError): verify_admission(root)

    def test_raw_hardware_identifier_rejected(self):
        r=example(); r['hosts']['host_a']['hardware_identifier']='raw-example-for-test'
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_notice_acceptance_is_boolean(self):
        r=example(); r['hosts']['host_a']['nemoclaw_notice']['accepted']=1
        with self.assertRaises(TCOPCommandError): validate_admission(r)

    def test_agent_tag_is_not_notice_version(self):
        r=example(); r['hosts']['host_a']['nemoclaw_notice']['version']='v0.0.140'
        with self.assertRaises(TCOPCommandError): validate_admission(r)
