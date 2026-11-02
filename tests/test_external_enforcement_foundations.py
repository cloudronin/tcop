"""Regression evidence for the amendment 003 foundation boundary."""
import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli_support import TCOPCommandError
from tcop.context_comparator import _root_digest
from tcop.external_adaptive_crosshost import verify_external_adaptive

class ManifestVersionTests(unittest.TestCase):
    def test_unknown_version_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'manifest.json').write_text(json.dumps({
                'version': '9.9', 'status': 'BLOCKED', 'evaluation_executed': False,
                'blockers': ['synthetic missing inputs']}))
            (root / 'artifact-root-digest.json').write_text(json.dumps({
                'artifact_root_digest': _root_digest(root)}))
            with self.assertRaisesRegex(TCOPCommandError, 'version'):
                verify_external_adaptive(root)

from copy import deepcopy
from unittest.mock import patch
from tcop.cli_support import load_config
from tcop.external_adaptive_crosshost import PLAN, _effective_plan_contract, _preflight, run_external_adaptive

class PlanAndSealTests(unittest.TestCase):
    def setUp(self):
        self.plan=load_config(PLAN)

    def test_plan_13_and_legacy_lists(self):
        self.assertEqual(str(self.plan['effective_plan_revision']),'1.3')
        self.assertTrue(_effective_plan_contract(self.plan)['amendment_003'])
        self.assertEqual(self.plan['conditions'],['E0','E1','E2','E2M','E2E','E3','S1','T2','S2'])
        self.assertEqual(self.plan['adaptive_branch_matrix']['A4']['trigger'],'any_harmful_branch_denied')

    def test_plan_each_ladder_gate(self):
        mutations=[lambda p:p.pop('enforcement_ladder'),
                   lambda p:p['amendments'].pop(),
                   lambda p:p['enforcement_ladder']['arms'].pop('E2'),
                   lambda p:p['enforcement_ladder'].__setitem__('pool_e2_modes',True),
                   lambda p:p['enforcement_ladder']['families'].pop('S-C')]
        for mutate in mutations:
            p=deepcopy(self.plan); mutate(p)
            with self.subTest(plan=p): self.assertFalse(_effective_plan_contract(p)['amendment_003'])

    def test_ladder_entries_cannot_enter_any_legacy_list(self):
        for where in ('conditions','valid_broader_risk','timing_phase_diagram'):
            p=deepcopy(self.plan)
            target=p['conditions'] if where=='conditions' else p[where]['required_conditions']
            target.append('enforcement_ladder.E0')
            with self.subTest(where=where): self.assertFalse(_effective_plan_contract(p)['amendment_003'])

    def test_named_plan_and_foundation_blockers(self):
        p=deepcopy(self.plan); p.pop('enforcement_ladder',None)
        with patch.dict('os.environ',{},clear=True): report=_preflight(p)
        blockers='\n'.join(report['blockers'])
        for name in ('AM003_EFFECTIVE_PLAN','AM003_ADMISSION','AM003_ROLE_CENSUS','AM003_EXPECTED_PATTERN',
                     'AM003_OPEN_ISSUE_7','AM003_OPEN_ISSUE_8','AM003_OPEN_ISSUE_10'):
            with self.subTest(name=name): self.assertIn(name,blockers)

    def test_13_amendment_sidecars_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'study'; run_external_adaptive(root)
            manifest=json.loads((root/'manifest.json').read_text())
            self.assertEqual(manifest['version'],'1.3')
            self.assertEqual(set(manifest['amendment_hashes']),{'001','002','003'})
            for suffix in ('canonical.json','sha256'): self.assertTrue((root/f'amendments/003.{suffix}').is_file())
            effective=json.loads((root/'effective-plan-manifest.json').read_text())
            self.assertEqual(set(effective['amendment_hashes']),{'001','002','003'})
            self.assertIn('expected_pattern_sha256',manifest)
            self.assertTrue(verify_external_adaptive(root)['valid'])

    def test_each_13_amendment_or_sidecar_tamper_rejected_after_root_reseal(self):
        from hashlib import sha256
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'study'; run_external_adaptive(root)
            paths=['amendments/001-stix-taxii-comparator.md','amendments/002-adaptive-mismatch-timing.md',
                   'amendments/003-enforcement-ladder.md','amendments/003.canonical.json','amendments/003.sha256',
                   'effective-plan-manifest.json','plan.canonical.json']
            for rel in paths:
                with self.subTest(path=rel):
                    path=root/rel; original=path.read_bytes(); path.write_text('{}')
                    (root/'artifact-root-digest.json').write_text(json.dumps({'artifact_root_digest':_root_digest(root)}))
                    with self.assertRaises(TCOPCommandError): verify_external_adaptive(root)
                    path.write_bytes(original)

    def test_legacy_versions_unchanged(self):
        from hashlib import sha256
        for version in ('1.1','1.2'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as d:
                root=Path(d); (root/'amendments').mkdir()
                targets={'001':'001-stix-taxii-comparator.md'}
                if version=='1.2': targets['002']='002-adaptive-mismatch-timing.md'
                hashes={}
                for key,name in targets.items():
                    (root/'amendments'/name).write_text('synthetic legacy input '+key)
                    hashes[key]=sha256((root/'amendments'/name).read_bytes()).hexdigest()
                manifest={'version':version,'status':'BLOCKED','evaluation_executed':False,'blockers':['synthetic legacy gate']}
                manifest.update({'amendment_hash':hashes['001']} if version=='1.1' else {'amendment_hashes':hashes})
                (root/'manifest.json').write_text(json.dumps(manifest))
                (root/'artifact-root-digest.json').write_text(json.dumps({'artifact_root_digest':_root_digest(root)}))
                before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                self.assertTrue(verify_external_adaptive(root)['valid'])
                self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_admission_seal_is_required_even_with_distinct_environment_hosts(self):
        with patch.dict('os.environ', {'TCOP_EXTERNAL_HOST_A':'host-a','TCOP_EXTERNAL_HOST_B':'host-b'},clear=True):
            report=_preflight(self.plan)
        self.assertTrue(any(b.startswith('AM003_ADMISSION:') for b in report['blockers']))

    def test_synthetic_admission_cannot_start_real_run(self):
        from tcop.external_enforcement_admission import seal_admission
        from test_external_enforcement_admission import example
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'admission'; seal_admission(example(),root)
            with patch.dict('os.environ', {'TCOP_EXTERNAL_HOST_A':'synthetic-host_a','TCOP_EXTERNAL_HOST_B':'synthetic-host_b'}, clear=True), patch('socket.gethostname',return_value='synthetic-runner'):
                report=_preflight(self.plan,admission=root)
            self.assertTrue(any(b.startswith('AM003_ADMISSION:') for b in report['blockers']))

    def test_verified_foundations_are_copied_bound_and_hashed(self):
        import contextlib
        import shutil
        from tcop.external_enforcement_admission import seal_admission
        from tcop.external_role_scripts import seal_roles
        from tcop.external_expected_pattern import seal_expected_pattern
        from tcop.external_foundation_seals import digest
        from test_external_enforcement_admission import example
        from test_external_expected_pattern import fixture
        from hashlib import sha256
        repo=Path.cwd()
        with tempfile.TemporaryDirectory() as d:
            work=Path(d); source=work/'role-inputs'
            shutil.copytree('benchmark/role-scripts/amendment-003',source)
            (work/'docs').mkdir(); (work/'docs/case-hugging-face.md').write_text('Synthetic fixture mapping only.')
            mapping_hash=sha256((work/'docs/case-hugging-face.md').read_bytes()).hexdigest()
            for path in source.glob('*.json'):
                r=json.loads(path.read_text()); r['status']='mapped'
                r['source_mapping']={'path':'docs/case-hugging-face.md','sha256':mapping_hash}
                path.write_text(json.dumps(r))
            plan=deepcopy(self.plan); plan['enforcement_ladder']['role_script_directory']=str(source)
            plan_path=work/'plan.json'; plan_path.write_text(json.dumps(plan))
            for amendment in plan['amendments']:
                target=work/amendment['source']; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(repo/amendment['source'],target)
            admission=example(); admission['synthetic_fixture']=False
            admission_seal=work/'admission'; a=seal_admission(admission,admission_seal)
            census_seal=work/'roles'; c=seal_roles(source,census_seal)
            prediction=fixture(); prediction['bindings']={'plan_sha256':digest(plan),'admission_sha256':a['record_sha256'],'census_sha256':c['census_sha256']}
            expected=work/'prediction'; e=seal_expected_pattern(prediction,expected)
            output=work/'run'
            with contextlib.chdir(work), patch.dict('os.environ',{'TCOP_EXTERNAL_HOST_A':'synthetic-host_a','TCOP_EXTERNAL_HOST_B':'synthetic-host_b'},clear=True),patch('socket.gethostname',return_value='synthetic-runner'),patch('tcop.external_adaptive_crosshost._source_roots',return_value={'federated_evidence':self.plan['source_roots']['federated_evidence'],'validation_value_v2':self.plan['source_roots']['validation_value_v2']}):
                run_external_adaptive(output,plan_path,admission=admission_seal,census=census_seal,expected_pattern=expected)
                manifest=json.loads((output/'manifest.json').read_text())
                self.assertEqual(manifest['expected_pattern_sha256'],e['record_sha256'])
                self.assertEqual(set(manifest['foundation_hashes']),{'admission','role-census','expected-pattern'})
                self.assertTrue(verify_external_adaptive(output)['valid'])
                manifest['expected_pattern_sha256']='f'*64
                (output/'manifest.json').write_text(json.dumps(manifest))
                (output/'artifact-root-digest.json').write_text(json.dumps({'artifact_root_digest':_root_digest(output)}))
                with self.assertRaises(TCOPCommandError): verify_external_adaptive(output)

    def test_malformed_ladder_is_false_instead_of_crashing(self):
        for section in ('enforcement_ladder','valid_broader_risk','timing_phase_diagram'):
            with self.subTest(section=section):
                p=deepcopy(self.plan); p[section]=['invalid']
                self.assertFalse(_effective_plan_contract(p)['amendment_003'])

    def test_malformed_amendments_and_condition_objects_fail_contract(self):
        for key,value in (('amendments',None),('conditions',[{'arm':'E0'}])):
            with self.subTest(key=key):
                p=deepcopy(self.plan); p[key]=value
                self.assertFalse(_effective_plan_contract(p)['amendment_003'])
        p=deepcopy(self.plan); p['amendments'].append(deepcopy(p['amendments'][-1]))
        self.assertFalse(_effective_plan_contract(p)['amendment_003'])

    def test_missing_003_plan_entry_still_seals_named_blocked_preflight(self):
        with tempfile.TemporaryDirectory() as d:
            plan=deepcopy(self.plan); plan['amendments']=[a for a in plan['amendments'] if a['id']!='003']
            path=Path(d)/'plan.json';path.write_text(json.dumps(plan));root=Path(d)/'run'
            run_external_adaptive(root,path)
            self.assertTrue(verify_external_adaptive(root)['valid'])
            self.assertTrue(any(b.startswith('AM003_EFFECTIVE_PLAN:') for b in json.loads((root/'manifest.json').read_text())['blockers']))

    def test_13_cannot_claim_complete_while_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            manifest=json.loads((root/'manifest.json').read_text());manifest['complete']=True
            (root/'manifest.json').write_text(json.dumps(manifest))
            (root/'artifact-root-digest.json').write_text(json.dumps({'artifact_root_digest':_root_digest(root)}))
            with self.assertRaises(TCOPCommandError): verify_external_adaptive(root)
