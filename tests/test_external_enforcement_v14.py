"""Plan/manifest 1.4, admission and verifier integration. No live execution."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tcop.cli_support import TCOPCommandError, load_config
from tcop.context_comparator import _root_digest
from tcop.external_adaptive_crosshost import PLAN, _effective_plan_contract, _preflight, run_external_adaptive, verify_external_adaptive, report_external_adaptive
from tcop.external_enforcement_admission import validate_admission, seal_admission, verify_admission
from tcop.external_foundation_seals import digest, write_seal
from test_external_enforcement_validation import fixture, ep, refresh_hashes

SEAL='9546e30627eab69924f47d595fa536da22acee8edd818d1b268eee8ba02b0706'


def admission_fixture():
    r=fixture(); r.update(stage='admission',status='ADMISSION',valid_for_results=False)
    r['episodes']=[]; r['frontier']=[]
    for extension in r['extensions']:extension['contrasts']=[]
    return r


class Plan14Tests(unittest.TestCase):
    def setUp(self): self.plan=load_config(PLAN)

    def test_plan_14_and_named_contract(self):
        self.assertEqual(str(self.plan['effective_plan_revision']),'1.4')
        self.assertTrue(_effective_plan_contract(self.plan)['amendment_004'])
        self.assertTrue(_effective_plan_contract(self.plan)['amendment_003'])
        entry=next(a for a in self.plan['amendments'] if a['id']=='004')
        self.assertEqual(entry['sha256'],SEAL)
        self.assertEqual(sha256(Path(entry['source']).read_bytes()).hexdigest(),SEAL)

    def test_legacy_grid_and_lists_preserved_in_legacy_contract(self):
        old=load_config(Path('tests/fixtures/amendment-003-plan-1.3.json'))
        self.assertTrue(_effective_plan_contract(old)['amendment_003'])
        self.assertTrue(_effective_plan_contract(old)['timing_phase_diagram'])
        old['timing_phase_diagram']['action_interval_ms']=[25,400,5000,20000]
        self.assertFalse(_effective_plan_contract(old)['timing_phase_diagram'])
        for key in ('conditions','valid_broader_risk','timing_phase_diagram'):
            value=lambda p: p[key] if key=='conditions' else p[key]['required_conditions']
            self.assertEqual(value(self.plan),value(load_config(Path('tests/fixtures/amendment-003-plan-1.3.json'))))
        self.assertEqual(self.plan['timing_phase_diagram']['action_interval_ms'],[25,400,5000,20000])
        self.assertEqual(self.plan['timing_phase_diagram']['legacy_action_interval_ms'],[25,100,250,500])

    def test_a4_and_retry_triggers(self):
        branches=self.plan['adaptive_branch_matrix']
        self.assertEqual(branches['A4']['trigger'],'harmful_attempts_stop_by_denial_success_or_exhaustion')
        self.assertIs(branches['A4']['independent_of_harmful_side_effects'],True)
        old=load_config(Path('tests/fixtures/amendment-003-plan-1.3.json'))
        for key in ('A1','A2','A3'):self.assertEqual(branches[key],old['adaptive_branch_matrix'][key])

    def test_each_004_plan_gate_rejects(self):
        changes=[lambda p:p['amendments'].pop(),
          lambda p:p['amendments'][-1].__setitem__('sha256','f'*64),
          lambda p:p['enforcement_ladder']['rows_per_cell'].pop(),
          lambda p:p['enforcement_ladder']['approval_delay'].__setitem__('D_ms',1),
          lambda p:p['enforcement_ladder']['poll_configurations'].__setitem__('E2-native-min-a',0),
          lambda p:p['enforcement_ladder']['selection']['S-B'].__setitem__('E2-extended-a','freeze'),
          lambda p:p['enforcement_ladder']['bindings']['instant-egress'].__setitem__('layering','pure layering'),
          lambda p:p['enforcement_ladder'].pop('grid_finalization_record'),
          lambda p:p['enforcement_ladder'].pop('tlc_pass_record'),
          lambda p:p['enforcement_ladder']['expected_pattern_requirement'].pop('calibration_sha256'),
          lambda p:p['enforcement_ladder']['abstract_actions'].pop('deny_egress'),
          lambda p:p['enforcement_ladder']['binding_table']['freeze_sandbox'].__setitem__('native_grade','meets'),
          lambda p:p['timing_phase_diagram'].__setitem__('action_interval_ms',[25,100,250,500]),
          lambda p:p['adaptive_branch_matrix']['A4'].__setitem__('trigger','any_harmful_branch_denied')]
        for mutate in changes:
            p=deepcopy(self.plan);mutate(p)
            with self.subTest(plan=p): self.assertFalse(_effective_plan_contract(p)['amendment_004'])

    def test_missing_004_has_own_preflight_blocker_no_owner_blockers(self):
        p=deepcopy(self.plan);p['amendments']=[a for a in p['amendments'] if a['id']!='004']
        report=_preflight(p)
        self.assertTrue(any(b.startswith('AM004_EFFECTIVE_PLAN:') for b in report['blockers']))
        self.assertFalse(any('OPEN_ISSUE' in b for b in report['blockers']))
        self.assertTrue(any(b.startswith('AM004_VALIDATION_RECORDS:') for b in report['blockers']))


class Manifest14Tests(unittest.TestCase):
    def reseal(self,root):
        (root/'artifact-root-digest.json').write_text(json.dumps({'artifact_root_digest':_root_digest(root)}))

    def test_manifest_14_copies_all_four_with_sidecars(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            m=json.loads((root/'manifest.json').read_text());self.assertEqual(m['version'],'1.4')
            self.assertEqual(set(m['amendment_hashes']),{'001','002','003','004'})
            self.assertEqual(m['amendment_hashes']['004'],SEAL)
            self.assertTrue((root/'amendments/004-runtime-bindings.md').is_file())
            for ext in ('canonical.json','sha256'):self.assertTrue((root/f'amendments/004.{ext}').is_file())
            self.assertEqual(json.loads((root/'effective-plan-manifest.json').read_text())['amendment_hashes'],m['amendment_hashes'])
            self.assertTrue(verify_external_adaptive(root)['valid'])

    def test_004_bytes_and_sidecars_rejected_even_with_new_root(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            for name in ('004-runtime-bindings.md','004.canonical.json','004.sha256'):
                p=root/'amendments'/name;original=p.read_bytes();p.write_text('{}');self.reseal(root)
                with self.subTest(name=name),self.assertRaises(TCOPCommandError):verify_external_adaptive(root)
                p.write_bytes(original)

    def test_self_consistent_004_replacement_rejected_by_pinned_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            p=root/'amendments/004-runtime-bindings.md';p.write_text('Synthetic substituted amendment')
            replacement=sha256(p.read_bytes()).hexdigest()
            for name in ('manifest.json','effective-plan-manifest.json'):
                record=json.loads((root/name).read_text());record['amendment_hashes']['004']=replacement;(root/name).write_text(json.dumps(record))
            (root/'amendments/004.sha256').write_text(replacement+'\n')
            meta=json.loads((root/'amendments/004.canonical.json').read_text());meta['sha256']=replacement;(root/'amendments/004.canonical.json').write_text(json.dumps(meta))
            self.reseal(root)
            with self.assertRaises(TCOPCommandError):verify_external_adaptive(root)

    def test_verify_runs_semantic_gates_after_resealing_records(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'run';run_external_adaptive(root)
            record=admission_fixture();record['profiles'][2]['tag']='harness'
            (root/'enforcement-validation.json').write_text(json.dumps(record))
            for name in ('manifest.json','effective-plan-manifest.json'):
                m=json.loads((root/name).read_text());m['validation_records_sha256']=digest(record);(root/name).write_text(json.dumps(m))
            self.reseal(root)
            with self.assertRaisesRegex(TCOPCommandError,'AM004_SELECTION_BINDING'):verify_external_adaptive(root)

    def test_13_full_artifact_still_verifies_unchanged(self):
        # Construct the exact 1.3 closure without rewriting historical artifacts.
        from tcop.external_adaptive_crosshost import OWNER_BLOCKERS, FEDERATED, VALIDATION_V2
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'amendments').mkdir()
            plan=load_config(Path('tests/fixtures/amendment-003-plan-1.3.json'));ph=digest(plan)
            docs={};targets={'001':'001-stix-taxii-comparator.md','002':'002-adaptive-mismatch-timing.md','003':'003-enforcement-ladder.md'}
            for a in plan['amendments']:
                key=a['id'];data=Path(a['source']).read_bytes();h=sha256(data).hexdigest();docs[key]=h
                (root/'amendments'/targets[key]).write_bytes(data)
                (root/f'amendments/{key}.canonical.json').write_text(json.dumps({'id':key,'path':a['source'],'sha256':h}))
                (root/f'amendments/{key}.sha256').write_text(h+'\n')
            blockers=OWNER_BLOCKERS+['AM003_ADMISSION: missing','AM003_ROLE_CENSUS: missing','AM003_EXPECTED_PATTERN: missing']
            m={'artifact_type':'external-warning-adaptive-crosshost','version':'1.3','status':'BLOCKED','complete':False,'evaluation_executed':False,'blockers':blockers,'plan_hash':ph,'amendment_hashes':docs,'foundation_hashes':{},'expected_pattern_sha256':None}
            values={'manifest.json':m,'plan.canonical.json':plan,'study-plan.yaml':plan,'effective-plan-manifest.json':{'effective_plan_revision':1.3,'plan_hash':ph,'amendment_hashes':docs,'foundation_hashes':{},'expected_pattern_sha256':None},'preflight-report.json':{'status':'BLOCKED','blockers':blockers},'source-roots.json':{'federated_evidence':FEDERATED,'validation_value_v2':VALIDATION_V2}}
            for name,value in values.items():(root/name).write_text(json.dumps(value))
            (root/'plan.sha256').write_text(ph+'\n');self.reseal(root)
            before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertTrue(verify_external_adaptive(root)['valid'])
            self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})


    def test_verified_v14_foundations_and_result_gate_round_trip(self):
        import contextlib
        import shutil
        from datetime import datetime, timezone
        from tcop.external_role_scripts import seal_roles
        from tcop.external_expected_pattern import seal_expected_pattern
        from tcop.external_enforcement_validation import SOURCE_ROOTS
        repo=Path.cwd();bundle=fixture();plan=load_config(PLAN)
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);source=work/'role-inputs';source.mkdir();(work/'docs').mkdir()
            mapping=work/'docs/case-hugging-face.md';mapping.write_text('Synthetic mapping fixture, not public-source admission evidence.')
            for script in bundle['scripts']:
                script['content']['source_mapping']['sha256']=sha256(mapping.read_bytes()).hexdigest()
                script['sha256']=digest(script['content'])
                (source/(script['script_id']+'.json')).write_text(json.dumps(script['content']))
            for row in bundle['census']['body']['scripts']:
                row['sha256']=next(s['sha256'] for s in bundle['scripts'] if s['script_id']==row['script_id'])
            plan['enforcement_ladder']['role_script_directory']=str(source);plan['seed']=42
            for amendment in plan['amendments']:
                target=work/amendment['source'];target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(repo/amendment['source'],target)
            with patch('tcop.external_foundation_seals.datetime',wraps=datetime) as clock:
                clock.now.return_value=datetime(2026,11,2,0,0,tzinfo=timezone.utc)
                roles=work/'census';c=seal_roles(source,roles)
                bundle['admission']['synthetic_fixture']=False
                binding={'plan_sha256':digest(plan),'census_sha256':c['census_sha256'],'admission_sha256':digest(bundle['admission'])}
                bundle['foundation_bindings']=binding
                bundle['expected_pattern']['body']['bindings']=deepcopy(binding)
                refresh_hashes(bundle)
                clock.now.return_value=datetime(2026,11,2,0,3,tzinfo=timezone.utc)
                prediction=work/'prediction';seal_expected_pattern(bundle['expected_pattern']['body'],prediction)
                prospective=deepcopy(bundle);prospective.update(stage='admission',status='ADMISSION',valid_for_results=False)
                prospective['episodes']=[];prospective['frontier']=[]
                for extension in prospective['extensions']:extension['contrasts']=[]
                admitted=deepcopy(bundle['admission']);admitted['schema']='tcop.external-enforcement-admission/1.1';admitted['validation_records']=prospective
                admission=work/'admission';clock.now.return_value=datetime(2026,11,2,0,4,tzinfo=timezone.utc)
                seal_admission(admitted,admission)
            plan_path=work/'plan.json';plan_path.write_text(json.dumps(plan));root=work/'run'
            with contextlib.chdir(work),patch.dict('os.environ',{'TCOP_EXTERNAL_HOST_A':'synthetic-host_a','TCOP_EXTERNAL_HOST_B':'synthetic-host_b'},clear=True),patch('socket.gethostname',return_value='synthetic-runner'),patch('tcop.external_adaptive_crosshost._source_roots',return_value=SOURCE_ROOTS):
                run_external_adaptive(root,plan_path,admission=admission,census=roles,expected_pattern=prediction)
                self.assertTrue(verify_external_adaptive(root)['valid'])
                self.assertEqual(json.loads((root/'enforcement-validation.json').read_text()),prospective)
                # A record-only result fixture, never an executed study or runner.
                (root/'enforcement-validation.json').write_text(json.dumps(bundle))
                for name in ('manifest.json','effective-plan-manifest.json'):
                    m=json.loads((root/name).read_text());m['validation_records_sha256']=digest(bundle)
                    if name=='manifest.json':m.update(status='COMPLETE',complete=True,evaluation_executed=True,valid_for_results=True,blockers=[])
                    (root/name).write_text(json.dumps(m))
                preflight=json.loads((root/'preflight-report.json').read_text());preflight.update(status='READY',blockers=[])
                (root/'preflight-report.json').write_text(json.dumps(preflight));self.reseal(root)
                self.assertTrue(verify_external_adaptive(root)['valid_for_results'])
                self.assertEqual(report_external_adaptive(root)['status'],'COMPLETE')
                # Well-formed smoke is verifiable but every result reader refuses it.
                bundle.update(stage='smoke',status='SMOKE_INVALID_FOR_RESULTS',valid_for_results=False)
                (root/'enforcement-validation.json').write_text(json.dumps(bundle))
                for name in ('manifest.json','effective-plan-manifest.json'):
                    m=json.loads((root/name).read_text());m['validation_records_sha256']=digest(bundle)
                    if name=='manifest.json':m.update(status='SMOKE_INVALID_FOR_RESULTS',valid_for_results=False)
                    (root/name).write_text(json.dumps(m))
                self.reseal(root);self.assertTrue(verify_external_adaptive(root)['valid'])
                with self.assertRaises(TCOPCommandError):report_external_adaptive(root)

    def test_report_refuses_14_smoke(self):
        with patch('tcop.external_adaptive_crosshost.verify_external_adaptive',return_value={'valid':True,'version':'1.4','status':'SMOKE_INVALID_FOR_RESULTS','valid_for_results':False}):
            with self.assertRaises(TCOPCommandError):report_external_adaptive(Path('/synthetic/not-read'))


class Admission14Tests(unittest.TestCase):
    def record(self):
        bundle=admission_fixture();r=deepcopy(bundle['admission'])
        r['schema']='tcop.external-enforcement-admission/1.1';r['validation_records']=bundle
        return r

    def test_v14_admission_round_trip_and_semantic_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'admission';r=self.record();seal_admission(r,root)
            self.assertTrue(verify_admission(root)['valid'])
            r['validation_records']['profiles'][2]['tag']='harness'
            with self.assertRaisesRegex(TCOPCommandError,'AM004_SELECTION_BINDING'):validate_admission(r)

    def test_admission_sealer_returns_cycle_free_base_hash(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.record();result=seal_admission(r,Path(d)/'seal')
            self.assertEqual(result['base_record_sha256'],digest(r['validation_records']['admission']))

    def test_new_admission_cannot_omit_validation_records(self):
        r=self.record();r.pop('validation_records')
        with self.assertRaises(TCOPCommandError):validate_admission(r)


    def test_admission_bundle_cannot_carry_raw_efficacy_contrasts(self):
        r=self.record();r['validation_records']['extensions'][0]['contrasts']=[{'raw':{'synthetic':1}}]
        with self.assertRaises(TCOPCommandError):validate_admission(r)

    def test_new_admission_cannot_bind_another_host_record(self):
        r=self.record();r['validation_records']['admission']['hosts']['host_a']['identity']='different'
        with self.assertRaises(TCOPCommandError):validate_admission(r)
