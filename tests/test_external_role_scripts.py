import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli_support import TCOPCommandError
from tcop.external_role_scripts import census_roles, seal_roles, verify_roles, validate_script

SCRIPTS=Path('benchmark/role-scripts/amendment-003')

class RoleScriptTests(unittest.TestCase):
    def test_census_and_seal_roundtrip(self):
        census=census_roles(SCRIPTS)
        self.assertEqual({r['family'] for r in census['scripts']},{'S-A','S-B','S-C'})
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'roles'; seal_roles(SCRIPTS,root)
            self.assertEqual(verify_roles(root)['census'],census)

    def test_drafts_rejected_for_non_smoke(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'roles'; seal_roles(SCRIPTS,root)
            with self.assertRaises(TCOPCommandError): verify_roles(root,non_smoke=True)

    def test_unsealed_and_uncensused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'roles'
            with self.assertRaises(TCOPCommandError): verify_roles(root)
            seal_roles(SCRIPTS,root)
            with self.assertRaises(TCOPCommandError): verify_roles(root,script_id='not-in-census')

    def test_changed_after_seal(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source'; shutil.copytree(SCRIPTS,source)
            root=Path(d)/'roles'; seal_roles(source,root)
            p=source/'S-A.json'; r=json.loads(p.read_text()); r['harmful_intent']='changed'; p.write_text(json.dumps(r))
            with self.assertRaises(TCOPCommandError): verify_roles(root,scripts_dir=source)
            (root/'scripts/S-A.json').write_text('{}')
            with self.assertRaises(TCOPCommandError): verify_roles(root)

    def test_missing_family(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source'; shutil.copytree(SCRIPTS,source); (source/'S-C.json').unlink()
            with self.assertRaises(TCOPCommandError): census_roles(source)

    def test_each_script_gate(self):
        base=json.loads((SCRIPTS/'S-A.json').read_text())
        import copy
        for field in ('harmful_intent','A0','branches','public_source_tag','status'):
            with self.subTest(field=field):
                r=copy.deepcopy(base); del r[field]
                with self.assertRaises(TCOPCommandError): validate_script(r)
        for branch in ('A1','A2','A3','A4'):
            with self.subTest(branch=branch):
                r=copy.deepcopy(base); r['branches'][branch]['disposition']='pending'
                with self.assertRaises(TCOPCommandError): validate_script(r)

    def test_non_synthetic_target_rejected(self):
        r=json.loads((SCRIPTS/'S-A.json').read_text()); r['targets']=['https://example.com']
        with self.assertRaises(TCOPCommandError): validate_script(r)

    def test_native_provider_detach_remains_a_draft_mapping(self):
        r=json.loads((SCRIPTS/'S-C.json').read_text())
        self.assertEqual(r['runtime_capability']['native_path'],'DetachSandboxProvider')
        self.assertEqual(r['runtime_capability']['credential_unit'],'whole_provider')
        self.assertEqual(r['runtime_capability']['amendment_status'],'draft_pending_owner_seal')
        self.assertEqual(r['status'],'draft-pending-mapping')

    def test_mapping_required_even_if_status_changed(self):
        r=json.loads((SCRIPTS/'S-A.json').read_text()); r['status']='mapped'
        with self.assertRaises(TCOPCommandError): validate_script(r,non_smoke=True)

    def test_invalid_status_and_disposition_types_rejected(self):
        import copy
        for field in ('status','family'):
            with self.subTest(field=field):
                r=json.loads((SCRIPTS/'S-A.json').read_text()); r[field]=[]
                with self.assertRaises(TCOPCommandError): validate_script(r)
        r=json.loads((SCRIPTS/'S-A.json').read_text()); r['branches']['A1']['disposition']=[]
        with self.assertRaises(TCOPCommandError): validate_script(r)

    def test_source_byte_change_after_seal_is_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source'; shutil.copytree(SCRIPTS,source)
            root=Path(d)/'roles'; seal_roles(source,root)
            p=source/'S-A.json'; p.write_bytes(p.read_bytes()+b'\n')
            with self.assertRaises(TCOPCommandError): verify_roles(root,scripts_dir=source)

    def test_representable_a4_requires_independence_declaration(self):
        r=json.loads((SCRIPTS/'S-A.json').read_text())
        r['branches']['A4']['representable']=True
        r['branches']['A4']['disposition']='excluded_before_execution'
        with self.assertRaisesRegex(TCOPCommandError,'independen'):
            validate_script(r)

    def test_a4_independence_must_be_boolean_true(self):
        for value in (False,1,'true',None):
            with self.subTest(value=value):
                r=json.loads((SCRIPTS/'S-A.json').read_text())
                r['branches']['A4']['independent_of_harmful_side_effects']=value
                with self.assertRaisesRegex(TCOPCommandError,'independen'):
                    validate_script(r)

    def test_independent_representable_a4_is_valid(self):
        r=json.loads((SCRIPTS/'S-A.json').read_text())
        r['branches']['A4'].update(representable=True,disposition='excluded_before_execution',
                                 independent_of_harmful_side_effects=True)
        validate_script(r)

    def test_sc_requires_bound_b_replay_origin(self):
        import copy
        base=json.loads((SCRIPTS/'S-C.json').read_text())
        base.pop('replay_origin',None)
        with self.assertRaisesRegex(TCOPCommandError,'replay'):
            validate_script(base)
        valid={'domain':'B','boundary':'bound_domain_b_sandbox','actor':'domain_b_agent','egress':'domain_b_proxy'}
        for key in valid:
            with self.subTest(key=key):
                r=copy.deepcopy(base); r['replay_origin']=dict(valid);r['replay_origin'][key]='outside_b_sandbox'
                with self.assertRaisesRegex(TCOPCommandError,'replay'):
                    validate_script(r)
