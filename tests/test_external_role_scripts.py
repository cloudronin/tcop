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

    def test_scope_path_remains_open(self):
        r=json.loads((SCRIPTS/'S-C.json').read_text())
        self.assertEqual(r['runtime_capability']['native_path'],'none')
        self.assertEqual(r['runtime_capability']['open_issue'],7)

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
