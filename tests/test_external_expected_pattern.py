import copy
import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli_support import TCOPCommandError
from tcop.external_expected_pattern import seal_expected_pattern, verify_expected_pattern, validate_expected_pattern

DRAFT=Path('benchmark/studies/amendment-003-expected-pattern.json')

def fixture():
    r=json.loads(DRAFT.read_text()); r['status']='preregistered'; r['open_owner_issues']=[]
    r['bindings']={k:'a'*64 for k in ('plan_sha256','census_sha256','admission_sha256')}
    return r

class ExpectedPatternTests(unittest.TestCase):
    def test_fixture_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'prediction'; seal_expected_pattern(fixture(),root)
            self.assertEqual(verify_expected_pattern(root)['record'],fixture())

    def test_real_draft_cannot_be_sealed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TCOPCommandError): seal_expected_pattern(json.loads(DRAFT.read_text()),Path(d)/'seal')

    def test_missing_family(self):
        r=fixture(); del r['families']['S-C']
        with self.assertRaises(TCOPCommandError): validate_expected_pattern(r)

    def test_missing_prediction_or_binding(self):
        for family in ('S-A','S-B','S-C'):
            with self.subTest(family=family):
                r=fixture(); r['families'][family]=''
                with self.assertRaises(TCOPCommandError): validate_expected_pattern(r)
        for key in fixture()['bindings']:
            with self.subTest(key=key):
                r=fixture(); del r['bindings'][key]
                with self.assertRaises(TCOPCommandError): validate_expected_pattern(r)

    def test_open_owner_issues_rejected(self):
        r=fixture(); r['open_owner_issues']=[7]
        with self.assertRaises(TCOPCommandError): validate_expected_pattern(r)

    def test_unsealed_tampered_or_rebound(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'
            with self.assertRaises(TCOPCommandError): verify_expected_pattern(root)
            seal_expected_pattern(fixture(),root)
            with self.assertRaises(TCOPCommandError): verify_expected_pattern(root,bindings={'plan_sha256':'b'*64})
            (root/'record.json').write_text('{}')
            with self.assertRaises(TCOPCommandError): verify_expected_pattern(root)
