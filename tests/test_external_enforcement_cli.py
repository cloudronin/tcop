import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli import build_parser, dispatch
from tcop.cli_support import TCOPCommandError
from test_external_expected_pattern import fixture

class FoundationCLITests(unittest.TestCase):
    def call(self,*args):
        return dispatch(build_parser().parse_args(['study','external-adaptive',*map(str,args)]))[0]

    def test_admit_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'admission'
            self.call('admit','--record','tests/fixtures/amendment-003-admission.json','--output',output)
            self.assertTrue(self.call('admit','--verify',output)['valid'])

    def test_role_census_seal_verify(self):
        self.assertEqual(len(self.call('roles','census')['scripts']),3)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'roles'; self.call('roles','seal','--output',root)
            self.assertTrue(self.call('roles','verify','--artifact-dir',root)['valid'])
            with self.assertRaises(TCOPCommandError): self.call('roles','verify','--artifact-dir',root,'--non-smoke')

    def test_prediction_fixture_seal_verify_and_real_draft_refused(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'fixture.json';source.write_text(json.dumps(fixture()))
            root=Path(d)/'prediction';self.call('expected-pattern','seal','--input',source,'--output',root)
            self.assertTrue(self.call('expected-pattern','verify','--artifact-dir',root)['valid'])
            with self.assertRaises(TCOPCommandError): self.call('expected-pattern','seal','--input','benchmark/studies/amendment-003-expected-pattern.json','--output',Path(d)/'real')

    def test_run_accepts_foundation_options_and_stays_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'study'
            value=self.call('run','--output',root,'--admission',Path(d)/'absent','--census',Path(d)/'absent','--expected-pattern',Path(d)/'absent')
            self.assertEqual(value['status'],'BLOCKED')

    def test_later_phase_commands_are_absent(self):
        parser=build_parser()
        import contextlib,io
        for command in ('adapter-check','frontier','freeze','replay','smoke'):
            with self.subTest(command=command),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                parser.parse_args(['study','external-adaptive',command])
