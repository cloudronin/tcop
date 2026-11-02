"""CLI uses fake host components; no process/network calls."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tcop.cli_support import TCOPCommandError
from test_external_conformance_checks import Probe
from test_external_tightening_adapter import bound,FakeTransport,Clock

class ConformanceCLITests(unittest.TestCase):
    def test_run_check_writes_record_with_fake_host(self):
        from tcop.external_conformance import main
        t=FakeTransport();t.events=[{'kind':'tuple','at_ms':20,'effect_at_ms':18,'sandbox_id':'sandbox-B','generation':'gen-1','container_id':'a'*64,'installed':True,'tuple_matches':True}]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);config=p/'config.json';config.write_text('{}')
            with patch('tcop.external_conformance.load_host_driver',return_value=(bound(),t,Probe('C1'),Clock())):
                self.assertEqual(main(['run','--config',str(config),'--check','C1','--binding','instant-egress','--output',str(p/'result.json')]),0)
            self.assertTrue(json.loads((p/'result.json').read_text())['passed'])
    def test_refuses_existing_output(self):
        from tcop.external_conformance import write_record
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'record.json';p.write_text('existing')
            with self.assertRaises(TCOPCommandError):write_record(p,{})
            self.assertEqual(p.read_text(),'existing')
