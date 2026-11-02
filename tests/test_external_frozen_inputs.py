"""Frozen-input schema/writer, temporary roots only."""
from pathlib import Path
import tempfile
import unittest
from tcop.cli_support import TCOPCommandError


class FrozenInputTests(unittest.TestCase):
    def test_refuses_freeze_after_any_live_episode(self):
        from tcop.external_frozen_inputs import freeze_inputs
        with tempfile.TemporaryDirectory() as d,self.assertRaises(TCOPCommandError):freeze_inputs(Path(d)/'seal',first_live_at='2026-01-01T00:00:00Z')
    def test_missing_required_category(self):
        from tcop.external_frozen_inputs import build_inputs
        with self.assertRaises(TCOPCommandError):build_inputs({'spec_modules':[]},{'MaxMessages':7})
    def test_hashes_all_declared_inputs_and_seals_outside_formal(self):
        from tcop.external_frozen_inputs import freeze_inputs,verify_inputs
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'seal';r=freeze_inputs(target)
            self.assertTrue(verify_inputs(target)['valid']);self.assertIn('formal/tla/TCOPReceiver.tla',r['body']['inputs']['spec_modules'])
    def test_changed_input_after_seal_rejected(self):
        from tcop.external_frozen_inputs import freeze_inputs,verify_inputs
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'seal';freeze_inputs(target)
            p=target/'record.json';p.write_text('{}')
            with self.assertRaises(TCOPCommandError):verify_inputs(target)
