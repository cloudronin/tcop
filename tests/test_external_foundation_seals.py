import json
import tempfile
import unittest
from pathlib import Path
from tcop.cli_support import TCOPCommandError
from tcop.external_foundation_seals import write_seal, read_seal, read_json

class FoundationSealTests(unittest.TestCase):
    def test_no_new_output_inside_existing_seal(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'; write_seal(root,'fixture',{'record.json':{'synthetic':True}})
            before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with self.assertRaises(TCOPCommandError): write_seal(root/'nested','fixture',{'record.json':{}})
            self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_raw_json_member_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'; payload=b'{ "synthetic" : true }\n\n'
            write_seal(root,'fixture',{'record.json':payload})
            self.assertEqual((root/'record.json').read_bytes(),payload)
            self.assertEqual(read_seal(root,'fixture')['documents']['record.json'],{'synthetic':True})

    def test_symlink_and_extra_member_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'; write_seal(root,'fixture',{'record.json':{}})
            extra=root/'extra.json';extra.write_text('{}')
            with self.assertRaises(TCOPCommandError): read_seal(root,'fixture')
            extra.unlink();extra.symlink_to(root/'record.json')
            with self.assertRaises(TCOPCommandError): read_seal(root,'fixture')

    def test_duplicate_json_and_nonfinite_values_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'record.json'
            for data in ('{"a":1,"a":2}','{"a":NaN}'):
                with self.subTest(data=data):
                    path.write_text(data)
                    with self.assertRaises(TCOPCommandError): read_json(path)

    def test_traversal_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'seal'
            with self.assertRaises(TCOPCommandError): write_seal(root,'fixture',{'../escape.json':{}})
            self.assertFalse(root.exists())
