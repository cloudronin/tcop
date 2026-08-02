from __future__ import annotations
import unittest
from pathlib import Path
from tcop.independent_warning_admission import _evaluate, _normalizer, verify_independent_warning
class IndependentWarningTests(unittest.TestCase):
 def test_sealed_external_warning_artifact_preserves_thirty_items(self)->None:
  value=verify_independent_warning(Path("artifacts/independent-warning-admission-v1"))
  self.assertTrue(value["valid"]);self.assertEqual(value["items"],30);self.assertEqual(value["rows"],150)
 def test_declared_successor_normalizer_is_config_complete_and_admits_only_label_one(self)->None:
  normalizer=_normalizer({"normalizer":{"label_source":"model.config.id2label","label_to_category":{"LABEL_0":"no_warning","LABEL_1":"exact_binding"},"unknown_label":"reject"}}, {"LABEL_0","LABEL_1"})
  rows=_evaluate([{"case_id":"a","raw_label":"LABEL_0","input_digest":"0"*64},{"case_id":"b","raw_label":"LABEL_1","input_digest":"1"*64}],normalizer)
  self.assertEqual(sum(row["admitted"] for row in rows),5)
  self.assertEqual(sum(row["harmful_blocked"] for row in rows),4)
 def test_successor_normalizer_rejects_incomplete_model_label_mapping(self)->None:
  with self.assertRaises(Exception):_normalizer({"normalizer":{"label_source":"model.config.id2label","label_to_category":{"LABEL_0":"no_warning"},"unknown_label":"reject"}}, {"LABEL_0","LABEL_1"})
