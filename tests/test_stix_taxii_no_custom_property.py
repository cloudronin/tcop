from __future__ import annotations

import unittest

from tcop.stix_native_mapping import audit_no_custom_properties, native_objects


class StixTaxiiNoCustomPropertyTests(unittest.TestCase):
    def test_native_fixture_has_no_tcop_or_custom_properties(self) -> None:
        self.assertTrue(audit_no_custom_properties(native_objects())["passed"])

    def test_native_audit_rejects_hidden_tcop_extension(self) -> None:
        objects = native_objects()
        objects[0]["extensions"] = {"x-tcop": {"receipt_ref": "hidden"}}
        result = audit_no_custom_properties(objects)
        self.assertFalse(result["passed"])
        self.assertTrue(result["findings"])
