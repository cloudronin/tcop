from __future__ import annotations

import unittest

from tcop.stix_native_mapping import MATRIX_ROWS, native_objects, semantic_capability_matrix, structural_validate_native_objects


class StixNativeMappingConformanceTests(unittest.TestCase):
    def test_native_fixture_has_required_structural_fields(self) -> None:
        result = structural_validate_native_objects(native_objects())
        self.assertTrue(result["passed"])
        self.assertEqual(result["external_pinned_schema_validator"], "not_admitted")

    def test_matrix_has_all_required_capabilities_and_evidence(self) -> None:
        rows = semantic_capability_matrix()
        self.assertEqual([row["Capability"] for row in rows], list(MATRIX_ROWS))
        for row in rows:
            for condition in ("S1", "T2", "S2"):
                self.assertIn(row[condition], {"standard", "local-composition", "TCOP-profile", "absent", "not-applicable"})
                self.assertTrue(row[condition + "_evidence"])
