from __future__ import annotations

import unittest

from tcop.stix_tcx_profile import decode_tcx, encode_tcx, extension_definition, semantic_equivalence


class TcxStixProfileEquivalenceTests(unittest.TestCase):
    def test_profile_preserves_exact_context(self) -> None:
        context = {"accepted": True, "subject": "agent-17", "resource_namespace": "repo:finance", "capability_class": "repository.write", "scope": "guarded-capability"}
        self.assertEqual(decode_tcx(encode_tcx(context)), context)
        self.assertTrue(semantic_equivalence(context)["equivalent"])

    def test_extension_is_declared(self) -> None:
        definition = extension_definition()
        self.assertEqual(definition["type"], "extension-definition")
        self.assertEqual(definition["extension_types"], ["property-extension"])
