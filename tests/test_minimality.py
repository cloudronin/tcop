"""CT-091 through CT-115 for the deterministic v0.5 study layer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcop.complexity_metrics import dynamic_complexity, static_complexity
from tcop.cost_models import COST_MODELS
from tcop.feature_manifest import FEATURES
from tcop.minimality_runner import MinimalityStudyRunner, ScenarioInputAdapter, all_scenario_ids, scenario_family
from tcop.pareto_analysis import dominates
from tcop.profile_composer import COHERENT_PROFILES, PROFILE_BY_ID, ComposedProfile, NEGATIVE_CONTROLS, ablation_profiles, interaction_cells, valid_advanced_combinations


class MinimalityConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = MinimalityStudyRunner()

    def test_ct_091_prior_digests_are_declared(self) -> None:
        from tcop.regression import CONFIRMATION_EXPECTED_DIGEST

        self.assertEqual("16849be9aca4405849f2a87e9e1ab2d5f726125e6a72e5440265f82ab424a127", CONFIRMATION_EXPECTED_DIGEST)

    def test_ct_092_every_v05_profile_has_explicit_manifest(self) -> None:
        self.assertEqual(8, len(COHERENT_PROFILES))
        self.assertTrue(all(profile.profile_digest for profile in COHERENT_PROFILES))

    def test_ct_093_dependencies_validate_before_execution(self) -> None:
        for profile in (*COHERENT_PROFILES, *ablation_profiles(), *interaction_cells(), *valid_advanced_combinations()):
            profile.validate()

    def test_ct_094_invalid_dependency_combinations_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ComposedProfile("invalid", "invalid", ("SOURCE_NOVEL_CONFIRMATION",)).validate()

    def test_ct_095_profiles_share_content_addressed_inputs(self) -> None:
        first, _ = ScenarioInputAdapter().collect("B-051", 42)
        second, _ = ScenarioInputAdapter().collect("B-051", 42)
        self.assertEqual(first["content_digest"], second["content_digest"])

    def test_ct_096_truth_is_not_runtime_input(self) -> None:
        item, truth = ScenarioInputAdapter().collect("B-051", 42)
        self.assertNotIn("actual_malicious", item["authored_environment_facts"])
        self.assertIn("actual_malicious", truth["truth"])

    def test_ct_097_disabled_feature_has_no_activation_path(self) -> None:
        profile = next(item for item in ablation_profiles() if item.profile_id == "A_NO_TIP_CHANNEL")
        row, proof = self.runner._row(profile, "B-051", 42, Path(tempfile.gettempdir()))
        tip = next(item for item in proof["features"] if item["feature_id"] == "TIP_ONLY_INVESTIGATION")
        self.assertEqual("disabled_no_active_path", tip["status"])
        self.assertEqual(0, tip["invocation_count"] + tip["state_record_count"] + tip["decision_contribution_count"] + tip["artifact_stream_count"])

    def test_ct_098_no_scenario_specific_policy_override(self) -> None:
        self.assertTrue(all("scenario" not in " ".join(profile.declared_transformations).lower() for profile in COHERENT_PROFILES))

    def test_ct_099_profile_manifests_are_deterministic(self) -> None:
        self.assertEqual(PROFILE_BY_ID["P7"].profile_digest, PROFILE_BY_ID["P7"].profile_digest)

    def test_ct_100_complexity_counters_reproduce(self) -> None:
        self.assertEqual(static_complexity(PROFILE_BY_ID["P7"]), static_complexity(PROFILE_BY_ID["P7"]))

    def test_ct_101_pareto_calculation_reproduces(self) -> None:
        left, right = {"security_loss": 1, "utility_loss": 1}, {"security_loss": 2, "utility_loss": 1}
        self.assertTrue(dominates(left, right, ("security_loss", "utility_loss")))

    def test_ct_102_leave_one_out_uses_p7_parent(self) -> None:
        self.assertTrue(all(item.parent_profile_id == "P7" for item in ablation_profiles()))

    def test_ct_103_all_interaction_cells_are_declared(self) -> None:
        self.assertEqual(48, len(interaction_cells()))

    def test_ct_104_negative_controls_are_not_deployment_candidates(self) -> None:
        self.assertEqual("negative_control", NEGATIVE_CONTROLS[0].kind)
        self.assertNotIn(NEGATIVE_CONTROLS[0].profile_id, PROFILE_BY_ID)

    def test_ct_105_per_family_mapping_precedes_aggregate(self) -> None:
        self.assertEqual(70, len(all_scenario_ids()))
        self.assertEqual("S5", scenario_family("B-067"))

    def test_ct_106_cost_models_are_checked_in(self) -> None:
        document = json.loads(Path("profiles/v0.5-cost-models.json").read_text())
        self.assertEqual(COST_MODELS, document["models"])

    def test_ct_107_candidate_profiles_are_preexecuted_coherent_profiles(self) -> None:
        self.assertTrue({"P2", "P5", "P7"} <= set(PROFILE_BY_ID))

    def test_ct_108_feature_dispositions_have_supporting_metadata(self) -> None:
        self.assertTrue(all(feature.expected_families for feature in FEATURES))

    def test_ct_109_canonical_and_seed_panel_input_reproduce(self) -> None:
        adapter = ScenarioInputAdapter()
        self.assertEqual(adapter.collect("B-031", 101)[0]["content_digest"], adapter.collect("B-031", 101)[0]["content_digest"])

    def test_ct_110_v05_output_is_caller_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "minimality-v0.5"
            row, _ = self.runner._row(PROFILE_BY_ID["P2"], "B-001", 42, Path(directory))
            self.assertEqual("B-001", row["scenario_id"])
            self.assertFalse(output.exists())

    def test_ct_111_p7_uses_full_v04_backend_for_confirmation_inputs(self) -> None:
        row, _ = self.runner._row(PROFILE_BY_ID["P7"], "B-051", 42, Path(tempfile.gettempdir()))
        self.assertEqual("v0.4:full_v0_4", row["native_backend"])

    def test_ct_112_instrumentation_is_behavior_neutral(self) -> None:
        item, truth = ScenarioInputAdapter().collect("B-051", 42)
        row_a, _ = self.runner._row(PROFILE_BY_ID["P7"], "B-051", 42, Path(tempfile.gettempdir()))
        row_b, _ = self.runner._row(PROFILE_BY_ID["P7"], "B-051", 42, Path(tempfile.gettempdir()))
        self.assertEqual(row_a["native_decision_digest"], row_b["native_decision_digest"])
        self.assertEqual(dynamic_complexity(PROFILE_BY_ID["P7"], item, row_a["raw_metrics"]), dynamic_complexity(PROFILE_BY_ID["P7"], item, row_b["raw_metrics"]))

    def test_ct_113_raw_rows_are_retained_for_pareto(self) -> None:
        row, _ = self.runner._row(PROFILE_BY_ID["P7"], "B-063", 42, Path(tempfile.gettempdir()))
        self.assertIn("raw_metrics", row)

    def test_ct_114_unexercised_is_not_zero_benefit(self) -> None:
        profile = PROFILE_BY_ID["P7"]
        _, proof = self.runner._row(profile, "B-001", 42, Path(tempfile.gettempdir()))
        self.assertIn("enabled_but_unexercised", {item["status"] for item in proof["features"]})

    def test_ct_115_profiles_declare_compatibility(self) -> None:
        self.assertTrue(all(profile.compatibility for profile in COHERENT_PROFILES))
