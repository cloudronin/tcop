# Amendment 004 plan and record validators

Phase 2a implements plan revision 1.4 and pure record validation. It does not
implement a runtime binding, adapter, conformance probe, simulator, runner or
replay engine. Amendment 004 remains byte-identical to seal commit 619cb4e:
`9546e30627eab69924f47d595fa536da22acee8edd818d1b268eee8ba02b0706`.

## Plan and compatibility

The 1.4 plan puts provisional `[25, 400, 5000, 20000]` milliseconds in
`timing_phase_diagram.action_interval_ms`. It retains `[25, 100, 250, 500]`
in `legacy_action_interval_ms` and labels the supersession explicitly.
Contract dispatch reads the provisional 004 values only for revision 1.4.
The 1.2/1.3 contracts still require the legacy values. The separate
`timing_phase.py` amendment 002 constants and comparator paths are unchanged.
All three legacy condition lists are unchanged.

The ladder keeps the base E0/E1/E2 descriptions and names the seven executed
rows in `rows_per_cell`. Separate operating modes, approval delay, poll
settings, per-family selections, implementation bindings, abstract
guarantees and a binding-capability table encode the sealed decisions.
The capability table explicitly records absent native freeze/snapshot and
keeps approval delay a submission condition. The provisional grid is not an
admitted final grid. Conformance evidence must support the later sealed
finalization record. The fixture's finalized 2 ms first interval illustrates
that rule; it is synthetic and does not finalize the real study grid.

New manifests copy 001-004, their canonical/hash sidecars, and the effective
plan. The 004 bytes, manifest hash and plan pin must match the fixed seal
hash, even after an attacker recomputes an artifact root. Unknown manifest
versions reject. Historical 1.1, 1.2 and full 1.3 fixture closures still
verify without mutation; 1.3 owner blockers apply only to that legacy path.

## Record schemas and seals

`validate_enforcement_records(record, purpose=...)` in
`src/tcop/external_enforcement_validation.py` is pure. It accepts parsed JSON
and raises TCOPCommandError with a named AM003/AM004 gate. It performs no
network, process, simulator, TLC or runtime operation. Admission and artifact
verify call it; the report reader additionally requires result eligibility.
Purposes are admission, verify, result, report, paper and seal. Smoke is
verifiable only, never eligible for the other paths.

| Record | Schema and required content |
| --- | --- |
| Validation bundle | `tcop.external-enforcement-validation/1.0`; stage admission/results/smoke; explicit status and eligibility; base admission, foundation hashes, source roots, prior-gate records, sandbox generation, finite baseline authority, dedicated provider inventory, scripts/census, profiles/cells, conformance, finalized grid, calibration, prediction, TLC, episodes/replays, raw frontier points and extension contrasts |
| Grid finalization | `tcop.external-grid-finalization/1.0`; interface and final action axes, hashes of C1 native-10/native-1/instant and C3 freeze measurements, a straddling justification and change history |
| Calibration reference | `tcop.external-calibration-reference/1.0`; calibrated status, simulator hash, calibration-data hash, seed and evidence hash |
| TLC pass | `tcop.external-tlc-pass/1.0`; tool/version/hash, model/config hashes, explicit finite bounds, exhaustive pass, all five required property names, zero violations and an empty violation list |
| Conformance reference | `tcop.external-conformance/1.0`; binding/pin, check ID, tag, grade, layering, poll configuration, measured lag, scoped observations/controls/continuity, pass and evidence hash |
| Expected pattern | `tcop.external-expected-pattern/1.1`; existing family predictions and foundation bindings, simulator/calibration hashes, calibrated status, seed, finalized grid/hash and zero native prevention below lag in S-B/S-C |
| Admission | `tcop.external-enforcement-admission/1.1`; existing pinned three-machine admission plus the prospective validation bundle. Original 1.0 admission and expected-pattern schemas retain their legacy validation |

Each embedded census, conformance, grid, calibration, prediction and TLC
record has exactly `{body, sha256, sealed_at}`. SHA-256 commits canonical JSON
of body; timestamps must be timezone-aware ISO values. These integrity seals
are not signatures or external timestamps. The bundle is copied into
`enforcement-validation.json` and its canonical hash appears in both
manifests. The existing foundation directory seals still inventory exact
file bytes and use context_comparator._root_digest.

The full admission contains the gate bundle, which itself contains a
prediction referring to admission. To avoid a hash cycle, prediction binds
`digest(base_admission(record))`, the normalized 1.0 admission without the
bundle. The full admission seal still commits every byte of the 1.1 record.
The API returns both record_sha256 and base_record_sha256. Verify compares
that base, the actual plan hash, actual role-census hash, copied script
contents and actual census/prediction seal timestamps against the bundle.

Profiles normalize the seven configurations, but each episode and frontier point also carries
its explicit action, binding pin, implementation, tag, grade, layering,
mode, approval, poll setting and D. An episode must match its profile.
Pairing uses family/script/seed/interface-delay/action-interval/row.
Each bundle uses one pinned prediction seed; additional seed runs use
separate bundles. Closure and outcome hashes bind strict replay to the live
row, including the timing partition and measured effect lag. Mismatches require environment_failure and a reason and cannot enter
frontier points or extension contrasts. Raw failure evidence remains in the
episode inventory. Zero denominators remain undefined with both raw counts.

A4 dependency entries describe harmful side-effect dependencies and must be
empty, with a true baseline-provisioned independence declaration. This is
record evidence, not an empirical proof of causality. Target, provider and
machine attestations likewise require later acquisition/conformance checks.
Instant-cut records admit private or documentation IPv4 targets, require the
synthetic/dedicated/routed declarations and .invalid role-script targets,
and forbid alternate transport or namespace substitutions. Container IDs
are full 64-digit Docker hashes. No raw credential material is needed.

## Admission and result boundaries

An admission-stage bundle contains prospective cells/profiles, seals and
conformance references, but no episodes, frontier points or raw efficacy
contrasts. A 1.4 preflight cannot start on a legacy admission alone. It
requires a verified 1.1 admission and all bound foundations, otherwise
AM004_VALIDATION_RECORDS remains explicit. Malformed 004 plans get their
own AM004_EFFECTIVE_PLAN blocker. Resolved owner issues are removed from
1.4 preflight. AM004_RUNNER_NOT_IMPLEMENTED remains because this phase does
not execute the study. No record-only pass becomes a live run.

COMPLETE records require all 16 cells and seven rows per family, all frozen
strict replays, explicit prior gates, admitted evidence and raw counts.
Well-formed smoke retains SMOKE_INVALID_FOR_RESULTS and false eligibility;
report refuses it. Grid/calibration/census precede prediction; grid,
prediction, required conformance and TLC precede every live episode. The
validator checks the grid-change history against execution chronology.
A content commitment cannot prove that an omitted history entry or tool
invocation actually happened; the later acquisition/runner closure must
supply that evidence. No simulator or formal-model file is imported here.

## Gate tests

Every negative case below was written before its gate implementation. The
initial validator run failed on the missing module. Additional batches
exposed acceptance gaps before their fixes. The complete passing fixture
contains 336 synthetic episodes and matched replay commitments. Its
attestations, tool hashes and outcomes are test data, not study findings.

The methods below are in `EnforcementRecordTests` in
`tests/test_external_enforcement_validation.py`. Each changes one feature
of the complete fixture. Content seals are recomputed so a semantic failure
cannot be hidden behind an unrelated stale seal.

| Rejection gate | Test method |
| --- | --- |
| widening adapter call | `test_reject_widening_adapter_call` |
| unpinned agent | `test_reject_unpinned_agent` |
| unpinned runtime | `test_reject_unpinned_runtime` |
| uncensused script | `test_reject_uncensused_script` |
| script changed after seal | `test_reject_script_changed_after_seal` |
| draft script non smoke | `test_reject_draft_script_non_smoke` |
| live without frozen replay | `test_reject_live_without_frozen_replay` |
| replay not frozen | `test_reject_replay_not_frozen` |
| replay disagreement not environment failure | `test_reject_replay_disagreement_not_environment_failure` |
| replay wrong pair | `test_reject_replay_wrong_pair` |
| missing row in cell | `test_reject_missing_row_in_cell` |
| missing family report | `test_reject_missing_family_report` |
| missing grid cell | `test_reject_missing_grid_cell` |
| missing live episode | `test_reject_missing_live_episode` |
| missing frontier numerator | `test_reject_missing_frontier_numerator` |
| missing frontier denominator | `test_reject_missing_frontier_denominator` |
| zero denominator not undefined | `test_reject_zero_denominator_not_undefined` |
| missing expected pattern | `test_reject_missing_expected_pattern` |
| expected pattern not preregistered | `test_reject_expected_pattern_not_preregistered` |
| pooled e2a e2b | `test_reject_pooled_e2a_e2b` |
| extra minimum poll b row | `test_reject_extra_minimum_poll_b_row` |
| duplicate cell row | `test_reject_duplicate_cell_row` |
| pooled tag | `test_reject_pooled_tag` |
| pooled grade | `test_reject_pooled_grade` |
| pooled layering | `test_reject_pooled_layering` |
| pooled poll configuration | `test_reject_pooled_poll_configuration` |
| pooled mode | `test_reject_pooled_mode` |
| missing abstract action | `test_reject_missing_abstract_action` |
| missing binding identity | `test_reject_missing_binding_identity` |
| missing binding pin | `test_reject_missing_binding_pin` |
| missing tag | `test_reject_missing_tag` |
| missing grade | `test_reject_missing_grade` |
| missing layering | `test_reject_missing_layering` |
| grade mismatch | `test_reject_grade_mismatch` |
| tag mismatch | `test_reject_tag_mismatch` |
| layering mismatch | `test_reject_layering_mismatch` |
| e0 without not applicable | `test_reject_e0_without_not_applicable` |
| e1 without not applicable | `test_reject_e1_without_not_applicable` |
| accepted does not meet | `test_reject_accepted_does_not_meet` |
| snapshot on frontier | `test_reject_snapshot_on_frontier` |
| multiple writes per tcx | `test_reject_multiple_writes_per_tcx` |
| write without validated tcx | `test_reject_write_without_validated_tcx` |
| wrong sandbox write | `test_reject_wrong_sandbox_write` |
| wrong container generation | `test_reject_wrong_container_generation` |
| adapter reversal or exec | `test_reject_adapter_reversal_or_exec` |
| selection outside table | `test_reject_selection_outside_table` |
| selection depends on outcome | `test_reject_selection_depends_on_outcome` |
| selection depends on cell | `test_reject_selection_depends_on_cell` |
| selection depends on poll phase | `test_reject_selection_depends_on_poll_phase` |
| a4 suppressed after success | `test_reject_a4_suppressed_after_success` |
| a4 harmful side effect | `test_reject_a4_harmful_side_effect` |
| a4 missing independence | `test_reject_a4_missing_independence` |
| retry without prior denial | `test_reject_retry_without_prior_denial` |
| native a0 prevention below lag | `test_reject_native_a0_prevention_below_lag` |
| native prediction below lag | `test_reject_native_prediction_below_lag` |
| delay not 3000 | `test_reject_delay_not_3000` |
| delay missing basis | `test_reject_delay_missing_basis` |
| missing poll configuration | `test_reject_missing_poll_configuration` |
| minimum poll wrong setting | `test_reject_minimum_poll_wrong_setting` |
| missing measured effect lag | `test_reject_missing_measured_effect_lag` |
| missing grid finalization | `test_reject_missing_grid_finalization` |
| grid differs from finalization | `test_reject_grid_differs_from_finalization` |
| grid sealed after prediction | `test_reject_grid_sealed_after_prediction` |
| grid sealed after episode | `test_reject_grid_sealed_after_episode` |
| grid changed after efficacy | `test_reject_grid_changed_after_efficacy` |
| grid does not straddle lags | `test_reject_grid_does_not_straddle_lags` |
| missing c1 lag measurement | `test_reject_missing_c1_lag_measurement` |
| provisional calibration | `test_reject_provisional_calibration` |
| missing simulator hash | `test_reject_missing_simulator_hash` |
| missing calibration hash | `test_reject_missing_calibration_hash` |
| missing prediction seed | `test_reject_missing_prediction_seed` |
| prediction sealed after episode | `test_reject_prediction_sealed_after_episode` |
| post hoc on sealed path | `test_reject_post_hoc_on_sealed_path` |
| nested post hoc output | `test_reject_nested_post_hoc_output` |
| missing tlc before live | `test_reject_missing_tlc_before_live` |
| tlc violation | `test_reject_tlc_violation` |
| tlc violation count | `test_reject_tlc_violation_count` |
| tlc after live start | `test_reject_tlc_after_live_start` |
| tlc missing tool pin | `test_reject_tlc_missing_tool_pin` |
| tlc missing property | `test_reject_tlc_missing_property` |
| block time from rpc return | `test_reject_block_time_from_rpc_return` |
| block time from persistence | `test_reject_block_time_from_persistence` |
| block time from refresh | `test_reject_block_time_from_refresh` |
| detach without refresh | `test_reject_detach_without_refresh` |
| detach wrong fingerprint | `test_reject_detach_wrong_fingerprint` |
| detach wrong observer | `test_reject_detach_wrong_observer` |
| detach no change credited | `test_reject_detach_no_change_credited` |
| detach observation after deadline | `test_reject_detach_observation_after_deadline` |
| detach provider still bound | `test_reject_detach_provider_still_bound` |
| sc replay outside b | `test_reject_sc_replay_outside_b` |
| freeze without paused observation | `test_reject_freeze_without_paused_observation` |
| instant cut without vm access | `test_reject_instant_cut_without_vm_access` |
| instant cut without dedicated target | `test_reject_instant_cut_without_dedicated_target` |
| instant cut not routed off bridge | `test_reject_instant_cut_not_routed_off_bridge` |
| instant cut without continuity | `test_reject_instant_cut_without_continuity` |
| instant cut in sandbox netns | `test_reject_instant_cut_in_sandbox_netns` |
| instant cut with eci | `test_reject_instant_cut_with_eci` |
| instant cut reused connection | `test_reject_instant_cut_reused_connection` |
| instant cut worker delete | `test_reject_instant_cut_worker_delete` |
| instant cut expiring deny | `test_reject_instant_cut_expiring_deny` |
| missing passing conformance | `test_reject_missing_passing_conformance` |
| missing extension proposal | `test_reject_missing_extension_proposal` |
| extension missing interface | `test_reject_extension_missing_interface` |
| extension missing retirement | `test_reject_extension_missing_retirement` |
| mixed freeze claimed isolated | `test_reject_mixed_freeze_claimed_isolated` |
| snapshot frontier value | `test_reject_snapshot_frontier_value` |
| reliability field name | `test_reject_reliability_field_name` |
| reliability record name | `test_reject_reliability_record_name` |
| changed source root | `test_reject_changed_source_root` |
| prior gate failed | `test_reject_prior_gate_failed` |
| malformed nonfinite lag | `test_reject_malformed_nonfinite_lag` |
| boolean raw count | `test_reject_boolean_raw_count` |
| missing episode action | `test_reject_missing_episode_action` |
| missing episode tag | `test_reject_missing_episode_tag` |
| episode profile grade mismatch | `test_reject_episode_profile_grade_mismatch` |
| episode poll missing | `test_reject_episode_poll_missing` |
| episode seed differs from prediction | `test_reject_episode_seed_differs_from_prediction` |
| missing outcome partition | `test_reject_missing_outcome_partition` |
| multiple outcome partitions | `test_reject_multiple_outcome_partitions` |
| accepted native without loaded revision | `test_reject_accepted_native_without_loaded_revision` |
| accepted native wrong policy hash | `test_reject_accepted_native_wrong_policy_hash` |
| accepted instant without kernel observation | `test_reject_accepted_instant_without_kernel_observation` |
| accepted instant past deadline | `test_reject_accepted_instant_past_deadline` |
| snapshot default pause | `test_reject_snapshot_default_pause` |
| snapshot false memory claim | `test_reject_snapshot_false_memory_claim` |
| snapshot wrong driver | `test_reject_snapshot_wrong_driver` |
| snapshot missing integrity | `test_reject_snapshot_missing_integrity` |
| snapshot binding grade mismatch | `test_reject_snapshot_binding_grade_mismatch` |
| missing extension raw contrast | `test_reject_missing_extension_raw_contrast` |
| changed extension raw counts | `test_reject_changed_extension_raw_counts` |
| native a0 credit frontier below lag | `test_reject_native_a0_credit_frontier_below_lag` |
| detaching uninventoried authority | `test_reject_detaching_uninventoried_authority` |
| unknown adapter write field | `test_reject_unknown_adapter_write_field` |
| conformance after live | `test_reject_conformance_after_live` |
| census after prediction | `test_reject_census_after_prediction` |
| episode role representability differs | `test_reject_episode_role_representability_differs` |
| invalid time to detect | `test_reject_invalid_time_to_detect` |
| missing tcx arrival | `test_reject_missing_tcx_arrival` |
| snapshot unknown outcome | `test_reject_snapshot_unknown_outcome` |
| frontier snapshot metadata | `test_reject_frontier_snapshot_metadata` |
| frontier grade mismatch | `test_reject_frontier_grade_mismatch` |
| frontier missing tag | `test_reject_frontier_missing_tag` |
| frontier missing layering | `test_reject_frontier_missing_layering` |
| replay timing partition disagreement | `test_reject_replay_timing_partition_disagreement` |
| replay measured lag disagreement | `test_reject_replay_measured_lag_disagreement` |
| a4 denominator erased by freeze | `test_reject_a4_denominator_erased_by_freeze` |

Additional positive, lifecycle and integration tests:

- `EnforcementRecordTests.test_admission_stage_has_no_efficacy_findings`
- `EnforcementRecordTests.test_complete_passing_fixture`
- `EnforcementRecordTests.test_malformed_record_types_raise_command_error`
- `EnforcementRecordTests.test_replay_disagreement_closed_as_environment_failure_is_diagnostic_only`
- `EnforcementRecordTests.test_smoke_verify_only_never_result_report_paper_or_seal`
- `EnforcementRecordTests.test_valid_zero_denominator_retained`
- `Plan14Tests.test_a4_and_retry_triggers`
- `Plan14Tests.test_each_004_plan_gate_rejects`
- `Plan14Tests.test_legacy_grid_and_lists_preserved_in_legacy_contract`
- `Plan14Tests.test_missing_004_has_own_preflight_blocker_no_owner_blockers`
- `Plan14Tests.test_plan_14_and_named_contract`
- `Manifest14Tests.test_004_bytes_and_sidecars_rejected_even_with_new_root`
- `Manifest14Tests.test_13_full_artifact_still_verifies_unchanged`
- `Manifest14Tests.test_manifest_14_copies_all_four_with_sidecars`
- `Manifest14Tests.test_report_refuses_14_smoke`
- `Manifest14Tests.test_self_consistent_004_replacement_rejected_by_pinned_hash`
- `Manifest14Tests.test_verified_v14_foundations_and_result_gate_round_trip`
- `Manifest14Tests.test_verify_runs_semantic_gates_after_resealing_records`
- `Admission14Tests.test_admission_bundle_cannot_carry_raw_efficacy_contrasts`
- `Admission14Tests.test_admission_sealer_returns_cycle_free_base_hash`
- `Admission14Tests.test_new_admission_cannot_bind_another_host_record`
- `Admission14Tests.test_new_admission_cannot_omit_validation_records`
- `Admission14Tests.test_v14_admission_round_trip_and_semantic_tamper`

Existing `AdmissionTests`, `ExpectedPatternTests`, `RoleScriptTests`,
`ManifestVersionTests` and `PlanAndSealTests` continue to cover machine
identity/attestation, notice/preset/baseline pins, seal tampering, public
mapping, draft exclusion, unknown versions and legacy foundation closure.

## Implementation decisions not fixed by the specs

- The plan uses the main action_interval_ms field for 1.4 provisional
  values and a separate legacy_action_interval_ms field. Version dispatch,
  not mutation of the old timing module, selects the contract.
- The record identifiers, JSON member names, seven implementation IDs and
  named AM003/AM004 errors are local schema choices. Embedded content-seal
  envelopes use canonical hashes and ISO timestamps; existing foundation
  seals continue to inventory raw file bytes. The embedded census commits
  canonical script content, while the outer role seal checks exact source
  bytes and the binder compares the two parsed contents.
- Admission and prediction use schema 1.1 to preserve legacy 1.0 behavior.
  The base-admission hash avoids a cyclic prediction commitment; the full
  admission remains separately sealed. A bundle holds one pre-registered
  seed. Profiles normalize configurations, with explicit metadata repeated
  and checked on episodes and frontier points.
- Result manifests use COMPLETE with complete/evaluation_executed and
  valid_for_results true. Prospective bundles use ADMISSION and hold no
  efficacy. Smoke remains the owner-defined invalid status and can only be
  verified. The existing CLI commands inherit these checks without adding
  a new permissive command. Live execution remains blocked explicitly.
- Conformance/TLC/calibration records are supplied evidence references,
  never calls to those tools. The TLC property names and bounds object are
  normalized schema labels. Actual tool/calibration/conformance provenance
  must be supplied by those jobs and admitted before a live run.
- The full passing fixture includes one script/seed pair per family and
  all 336 rows. Its 2 ms finalized first interval, test tool hashes, mapped
  script declarations and synthetic host attestations are fixtures only.
  The real role drafts, prediction draft and final grid are untouched.

## Validation and file scope

- `PYTHONPATH=src python3.11 -m unittest discover -s tests -p 'test_external_*.py'`:
  235 tests passed. The two new modules contribute 169 tests, including the
  146 individually named negative gate cases above.
- `make test PYTHON=python3.11`: 463 tests ran; 462 passed and one existing
  loopback-listener test was skipped because this execution sandbox disables
  local listeners.
- `make schema`: TCX v0.1 through v0.6 and agent-validation schemas passed.
- `git diff --check` passed. All 5,559 original protected file hashes,
  including amendments 001-004, artifacts, paper, integrations and the STIX
  comparator, remain unchanged. The 004 seal hash matches the owner pin.

Changed files:

- `benchmark/studies/external-warning-adaptive-crosshost-v1.yaml`
- `src/tcop/external_adaptive_crosshost.py`
- `src/tcop/external_enforcement_admission.py`
- `src/tcop/external_expected_pattern.py`
- `tests/test_external_enforcement_foundations.py`

Added files:

- `src/tcop/external_enforcement_validation.py`
- `tests/test_external_enforcement_validation.py`
- `tests/test_external_enforcement_v14.py`
- `tests/fixtures/amendment-003-plan-1.3.json`
- `tests/fixtures/amendment-004-validation.json`
- `docs/amendment-004-validation-gates.md`

During this job HEAD advanced from 619cb4e to 42c5cfe as concurrent jobs were
committed. The unscoped diff against 619cb4e therefore includes their
simulator and formal files. This job made no edits there. The working-tree
changes listed above exclude every protected path. The concurrent untracked
amendment 005 is also untouched. No git state-changing command was run.
