# Unearned outcome issues: supplement to KNOWN_ISSUES.md

This is a new supplement to [KNOWN_ISSUES.md](KNOWN_ISSUES.md), which another job created during the sweep and which this task did not edit. These are bugs, not accepted evidence. An allowlist entry preserves buildability while existing producers are repaired without rewriting sealed results. Fix a producer, emit a separately rooted successor when evidence must be rerun, and remove its exact exception. Eight dataflow findings are tracked here even though they are not literal successes.

Current sweep: 52 class A sites. Source sites and artifact attribution are detailed in [the sweep](unearned-pass-sweep.md). The paths marked absent below are intended outputs, not sealed artifacts known to exist.

<a id="uep-001"></a>
## UEP-001: src/tcop/adaptive_agent_authorization.py:47 (passed)

Nine named negative controls are enumerated with passed=true and restriction_created=false; no mutation or receiver execution occurs.

Function: `run_adaptive_authorization`. Paper affected: **no**.

`artifacts/adaptive-agent-authorization-v1/control-results.jsonl`

<a id="uep-002"></a>
## UEP-002: src/tcop/agent_eval/runner.py:306 (opaque_handle_verified)

Correlation verification is asserted independently of context admission outcomes; replay records admissions but does not raise if an import is rejected.

Function: `AgentStudy.replay`. Paper affected: **no**.

`artifacts/v0.6-agent-validation/reports/correlation-success.json` (absent; intended output)

Scripted parent is referenced by paper source specs but absent here; live fields are separate sites below.

<a id="uep-003"></a>
## UEP-003: src/tcop/agent_eval/runner.py:338 (receipt_correlation_verified)

Correlation verification is asserted independently of context admission outcomes; replay records admissions but does not raise if an import is rejected.

Function: `AgentStudy.replay`. Paper affected: **no**.

`artifacts/v0.6-agent-validation/reports/agent-study-claim-readiness.json` (absent; intended output)

Scripted parent is referenced by paper source specs but absent here; live fields are separate sites below.

<a id="uep-004"></a>
## UEP-004: src/tcop/agent_eval/runner.py:579 (passed)

unknown_peer is marked passed without submitting an unknown-peer context.

Function: `AgentStudy._failure_modes`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

paperlib.py:522-535 exports it; :743-762 prints the table; claim C-FAILURE-01 includes it.

<a id="uep-005"></a>
## UEP-005: src/tcop/agent_eval/runner.py:580 (passed)

disallowed_import_type is marked passed without submitting a forbidden import type.

Function: `AgentStudy._failure_modes`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

paperlib.py:522-535 exports it; :743-762 prints the table; claim C-FAILURE-01 includes it.

<a id="uep-006"></a>
## UEP-006: src/tcop/agent_eval/runner.py:585 (passed)

session_termination_before_context_arrival is marked passed without terminating a session and delivering late context.

Function: `AgentStudy._failure_modes`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

paperlib.py:522-535 exports it; :743-762 prints the table; claim C-FAILURE-01 includes it.

<a id="uep-007"></a>
## UEP-007: src/tcop/agent_eval/runner.py:739 (opaque_handle_verified)

opaque_handle_verified is unconditional; successful_imports counts context_delivered while live_gateway_imports counts acceptance, with neither gating this flag.

Function: `AgentStudy.run_live`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/correlation-success.json`

Retained in the paper source root; source verification hashes it, but the numerical extractor does not use this field.

<a id="uep-008"></a>
## UEP-008: src/tcop/agent_eval/runner.py:767 (receipt_correlation_verified)

receipt_correlation_verified is unconditional, including when live execution is incomplete or no context was admitted.

Function: `AgentStudy.run_live`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/agent-study-claim-readiness.json`

Retained in the paper source root; source verification hashes it, but the numerical extractor does not use this field.

<a id="uep-009"></a>
## UEP-009: src/tcop/benchmark.py:434 (state_stabilized)

state_stabilized is asserted after draining transport, without measuring response-state convergence.

Function: `BenchmarkRunner._metrics`. Paper affected: **no**.

`artifacts/minimality-v0.5/per-run-metrics.jsonl`<br>`artifacts/minimality-v0.5-validation/consolidation-candidate-per-run-metrics.jsonl`

Retained as raw_metrics in per-run records; no paper script extracts this flag.

<a id="uep-010"></a>
## UEP-010: src/tcop/benchmark.py:435 (decision_compatible)

decision_compatible is asserted without comparing decisions for compatibility.

Function: `BenchmarkRunner._metrics`. Paper affected: **no**.

`artifacts/minimality-v0.5/per-run-metrics.jsonl`<br>`artifacts/minimality-v0.5-validation/consolidation-candidate-per-run-metrics.jsonl`

<a id="uep-011"></a>
## UEP-011: src/tcop/benchmark.py:520 (oracle_isolation)

oracle_isolation is asserted; the only verification predicate compares same-seed digests, not runtime truth access.

Function: `verify`. Paper affected: **no**.

`artifacts/verify/verification-summary.json` (absent; intended output)

No sealed verification-summary.json is present in this checkout; path is the intended default output.

<a id="uep-012"></a>
## UEP-012: src/tcop/c2e_frontier.py:191 (passed)

Eight named relation controls are emitted as passes without executing those controls.

Function: `run_c2e_frontier`. Paper affected: **no**.

`artifacts/c2e-frontier-v1/control-results.jsonl`

<a id="uep-013"></a>
## UEP-013: src/tcop/confirmation_benchmark.py:486 (oracle_isolation)

oracle_isolation is asserted independently of the reproducibility digest check; no runtime truth-access observation establishes it.

Function: `run_confirmation_suite`. Paper affected: **no**.

`artifacts/confirmation-v0.4/confirmation-verification-summary.json` (absent; intended output)

No sealed suite summary is present here; intended filename is confirmed from the producer.

<a id="uep-014"></a>
## UEP-014: src/tcop/context_comparator.py:206 (passed)

C3 no-message control is declared passed without invoking or inspecting the policy interface.

Function: `_controls`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/controls/control-results.json`

<a id="uep-015"></a>
## UEP-015: src/tcop/context_comparator.py:206 (passed)

Four protocol-rejection names times four conditions are declared passed without receiver execution (16 sealed records).

Function: `_controls`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/controls/control-results.json`

<a id="uep-016"></a>
## UEP-016: src/tcop/context_comparator.py:206 (passed)

C1 opaque-interface control is declared passed without attempting forbidden field access.

Function: `_controls`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/controls/control-results.json`

<a id="uep-017"></a>
## UEP-017: src/tcop/context_comparator.py:206 (passed)

C2 target-mismatch control is declared passed without invoking the C2 policy.

Function: `_controls`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/controls/control-results.json`

<a id="uep-018"></a>
## UEP-018: src/tcop/context_comparator.py:206 (passed)

C1 target-mismatch control is declared passed without invoking the C1 policy.

Function: `_controls`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/controls/control-results.json`

<a id="uep-019"></a>
## UEP-019: src/tcop/context_comparator.py:261 (source_dependencies_unmodified)

source_dependencies_unmodified is asserted after generation without a post-run source digest comparison.

Function: `run_context_comparator`. Paper affected: **no**.

`artifacts/context-value-comparator-v1/manifest.json`

<a id="uep-020"></a>
## UEP-020: src/tcop/context_comparator.py:263 (controls_passed)

controls_passed in the returned summary is unconditional rather than aggregated from the control outcomes. The manifest uses all(), but inherits the fabricated controls.

Function: `run_context_comparator`. Paper affected: **no**.

None found; return value only, or no retained producer output.

<a id="uep-021"></a>
## UEP-021: src/tcop/evidence_round.py:525 (invalid_evidence_detection)

invalid_evidence_detection defaults to true outside S18 without observing invalid-evidence detection; this contributes to reconstruction score.

Function: `EvidenceRound.forensics`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/forensics/forensic-cell-scores.jsonl`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-quality.json`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-duplication.json`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-efficiency.json`

Source verification hashes these retained forensic scores; paper numerical extraction does not consume this criterion.

<a id="uep-022"></a>
## UEP-022: src/tcop/evidence_round.py:525 (relay_provenance_completeness)

relay_provenance_completeness is always true without checking a relay chain, and directly determines provenance_completeness and reconstruction score.

Function: `EvidenceRound.forensics`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/forensics/forensic-cell-scores.jsonl`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-quality.json`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-duplication.json`<br>`artifacts/federated-domain-v0.6-evidence/reports/forensic-efficiency.json`

Source verification hashes these retained forensic scores; paper numerical extraction does not consume this criterion.

<a id="uep-023"></a>
## UEP-023: src/tcop/evidence_round.py:564 (cohort_comparability_verified)

cohort_comparability_verified is asserted without testing the comparability report; that report includes noncomparable cohort pairs.

Function: `EvidenceRound.pareto_and_readiness`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/reports/paper-claim-readiness.json`

Read by paper source verification through the evidence artifact verifier; no direct numerical extraction of the flag.

<a id="uep-024"></a>
## UEP-024: src/tcop/evidence_round.py:618 (passed)

Overall evidence passed is unconditional after report generation and replay. No aggregate predicate checks the recorded invariants or readiness before it is emitted.

Function: `EvidenceRound.run`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/manifest.json`

paperlib.py:278-294 source verification requires status.passed; evidence verification trusts both manifest and status.

<a id="uep-025"></a>
## UEP-025: src/tcop/evidence_round.py:618 (report_regeneration_digest_stable)

report_regeneration_digest_stable is asserted without regenerating the reports and comparing their digests.

Function: `EvidenceRound.run`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/manifest.json`

Read as part of the source manifest, and hashed during paper source verification; no direct numerical extraction of this flag.

<a id="uep-026"></a>
## UEP-026: src/tcop/evidence_round.py:620 (passed)

Overall evidence passed is unconditional after report generation and replay. No aggregate predicate checks the recorded invariants or readiness before it is emitted.

Function: `EvidenceRound.run`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/status.json`

paperlib.py:278-294 source verification requires status.passed; evidence verification trusts both manifest and status.

<a id="uep-027"></a>
## UEP-027: src/tcop/evidence_round.py:621 (frozen_strategy_digests_unchanged)

frozen_strategy_digests_unchanged is asserted without a before/after digest comparison around the evidence run.

Function: `EvidenceRound.run`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/validation/invariants.json`

Required by the evidence artifact verifier and hashed by source verification. The file supplies no observed strategy digests.

<a id="uep-028"></a>
## UEP-028: src/tcop/evidence_round.py:621 (passed)

The invariants record passed flag has no executed aggregate check of its literal strategy, truth-access or remote-enforcement claims.

Function: `EvidenceRound.run`. Paper affected: **yes**.

`artifacts/federated-domain-v0.6-evidence/validation/invariants.json`

Required file in evidence verification and read by paper source verification hashing; no direct numerical extraction of this flag.

<a id="uep-029"></a>
## UEP-029: src/tcop/external_adaptive_crosshost.py:245 (source_roots_unmodified)

source_roots_unmodified is asserted in the preflight manifest without a post-generation comparison of source-root digests.

Function: `run_external_adaptive`. Paper affected: **no**.

`artifacts/external-warning-adaptive-crosshost/manifest.json` (absent; intended output)

No external-warning preflight artifact is present here; intended output root is caller supplied.

<a id="uep-030"></a>
## UEP-030: src/tcop/federation.py:1107 (passed)

Smoke artifact verification is bypassed and replaced by passed=true. Harness conformance and replay are separate checks; this record never runs verify_artifacts.

Function: `run_federated_study`. Paper affected: **no**.

`artifacts/federated-domain-v0.6-smoke/validation/artifact-verification.json` (absent; intended output)

No sealed smoke artifact is present; full/core output in the paper uses the real verify_artifacts branch, not this fallback.

<a id="uep-031"></a>
## UEP-031: src/tcop/independent_warning_admission.py:79 (passed)

Seven named independent-warning controls are emitted as passed with restriction_created=false without running those controls.

Function: `run_independent_warning`. Paper affected: **no**.

`artifacts/independent-warning-admission-v1/control-results.jsonl`<br>`artifacts/independent-warning-admission-v1-normalizer-amendment-001/control-results.jsonl`

<a id="uep-032"></a>
## UEP-032: src/tcop/independent_warning_full.py:147 (all_passed)

all_passed is asserted rather than derived from all gates. The purported byte-stability test compares each row to its own deepcopy, and predecessor_unchanged is not measured.

Function: `run_full_population`. Paper affected: **no**.

`artifacts/independent-warning-admission-v3-full-population/reports/gates.json` (absent; intended output)<br>`artifacts/independent-warning-admission-v3-full-population/manifest.json` (absent; intended output)

v3 root is absent here; these are intended output paths, not evidence of execution.

<a id="uep-033"></a>
## UEP-033: src/tcop/independent_warning_full.py:147 (predecessor_unchanged)

predecessor_unchanged checks only the saved predecessor digest file at entry, not the predecessor content nor any before/after digest.

Function: `run_full_population`. Paper affected: **no**.

`artifacts/independent-warning-admission-v3-full-population/reports/gates.json` (absent; intended output)<br>`artifacts/independent-warning-admission-v3-full-population/manifest.json` (absent; intended output)

v3 root is absent here; these are intended output paths.

<a id="uep-034"></a>
## UEP-034: src/tcop/independent_warning_v2.py:159 (all_passed)

all_passed is a literal. Although other gate failures raise, protocol_controls_no_restriction accepts two fabricated rejection dictionaries (malformed, unknown_issuer).

Function: `run_v2`. Paper affected: **no**.

`artifacts/independent-warning-admission-v2-external-stratified/control-results.jsonl`<br>`artifacts/independent-warning-admission-v2-external-stratified/reports/gates.json`<br>`artifacts/independent-warning-admission-v2-external-stratified/manifest.json`

<a id="uep-035"></a>
## UEP-035: src/tcop/minimality_runner.py:492 (instrumentation_enabled_equals_disabled)

Instrumentation equality is declared without an instrumentation-disabled run or a comparison of independent outcomes.

Function: `MinimalityStudyRunner._equivalence`. Paper affected: **no**.

`artifacts/minimality-v0.5/semantic-equivalence.json` (absent; intended output)

Only per-run-metrics.jsonl is retained under this root; the equivalence report itself is absent.

<a id="uep-036"></a>
## UEP-036: src/tcop/minimality_runner.py:499 (equal)

The same native_decision_digest is copied into with/without instrumentation fields and equal is set true, so the equality is circular.

Function: `MinimalityStudyRunner._equivalence`. Paper affected: **no**.

`artifacts/minimality-v0.5/instrumentation-equivalence.json` (absent; intended output)

The equivalence file is absent here; path is the producer output.

<a id="uep-037"></a>
## UEP-037: src/tcop/minimality_validation.py:355 (P0_P1_behaviorally_identical)

Per-scenario first differing decision is computed, but P0_P1_behaviorally_identical is always true even if a difference was found.

Function: `MinimalityValidationRunner._policy_report`. Paper affected: **no**.

`artifacts/minimality-v0.5-validation/policy_activation_report.json`

<a id="uep-038"></a>
## UEP-038: src/tcop/minimality_validation.py:483 (patrol_findings_can_enter_selected_native_backends)

Patrol reachability is asserted without tying it to observed patrol events or executing a native-backend admission check.

Function: `MinimalityValidationRunner._patrol_report`. Paper affected: **no**.

`artifacts/minimality-v0.5-validation/patrol-validation-report.json`

<a id="uep-039"></a>
## UEP-039: src/tcop/reliability_benchmark.py:554 (oracle_isolation)

oracle_isolation is asserted independently of same-seed reproducibility; no runtime truth-access outcome is checked.

Function: `run_reliability_suite`. Paper affected: **no**.

`artifacts/reliability-v0.3/reliability-verification-summary.json` (absent; intended output)

No sealed suite summary is present here; intended filename is confirmed from the producer.

<a id="uep-040"></a>
## UEP-040: src/tcop/stix_taxii_comparator.py:93 (passed)

A5 claims every matrix cell has a protocol/trace reference, but no reference-completeness predicate is evaluated.

Function: `run_deterministic_fixtures`. Paper affected: **no**.

`artifacts/external-warning-adaptive-crosshost/preflight-report.json` (absent; intended output)

No preflight artifact containing these gates is retained here; output root is caller supplied.

<a id="uep-041"></a>
## UEP-041: src/tcop/validation_value.py:177 (predecessor_artifacts_unmodified)

predecessor_artifacts_unmodified is asserted in the exclusion ledger without a post-run digest comparison.

Function: `_run`. Paper affected: **no**.

`artifacts/tcx-validation-value-v2/exclusion-ledger.json`

<a id="uep-042"></a>
## UEP-042: src/tcop/validation_value.py:181 (source_roots_unmodified)

source_roots_unmodified is asserted in the manifest without comparing digests after generation.

Function: `_run`. Paper affected: **no**.

`artifacts/tcx-validation-value-v2/manifest.json`

The claim ledger references v2 condition/matching/gate reports; no extraction reads this manifest.

<a id="uep-043"></a>
## UEP-043: src/tcop/witness_benchmark.py:331 (state_stabilized)

state_stabilized is unconditional; draining the private delivery queue is not an observation of state convergence.

Function: `WitnessBenchmarkRunner._metrics`. Paper affected: **no**.

`artifacts/minimality-v0.5/per-run-metrics.jsonl`<br>`artifacts/minimality-v0.5-validation/consolidation-candidate-per-run-metrics.jsonl`

<a id="uep-044"></a>
## UEP-044: src/tcop/witness_benchmark.py:405 (oracle_isolation)

oracle_isolation is asserted independently of reproducibility; no truth-access check supplies an observed isolation outcome.

Function: `run_witness_suite`. Paper affected: **no**.

`artifacts/witness-v0.2/witness-verification-summary.json` (absent; intended output)

No sealed suite summary is present here; intended filename is confirmed from the producer.

<a id="uep-045"></a>
## UEP-045: src/tcop/cli_artifact.py:70 (derived result)

The smoke/non-core verification passed flag is bool(cells), a nonempty input matrix rather than observed per-run artifact verification.

Function: `verify_artifact`. Paper affected: **no**.

None found; return value only, or no retained producer output.

Returned by a read-only verifier; no sealed record found. Full/core paper roots take the real verifier branch.

<a id="uep-046"></a>
## UEP-046: src/tcop/independent_warning_v2.py:157 (derived result)

malformed control is a fixed validated=false/restriction_created=false dictionary, consumed as a passing protocol gate without submitting malformed input.

Function: `run_v2`. Paper affected: **no**.

`artifacts/independent-warning-admission-v2-external-stratified/control-results.jsonl`<br>`artifacts/independent-warning-admission-v2-external-stratified/reports/gates.json`<br>`artifacts/independent-warning-admission-v2-external-stratified/manifest.json`

The invalid_signature sibling actually executes verify_signature; these two controls do not.

<a id="uep-047"></a>
## UEP-047: src/tcop/independent_warning_v2.py:157 (derived result)

unknown_issuer control is a fixed validated=false/restriction_created=false dictionary, consumed as a passing protocol gate without trying an unknown issuer.

Function: `run_v2`. Paper affected: **no**.

`artifacts/independent-warning-admission-v2-external-stratified/control-results.jsonl`<br>`artifacts/independent-warning-admission-v2-external-stratified/reports/gates.json`<br>`artifacts/independent-warning-admission-v2-external-stratified/manifest.json`

The enclosing gate is computed from invented rejection values, not receiver outcomes.

<a id="uep-048"></a>
## UEP-048: src/tcop/independent_warning_full.py:132 (derived result)

byte_stable compares each row to its own deepcopy after dropping row_id; it does not execute a second clean run as the emitted field claims.

Function: `run_full_population`. Paper affected: **no**.

`artifacts/independent-warning-admission-v3-full-population/reports/byte-stability-report.json` (absent; intended output)<br>`artifacts/independent-warning-admission-v3-full-population/reports/gates.json` (absent; intended output)

v3 artifact is absent from this checkout; paths are intended outputs.

<a id="uep-049"></a>
## UEP-049: src/tcop/agent_eval/runner.py:266 (derived result)

no_remote_enforcement compares remote_enforcement_successes to zero, but invariant_snapshot supplies the literal zero rather than observing attempted or successful remote commands.

Function: `AgentStudy._negative_controls`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

Directly exported to failure-controls.csv and included among the 16 passed paper controls. The raw zero originates at agent_eval/authorization.py:246.

<a id="uep-050"></a>
## UEP-050: src/tcop/agent_eval/runner.py:268 (derived result)

remote_tcx_action_not_interpreted checks local-authority invariants on fixtures that contain no action/enforcement payload. It never exercises interpretation of a remote action field.

Function: `AgentStudy._negative_controls`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

create_fixture defaults to scenario and synthetic_only metadata. The mutation in validation_value._properties does inject remote action fields, but this control does not use its result.

<a id="uep-051"></a>
## UEP-051: src/tcop/agent_eval/runner.py:583 (derived result)

gateway_restart runs a fresh NO_CONTEXT replay and checks its hard-coded remote_enforcement_successes=0. It neither restarts a gateway nor observes restart behavior.

Function: `AgentStudy._failure_modes`. Paper affected: **yes**.

`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`<br>`artifacts/v0.6-agent-validation-live-origin-certified/reports/invariant-report.json`

Directly exported to failure-controls.csv and reported as a passed restart control.

<a id="uep-052"></a>
## UEP-052: src/tcop/validation_value.py:167 (derived result)

no_cross_session_restriction compares values from _correlation(), whose cross_session_restrictions and misbindings are hard-coded zero. No concurrent sessions or receiver bindings are exercised.

Function: `_run`. Paper affected: **yes, in prose** (orchestrator correction): `paper/usenix27/sections/06-deterministic-evaluation.tex` line 22 states "correlation ambiguity at one, two, and eight concurrent sessions with zero cross-session restrictions". No extraction script reads this gate, but the sentence reports the formula's zeros as a result.

`artifacts/tcx-validation-value-v2/correlation-results.csv`<br>`artifacts/tcx-validation-value-v2/reports/gates.json`<br>`artifacts/tcx-validation-value-v2/expected-results.json`

This gate is not a correlation implementation outcome; the rows are declared arithmetic fixtures. Paper scripts name v2 condition/matching/gate reports in the claim ledger but do not extract this gate.

## Already fixed producers

Commit `a3af84cacf26c10d6c38c031ff73a7761b1bf2c3` replaced the literal passes for `receipt_reference` and `expires_at` in `validation_value._properties` with predicates on the returned code and restriction flag. The retained `artifacts/tcx-validation-value-v2/property-test-report.json` still contains those records. A source fix alone does not prove when a sealed record was generated. These two historical A sites are excluded from the current counts and allowlist, because they no longer exist.
