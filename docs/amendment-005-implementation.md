# Phase 2b implementation

Plan and manifest 1.5 include sealed amendment 005:
`3b45fef22a9b00cff1a3e001db07404a10a396445620d7c8298459e672cdd22b`.
The 1.1-1.4 verification paths remain available. Unknown versions reject.
The 004 and 005 effective-plan blockers are independent.

The provisional action intervals remain 25/400/5000/20000 ms. The added
005 placement rule governs finalization. It uses 1024 seeded samples,
reference interface delay 10 ms, and separate S-B/S-C transitions. The
simulator retains every sampled effect time in its placement record. The
first floating-point interval strictly above the empirical median avoids
giving E2 credit for a tie. Nonseparable transitions reject finalization.
No real grid, expected pattern, calibration or model-input seal was made.

## Record schemas

| Record | Shape and commitment |
| --- | --- |
| Gate bundle | `tcop.external-enforcement-validation/1.1`. Reuses all 003/004 checks, then applies 005. Schema 1.0 keeps its original semantics. |
| Frozen inputs | `tcop.external-frozen-inputs/1.0` in the existing body/hash/sealed-at envelope. Nonempty maps for spec modules, trace checker, converter, schema and TLC configurations; numeric bounds; fixed pinned-tools record hash. Property and trace checks reference these hashes. |
| Tools | Exact original pinned-tools JSON bytes and their sealed hash. Trace/property execution metadata must match its jar, version, size and JDK record. A malformed trace states that TLC did not run. |
| Trace result | Formal `tcop.trace-result/1` record plus execution metadata, exhaustive/end-count evidence, episode ID and original frozen trace text or strict base64 bytes for non-UTF8 malformed input. Original byte SHA-256 must equal both the result and replay commitments. |
| Finding | Exact first rejected index/record where identifiable; evidence; model gap, implementation deviation or mapping error. Pending classifications cannot enter complete results. Widening is also reconstructed from the rejected authority step. Safety stops forbid subsequent episode starts. |
| Receive event | The exact closed `receive` shape from `formal/TRACE_SCHEMA.md`. Accepted events reconstruct consumed IDs/nonces. Episode intake must equal its frozen trace's receive events. Replay state is shared across the bound receiver's live episodes. |
| Adapter write/result | `tcop.tightening-write/1` and `tcop.tightening-result/1`. Closed canonical write; exact local family/row/target/generation; binding metadata and implementation source hashes; one mutating attempt; scheduled/actual submission, deadline, observations and fixed decision. |
| Conformance | `tcop.binding-conformance/1`. Full before/after controls, bound identity, pins, exact write hash, observations, lag and recomputable pass/fail. It is not a runtime admission seal. |
| Calibration | Existing `tcop.crosshost-calibration/1.0`, status `calibrated`. C1-C3 and acquisition evidence hashes; empirical samples; explicit per-binding lag overrides. It remains unsealed after import. |

The generic TCX schemas and validators are unchanged. Study intake uses the
existing signed v0.1 `metadata.interaction_id`, receipt reference and
`session_id`, plus the existing nonce. Unsupported profiles reject through
the existing validator. The receiver's acquisition controller registers
actual verified receipts with local receiver/session/sandbox ownership.
No observation can register its own receipt.

## 005 gate families

There are 14 named 005 gate families. Each is exercised by negative tests.

| Gate | What it rejects | Principal tests |
| --- | --- | --- |
| AM005_EFFECTIVE_PLAN | Wrong/missing 005 pin or conventions | `Plan15Tests`, `Manifest15IntegrationTests` |
| AM005_FROZEN_INPUTS | Missing/changed seal, incomplete inventory, freeze after live | `test_reject_unsealed_frozen_inputs`, `test_reject_inputs_frozen_after_live`, `FrozenInputTests` |
| AM005_TOOLS | Different tools record, jar or JDK; false TLC execution claim | `test_reject_wrong_tools_hash`, `test_reject_wrong_jar`, `test_reject_wrong_jdk`, property pin tests |
| AM005_TRACE_HASH | Different frozen source, original trace or property witness bytes | `test_reject_wrong_frozen_spec_hash`, `test_reject_changed_frozen_trace_bytes`, `test_reject_property_witness_hash_mismatch` |
| AM005_TRACE_RECORD | Missing result, false acceptance, tool error, missing end/count | `test_reject_missing_trace_validation`, `test_reject_malformed_counted_accepted`, `test_reject_tool_error`, `test_reject_empty_accepted_trace` |
| AM005_TRACE_FINDING | Missing classification/evidence or mismatched rejected prefix | `test_pending_classification_cannot_be_final_result`, preserved live-finding tests |
| AM005_SMOKE | Unresolved rejected/malformed smoke before live | `test_reject_unresolved_smoke_rejection`, `test_reject_unresolved_smoke_malformed` |
| AM005_POST_HOC | Replacing frozen results with post-hoc model results | `test_reject_post_hoc_trace`; the inherited 004 sealed/result walker also rejects this |
| AM005_INTAKE | Replayed/missing tokens, invalid correlation or differing event ledgers | `ReceiverIntakeTests`, `IntakeClockGates`, `IntakeTraceStateTests` |
| AM005_TIES | Computed E2 tie credit or missing computation timestamps | `test_reject_tie_credited_computed`, `test_reject_computed_outcome_without_timestamps`, exact simulator tie tests |
| AM005_DEADLINE | Anything other than ready + D + 20000 | `test_reject_deadline_missing_delay`, adapter b/deadline tests, simulator deadline tests |
| AM005_NO_CHANGE | S-A no-change acceptance or E2 prevention credit | `test_reject_no_change_prevention`, `test_sa_baseline_prevention_kept_without_e2_credit`, adapter/simulator no-change tests |
| AM005_GRID | Different rule, count, seed/hash, transition or inseparable placement | `test_reject_grid_rule`, `test_reject_grid_not_1024`, `test_reject_grid_effect_samples_replaced`, `test_reject_separation_failure` |
| AM005_SAFETY_STOP | Missing widening/command stop or subsequent episode starts | `test_safety_stop_derived_from_rejected_authority_step`, `test_safety_stop_requires_no_subsequent_episode` |

Some malformed records fail at an inherited schema/seal gate first. This
never makes them acceptable. Live rejected/malformed traces remain findings;
result reports return raw accepted/rejected/malformed counts per family/row.
The pure 005 checker can examine partial diagnostic records. Complete-result
verification still requires the full study matrix. No runner or partial-run
artifact publisher is supplied in this phase.

## Cannot-widen enumeration

The test enumerates 78,848 candidates:

- Four families, including the capability assessment.
- Eight rows, including the capability row.
- Eleven actions: four abstract actions and seven widening/command candidates.
- Seven named targets, including the absent relay, leaked credential, its
  provider peer, sandbox, control and an unadmitted target.
- Two sandbox identities, two generations and eight binding candidates.

Sixteen combinations serialize: fifteen fixed E2 family/row selections and
one snapshot capability assessment. Every accepted authority result is a
subset of the finite admitted baseline. Every invalid candidate is also
submitted to the adapter and rejected before a mutating transport call.
Separate fake-driver tests tamper with serialized operations/targets and
check that no RPC, Docker or worker mutation occurs. This is exhaustive for
the declared finite representable space, not a proof about arbitrary host
programs or an untrusted Docker daemon.

## Implementation choices

1. Added a 1.1 record bundle rather than changing the meaning of existing
   1.0 gate bundles. Frozen legacy plan fixtures exercise the original
   manifest paths. The plan keeps the 004 provisional axis and adds the
   exact 005 finalization rule beside it.
2. Used signed v0.1 metadata for receipt correlation. No TCX field was added.
   Intake owns its validator/replay window and a lock. It consumes the nonce
   with `use_challenge_nonce` and commits the ID only after every check.
3. Accepted intake returns an opaque in-process ticket. The adapter checks
   its issuing intake, identity and fixed selection and reserves it once,
   including uncertain transport attempts. It cannot substitute another
   action after the receive event.
4. Added a ready-clock callback and exact trace quantum. Expiry is checked
   again at actual ready time. Real exporters can use integer nanosecond
   ticks; metric fields use milliseconds. Missing or out-of-domain nonce
   evidence stays rejected; it is never repaired to make a trace mappable.
5. Kept actual dispatch deviation beside scheduled submission. Ordinary
   scheduler latency cannot silently move the deadline. No artificial delay
   is added to a rows; b rows wait until their fixed D boundary.
6. Bound family targets before intake. S-A's absent relay differs from S-B's
   allowed destination. S-A's known absent-baseline selection records
   `no_change`; it never gains E2 block or prevention credit. Overall row
   counts may still retain prevention explicitly attributed to the E1
   baseline. Live outcomes are not overwritten by computed tie rules.
7. Used canonical JSON as the closed transport boundary. Native writes are
   merge removal or detach only. Harness writes are one worker tuple, Docker
   pause or non-pausing commit. Drivers reconstruct allowed bytes again.
   Result identity records hash the adapter and transport implementation.
8. Native egress reads the baseline revision before its one write to identify
   unchanged revision/hash results. Acceptance queries the exact submitted
   revision, never the latest revision. Detach persistence without a usable
   fingerprint remains unobserved. An explicit rejection arriving after the
   deadline cannot reopen `timed_out`.
9. Initial collection continues 20000 ms beyond the deadline. `observe_until`
   extends read-only collection through later episode closure, without
   another write or decision relabeling. Repeat readback of an already
   observed effect is not a second late effect. The future runner must keep
   that collection open through the episode and preserve every observation.
10. Snapshot is available to the separate C4 capability controller. The
    efficacy selection table has no snapshot row, and the formal receive
    schema has no snapshot choice. No efficacy TCX can route to it.
11. Used injected real host drivers plus a separate staged fixture controller
    and preinstalled VM worker. Neither is replaced by a passing stub on a
    host path. Host commands refuse the synthetic configuration. Their
    concrete endpoints and actual measurements remain host admission work.
12. C2 runs at both 10 s and 1 s configurations. Calibration requires all six
    C1-C3 binding/configuration records, acquisition timings and measured
    persistence/poll/effect barriers. It does not infer processing latency by
    subtracting a guessed poll phase. No poll/configuration measurements are
    pooled. The importer accepts one aggregate record per configuration.
13. Sealed-eligible prediction generation requires 1024 samples. Exploratory
    unsealed calls can request fewer samples. The fixed 20000 ms decision
    window is enforced even for simulator calibration inputs. The existing
    calibration key `decision_deadline_after_ready_ms` holds this base window;
    the simulator adds D separately when it constructs each timeline.
14. Kept the live-runner blocker. These modules implement intake, writes,
    observation and checks. They do not implement efficacy orchestration,
    baseline resets, cross-episode lifecycle management or trace export.
    Before live admission, demonstrate each row's actual poll configuration
    and generation. The existing result bundle retains the 1.4 single-global-
    generation contract; mixed startup configurations need a demonstrated
    lifecycle/record mapping in the runner phase. Do not fabricate continuity.

See [host procedures](amendment-004-conformance-on-hosts.md) for prerequisites,
commands and the fixture/capture interfaces. No OpenShell, Docker, VM, TLC
or network call was run by the new unit tests.

## Files in this change

Changed:

```text
benchmark/studies/external-warning-adaptive-crosshost-v1.yaml
src/tcop/crosshost_sim.py
src/tcop/crosshost_sim_predictions.py
src/tcop/external_adaptive_crosshost.py
src/tcop/external_enforcement_validation.py
tests/test_crosshost_sim.py
tests/test_external_enforcement_foundations.py
tests/test_external_enforcement_v14.py
```

Added:

```text
src/tcop/external_binding_transports.py
src/tcop/external_conformance.py
src/tcop/external_frozen_inputs.py
src/tcop/external_receiver_intake.py
src/tcop/external_tightening_adapter.py
src/tcop/external_trace_validation.py
tests/test_external_binding_transports.py
tests/test_external_conformance_checks.py
tests/test_external_conformance_cli.py
tests/test_external_enforcement_v15.py
tests/test_external_frozen_inputs.py
tests/test_external_receiver_intake.py
tests/test_external_tightening_adapter.py
tests/fixtures/amendment-004-plan-1.4.json
tests/fixtures/amendment-005-host-config.json
docs/amendment-004-conformance-on-hosts.md
docs/amendment-005-implementation.md
```

## Reproduce unit validation

```sh
PYTHONPATH=src:tests python3.11 -m unittest test_external_enforcement_v15 test_external_receiver_intake test_external_tightening_adapter test_external_binding_transports test_external_conformance_checks test_external_conformance_cli test_external_frozen_inputs test_crosshost_sim.Amendment005SimulatorTests
make test PYTHON=python3.11
make schema
git diff --check
```

The first command covers 135 new tests. It includes the complete synthetic
record fixture, all named 005 gate families, intake, serializer/transport
boundaries, exhaustive enumeration, C1-C4 and calibration import. These are
unit results, not TLC execution, runtime conformance or study results.

Final local validation: all 135 new tests passed. `make test
PYTHON=python3.11` ran 602 tests: 601 passed and one skipped because this
execution sandbox disables local loopback listeners. `make schema` passed.
`git diff --check` passed. The new tests used no real OpenShell, Docker, VM
or TLC transport.

The working-tree diff has no change under spec, artifacts, paper,
integrations or formal, or to the STIX comparator. The requested comparison
with 346ee78 includes other jobs' committed formal/canary and paper environment
changes. Those files were not edited or reverted by this job.
