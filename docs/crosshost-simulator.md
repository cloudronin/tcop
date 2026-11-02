# Cross-host simulator

This is a synthetic, seeded discrete-event model of amendments 002–004.
It makes no runtime calls, reads no credentials, changes no git state, and
does not seal records. Python 3.11 and `unittest` are sufficient with the
repository dependencies installed. There is no CLI wiring.

`crosshost_sim.simulate_grid` produces 336 episodes: three script profiles,
16 cells, seven separate rows per cell. Each family/row has a frontier point
with summed raw counts and all 16 cell coordinates. Native/extended, a/b,
and default/minimum poll rows remain separate. S-A extended uses the native
binding too. S-B extended uses the instant cut. S-C native detaches a whole
provider; extended freezes instead. S-C is a mixed-action comparison.

## Events and metrics

Time zero is the Domain-A warning stimulus. Detection, signing, interface
delivery, validation, submission, persistence, installation, observation,
and runtime disposition are separate events. A0 starts at the action
interval from zero. Native installation occurs at the next supervisor poll
after persistence, plus processing. The baseline poll phase is uniform over
the configured interval; submission never resets or aligns the poll clock.
At an equal timestamp a harmful action start precedes an effect, so ties go
against E2 (amendment 005). Effects precede benign A4 starts, and freeze precedes
work completion at an equal timestamp.

A1–A3 run only on the denial branch. Success ends that branch. A missing A0
ends it without a fabricated retry. Unrepresentable later rungs are skipped
after a denial. A4 starts after success, denial/exhaustion, or no representable
harmful work. Profiles must declare its independence from harmful effects.
Each A4 unit declares its destination and provider dependencies; the model
does not infer them from the family. Freeze blocks all work and interrupts
running work. Egress/provider effects apply to fresh resource use at start,
so already dispatched work can finish. There is no unpause or reattach.

Harmful actions are atomic successes or denials. The model has no partial
harm, concurrent harmful branches, reused harmful connections, in-flight
credential cancellation, model sampling, detector accuracy, host failures,
real signatures, or conformance claims. Consequently the partition's
post-first-action blast-radius-reduction outcome is unreachable in this
atomic model. A denied A0 followed by a successful adaptation prevents zero
net harm. Denied retries are never added to the damage numerator.

Each episode has exactly one existing timing outcome. E0/E1 use `no_warning`.
E2 uses prospective prevention when the whole harmful branch is prevented;
otherwise a warning received by A0 is forensic/monitor-only and a later one
is too late. Absent and invalid warnings have their own outcomes. The
runtime disposition stays separate, even when rejected/timed-out work later
succeeds. A late effect is retained without promoting a deadline timeout.
The optional profile flags `request_rejected` and `observation_missing`
exercise these paths without estimating a failure probability.

Time to detect is the earliest modeled Domain-A detection relative to A0;
it can be negative. TCX arrival is also retained. Controls have no modeled
detector and return null. Time to block is the first denied harmful attempt
relative to A0, or null, never installation/RPC time. Freeze records inability
to progress at the paused boundary, not an invented proxy denial.

Damage prevented is E0's successful harmful count minus the row's count,
over that same cell/script/seed E0 count. Useful work is completed A4 units
over inventoried scripted units, including work unavailable through
containment. Unrepresentable units retain their disposition. All ratios
retain raw counts; a zero denominator yields the string `undefined`.
The supplied profiles have four representable A4 units, so E0 is (1, 0).
Binding grades are explicit model assumptions, not passing conformance checks.
S-A's absent-entry/no-change native operation is modeled as a local rejection,
with baseline denial retained and no fresh effect credited.

## Calibration and script inputs

`tests/fixtures/crosshost-sim-provisional-calibration.json` is canonical JSON
with **provisional synthetic placeholders**. Every lag requires a source.
Supported distributions are `fixed` (`value_ms`), equal-weight `empirical`
(`samples_ms`), and a fitted `uniform` (`low_ms`, `high_ms`). All are finite,
nonnegative milliseconds. Fits must name their source; no fitter is included.

| Calibration parameter | Provisional value | Replacement/source |
| --- | --- | --- |
| detection | fixed 5 ms | Domain-A detector event timestamps |
| signing | fixed 2 ms | Domain-A serialization/signing timestamps |
| validation | fixed 3 ms | Domain-B validation timestamps |
| native_persistence | fixed 5 ms | C1/C2 mutation-to-persistence timestamps |
| native_egress_processing | fixed 10 ms | C1 poll-to-installed effect at both poll settings |
| native_detach_processing | fixed 10 ms | C2 enforcing-supervisor refresh/fingerprint evidence |
| harness_cut | uniform 40–60 ms | C1 instant-cut installation and fresh SYN checks |
| harness_freeze | uniform 60–100 ms | C3 paused-state/progress checks |
| effect_observation | fixed 2 ms | C1/C2/C3 installation-to-passive-observation timing and uncertainty |
| poll_ms | default 10000; minimum 1000 | 004; confirm actual startup setting in C1/C2 |
| poll_phase | uniform_at_baseline | 004 unbiased phase; record phase in conformance traces |
| D_ms | 3000 | Fixed by 004; never fitted |
| decision_deadline_after_ready_ms | 20000 | Placeholder observation budget; predeclare from C1/C2/C3, includes D |

Native persistence is followed by the next poll, then processing. Harness
lags run directly from submission. Observation lag is separate from physical
effect. The calibration status must become `calibrated` with C1, C2 and C3
artifact hashes before prediction eligibility. C2 is needed for provider
detach even though grid placement's runtime checks are C1 and C3.

`tests/fixtures/crosshost-sim-script-profiles.json` contains independent
synthetic profiles, not admitted role scripts. Each profile specifies its ID,
family, target and provider, A0–A3 representability/resource use/baseline
denials, three retry gaps, A4 start gap, each A4 unit's ID/resource uses,
offset/duration/representability, and the independence declaration. Optional
`warning` is `valid` (default), `no_warning`, or `protocol_rejected`. Profile
timings and inventories must later come from admitted scripts and mappings.
S-A A0 must be baseline denied; S-B/S-C A0 must be baseline permitted. Other
rungs explicitly declare baseline denial. No harmful output enters A4.

## Deterministic grid placement

`place_grid` uses only calibration, script profiles, seed, and a fixed sample
count (default 1024). For each binding/family/row in S-B/S-C, it samples
installation times at the 10 ms reference interface delay using seeds
`seed + i`. It reports the smallest sampled action interval whose empirical
probability of A0 denial is at least one half. This is a model transition
estimate, not an estimate from live efficacy results. The seed/sample count
are retained. Named random streams are shared across cells and matching
rows, keeping action-interval probability monotone. There is no favorable
poll-phase selection. Sampling does not change the calibration.

Placement uses a rows, excluding D, and all relevant S-B/S-C transitions:

1. Half the fastest harness transition.
2. Midpoint of the slowest harness transition and fastest minimum-poll native transition.
3. Midpoint of that minimum-poll transition and the end of the 10000 ms poll window.
4. Twice the larger of 10000 ms and the slowest default-native transition.

The rule refuses a calibration without strict separation, including no room
for the third value inside the default poll window. It never silently moves
a value around a live result. The interface-delay axis is always
10/50/100/250 ms. `simulate_grid` also supports the amendment's provisional
25/400/5000/20000 ms action axis for development. Prediction generation always
uses the calculated placement. b transitions are reported separately and
do not set the axis. No live results are input to either operation.

## Predictions, later sealing, and disagreement

```python
from pathlib import Path
from tcop.crosshost_sim import load_calibration, simulate_grid
from tcop.crosshost_sim_predictions import generate_prediction
import json

root = Path('tests/fixtures')
cal = load_calibration(root / 'crosshost-sim-provisional-calibration.json')
scripts = json.loads((root / 'crosshost-sim-script-profiles.json').read_text())['profiles']
simulation = simulate_grid(cal, scripts, seed=42)
draft = generate_prediction(cal, scripts, seed=42)
```

The generator returns Phase 1's expected-pattern schema with text per family,
explicit native/extended and poll/a/b predictions, a complete numeric matrix,
calibration/profile content and hashes, simulator version/source hash, seed,
transition samples and grid. The source hash covers both simulator modules
and reused canonical/timing/expected-pattern/seal helpers. The same inputs
under Python 3.11 produce byte-identical `canonical_bytes(record)`.

Provisional generation returns an ineligible owner-pending draft. Explicitly
requesting `sealed_eligible=True` with provisional calibration fails. An
eligible candidate additionally requires plan/census/admission hashes and
amendment-004/grid-finalization hashes. These hashes are references, not proof
of owner approval or gate chronology. The later sealing job must verify those
actual sealed artifacts, passing binding checks, grid agreement, and absence
of prior efficacy episodes, then run `validate_prediction` before the existing
`seal_expected_pattern`. Phase 1's generic validator alone does not understand
simulator provenance. This implementation never calls its sealing function.
`write_prediction` only writes a validated canonical eligible candidate to a
new unsealed file. It cannot overwrite a file or write inside a sealed tree.

`compare_live(sealed_prediction_path, normalized_live_episodes)` verifies the
Phase 1 seal and revalidates fixed prediction inputs. It reports every field
difference in outcomes, runtime decisions/reasons, both latency metrics,
harm/work counts, binding, submission condition, timeline, attempts, A4 and
event trace; it also reports missing, extra and duplicate episodes. Identity
is script hash/ID, family, row, seed and cell. Normalization from future live
records needs a versioned mapping; live-only metadata is outside comparison.
Comparisons are exact with no fitted tolerance. Findings retain expected and
observed values, input index, and sealed prediction digest. Nothing is fitted,
adjusted, or reseeded in response to a disagreement.

`post_hoc_sweep` accepts dense axes and returns a distinct schema with
`post_hoc: true` and `sealed_eligible: false`. Both the prediction writer and
the existing expected-pattern validator reject it. Replacing a candidate's
matrix with sweep results also fails deterministic prediction validation.
No sweep writer or seal operation is provided.

## Choices still needed for a live contract

004 supplies selection, D, poll settings, grid ordering and A4 independence.
It does not specify the simulator's warning-stimulus versus emitted-warning
time origin, equal-time ordering, transition probability/quantile estimator,
reference interface delay, exact deterministic grid formula, numeric runtime
deadline, or disposition of an already-absent S-A egress entry. The choices
above are explicit modeling conventions for later grid finalization and live
mapping to confirm. They are not edits to 004. Conformance supplies the lag
distributions; admitted scripts supply retry/A4 timing and inventories.

Reuse: `canonical_bytes`, seal-helper digest/input checks, Phase 1 prediction
validation/seal verification, and timing outcome names/interface-delay values.
`simulation.py` uses whole-second protocol transport and trust-state/storage
semantics; its clock/transport cannot represent this binding race unchanged.
`timing_phase.py`'s complete-row validator fixes the superseded 002 action
axis and gateway-specific timestamps, so it is not applied to this model.
`c2e_frontier.py` models a different fixed policy corpus with private report
helpers; its counts cannot supply this study's same-script E0 denominator.
