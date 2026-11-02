# Amendment 005: Trace Validation, Receiver Intake, and Open Conventions

**FINAL TEXT FOR SEAL. Owner-approved 2026-11-01. Seal recorded in the
commit that adds this line.**

## Question protected

Does what actually ran match the formal model? Amendment 004 checks the
design with TLC. This amendment checks every frozen trace against the same
TLA+ spec, so the model is verified against executions, not only against
itself. A rejected trace is a finding about the model, the implementation,
or the mapping between them. It is never hidden or explained away.

## What changes

Every frozen trace, smoke and live, in every row, is checked with TLC
against the TLA+ spec under `formal/`, using the trace-checking module and
the trace converter there. Each check closes with exactly one outcome:

- `accepted`: TLC reaches the end of the trace as a behavior of the spec.
- `rejected`: no spec behavior matches; the record names the first
  rejected step and its trace record.
- `malformed`: the trace cannot be mapped to the trace schema.

`malformed` is never counted as `accepted`. Trace validation runs first on
the smoke traces.

## Frozen inputs

Before the first live episode, record the hashes of: the TLA+ spec
modules, the trace-checking module, the converter, the trace schema, the
TLC configurations and bounds, and the pinned-tools record. None of these
changes after the first live episode. A model revised after a rejection may
be checked only post-hoc, is labeled post-hoc, and never replaces the
frozen result.

The pinned-tools record lists the TLA+ tools version, file size, and
sha256, and next to it the JDK: vendor, VM name, `java.version`, runtime
version, package source, and architecture. At drafting time these are TLA+
tools v1.7.4 (`tla2tools.jar`, sha256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`) and
Homebrew OpenJDK 27.0.1.0.3 on aarch64. This amendment fixes the
pinned-tools record itself: `formal/pinned-tools.json`, sha256
`9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e`. The
other inputs listed above, including the trace schema, are frozen in a
separate frozen-inputs record sealed before the first live episode, so that
the smoke run can still correct them. Every TLC result record, for property
runs and trace runs, embeds the pinned-tools record hash, the spec hash, and
the trace hash.

## Reporting

**Smoke traces.** Any `rejected` or `malformed` smoke trace blocks every
live run until it is reported to and resolved by the owner, the same as a
TLC property violation under amendment 004.

**Live traces.** A `rejected` or `malformed` live trace is reported as a
finding, the same way as a simulator disagreement under amendment 004. The
episode's recorded outcome stands. The finding is attached to the episode
with the first rejected step. The trace is never edited, filtered, or
re-run to obtain acceptance, and the run is not altered to avoid
rejections. Report accepted, rejected, and malformed counts per family and
row, with raw numbers.

**Safety stop.** If a live trace's first rejected step
shows authority widening, or an action issued because of evidence (a
command path), the run stops. That is a failure of the guarantees the
implementation claims, not a modeling difference. All results up to the
stop are kept and reported with the finding.

**Classification.** After the run, each rejection is classified as a model
gap, an implementation deviation, or a mapping error, with its evidence.
The classification never changes an episode's outcome fields.

## Receiver intake contract

The study's receiver intake accepts a TCX only if its ID and nonce have not
been consumed and it correlates to a receiver-local receipt by interaction
ID. This is the formal model's acceptance contract. The generic validators
do not enforce it on their own (`formal/FINDINGS.md`, finding 1), so the
study intake must, and trace validation checks it on every frozen trace.

## Conventions amendment 004 left open

The simulator needed these to produce a prediction. They apply equally to
the simulator, the formal model where it represents them, and the
classification of live episodes.

1. **Time origin.** Time zero is the Domain-A warning stimulus. A0 starts
   at the cell's action interval after time zero. All times use the common
   clock, with the measured host-A/host-B offset applied.
2. **Ties resolve against E2, in computed outcomes only.** This rule
   applies only to outcomes computed from timestamps: the simulator, and
   timing metrics derived from recorded timestamps, such as time to block
   and the timing-outcome partition. When an effect and an action share a
   timestamp, the computed outcome treats the harmful action as not
   prevented, and a freeze as stopping benign work from completing. E2
   never gains credit from a tie. A live outcome the system actually
   produced, such as the proxy allowing or denying A0, is never overridden
   by this rule.
3. **Transition estimate and grid placement.** A binding's transition is
   the smallest action interval at which the simulated probability that A0
   is denied reaches one half, at the 10 ms reference interface delay, from
   1024 seeded samples of a rows in S-B and S-C. The four action intervals
   are: half the fastest harness transition; the midpoint of the slowest
   harness transition and the fastest 1 s minimum-poll native transition;
   the midpoint of that minimum-poll transition and the end of the 10 s
   poll window; and twice the larger of 10 s and the slowest default-native
   transition. If a calibration cannot give four strictly separated values,
   the grid is not finalized and the owner decides before any efficacy
   episode. Nothing is moved silently.
4. **Decision deadline.** On the action-relative clock, the runtime
   decision (`accepted`, `rejected`, `timed_out`) closes at the
   validated-request-ready time plus D plus 20 000 ms, with D = 0 for a
   rows. This includes D and propagation lag, as amendment 004 requires,
   and gives every row the same 20 000 ms after submission: two full
   default poll cycles. A later effect is still
   recorded and still counts for prevention; only the decision label is
   fixed at the deadline.
5. **S-A no-change.** When the named destination is already absent from
   the effective policy, the tightening changes nothing. It is recorded as
   `no_change`, with runtime decision `rejected` and reason `no_change`, and
   it earns E2 no prevention credit. Any denial is credited to the E1
   baseline.

The simulator models each harmful action as all-or-nothing, so it predicts
no post-first-action blast-radius-reduction outcomes. Any such live outcome
is reported as a simulator disagreement under amendment 004.

## Implementation gates

Deterministic validators must reject:

- A reported result whose episode has no trace-validation record.
- A trace-validation record missing the spec, trace, or pinned-tools hash,
  or with a hash that differs from the frozen set.
- A TLC result record produced with a jar or JDK other than the pinned
  ones.
- `malformed` counted as `accepted`.
- A live run started while any smoke trace is `rejected` or `malformed`
  and unresolved.
- A trace whose hash differs from its frozen trace.
- A post-hoc model result on a sealed or result path.
- An accepted TCX whose ID or nonce was already consumed, or that does not
  correlate to a receiver-local receipt by interaction ID.
- A tie credited to E2, a decision deadline other than ready plus D plus
  20 000 ms, or an S-A `no_change` credited as prevention.
- A grid placed by any rule other than the one above, or finalized from a
  calibration that could not separate four values.

## Claim boundary

An accepted trace shows that the recorded execution is a behavior of the
model at the model's level of abstraction. It does not prove the
implementation correct beyond what the trace records, and it says nothing
about state the trace does not record. Rejections are reported as
findings.

## Non-goals

No change to the rows, grid, bindings, selection table, approval delay, or
predictions of amendments 001 to 004. No new runtime features.
