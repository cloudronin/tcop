# Frozen receiver trace v1

The normative structural schema is [trace-v1.schema.json](trace-v1.schema.json).
`trace_to_tla.py` validates that closed schema using the Python standard
library, then validates references, domains, ordering, closure, and mapping.
Duplicate JSON keys, nonfinite values, unknown fields, missing fields,
unmappable capabilities/commands, and out-of-domain inputs are malformed.
No event is discarded, reordered, sampled, rounded, or repaired.

## File and clock

| Required field | Meaning / model mapping |
| --- | --- |
| `schema_version` | Exactly `tcop.trace/1`. |
| `trace_id` | Stable episode identifier retained in the immutable input. |
| `sandbox_id`, `sandbox_generation` | One admitted sandbox/generation for the entire file; all events must belong to it. The current model has one implicit sandbox. |
| `clock.origin` | Exactly `evidence_emitted`; time zero is evidence emission, or the same predeclared reference event in a no-evidence episode. |
| `clock.tick_duration_ns` | Positive integer duration of one exact model tick in nanoseconds. |
| `parameters` | The predeclared model instance, listed below. |
| `initial_authority` | Entire initial capability set, projected onto `Authority` at `Init`. |
| `events` | Nonempty, complete, ordered event array; the last event must be `end`. |

All `t`, `expires_at`, intervals, delays and lag bounds use the same exact
integer tick scale. `t` is nonnegative; `expires_at` can be negative for
already-expired evidence. Event timestamps are nondecreasing. Array order
is the observed ordering at equal timestamps. Preserve a common clock or
an independently established exact mapping to one; do not round timestamps
or fit parameters after observing outcomes. This checker does not infer
clock synchronization. Pick a lossless quantum; high-resolution traces can
require many single-tick model steps and may need longer timeouts.

Identifiers are ASCII `[A-Za-z0-9_.:/-]{1,128}`. Authority and capability
values are two-element arrays `[kind, target]`, where `kind` is `egress`,
`credential`, or `work`. Work is exactly `["work", "benign"]`. Targets must
be declared in the corresponding parameter domain. Sets are encoded as
arrays without duplicates; array order within an authority set has no
meaning. A selected tightening is `["deny_egress", destination]`,
`["revoke_credential", credential]`, or `["freeze", "sandbox"]`.

| `parameters` field | TLA+ constant |
| --- | --- |
| `destinations`, `credentials` | `Destinations`, `Credentials`; one or two distinct identifiers each. |
| `primary_destination`, `primary_credential` | `PrimaryDest`, `PrimaryCredential`; members of those domains. |
| `a0_kind` | `A0Kind`: `egress` or `credential`. |
| `baseline_denies_a0` | `BaselineDeniesA0`. |
| `action_interval` | Positive `ActionInterval`. |
| `approval_delay` | Nonnegative fixed `ApprovalDelay`. |
| `min_lag`, `max_lag` | Maps with exactly `deny_egress`, `revoke_credential`, `freeze`; per-kind nonnegative bounds, minimum at most maximum. |
| `receive_until` | Nonnegative `ReceiveUntil`, the last model tick admitting receipt/selection. |

The initial set must equal the model's `Baseline`, including independent
benign work and excluding A0 exactly when the baseline flag is true. A
contradictory known initial set is rejected, not silently replaced. A
capability outside the declared domains is unmappable/malformed.

The adapter allows zero through seven evidence deliveries. It specializes
only the model's bounded `Messages` and `Msg` fixture-data operators to the
actual input records, leaving validation, transitions, and properties
unchanged. `MaxMessages = max(1, delivery_count)` meets the unchanged base
assumption; an empty `Messages` set admits a no-evidence episode. All other
instances use `ReadyAtEmission = FALSE` and `LocalChoices = Tightenings`;
the observed selected pair constrains each local choice. No synthetic
acceptance or evidence is inserted.

## Event fields and projection

**Every event requires `type`, `t`, and `authority`.** `authority` is the
complete projected capability set **after** that event; it constrains
`Authority'`. `t` constrains both pre- and post-state `now` for that event.
All additional fields below are required for their event type, and no
other fields are permitted.

| `type` | Additional required fields | Model action / projection |
| --- | --- | --- |
| `receive` | `message`, `observation_id`, `nonce`, `signature_valid`, `peer_authorized`, `expires_at`, `interaction_id`, `receipt_interaction_id`, `receipt_verified`, `receipt_receiver_local`, `decision`, `selected` | `Receive(m)`; envelope, replay tokens, post-status and local choice as detailed below. |
| `submit` | `message` | `Submit(m)` at exactly `submitAt[m]`; one submission per accepted delivery. |
| `effect` | `message` | `TakeEffect(m)` at exactly `effectAt[m]`; post-authority must reflect the selected removal. |
| `attempt` | `action`, `capability`, `authorized`, `denied`, `executed` | `HarmfulAttempt` for A0-A3, `BenignAttempt` for A4; admission flags, capability and outcome all match the model. |
| `authority` | None | A state observation using the stuttering case of `[Next]_vars`; authority must equal current `Authority`. It cannot authorize an unexplained change. |
| `end` | None | A final state observation requiring A4 attempted and all received messages rejected or effective, with no approval/pending binding. |

`receive` denotes the model's atomic receiver intake: validation/decision
and local selection at timestamp `t` (validated-request-ready for an
accepted observation). This is not a claim that network arrival,
cryptographic processing, and selection take no wall time. If an exporter
cannot identify this event without inventing or moving an observed event,
the trace is unmappable; preserve the underlying acquisition log for
investigation. Emission and the action interval retain the same clock
origin. The current model cannot separately represent a gap between the
validation decision and local selection.

| `receive` field | Exact mapping |
| --- | --- |
| `message` | Unique delivery key, mapped to integer slot `m`. A repeated delivery gets a new key, while retaining the wire observation ID and/or nonce. |
| `observation_id`, `nonce` | `Msg(m).id`, `.nonce`; checked against `seenIds` and `seenNonces`. Missing nonce is malformed. Do not export an already-validated replay boolean. |
| `signature_valid` | Boolean `Msg(m).signed`, as established by the actual signature verifier. |
| `peer_authorized` | Boolean `Msg(m).authorized`, from the actual admitted peer/scope decision. It is independent of signature validity. |
| `expires_at` | `Msg(m).expires`, compared with `now` at the decision. Equality is unexpired. |
| `interaction_id`, `receipt_interaction_id` | String or null. The adapter computes equality; both must be present to correlate. |
| `receipt_verified` | Boolean reporting actual receipt verification. |
| `receipt_receiver_local` | Boolean reporting ownership/correlation in the receiver's admitted local receipt/session registry for this sandbox/generation. |
| Correlation conjunction | `Msg(m).correlated = receipt_verified AND receipt_receiver_local AND interaction_id != null AND interaction_id == receipt_interaction_id`. |
| `decision` | Exactly `accepted` or `rejected`, projected to post-`status[m]` (`approval` or `rejected`). |
| `selected` | Receiver-local tightening selection, never a TCX command: pair for acceptance; null for rejection, projected to post-`choice[m]` (`NoChoice` for null). An unsupported kind/target is malformed; a mismatching decision/choice is rejected by TLC. |

Truth is not a receiver input. `Msg(m).lie` is set to false because it is
unused by receiver acceptance or action selection; the checker does not
establish whether harm happened. Authentication and receipt booleans are
recorded observations, not cryptographic proofs embedded in the trace.
The exporter must obtain them from actual checks, not fill them from the
claimed decision. Source signatures and raw receipt evidence remain in the
frozen evidence package.

For `attempt`, `action` is exactly `A0`, `A1`, `A2`, `A3`, or `A4`.
`capability` must equal `AttemptCapability(i)` for A0-A3, or the independent
work capability for A4. `authorized` constrains membership in pre-state
`Authority`; `denied = NOT authorized` and `executed = authorized` match the
model's synchronous new-action attempt. Contradictory observed flags are
well-formed input but are rejected by TLC. They are not normalized. Separate
in-flight operations, partial execution, environment failures, and other
capability ladders are outside the current contract; they must not be
silently mapped to a successful trace.

## Existential state, completeness, and outcomes

`TCOPTrace` extends `TCOPReceiver` and adds only `traceIndex`. It starts at
`Init` with the projected initial authority. Each next record requires the
matching base action and matching post-state projection; state observations
use base-spec stuttering. Between records **only `Tick` may be hidden**.
No evidence decision, submission, effect, or A0-A4 attempt can be invented
by the checker. Urgent model events block ticking past their due time.

Unobserved variables are `status`, `choice`, `submitAt`, `effectAt`,
`seenIds`, `seenNonces`, `accepted`, `delivered`, `Covered`, `effective`,
`attempt`, `nextAttempt`, `result`, `a4`, and `Executed`. TLC maintains them
through the unchanged transitions. Observed events constrain the relevant
parts rather than letting Python manufacture internal state. In particular,
`Submit` existentially chooses an in-bounds lag; the recorded effect fixes
which choices can extend to the end. Hidden `now` values are successive
single ticks. Observed authority, outcomes, selection and timestamps are
never existentially changed.

The wrapper explicitly allows a nonmatching branch to stutter. This avoids
confusing a failed lag choice with rejection when another lag choice can
match the whole trace. **TLC success alone never means accepted.** Exhaustive
search must finish successfully and reach `traceIndex = Len(TraceEvents)`.
The invariant `TraceReport` emits reached indices without deliberately
failing a property. The first rejected event is the maximum reachable index
(number of consumed events), interpreted as a **zero-based** `events` index.
An initial mismatch uses index **-1** and an `initial_authority` record.
At `end`, all logged bindings must be settled and A4 attempted, so an
accepted finite prefix can extend to the base model's fair terminal run.

| Result | Meaning |
| --- | --- |
| `accepted` | A complete conforming execution exists, demonstrated by TLC reaching the final index after an exhaustive successful run. |
| `rejected` | Exhaustive search cannot extend a prefix through the next record, or no model initial state matches the initial authority. |
| `malformed` | Invalid JSON/schema or an unmappable trace; TLC was not used to grant acceptance. |
| `tool_error` | Pin mismatch, timeout, parser/checker failure, or other execution problem. This is never relabeled as trace rejection or acceptance. |

Every result records the original byte SHA-256, receiver and wrapper spec
hashes, converter and schema hashes, generated module/config hashes when
present, pinned-tools record hash, TLC command/mode/stats, elapsed time,
and first rejected index/record where identifiable. Malformed JSON has no
identifiable record. Missing input files are command errors, not accepted
traces. Real rejected traces also get `FINDING.md` beside their result;
intentional fixture rejections remain test results. Preserve rejected
inputs and results exactly like simulator disagreements. Do not fix the
trace or weaken a property to obtain acceptance.

## Run commands

Smoke traces do not exist yet. **Phase 3 smoke traces are the first real
input.** All current examples are authored fixtures.

From the repository root, to validate every JSON file recursively in a
directory of frozen traces (the directory must contain only trace JSON):

```sh
python3 -B formal/trace_to_tla.py formal/traces/frozen --output-dir formal/traces/validation-results
```

Replace `formal/traces/frozen` with the actual frozen-trace directory. The
output must be under `formal/` and outside the input directory. A single
file uses the same command. Default is sandbox-compatible DFID; add `--bfs`
outside the sandbox for breadth-first checking. `--timeout 120` is the
per-trace wall-time limit in seconds; a timeout is a tool error, never a
pass. The directory command checks every discovered input and exits nonzero
if any result is rejected, malformed, or a tool error. Per-trace output
folders use input filename and trace-hash prefix, keeping source files
untouched. A directory `summary.json` retains full result records.

Run fixture expectations with:

```sh
sh formal/run_trace_fixtures.sh
```

The fixture runner checks both outcome and first rejected index, verifies
manifest coverage, and fails on the first mismatch. Expected rejection is
not a TLC property violation. The base contract and its properties remain
unchanged.
