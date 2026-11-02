# TCOP receiver and tightening bindings

This is a finite abstract model of the requested receiver contract and
amendment 004's one-sandbox, tightening-only adapter. It is not a refinement
proof of the Python implementation or evidence of runtime conformance.
The model is [tla/TCOPReceiver.tla](tla/TCOPReceiver.tla); the bounded instance
and positive reachability reports are in [tla/MC.tla](tla/MC.tla).

## Properties

| Property | Meaning |
| --- | --- |
| `NoWidening` | Every transition preserves or removes sandbox authority: `[][Authority' \subseteq Authority]_vars`. |
| `AcceptOnlyValid` | Every acceptance audit records a signed, authorized, unexpired, receiver-correlated message with neither its ID nor its nonce previously consumed. |
| `EffectHolds` | Effective restrictions remain installed and no subsequently executed sandbox action uses an authority they cover. |
| `LyingPeerOnlyCostsAvailability` | A false accusation has exactly the same tightening-only authority boundary as true evidence, and receiver transitions never execute sandbox actions. |
| `TimingClaim` | With no baseline A0 denial and every possible selected binding's minimum lag strictly above the action interval, every post-A0 state records A0 success. |
| `FastTimingClaim` | With validated evidence ready at emission, a local action covering A0, and maximum lag plus approval delay strictly below the interval, every post-A0 state records A0 denial. |
| `LadderOrder`, `A4Independent` | Retries require the preceding denial, and A4 is attempted only after the harmful branch stops. |
| `BoundedCompletion` | Every state at the clock horizon is terminal, with A4 attempted and no outstanding binding. |

Deadlock checking stays enabled. Only explicit `Terminal` states have a
self-loop; terminality requires A4 to have executed or been denied. There is
no arbitrary nonterminal self-loop in `Next`. The temporal `Spec` permits
stuttering and assumes weak fairness of `Progress`. `Completes` states
fair termination, while `A4Completes` and `EffectReached` provide stronger
sanity properties in `SanityLiveness.cfg`.

Actual sanity runs use exhaustive reachability, so no failed invariant is
used as an existential probe. `WitnessReport` prints reachable terminal
states. `Sanity.cfg` requires a completed A4 and installed egress restriction
at every terminal state. `SanityLying.cfg` also exposes a reachable valid
false accusation that removes authority. One reported false-evidence witness has all harmful attempts and A4
denied by freeze, with no sandbox executions.

## Transitions and time

Evidence is emitted at clock zero. General runs can receive a bounded set
of wire variants at any interleaving through `ReceiveUntil`. `Receive`
atomically validates, consumes replay tokens, and makes one receiver-local
selection. It never reads the evaluator-only `lie` flag. Messages contain
no action or command field. `Submit` occurs after the fixed approval delay
and nondeterministically chooses an integer effect lag from the per-kind
`MinLag..MaxLag` interval. `TakeEffect` alone removes authority. There is
one submission and at most one effect per accepted message, including a
no-change restriction on authority already absent from the baseline.

A tick cannot skip a due submission, effect, harmful attempt, or A4. Events
due at the same tick may occur in either order, including A0 before an
effect at that tick. Thus the timing inequalities are deliberately strict.
Zero lag permits submission and effect at the same clock value, with other
same-tick events interleaved. The authority set stays unchanged until the
effect transition. Approval is not an extra action or write.

A0 occurs at `ActionInterval`; denied retries occur one interval apart.
Success or four denials ends the harmful branch. A4 is attempted in that
same clock tick, regardless of success or exhaustion. Its sole capability,
`<<"work", "benign">>`, exists in the baseline, is never created or removed
by harmful execution, and may be removed by freeze. Freeze prevents sandbox
action execution; the external model clock and receiver keep progressing.
There is no release, attach, restart, recovery, or new episode.

The timing configurations use `ReadyAtEmission = TRUE`: the initial state
represents a valid message already correlated, accepted, and locally
selected at zero. This makes transport, validation, and policy scheduling
latency zero. The slow conclusion also holds with later delivery, as the
general receiver can only delay the effect. The fast conclusion needs this
readiness assumption, or an additional upper bound on those omitted delays;
`MaxLag + ApprovalDelay < ActionInterval` alone cannot guarantee prompt
receipt. Both conclusions additionally have `BoundedCompletion`, so a
post-A0 conditional is not the only check.

## Bounds and configurations

Every configuration has two destinations and two credentials plus the
independent benign-work capability, one sandbox/generation, and seven wire
variants: true peer evidence, valid false peer evidence, reused ID, reused
nonce, unauthorized/forged signature, expired evidence, and uncorrelated
evidence. ID/nonce variants are replays only once their matching token was
actually consumed. Rejected evidence never consumes replay state. The
combined unauthorized/forged variant fails both signature and authority
predicates; these cryptographic predicates abstract their independent
implementation checks.

| Configurations | Interval | Approval | Lag, each kind | Baseline denies A0 | Delivery/selection |
| --- | ---: | ---: | --- | --- | --- |
| `NoWidening`, `AcceptOnlyValid`, `EffectHolds`, `LyingPeer`, `MC` | 1 | 0 | 0..1 | false | Up to 2 of 7 variants, ticks 0..1; any of 5 local tightenings |
| `MCApprovalBaseline` | 1 | 1 | 0..1 | true, credential A0 | Same general receiver and all safety groups |
| `TimingSlow` | 1 | 0 | 2..3 | false, egress A0 | Ready at zero, any A0-covering action |
| `TimingSlowApproval` | 1 | 1 | 2..3 | false, credential A0 | Ready at zero, any A0-covering action |
| `TimingFast` | 3 | 1 | 0..1 | false, egress A0 | Ready at zero, any A0-covering action |
| `TimingFastCredential` | 2 | 0 | 0..1 | false, credential A0 | Ready at zero, any A0-covering action |
| `BaselineDenial` | 1 | 0 | 0..1 | true, egress A0 | Ready at zero, any A0-covering action; slow implication intentionally inapplicable |
| `Sanity`, `SanityLiveness` | 3 | 0 | 0..1 | false | Ready at zero, primary-destination egress tightening |
| `SanityLying` | 1 | 0 | 0..1 | false | At most 1 of 7 variants at zero; receiver selects freeze |

The horizon is `4*ActionInterval + ReceiveUntil + ApprovalDelay + max(MaxLag) + 1`,
large enough for every retry, A4, and every admitted binding to finish.
There are no state-space truncation constraints. These ticks are abstract
units, not claims that 004's fixed 3000 ms approval or measured runtime lags
have these values. The bound sweep includes intervals 1, 2, 3, lag outcomes
0, 1, 2, 3, and approval 0/1. It is a set of explicit finite instances,
not a proof for all natural-number bounds.

No symmetry reduction is enabled. A0 and the retry distinguish the primary
destination and credential; swapping primary and alternate targets would be
unsound. With two of each, the remaining target classes are singletons and
have no nontrivial sound symmetry. Keeping all states is also suitable for
the optional temporal liveness configuration.

## Mapping to sources and differences

Source file hashes are recorded in [results/source-hashes.json](results/source-hashes.json)
to identify the source snapshot, since other jobs may edit amendment 004.

| Model | Source grounding |
| --- | --- |
| Authority pairs, `Covers`, `TakeEffect` | [Owner framing, Bindings](../docs/tcop-framing-layering-and-bindings.md), and [004, Abstract tightening actions / Rules for every binding](../spec/external-warning-adaptive-crosshost-amendment-004.md): new egress connection, new credential resolution, freeze, no widening and no adapter undo. |
| Local selection without wire commands | [003, What changes](../spec/external-warning-adaptive-crosshost-amendment-003.md); 004, Fixed abstract action-selection table; [federation.py](../src/tcop/federation.py), `_StrategyRuntime.receive/resolve`; [trust.py](../src/tcop/trust.py), `ReferenceResolver.resolve`, where observations become a local capability-specific operating envelope. |
| Signature/peer authorization abstraction | [identity.py](../src/tcop/identity.py), `ObserverIdentity.allows`, registry resolution, delegation validation, and `verify_signature` (25-29, 78-98, 127-135); [validation.py](../src/tcop/validation.py), checks 3-4 (123-140). No cryptographic algorithm is modeled. |
| Expiry, replay and acceptance audit | `validation.py`, expiry/future-time checks (142-152), `ReplayWindow` (53-78), validation replay check (154-156), and separate commit (178-179); `federation.py` receiver-local duplicate check/store in `_StrategyRuntime.receive`. Expiry is inclusive, matching `expires_at < now`. |
| Receiver correlation | [witness.py](../src/tcop/witness.py), `verify_interaction_receipt` (163-186), `WitnessValidator.validate` (294-356), receipt lookup/signatures and observer/subject correlation (329-340); [TCX v0.2 schema](../schemas/tcx-observation-v0.2.schema.json), receipt/interaction fields, and [receipt schema](../schemas/interaction-receipt-v0.1.json). |
| Envelope fields without commands | [v0.1 schema](../schemas/observation-v0.1.json), [v0.2 schema](../schemas/tcx-observation-v0.2.schema.json), and `validation.py` required/optional fields (27-34). General nested metadata is abstracted away, not proved harmless here. |
| `Submit`, delayed `TakeEffect` | 004, Approval delay is a submission condition; Binding grades and layering; Detach decision and propagation; Action-interval grid and finalization. Effect, rather than RPC return, controls authority removal. |
| Harmful branch and baseline flag | [002, Fixed adaptive contract](../spec/external-warning-adaptive-crosshost-amendment-002.md); 003, scenario families; 004, Retry assumption. The false baseline flag represents S-B/S-C-like A0, true represents S-A-like baseline denial. |
| A4 after success or exhaustion | 004, A4 timing and independence, which supersedes 002's denial-centric wording. |

Material abstraction boundaries and mismatches:

- This models the **requested strict receiver contract**, not the generic
  validators verbatim. Normal v0.1 validation checks IDs and sequences but
  does not invoke `use_challenge_nonce`; its `nonce` field is optional.
  `WitnessValidator` permits absent receipts, and its optional receipt check
  compares observer and subject without checking the observation's
  `interaction_id` against the receipt. The model requires receiver-local
  correlation and nonce uniqueness for every acceptance. It does not prove
  that either existing validator alone enforces this stronger contract.
- The generic `ReferenceResolver` also has recovery and healthy/allow
  states. This model concerns the one-episode tightening-only adapter,
  not that broader trust lifecycle.
- Validation and replay commit are atomic here. v0.1 exposes them separately;
  concurrent validation/commit races are not represented. Sequence numbers,
  future-clock skew, tenant/scope details, parser limits, rate limits,
  delegation/rotation, evidence availability, and trust diversity are
  abstracted into valid identity/evidence assumptions rather than reimplemented.
- The general model deliberately lets receiver-local policy select any of
  the three abstract kinds and admitted targets, independently of truth.
  It does not implement 004's fixed family/mode table. Timing cases restrict
  selection to a covering action. Credentials have exact target precision;
  provider-wide native detach coarsening and its collateral work costs are
  not modeled. Snapshot is omitted because it is nonrestricting.
- All bindings are successful and have bounded lag; refusal, unsupported
  guarantees, timeout, effect observation uncertainty, native/harness tags,
  and per-runtime conformance measurements are outside this model. Bounding
  effect lag is an assumption, not a discovered fact about OpenShell.
- A1 uses the admitted credential capability; A2/A3 reuse the admitted A0
  capability. Their indices stand for fresh sessions/subjects, without
  modeling creation, receipt generation, campaign inference, or identity
  changes. Every attempt remains in the same bound sandbox. Harmful side
  effects and in-flight operations are omitted; authority applies to new
  attempts only. Independent A4 resources are present by construction.
- Evidence truth is evaluator-only. False evidence can reduce availability;
  the model makes no claim that signatures or receipts establish truth.

## Tools and exact commands

No downloads, network operations, git operations, or writes outside `formal/`
were requested or performed by the checking scripts. Standard module
extraction by Java uses its normal temporary directory.

Pinned jar: TLA+ tools distribution **v1.7.4**, SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
Its executable identifies itself as **TLC2 Version 2.19 of 08 August 2024,
revision 5a47802**. Java: `/opt/homebrew/opt/openjdk/bin/java`, installed
OpenJDK 27 (the TLC runtime banner reports Homebrew 27.0.1.0.3).

From the repository root, the requested breadth-first command is:

```sh
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp formal/tools/tla2tools.jar tlc2.TLC -workers auto -config formal/tla/MC.cfg formal/tla/MC.tla
```

That command parses successfully but cannot start its fingerprint store in
this sandbox: `java.rmi.server.ExportException: Listen failed on port: 0`,
caused by `SocketException: Operation not permitted`. See
[results/setup-bfs.log](results/setup-bfs.log). No listener permission was
requested and no network workaround was used.

The exhaustive runs use TLC's built-in single-worker depth-first iterative
deepening (DFID), with the same model, properties, and bounds:

```sh
python3 formal/run_checks.py
```

The runner checks the jar hash and executes, for each configuration name N:

```sh
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp formal/tools/tla2tools.jar tlc2.TLC -workers 1 -dfid 50 -fp 0 -metadir formal/states/N -config formal/tla/N.cfg formal/tla/MC.tla
```

Names and exact expanded argument lists are also in
[results/summary.json](results/summary.json). The runner stops on any failed
check. `-dfid 50` is an iteration ceiling, not a state constraint; completed
runs report exhaustion before that ceiling. DFID counts include repeated
visits across iterations; the reported depth below is the last DFID search
level, not BFS diameter. All three temporal safety properties are checked
as TLC implied-action/state checks. Deadlock detection stays enabled.

DFID does not support temporal liveness checking. The optional unrestricted
BFS liveness command is therefore provided but is **not claimed as run**:

```sh
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp formal/tools/tla2tools.jar tlc2.TLC -workers auto -config formal/tla/SanityLiveness.cfg formal/tla/MC.tla
```

During setup, a random-polynomial DFID run exhausted its search but hit
`ArithmeticException: Division by zero` in the tool's final fingerprint
probability report; that run is not counted as a pass. The final runs pin
`-fp 0` and require TLC's explicit successful-completion message and zero
exit status. The original jar was not modified.

## Checked results

All 13 completed checks passed. No property violation was found. Each run
also checks types, denial-only retry order, A4 branch order, bounded
completion, and deadlocks. The `MC` and `MCApprovalBaseline` runs check
all four general receiver safety groups together.

| Configuration | Result | Generated / distinct | DFID level | Wall time (s) |
| --- | --- | ---: | ---: | ---: |
| [NoWidening](results/NoWidening.log) | pass | 1,053,524 / 61,566 | 20 | 19.432 |
| [AcceptOnlyValid](results/AcceptOnlyValid.log) | pass | 1,053,524 / 61,566 | 20 | 20.183 |
| [EffectHolds](results/EffectHolds.log) | pass | 1,053,524 / 61,566 | 20 | 20.082 |
| [LyingPeer](results/LyingPeer.log) | pass | 1,053,524 / 61,566 | 20 | 23.116 |
| [MC](results/MC.log) | pass | 1,053,524 / 61,566 | 20 | 24.999 |
| [TimingSlow](results/TimingSlow.log) | pass | 422 / 54 | 15 | 0.307 |
| [TimingSlowApproval](results/TimingSlowApproval.log) | pass | 606 / 60 | 16 | 0.295 |
| [TimingFast](results/TimingFast.log) | pass | 1,148 / 88 | 25 | 0.315 |
| [TimingFastCredential](results/TimingFastCredential.log) | pass | 762 / 74 | 20 | 0.329 |
| [BaselineDenial](results/BaselineDenial.log) | pass | 526 / 56 | 16 | 0.315 |
| [Sanity](results/Sanity.log) | pass | 463 / 41 | 22 | 0.242 |
| [SanityLying](results/SanityLying.log) | pass | 1,843 / 204 | 16 | 0.351 |
| [MCApprovalBaseline](results/MCApprovalBaseline.log) | pass | 880,913 / 54,198 | 21 | 17.777 |

Times are measured per Java process with Python's monotonic clock; TLC's
own rounded elapsed time, timestamps, worker count, and fingerprint
estimates remain in each log. Counts should not be summed as unique
states across configurations.

Positive witness details:

- `Sanity.log`: an installed egress restriction, A0 denied at tick 3,
  A1 executed at tick 6, and independent A4 executed at tick 6.
- `SanityLying.log`: accepted message 2 (false evidence) takes effect,
  authority differs from the baseline, all harmful attempts and A4
  are denied, and the sandbox execution log is empty. Other legal
  interleavings in this configuration permit A0 before a same-tick
  freeze; the log retains those witnesses as well.

No TLC violation was found. [FINDINGS.md](FINDINGS.md) now records the
model-code gap as finding 1, distinct from a TLC counterexample.


## Pinned-tools record and result binding

The exact observed record is [pinned-tools.json](pinned-tools.json), mirrored
below. Its byte SHA-256 is
`9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e`.
The jar size/hash and JDK properties are verified before every new TLC run.
The Homebrew installation receipt also confirms `poured_from_bottle: true`.
The release name/source/stable designation are the study owner's pin;
no network lookup was made.

```json
{
  "schema_version": "tcop.pinned-tools/1",
  "tla_plus": {
    "version": "v1.7.4",
    "release_name": "The Xenophanes release",
    "release_channel": "latest stable (study-owner supplied; no network verification)",
    "project": "tlaplus/tlaplus",
    "file": "tla2tools.jar",
    "path": "formal/tools/tla2tools.jar",
    "size_bytes": 2274532,
    "sha256": "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
    "source": "https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4",
    "tlc_banner": "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)"
  },
  "jdk": {
    "executable": "/opt/homebrew/opt/openjdk/bin/java",
    "observed_properties": {
      "java.vendor": "Homebrew",
      "java.vm.vendor": "Homebrew",
      "java.vm.name": "OpenJDK 64-Bit Server VM",
      "java.version": "27.0.1.0.3",
      "java.runtime.version": "27.0.1.0.3",
      "os.arch": "aarch64",
      "java.home": "/opt/homebrew/Cellar/openjdk/27.0.1.0.3/libexec/openjdk.jdk/Contents/Home"
    },
    "homebrew": {
      "formula": "openjdk",
      "version": "27.0.1.0.3",
      "path": "/opt/homebrew/Cellar/openjdk/27.0.1.0.3",
      "poured_from_bottle": true,
      "receipt_sha256": "ce5fa4d8794d2d7b6bba44f41246f3778246461dba4c51d2e84c97cb0a392363"
    },
    "observation_command": [
      "/opt/homebrew/opt/openjdk/bin/java",
      "-XshowSettings:properties",
      "-version"
    ],
    "observation_output": "formal/results/java-properties.txt",
    "observation_output_sha256": "dd79ee792e7eea8460d8d2422e132016f0501162bb65b2743dcd8adcc11a7ec3"
  },
  "observed_at_utc": "2026-11-02T02:53:40.047440+00:00"
}
```

Every property-run and trace-run JSON result embeds
`pinned_tools_record_sha256`. New runs bind the observed tools before
execution. Original results in `results/summary.json` retain their counts
and times and explicitly label the hash association as retrospective;
they are not represented as having captured that hash originally.
Raw TLC logs are preserved as raw logs; the corresponding JSON records
supply the tool-record binding.

## Breadth-first confirmation and checking modes

The study owner reports that outside this sandbox all four checks below
completed full breadth-first TLC with `-workers auto` and no `-dfid`:

| Property config | Mode | Result | Generated / distinct | Queue remaining | Complete graph depth |
| --- | --- | --- | ---: | ---: | ---: |
| NoWidening | BFS | pass | 93,987 / 61,566 | 0 | 19 |
| AcceptOnlyValid | BFS | pass | 93,987 / 61,566 | 0 | 19 |
| EffectHolds | BFS | pass | 93,987 / 61,566 | 0 | 19 |
| LyingPeer | BFS | pass | 93,987 / 61,566 | 0 | 19 |

Reported completion text: "Model checking completed. No error has been found."
The structured records are in
[results/owner-bfs-confirmation.json](results/owner-bfs-confirmation.json).
These are owner-reported results, not local executions or fabricated raw
logs. Run time was not supplied and is recorded as null. Their tool hash
associates the requested pin; this agent did not independently inspect the
external execution environment. Their 61,566 distinct states agree with
the local DFID results, while generated counts and depth metrics differ
by search mode.

`run_checks.py` now supports both modes:

```sh
# Outside a sandbox: full breadth-first runs, auto workers.
python3 -B formal/run_checks.py --bfs

# In this sandbox: exhaustive DFID, one worker.
python3 -B formal/run_checks.py

# Select named configurations when checking the runner or a specific group.
python3 -B formal/run_checks.py --config TimingSlow --config TimingFast
```

`--bfs` uses `-workers auto -fp 0` with no `-dfid`. Default DFID uses
`-workers 1 -fp 0 -dfid 50`. Both use the same unmodified model, properties,
and bounds. New logs are named `results/bfs-N.log` or `results/dfid-N.log`;
new records are in `results/summary-bfs.json` or
[results/summary-dfid.json](results/summary-dfid.json). Every record names
its mode, depth metric, exact command, spec/config hashes, and pinned-tools
hash. BFS is an explicit option, not a failed listener attempt followed by
an unreported fallback. DFID remains the sandbox-compatible default.

All 13 property configurations were re-run locally with the tools hash
bound before execution. Their state counts agree with the original runs;
the new elapsed times are in `summary-dfid.json`.

## Frozen trace validation

[TRACE_SCHEMA.md](TRACE_SCHEMA.md) defines every event field and model
projection. [trace-v1.schema.json](trace-v1.schema.json) is the closed JSON
schema. [tla/TCOPTrace.tla](tla/TCOPTrace.tla) adds an index over supplied
observations and restricts each record to a receiver-model transition with
matching projected post-state. Only clock ticks can be hidden; receipt,
selection, submission, effects, and attempts cannot be invented. The
adapter specializes the finite wire data table to actual IDs, nonces,
validity attributes, and expiry values; the receiver contract and every
property remain unchanged. Receiver spec SHA-256 remains
`8028cbaa4bf0b91871cf5278d4c66e9b3fe8ce44c058801879591cf0a5fa0e42`.

Acceptance requires successful exhaustive TLC **and** reachability of the
last trace index. A nonmatching branch can stutter so one wrong
existential lag choice cannot reject an otherwise matching trace. The
maximum reachable index identifies the first rejected record when all
choices fail. Tool failure/timeout is a separate `tool_error` outcome,
never an accepted or rejected trace. Invalid or unmappable input is
`malformed`. Real rejections write a first-prefix `FINDING.md` beside the
result and preserve the original trace unchanged.

Smoke traces do not exist yet. **Phase 3 smoke traces are the first real
input.** To validate a directory of frozen trace JSON files:

```sh
python3 -B formal/trace_to_tla.py formal/traces/frozen --output-dir formal/traces/validation-results
```

Use the actual directory path in place of `formal/traces/frozen`. Add
`--bfs` outside the sandbox. Output remains under `formal/` and outside the
input directory. The command checks all discovered JSON files and exits
nonzero if any is rejected, malformed, or a tool error.

The authored fixtures can be checked now:

```sh
sh formal/run_trace_fixtures.sh
```

Python 3.11 was used to verify the fixture runner and both single-file
and directory CLI paths. The directory check verified all three input
fixtures were checked, rejection caused exit status 1, and a rejection
finding was written (see `results/trace-directory-cli-check.json`). No external Python packages are required. All 22 fixture outcomes and first
rejected indices match their expectations; the full records and TLC logs
are under `traces/fixture-results/`, with the expectation summary at
[traces/fixture-results/summary.json](traces/fixture-results/summary.json).

| Fixture | Expected | Actual | First rejected event index |
| --- | --- | --- | ---: |
| accepted-slow.json | accepted | accepted | none |
| accepted-fast.json | accepted | accepted | none |
| rejected-widening.json | rejected | rejected | 3 |
| rejected-expired.json | rejected | rejected | 0 |
| rejected-replay-id.json | rejected | rejected | 3 |
| rejected-replay-nonce.json | rejected | rejected | 3 |
| rejected-covered-action.json | rejected | rejected | 3 |
| rejected-a1-without-denial.json | rejected | rejected | 2 |
| rejected-receipt-mismatch.json | rejected | rejected | 0 |
| rejected-receipt-absent.json | rejected | rejected | 0 |
| malformed-missing-nonce.json | malformed | malformed | 0 |
| malformed-command.json | malformed | malformed | 0 |
| accepted-no-evidence.json | accepted | accepted | none |
| rejected-initial-authority.json | rejected | rejected | -1 |
| accepted-replay-rejection.json | accepted | accepted | none |
| accepted-invalid-rejections.json | accepted | accepted | none |
| accepted-freeze.json | accepted | accepted | none |
| accepted-credential.json | accepted | accepted | none |
| rejected-missing-submit.json | rejected | rejected | 1 |
| rejected-missing-a4.json | rejected | rejected | 3 |
| rejected-lag-out-of-bounds.json | rejected | rejected | 2 |
| accepted-approval-delay.json | accepted | accepted | none |

Finding 1 remains open until Phase 2b's receiver intake enforces nonce
consumption and receipt-interaction correlation on every accepted TCX.
Trace checking will test the recorded behavior of that intake on every
frozen trace. It does not prove signature checks, logging completeness,
or truthful harm labels from the JSON alone. Amendment 004 is sealed at
`619cb4e` and was not edited.


## Safety-property canaries

These are deliberate isolated faults, not findings in the real receiver.
The real `TCOPReceiver.tla`, its properties, and the real configurations are
unchanged. Its SHA-256 remains
`8028cbaa4bf0b91871cf5278d4c66e9b3fe8ce44c058801879591cf0a5fa0e42`.
Each module under [tla/canaries/](tla/canaries/) extends the real model
through `CanaryBounds`, changes one mechanism, and checks the original
property by its original name. No property is overridden or copied.

| Canary module | Named fault | Unchanged property checked |
| --- | --- | --- |
| `CanaryNoWidening` | `FaultReattach` adds a removed A0 capability back to `Authority` after a binding effect. | `NoWidening` |
| `CanaryAcceptOnlyValid` | Config overrides only `Valid` with `FaultValidWithoutNonce`, omitting nonce consumption while preserving every other validity guard and the real acceptance audit. | `AcceptOnlyValid` |
| `CanaryEffectHolds` | Config overrides only `HarmfulAttempt` with `FaultHarmfulAuthorization`, permitting a covered action through an installed deny while leaving `Authority` narrowed. | `EffectHolds` |
| `CanaryLyingPeer` | A valid false observation gains a `command` field and `FaultReceiveCommand` executes that field during receiver intake. Other wire attributes of message 2 and normal intake logic are preserved. | `LyingPeerOnlyCostsAvailability` |

Bounds: two destinations, two credentials, the independent benign-work
capability, interval 1, approval delay 0, and exact lag 0. The egress
selection is fixed to the primary destination. NoWidening and EffectHolds
start with the ordinary valid message ready at zero, then must submit and
install its restriction before the fault is enabled or exercised. The
nonce canary starts from ordinary empty replay state and admits only
messages 1 and 4 (different IDs, the same nonce); the lying-peer canary
starts from ordinary empty replay state and admits only message 2. All
are normal bounded model specializations, with `TypeOK` also checked.

The four results below are local DFID runs. Counterexample length counts
printed states, including the initial state and the violating state;
transitions are one fewer. Counts include DFID's repeated generation across
iterations. No canary unexpectedly passed.

| Canary / violated property | Expected | Actual | Counterexample states / transitions | Generated / distinct | DFID level | Seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| [NoWidening](results/dfid-CanaryNoWidening.log) | violated | violated | 4 / 3 | 8 / 5 | 4 | 0.244 |
| [AcceptOnlyValid](results/dfid-CanaryAcceptOnlyValid.log) | violated | violated | 3 / 2 | 11 / 8 | 3 | 0.260 |
| [EffectHolds](results/dfid-CanaryEffectHolds.log) | violated | violated | 5 / 4 | 11 / 5 | 5 | 0.223 |
| [LyingPeerOnlyCostsAvailability](results/dfid-CanaryLyingPeer.log) | violated | violated | 2 / 1 | 2 / 2 | 2 | 0.215 |

Plain-language counterexamples:

- **NoWidening:** valid evidence is ready; submission and the effect remove
  the primary egress capability; `FaultReattach` puts it back. Authority
  grows on the final transition.
- **AcceptOnlyValid:** message 4 is accepted with nonce 1; message 1 is then
  accepted with a fresh ID but that already consumed nonce. Its unchanged
  audit contains `nonce = 1` and `priorNonces = {1}`.
- **EffectHolds:** submission and the effect remove primary egress at tick
  0; the clock reaches tick 1; faulty per-attempt authorization executes A0
  against that covered destination. Authority remains narrowed throughout.
- **LyingPeerOnlyCostsAvailability:** at tick 0 a valid, signed, fresh,
  correlated false observation executes its `command` as a receiver step.
  The sandbox execution log grows while harmful `attempt = 0` and A4 is
  still waiting. This is a command path, not an actor attempt.

TLC decomposes temporal conjunctions. For `EffectHolds` it reports the
violating action clause at `TCOPReceiver.tla:172-173`; for the lying-peer
property it first reports the execution-origin clause at lines 177-178.
Those spans lie wholly inside the original checked properties. The runner
preserves the exact TLC label and resolves it to the enclosing property,
with the original spec hash recorded. It does not rename a property or
substitute a weaker assertion. The command-path counterexample also changes
`Executed` during the overridden receiver intake; both that fact and the
receiver origin are visible in the saved trace.

Run the canaries alone or the full suite:

```sh
python3.11 -B formal/run_checks.py --canaries-only
python3.11 -B formal/run_checks.py
```

Outside the sandbox, append `--bfs` for auto-worker breadth-first runs.
Individual canaries can be selected with `--config CanaryNoWidening`,
`--config CanaryAcceptOnlyValid`, `--config CanaryEffectHolds`, or
`--config CanaryLyingPeer`. The runner supplies the absolute `TLA-Library`
path so sibling canary modules import the unchanged parent model.

The default suite now runs the four canaries first, expecting `violated`,
then all thirteen real configurations, expecting `satisfied`. A canary
that completes successfully is an unexpected property-detection failure
and is printed first before the runner exits nonzero. An unrelated
violation, missing counterexample, parse error, deadlock, or checker failure
cannot satisfy a canary. Expected rejection requires TLC's invariant/action
violation exit status, a diagnostic naming the checked property (or a
source span inside it), and a contiguous printed counterexample of at
least two states. All other mismatches fail immediately.

[results/canaries-dfid.json](results/canaries-dfid.json) records expected
and actual outcomes, fault, property, counterexample state/transition counts,
state counts, mode/depth/time, exact command, module/config/shared-bounds
hashes, raw-log hash, and the pinned-tools record hash. The complete
counterexamples are in `results/dfid-Canary*.log`. The full-suite record is
`results/summary-dfid.json`; `passed: true` for a canary means its expected
violation occurred, not that the safety property held in the broken model.

Every canary result embeds pinned-tools record SHA-256
`9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e`.
Runner classification checks, including rejection of a wrong-property
counterexample and a checker failure, are recorded separately in
`results/canary-runner-selfcheck.json` as synthetic-output checks.


The final combined local DFID run completed with all 17 expectations met:
four canaries violated their intended properties, and all thirteen real
configurations satisfied their checks. The real TLA+ modules and real
configurations were also compared against the preceding artifact hashes;
none changed. The combined JSON-lines runner output is retained in
`results/canary-and-real-checks.log`.

## Victim-observer trust extension

[tla/TCOPTrust.tla](tla/TCOPTrust.tla) extends the unchanged receiver model.
It adds receiver-local trust, per-issuer quarantine, and a B-side receipt
registry. [tla/TrustMC.tla](tla/TrustMC.tla) supplies the small model instances.
The original `TCOPReceiver.tla`, its properties, and all original real and
canary configurations remain unchanged. Trusted status expands which
**tightenings** local policy may select; it never adds sandbox authority.

| New property | Meaning |
| --- | --- |
| `ReceiptBoundRestrictions` | Every installed restriction is on the actual bound session and has a receiver-minted, peer-held receipt for that issuer/session/observed destination. |
| `QuarantinedIssuerNoEffect` | No installed restriction is caused by an issuer quarantined at installation time. |
| `ZeroTrustOwnDestinationsOnly` | If the issuer is untrusted when the effect occurs, its action is egress denial to a destination for which that issuer holds a valid receipt. |

The checks inspect `effectAudit`, which is appended atomically with the
unchanged `TakeEffect` action. Each record identifies the enforcing
`BoundSession`, the warning's session, issuer, observed destination,
selected action, actual removed authority, effect time, and snapshots of
trust, quarantine, arrival, minting, and receipt possession. The properties
recompute receipt membership from those snapshots; they do not trust an
exported “accepted” or “eligible” verdict. `BoundSession` is the actual
single enforcement context, not a session name copied from the warning.

New model elements:

- All peers start untrusted. `RaiseTrust(peer, actor)` can be taken only by
  the receiver or operator. The receiver branch abstracts qualifying local
  confirmations/local evidence, and the operator branch an explicit grant.
  Warning processing and receipt possession never raise trust. The
  independently checked `TrustRaisedLocally` invariant records grant origin.
- `QuarantinePeer` records receiver-local quarantine independently for each
  peer. Local policy checks it at intake, submission, and effect. If it
  becomes ineligible while queued, `CancelBlocked` cancels the uninstalled
  restriction. This removes no installed restriction and adds no authority.
  A restriction installed before quarantine stays installed; the property
  prevents new effects rather than retroactively changing its causal history.
- `TrafficArrival(<<peer, session, destination>>)` records actual traffic
  received at that peer. `MintReceipt` is a B-side operation after that
  arrival, and `DeliverReceipt` gives the resulting receipt only to that
  same peer. `ReceiptProvenance` separately checks `held ⊆ minted ⊆ traffic`.
  `TrafficRoutes` is the fixed admitted, authenticated peer/service routing
  census, not an address supplied by a warning. This abstracts the successful
  request/arrival correlation; it does not assert that a live receipt
  service already observes arrival or mints at this exact point in wall time.
- `OwnDestinations(peer)` is derived from valid held receipt triples. An
  untrusted issuer can select only egress denial within that set. A trusted
  issuer can select the original broader local action set but still needs
  the exact bound-session receipt. Trust never waives receipt or quarantine
  checks, signature/replay checks, or the no-command property.
- A study-policy refusal is recorded without a core acceptance or write.
  The protected A0-A4 ladder and binding lag remain the original actions.
  The extension introduces no release, reattach, unfreeze, or sandbox
  command path.

### Bounds and effect scope

The main trust instances have two peers, two session identifiers, two
destinations, two credentials, and two candidate warnings with at most one
examined warning per execution. Peer A receives bound-session traffic to d0;
peer B can receive traffic to d1 in a different session, so holding that
other receipt cannot authorize a restriction on the bound session. Both
warnings name the actual bound session. All peers can independently gain
receiver/operator trust or be quarantined. Receipts start empty.

The interval is 1 tick, approval delay 0, binding lag 0..1 for each kind,
intake through tick 0, auxiliary receipt/trust/quarantine events through
tick 1, and the original horizon is 6. There are no state constraints or
symmetry reductions; peer/session/route roles distinguish the model values.
The DFID iteration ceiling remains 50, above the completed search depth.
Each individual property gets its own configuration. `TrustMC.cfg` also
checks all three together with the original NoWidening, AcceptOnlyValid,
EffectHolds, LyingPeerOnlyCostsAvailability, ladder/A4 checks, and bounded
completion. Deadlock checking stays enabled.

This is one admitted sandbox/session enforcement context, as in the base
receiver model. The other session distinguishes foreign receipt context;
its execution is not another modeled live sandbox. Egress denial, revocation,
and freeze remove authority only in `BoundSession` in this abstraction.
It makes no claim that a coarse live binding affects only one active session.
Draft 006 requires inventorying every affected session: a multi-session
freeze/provider group needs matching receipt coverage and a corresponding
scope model before that mapping is admitted. It cannot be justified by
assigning the warning's session label to a wider physical effect.

`TrustSanity.cfg` uses one peer, one session, and one traffic route. Its
exhaustive reachable-state reports must include: a legitimate untrusted
restriction, a locally trusted freeze, a quarantined warning refused, and
a queued warning cancelled. Thus the passing predicates are accompanied
by actual allowed effects and trust/quarantine transitions, not an entirely
inactive receiver. This remains a finite design check rather than temporal
liveness checking in DFID.

### Trust canaries

The three new canaries each bypass exactly one named gate in their own
module/config. Their checked property definitions remain in `TCOPTrust`.
No canary changes the real model or the original safety canaries.

| Canary | Single injected fault | Property that must be violated |
| --- | --- | --- |
| `CanaryReceiptBound` | `FaultNoSessionReceipt`: omit the issuer/session/destination receipt gate. | `ReceiptBoundRestrictions` |
| `CanaryQuarantinedIssuer` | `FaultQuarantineBypass`: omit quarantine eligibility at intake/submission/effect. | `QuarantinedIssuerNoEffect` |
| `CanaryZeroTrust` | `FaultUntrustedBroadAction`: omit the untrusted own-destination action ceiling. | `ZeroTrustOwnDestinationsOnly` |

The receipt canary's trace gives p0 a receiver-local trust grant and then
revokes credential c1 in the bound session with no receipt, proving a grant
cannot substitute for receipt possession. The quarantine canary installs
an egress denial for p0 while p0 is quarantined, despite otherwise valid
receipt coverage. The zero-trust canary gives p0 a valid receipt for d0,
then lets the still-untrusted issuer cause denial of d1, which it does not
own. These are actual authority removals recorded with their causal
snapshots, not just incorrectly labelled receive events.

### Commands, fingerprints, and result records

```sh
# Full suite: all seven canaries, the thirteen original real configurations,
# and the five trust configurations (three properties, combined, sanity).
python3.11 -B formal/run_checks.py

# Only the three new properties and their canaries.
python3.11 -B formal/run_checks.py \
  --config CanaryReceiptBound --config CanaryQuarantinedIssuer \
  --config CanaryZeroTrust --config ReceiptBoundRestrictions \
  --config QuarantinedIssuerNoEffect --config ZeroTrustOwnDestinationsOnly
```

`--canaries-only` now checks all seven intentional failures. `--bfs` remains
available outside the sandbox. Any satisfied canary, violated real property,
unrelated violation, or tool error fails the runner. No expected outcome
of an original property or canary changed.

The new trust cases pin fingerprint polynomial **1**. Polynomial 0 reached
65,136 distinct states but hit the pinned TLC version's known final-report
`ArithmeticException: Division by zero`; that result is preserved as a
**tool error**, not a property pass, in
`results/trust-fp0-reporting-failure.json` and its log. Changing the fingerprint
polynomial changes only fingerprinting/reporting, not the specification,
properties, states, or bounds. Polynomial 1 completed with the same state
counts. The original thirteen checks and four canaries retain polynomial 0.
Every new result records which polynomial actually ran.

`results/summary-dfid.json` holds the full suite;
`results/canaries-dfid.json` holds all expected failures. The trust subset
is also retained in `results/trust-results-dfid.json`. Records include
expected/actual outcome, state counts, search depth, run time, counterexample
length for canaries, original receiver hash, trust-spec hash, checked-module
and config hashes, exact command, and raw-log hash. Every record embeds the
unchanged pinned-tools record SHA-256:
`9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e`.
Counterexample lengths include initial and violating states; DFID depth is
its last search level, not BFS diameter. Counts include repeated generations
across DFID iterations.

| Check | Expected | Actual | Generated / distinct | DFID depth | Counterexample states | Seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| [CanaryReceiptBound](results/dfid-CanaryReceiptBound.log) | violated | violated | 3,197 / 1,193 | 5 | 5 | 0.407 |
| [CanaryQuarantinedIssuer](results/dfid-CanaryQuarantinedIssuer.log) | violated | violated | 31,191 / 4,891 | 8 | 8 | 0.691 |
| [CanaryZeroTrust](results/dfid-CanaryZeroTrust.log) | violated | violated | 16,036 / 3,034 | 7 | 7 | 0.534 |
| [ReceiptBoundRestrictions](results/dfid-ReceiptBoundRestrictions.log) | satisfied | satisfied | 1,759,601 / 65,136 | 26 | none | 27.508 |
| [QuarantinedIssuerNoEffect](results/dfid-QuarantinedIssuerNoEffect.log) | satisfied | satisfied | 1,759,601 / 65,136 | 26 | none | 27.902 |
| [ZeroTrustOwnDestinationsOnly](results/dfid-ZeroTrustOwnDestinationsOnly.log) | satisfied | satisfied | 1,759,601 / 65,136 | 26 | none | 27.804 |
| [TrustMC](results/dfid-TrustMC.log) | satisfied | satisfied | 1,759,601 / 65,136 | 26 | none | 29.437 |
| [TrustSanity](results/dfid-TrustSanity.log) | satisfied | satisfied | 24,194 / 1,478 | 21 | none | 0.654 |

All 25 expected outcomes were met: seven canary violations and eighteen
satisfied real configurations. All 22 existing trace fixtures also retained
their expected outcomes. All 26 pre-existing TLA+ module/config inputs were
compared against the previous artifact hashes and remain unchanged.

### Mapping to draft 006 and code

The draft changed while this work was in progress. Its later text explicitly
contains the receipt/trust requirements. This mapping uses that version;
`results/trust-source-hashes.json` identifies the source snapshot. Nothing
outside `formal/` was edited.

| Model element | Draft 006 and code mapping |
| --- | --- |
| Victim traffic and receiver-local warning policy | Draft 006 “Domain roles and population”: A observes arrived traffic at its own services, sends TCX to B's receiver, and sends no instruction to B's agent. |
| B-minted, holder/session/destination-bound receipts | Draft 006 “Receipts in the victim direction” and “Formal properties and canaries.” `TrafficRoutes` abstracts the admitted authenticated peer/service binding from “Partner and zero-trust conditions.” Generic receipt validation exists in `witness.py`, but the proposed B-side acquisition/arrival/ownership registry is not implemented by `reliability.py` or `confirmation.py`; finding 1 still applies to the generic validators. |
| Untrusted default and local trust raising | Draft 006 “Partner and zero-trust conditions.” `reliability.py:170-187,254-286` has receiver-local issuer state keyed by control group/scope, initially `unknown` with factor 400; `:361-398,433-434` uses independent evidence for transitions. This is related local evidence machinery, not the model's per-peer boolean grant API or zero-trust destination ceiling. `seed` is a scenario helper, not a demonstrated production operator-grant interface. |
| Per-peer quarantine | Draft 006 “Profile wiring and release.” `reliability.py:41-85,399-439` defines/maintains quarantined state with factor zero; `:569-588` includes it in influence. The model abstracts thresholds, dwell, decay, confidence and scope to a per-peer quarantine set, with no recovery during the episode. |
| Receiver confirmations | `confirmation.py:546-577,586-595,629-645` makes staged, source-novel receiver-local confirmation decisions; an observation cannot create and satisfy the same confirmation stage. It confirms subject containment, not directly the new issuer-trust grant. `RaiseTrust(...,"receiver")` abstracts a qualifying local confirmation/evidence decision, not an arbitrary peer assertion. |
| Quarantine before all restrictive paths | `confirmation.py:442-460` admits quarantined-issuer investigative tips; `:612-628` can create a provisional response; `:469-480` denies a capability. Therefore the generic composition does **not** implement the new no-effect guard. Draft 006 explicitly calls for the study guard before this path, without changing generic profile rules. |
| Quarantine while a write is queued | Draft 006 requires checking before delayed submission. The model additionally checks before installation and suppresses an uninstalled pending effect. `reliability.py:591-603` normally caches originally issued influence and handles compromise windows separately; these files do not establish pending native-write cancellation. The live binding must demonstrate this ability or expose the mismatch; the model is not that demonstration. |

The new own-destination ceiling, receiver-only receipt acquisition/possession
registry, explicit grant interface, stricter quarantine composition, and
pending-effect suppression have no complete counterpart in the two generic
profile modules. [FINDINGS.md](FINDINGS.md), finding 2, records that gap.
The draft likewise describes profile wiring and receipt acquisition as work
requiring admission, not as already active behavior.

Cryptographic bytes, receipt IDs/expiry/rotation, multiple warnings per
interaction, multi-session binding coarsening, confirmation thresholds,
profile on/off ablations, recovery/release, and H1-Hn campaign timing are not
implemented by this trust abstraction. Receipt triples remain valid for the
bounded episode; actual arrivals and B-side provenance are explicit. The
original A0 timing checks are preserved, without asserting that they prevent
the victim's already-arrived H1. The existing trace schema/tool still checks
the original receiver projection; it does not yet encode grant, quarantine,
or receipt mint/delivery events and is not evidence of these new properties
on live traces. Draft 006 requires that trace mapping before its input seal.
