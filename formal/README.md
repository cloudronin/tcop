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
