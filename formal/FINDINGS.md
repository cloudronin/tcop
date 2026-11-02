# Formal findings

## Finding 1: generic receiver validation does not enforce the model's full acceptance contract

**Classification:** model-code gap, not a TLC violation. **Status:** open;
required resolution belongs to the study's Phase 2b receiver intake.

**Question protected:** Does every accepted TCX have an unconsumed ID and
nonce and correlate to a receiver-local receipt for the same interaction?

The unchanged `TCOPReceiver.AcceptOnlyValid` contract requires all of those
conditions. Its bounded model checks pass. The study owner also reports full
breadth-first confirmation of that property. Those results establish the
model's behavior, not enforcement by the generic Python validators.

Evidence from the current code:

- `src/tcop/validation.py:33` lists `nonce` as optional. The normal replay
  check at `src/tcop/validation.py:154-156` invokes only
  `ReplayWindow.duplicate_or_stale`, whose implementation at
  `src/tcop/validation.py:61-67` checks observation ID and sequence number.
  `use_challenge_nonce` exists at `src/tcop/validation.py:74-78`, but this
  validation path never calls it. `commit` at
  `src/tcop/validation.py:178-179` commits IDs/sequences, not the nonce.
- `src/tcop/witness.py:329-331` begins with `receipt_verified = False` and
  enters receipt validation only if a receipt hash is present. The return
  at `src/tcop/witness.py:356` can therefore accept evidence without a
  receipt. Where a receipt is supplied, the comparison at
  `src/tcop/witness.py:338-339` checks observer and subject, but does not
  compare the observation's `interaction_id` with the receipt's
  `interaction_id`. Receipt signature verification alone does not establish
  this missing equality or receiver-local correlation.

Concrete implications, without asserting that a live exploit was run:

- A distinct, otherwise valid observation with a fresh ID and sequence but
  an already consumed nonce is not rejected by the generic v0.1 replay path
  on the basis of that nonce.
- An otherwise valid witness observation can lack a receipt, or refer to a
  valid same-observer/same-subject receipt for a different interaction,
  without failing the shown optional receipt gate for those reasons.

**Required resolution:** Phase 2b's study receiver intake must require an
ID and nonce, check and consume them atomically for every accepted TCX,
and verify receiver-local receipt ownership and receipt/observation
interaction equality for every acceptance. The signed receipt must also
match the admitted subject/session/sandbox correlation. Reject missing,
invalid, reused, or mismatched inputs; do not weaken the model to admit them.

Every frozen trace will then be checked by `formal/trace_to_tla.py`.
The trace schema records the observation and receipt interaction IDs,
receipt verification and local ownership, ID, nonce, signature and peer
checks, expiry, decision, and selected tightening. Replay state and the
correlation conjunction are checked by the model/adapter rather than
accepted as an exported "fresh" verdict. Rejected real traces produce a
preserved first-prefix finding beside their result. Trace validation checks
the recorded attributes; it does not replace cryptographic verification
or prove that the exporter logged every event faithfully.

The negative fixture traces are intentional conformance tests, not observed
study incidents. There are no real smoke traces yet. The first real input
will be Phase 3 smoke traces. Amendment 004 is sealed at `619cb4e` and was
not edited.


## Finding 2: the new victim-observer trust contract is not the generic profile composition

**Classification:** model-code gap, not a TLC violation. **Status:** open;
implement the study's explicit eligibility guard and receipt acquisition.

**Question protected:** Can only a currently eligible, correctly receipted
issuer cause the permitted restriction on the admitted session?

`TCOPTrust` models the owner's three requested conditions. Draft amendment
006 now states them in “Receipts in the victim direction,” “Partner and
zero-trust conditions,” “Profile wiring and release,” and “Formal properties
and canaries.” The source snapshot hashes are in
`formal/results/trust-source-hashes.json`. The draft changed during this
work; the mapping uses the later explicit trust/receipt text, not the
initial roles-only version.

Existing code provides related pieces, with these material differences:

- `src/tcop/reliability.py:170-187` initializes an issuer as `unknown` with
  nonzero factors (400), and its state is keyed by local domain, control
  group and scope (`:254-286`), rather than the model's per-peer boolean
  trust grant. Independent clean evidence can raise `unknown` to `normal`
  (`:361-398`, `:433-434`). There is no receipt-owned-destination ceiling or
  explicit production operator-grant API in this path. `seed` (`:289-318`)
  is a deterministic scenario helper, not proof of such an API.
- Quarantined state has factor zero (`src/tcop/reliability.py:41-85`,
  `:436-437`), and factors enter warning influence (`:569-588`). That is
  not the same as “no restriction.” `src/tcop/confirmation.py:442-460`
  explicitly permits receipt-verified quarantined-issuer investigative
  tips. With the default enabled provisional profile (`:65-85`), a scoped
  provisional response can follow (`:612-628`); its envelope denies a
  capability (`:469-480`). The study needs the stricter quarantine guard
  before this route, without changing the generic profile's behavior.
- `src/tcop/reliability.py:591-603` normally preserves an observation's
  original influence and changes it retrospectively only for matching
  compromise windows. The model instead rechecks quarantine before
  submission and effect and cancels an uninstalled pending restriction.
  A live binding's ability to suppress an already submitted but not yet
  installed write is not established by this model or those profile files.
- `src/tcop/confirmation.py:546-577`, `:586-595`, and `:629-645` implement
  receiver-local staged/source-novel confirmation for subject containment.
  They do not directly implement the model's issuer trust-grant transition.
  A peer report cannot directly call the modeled receiver/operator grant.
- Generic witness receipts exist, but finding 1's optional/misbound receipt
  gaps remain. The B-owned issuance/actual-arrival/holder/session/destination
  registry, and the exact own-destination action ceiling, are not supplied
  by `reliability.py` or `confirmation.py`. Draft 006 describes receipt
  acquisition and profile wiring as work requiring admission, not an
  already deployed capability.

No generic profile, intake, adapter, or amendment was edited here. The
new checks are a bounded design contract, not proof of live implementation
parity. The legacy `TCOPTrace` schema does not yet record trust grants,
quarantine transitions, or B-side issuance/peer delivery. Its existing
checks remain unchanged and must not be described as validating these new
trust properties on actual traces. Draft 006 also requires that trace
mapping before the relevant frozen-inputs seal.
