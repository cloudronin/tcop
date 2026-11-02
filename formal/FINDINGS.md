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
