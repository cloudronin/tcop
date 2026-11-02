# Context-Value Comparator v2: Executed Controls

Comparator v1 (`artifacts/context-value-comparator-v1`) recorded its negative
controls as asserted, not tested. `_controls()` in
`src/tcop/context_comparator.py` wrote `invalid_signature`,
`unknown_receipt`, `expired_context`, and `replayed_context` as
`passed: true` for every condition with a fixed reason, and wrote the four
policy-interface controls the same way. Nothing was submitted to a receiver.
The v1 artifact stays sealed and unchanged. The v1 code path still rebuilds it
byte for byte, apart from the Python version in `environment.json`.

No paper claim depends on these controls. The paper's extraction scripts do
not read the comparator artifact, and the paper's replay and wrong-receipt
results come from the strict live intake, which runs its checks.
`artifacts/tcx-validation-value-v2` pins comparator v1's root digest as an
input and is not re-pinned.

## What v2 changes

Comparator v2 (`src/tcop/context_comparator_v2.py`, sealed at
`artifacts/context-value-comparator-v2`) changes only the controls and the
manifest metadata.

- **Rejection controls run through the real receiver intake.** Each control
  tampers with the unchanged RA-01 fixture pair and submits it to
  `LocalAuthorizationEvaluator.accept_imported_context`, the same path the
  live negative controls use: a changed signed field (`signature_invalid`),
  an unknown receipt hash (`receipt_unknown`), submission 61 s after issue
  (`expired`), and a second submission of an accepted context
  (`context_replayed`).
- **The comparator policy only sees accepted context.** The intake outcome is
  dispatched to C0 through C3. A token reaches the policy only when intake
  accepted the context.
- **`passed` is computed from a recorded observation.** Every control row
  carries `expected` and `observed`. `observed` holds the real intake code,
  `restriction_created` (from the intake and from the policy), and whether
  a token was dispatched. `passed` is true only when every expected key was
  observed and matches; a missing observation is an error, not a pass. A
  rejection control passes only when the code matches, intake created no
  restriction, no token was dispatched, and no condition's decision changed
  relative to having no context at all.
- **A positive control proves the controls can fail.** `accepted_context`
  submits the untampered pair. It must be accepted, create the receiver
  restriction, and change the decision for C1 and C2 only. Without it, a
  dispatcher that never forwarded context would make every rejection control
  pass.
- **Policy-interface controls are executed too.** Target mismatch, the C1
  opaque token, and C3's indifference to TCOP messages are now checked by
  calling the policy with the accepted, dispatched context.

## Guarantees

- The normalized comparator rows are identical to v1. The build refuses to
  seal if their digest differs from v1's `result_digest`
  (`6d8f6583…a120662f`), and the manifest records the v1 root digest it was
  compared against.
- Environment metadata (Python version, command) is written to
  `environment.sidecar.json`, which the v2 root digest does not cover. The
  root therefore matches on any Python version. v2 uses its own digest
  function; the v1 digest function, which other sealed studies pin, is
  unchanged.
- `tcop study comparator-v2 verify` checks the root digest, recomputes each
  sealed `passed` from its `expected` and `observed`, then re-executes all 24
  controls and requires them to equal the sealed
  `controls/control-results.json`.
- `tests/test_context_comparator_v2.py` includes failing cases. An untampered
  context submitted as `invalid_signature`, and a rejection with the wrong
  code, are both reported as failed.

Build and verify:

```bash
PYTHONPATH=src python3.11 -m tcop.cli study comparator-v2 run
PYTHONPATH=src python3.11 -m tcop.cli study comparator-v2 verify
```
