# Known issues

Sealed artifacts are never rewritten. Issues in them are recorded here and
fixed in new study versions.

## Comparator study: four negative controls recorded as passed without running

The context-value comparator study records four negative controls as
passed for every condition without executing them: invalid signature,
unknown receipt, expired context, and replayed context. The records are
written by `_controls()` in `src/tcop/context_comparator.py` and sealed in
`artifacts/context-value-comparator-v1/controls/control-results.json`.
They state an expected result; they do not test it.

These records do not feed the paper. The paper's extraction scripts do not
read this artifact, and none of its control records appear in any artifact
the paper reads. The paper's own negative controls (including wrong receipt
and replayed context) and its 11 signed-envelope mutations come from the
live receiver intake, `accept_imported_context` in
`src/tcop/agent_eval/authorization.py`. Those are executed, and each pass
is computed from the observed outcome: the rejection code and whether a
restriction was created, or, for the remote-action mutation, that the
remote action fields were ignored.

Fix in progress: a new comparator study version that executes these
controls through the same receiver intake. The sealed v1 artifact stays
unchanged.

## Root digests depend on the Python version

Several sealed artifacts record the Python interpreter version in
`environment.json`, and that file is part of each artifact's digested
root. A reviewer on a different Python version therefore gets a different
root digest even when every result file is byte-identical. To match the
sealed roots exactly, use CPython 3.12.2. Future study versions keep
environment metadata outside the digested root.
