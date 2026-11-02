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
the paper reads. The paper's invalid-signature, wrong-receipt,
expired-context, and replayed-context controls, and its 11 signed-envelope
mutations, come from the live receiver intake, `accept_imported_context` in
`src/tcop/agent_eval/authorization.py`. Those are executed, and each pass
is computed from the observed outcome: the rejection code and whether a
restriction was created, or, for the remote-action mutation, that the
remote action fields were ignored. This statement covers only those
controls; see the repository-wide review of recorded passes for the others.

Fixed in a new study version: `artifacts/context-value-comparator-v2/`
executes these controls through the same receiver intake and computes each
pass from the observed outcome (see
`docs/context-value-comparator-v2-controls.md`). The sealed v1 artifact
stays unchanged.

## Live negative controls and formula-computed validation tables

Six controls in the sealed live negative-controls report were recorded as
passed without executing the named condition:

| Control | Code that records the pass | What was actually checked |
|---|---|---|
| NC-05 unknown peer | `src/tcop/agent_eval/runner.py:579` | Literal `True`. |
| NC-06 disallowed import type | `src/tcop/agent_eval/runner.py:580` | Literal `True`. |
| NC-08 no remote enforcement | `src/tcop/agent_eval/runner.py:266`; `src/tcop/agent_eval/authorization.py:246` | A counter that is the literal `0` in every row. |
| NC-09 remote TCX action | `src/tcop/agent_eval/runner.py:268` | Rows containing no remote action. |
| NC-13 gateway restart | `src/tcop/agent_eval/runner.py:583`; `src/tcop/agent_eval/authorization.py:246` | The same literal-zero counter; no gateway restart occurs. |
| NC-15 session termination before arrival | `src/tcop/agent_eval/runner.py:585` | Literal `True`. |

The report is
`artifacts/v0.6-agent-validation-live-origin-certified/reports/negative-controls.json`.
The paper keeps all sixteen rows. Ten executed live controls retain their passes.
NC-05 instead cites the executed `issuer` signed-envelope mutation in
`artifacts/tcx-validation-value-v2/property-test-report.json`, which returns
`identity_unknown` and `restriction_created: false` through
`accept_imported_context`. NC-09 cites that report's executed `action_semantic`
mutation, which ignores remote `action` and `enforcement` fields. NC-06, NC-08,
NC-13, and NC-15 are marked **Not tested**, untested design properties rather
than results. The paper extraction preserves the live recorded flags separately
from these evidence classifications.

The same validation-value artifact's hostile-peer burst table is computed
from declared formulas in `src/tcop/validation_value.py:100-104`. Its correlation
table at one, two, and eight concurrent sessions is also formula-computed
(`src/tcop/validation_value.py:108-115`); `misbindings` and
`cross_session_restrictions` are typed in as zero. These are not executed or
measured studies. The paper draws no empirical result from either table and
retains only the executed signed-envelope mutation results as such.

Sealed artifacts remain unchanged. A later artifact version will execute the
six named live conditions and the hostile-peer and correlation studies.

## Root digests depend on the Python version

Several sealed artifacts record the Python interpreter version in
`environment.json`, and that file is part of each artifact's digested
root. A reviewer on a different Python version therefore gets a different
root digest even when every result file is byte-identical. To match the
sealed roots exactly, use CPython 3.12.2. Future study versions keep
environment metadata outside the digested root.
