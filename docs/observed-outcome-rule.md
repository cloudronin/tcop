# Record the outcome that earned the pass

The question this rule protects is: **what actually happened when this control, mutation, or conformance check ran?**

Every recorded result carries the observed outcome it passed on. Keep the expectation, the actual outcome, and a computed `passed` value together. A control name, a fixed reason, a statement about the architecture, or successful construction of an input is not evidence that the control ran. A failure also needs its outcome.

Use the shared helper:

```python
from tcop.observed_result import observed_pass, require_observation

outcome = receiver.accept_imported_context(mutated_context, receipt, **binding)
record = observed_pass(
    {"code": "signature_invalid", "restriction_created": False},
    outcome,
    predicate=lambda expected, observed: (
        observed["code"] == expected["code"]
        and observed["restriction_created"] == expected["restriction_created"]
    ),
)
require_observation(record)
```

Without a predicate, `observed_pass(expected, observed)` compares the two values for equality. A custom predicate receives `(expected, observed)` and its result becomes the boolean `passed`. Both original inputs are retained. An empty observation raises `ValueError`, even when it equals an empty expectation.

`require_observation(record)` rejects a record containing the **key** `passed` unless `observed` or `detail` contains an outcome. It checks failed results as well as successful ones. `False` and zero are real outcomes. `None`, blank strings, empty collections, and recursively empty structures are not. A non-pass-bearing metadata record needs no observation. Callers walking a bundle must apply it to each nested pass-bearing record, rather than only its outer wrapper.

`detail` supports existing outcome records, including diagnostic text. Its text must describe a measured or executed outcome. A narrative claim such as “an unknown peer cannot pass validation” does not establish that anyone submitted an unknown peer. The helper checks structure; producer review and the retained execution evidence establish truth. It cannot detect invented measurements hidden in a nonempty dictionary or prose string.

## What fails the build

`tests/test_no_unearned_passes.py` scans all Python recursively under `src/`, `paper/usenix27/scripts/`, `deploy/`, `integrations/`, `benchmark/`, and `tests/`, plus top-level `formal/*.py`. Ignored and newly added Python files are included. It rejects literal successes in dictionaries, keyword arguments, ordinary/annotated/attribute/subscript assignments, assignment expressions, and `__setitem__` calls. It catches positive status/result labels, common verification aliases, integer `1`, and optimistic literal fallback branches as well as `passed=True`. The explicit assertion aliases include the equivalence and verification claims found by the sweep. Ordinary operational booleans and filesystem options do not claim a check passed.

Every detected site must match an exact exception. A new, changed, deleted, or excess exception fails the test. Exceptions use the relative file, qualified function, field, and SHA256 of the enclosing location-free AST. Whitespace and line movement do not change identity; changing the record or assignment does. The stored line is for navigation only. No whole file or whole function is exempted.

The fixture test walks every nested pass-bearing record in `tests/fixtures/observed-outcome-records.json`. Outcome-bearing checks must be accepted; bare, empty, and reason-only passes must be rejected. The helper tests also check unequal outcomes, false and zero outcomes, and a custom predicate. The lint tests verify new-site rejection, stale and excess entries, changed records, and line movement.

The existing `make test` unittest discovery runs these tests. CI runs `make research` through `.github/workflows/verify.yml`, so a failed rule fails the build without a workflow edit. The AST rule is a guard against literal successes, not a proof of arbitrary Python dataflow. The sweep separately records eight nonliteral A findings. Existing amendment 003/004/005 validators are not wired to `require_observation` by this change; that integration belongs to the main thread. There is no claim that CI already validates every record in every sealed artifact.

## Legacy exceptions

Record a narrowly identified site in `tests/fixtures/unearned-pass-allowlist.json` with:

| Field | Meaning |
| --- | --- |
| `file`, `function`, `field`, `fingerprint` | Exact source-site identity, as emitted by `literal_pass_sites` |
| `class` | A: unearned and a bug; B: success follows fail-closed checks; C: not a check result |
| `reason` | The specific claim, missing execution, guard, or non-check meaning |
| `line`, `source` | Reviewable source snapshot; line is informational |
| `tracking` for A | Reference to `docs/KNOWN_ISSUES.md`, a detailed finding in the new supplement, and the retained sealed artifact path |

Class A entries reference `docs/KNOWN_ISSUES.md` and `docs/unearned-pass-issues.md#uep-...`. The existing known-issues file was created by another job and remains untouched. Some discovered producers have no retained sealed output in this checkout. Their intended output paths are explicitly marked `sealed_artifact_present: false`, and the sweep states that absence. Such a path is not proof that the producer ran. A returned-only summary may instead reference the related retained control record, with that relationship stated in the sweep.

An exception acknowledges a defect; it does not turn an unexecuted control into passing evidence. Do not add an exception merely to make a new producer pass CI. New producers should compute their result from execution and retain the outcome. For an existing B site, replace the literal with the observed predicate and retain its evidence. Remove the exact exception when the source is repaired. The test deliberately fails until stale entries are removed. The two sites fixed by `a3af84c` have no exceptions.

## Sealed evidence stays unchanged

A sealed artifact is a historical record with a content digest and a place in an evidence chain. Rewriting a false pass in place would conceal what the original run recorded and invalidate its provenance. Preserve the original bytes, record the defect and its paper impact, fix the producer, and execute a separately rooted successor when new evidence is needed. Keep the predecessor/successor link explicit. An existing seal proves byte identity, not that a control actually executed.

See [the full sweep](unearned-pass-sweep.md) and [the detailed issue supplement](unearned-pass-issues.md).
