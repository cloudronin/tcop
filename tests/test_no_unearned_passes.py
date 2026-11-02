"""Reject new literal successes and stale exceptions across research producers."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import unittest

from tcop.observed_result import observed_pass, require_observation


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "tests/fixtures/unearned-pass-allowlist.json"
FIXTURES = ROOT / "tests/fixtures/observed-outcome-records.json"
RECURSIVE_ROOTS = ("src", "paper/usenix27/scripts", "deploy", "integrations", "benchmark", "tests")
SUCCESS_WORDS = frozenset({"pass", "passed", "ok", "success", "successful", "succeeded", "verified", "valid", "certified", "conformant"})
# Include verification aliases found in the sweep, not operational booleans
# such as accepted, forwarded, healthy, or synthetic input flags.
ASSERTION_FIELDS = frozenset({
    "equal", "equivalent", "certified", "oracle_isolation", "state_stabilized",
    "decision_compatible", "patch_applies_cleanly", "no_new_protocol_fields",
    "no_remote_enforcement_for_a2", "instrumentation_enabled_equals_disabled",
    "P0_P1_behaviorally_identical", "patrol_findings_can_enter_selected_native_backends",
    "single_observer_false_containment", "withdrawal_restored_operation",
    "relay_provenance_completeness", "invalid_evidence_detection",
})
ASSERTION_SUFFIX = re.compile(r"(?:^|_)(?:pass|passed|ok|success|succeeded|valid|verified|certified|conformant|match|unchanged|unmodified|identical|stable)$")


def swept_python(root: Path = ROOT) -> list[Path]:
    """Use pathlib so ignored and newly added Python files are scanned too."""
    files = {path for name in RECURSIVE_ROOTS for path in (root / name).rglob("*.py")}
    files.update((root / "formal").glob("*.py"))
    return sorted(path for path in files if "__pycache__" not in path.parts)


def _literal_success(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant):
        return (
            value.value is True
            or type(value.value) is int and value.value == 1
            or isinstance(value.value, str) and value.value.lower() in SUCCESS_WORDS
        )
    # Catch optimistic fallbacks such as predicate(...) if applicable else True,
    # ``outcome or True``, and bool(True), without treating compared-to True as
    # an unconditional success. Nested evidence dicts are separate records.
    if isinstance(value, ast.IfExp):
        return _literal_success(value.body) or _literal_success(value.orelse)
    if isinstance(value, ast.BoolOp):
        return any(_literal_success(child) for child in value.values)
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "bool":
        return bool(value.args) and _literal_success(value.args[0])
    return False


def _assertion_field(field: str, value: ast.AST) -> bool:
    if field in {"exist_ok", "dirs_exist_ok"}:
        return False  # Filesystem API options, never check records.
    if field in {"status", "result", "outcome", "verdict"}:
        return isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.lower() in SUCCESS_WORDS
    return field in ASSERTION_FIELDS or bool(ASSERTION_SUFFIX.search(field))


@dataclass(frozen=True)
class Site:
    file: str
    function: str
    field: str
    fingerprint: str
    line: int
    expression: str

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return self.file, self.function, self.field, self.fingerprint


def literal_pass_sites(source: str, filename: str) -> list[Site]:
    tree = ast.parse(source, filename=filename)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def function(node: ast.AST) -> str:
        names = []
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
        return ".".join(reversed(names)) or "<module>"

    result = []

    def add(node: ast.AST, field: str | None, value: ast.AST) -> None:
        if field is None or not _assertion_field(field, value) or not _literal_success(value):
            return
        # Entire record/assignment content protects against reusing an old
        # exemption for changed behavior. Line movement and formatting are safe.
        fingerprint = sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
        result.append(Site(filename, function(node), field, fingerprint, value.lineno, ast.unparse(node)))

    def target_field(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return node.slice.value
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    add(node, key.value, value)
        elif isinstance(node, ast.keyword):
            add(node, node.arg, node.value)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if node.value is not None:
                for target in targets:
                    add(node, target_field(target), node.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "__setitem__" and len(node.args) == 2:
            key, value = node.args
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                add(node, key.value, value)
    return sorted(result, key=lambda site: (site.line, site.field, site.fingerprint))


def exception_errors(sites: list[Site], entries: list[dict]) -> list[str]:
    """Compare multisets: deleted sites and duplicated exemptions both fail."""
    actual = Counter(site.identity for site in sites)
    allowed = Counter()
    errors = []
    for entry in entries:
        required = {"file", "function", "field", "fingerprint", "class", "reason"}
        if not required <= entry.keys() or entry.get("class") not in {"A", "B", "C"} or not str(entry.get("reason", "")).strip():
            errors.append(f"invalid allowlist metadata: {entry}")
            continue
        if entry["class"] == "A":
            tracking = entry.get("tracking", {})
            if not isinstance(tracking, dict) or tracking.get("issue") != "docs/KNOWN_ISSUES.md" or not str(tracking.get("finding", "")).startswith("docs/unearned-pass-issues.md#") or not str(tracking.get("sealed_artifact", "")).startswith("artifacts/"):
                errors.append(f"class A needs a known issue and sealed-artifact path: {entry['file']}:{entry['function']}")
        allowed[(entry["file"], entry["function"], entry["field"], entry["fingerprint"])] += 1
    for key, count in (actual - allowed).items():
        locations = [str(site.line) for site in sites if site.identity == key]
        errors.append(f"unallowlisted literal success ({count}): {key[0]}:{','.join(locations)} {key[1]} [{key[2]}]")
    for key, count in (allowed - actual).items():
        errors.append(f"stale or duplicate allowlist entry ({count}): {key[0]} {key[1]} [{key[2]}]")
    return errors


def pass_records(value):
    """Yield every nested record with passed, including failed records."""
    if isinstance(value, dict):
        if "passed" in value:
            yield value
        for child in value.values():
            yield from pass_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from pass_records(child)


class NoUnearnedPassesTests(unittest.TestCase):
    def test_no_unallowlisted_literal_successes_or_stale_entries(self):
        sites = [site for path in swept_python() for site in literal_pass_sites(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())]
        entries = json.loads(ALLOWLIST.read_text(encoding="utf-8"))["sites"]
        self.assertEqual([], exception_errors(sites, entries))
        for entry in entries:
            if entry["class"] == "A":
                with self.subTest(entry=entry["file"], field=entry["field"]):
                    self.assertTrue((ROOT / entry["tracking"]["issue"]).is_file())
                    issue = entry["tracking"]["finding"]
                    path, anchor = issue.split("#", 1)
                    self.assertTrue((ROOT / path).is_file())
                    self.assertIn(f'id="{anchor}"', (ROOT / path).read_text(encoding="utf-8"))
                    # Some historic/intended roots are absent in this checkout;
                    # preserve that fact in the sweep instead of inventing data.
                    self.assertIn("sealed_artifact", entry["tracking"])

    def test_require_observation_for_every_fixture_record(self):
        fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        for case in fixtures:
            records = list(pass_records(case["payload"]))
            self.assertTrue(records, case["name"])
            rejected = []
            for index, record in enumerate(records):
                try:
                    require_observation(record)
                except ValueError:
                    rejected.append(index)
            with self.subTest(case=case["name"]):
                self.assertEqual(case["rejected_record_indices"], rejected)

    def test_observed_pass_computes_and_retains_the_outcome(self):
        for expected, observed in [("rejected", "rejected"), ("rejected", "accepted"), (False, False), (0, 0)]:
            with self.subTest(expected=expected, observed=observed):
                record = observed_pass(expected, observed)
                self.assertEqual(expected, record["expected"])
                self.assertEqual(observed, record["observed"])
                self.assertEqual(expected == observed, record["passed"])
        result = observed_pass({"code": "rejected"}, {"code": "rejected", "elapsed": 4}, predicate=lambda expected, observed: expected["code"] == observed["code"])
        self.assertTrue(result["passed"])
        for empty in (None, "", "  ", {}, [], {"nested": []}):
            with self.subTest(empty=empty), self.assertRaises(ValueError):
                observed_pass(empty, empty)

    def test_scanner_forms_and_exception_expiry(self):
        source = '''
def check():
    a = {"passed": True}
    b = dict(passed=True, ok=True)
    a["passed"] = True
    a.update({"pass": True})
    a.__setitem__("status", "passed")
    c = {"status": "passed", "result": "ok", "success": 1}
    d = {"passed": compare() if applicable else True}
    passed: bool = True
    if (ok := True):
        pass
    return {"passed": expected == observed, "observed": observed}
'''
        sites = literal_pass_sites(source, "src/example.py")
        self.assertEqual(12, len(sites))
        entries = [dict(file=s.file, function=s.function, field=s.field, fingerprint=s.fingerprint, **{"class": "C", "reason": "scanner self-test"}) for s in sites]
        self.assertEqual([], exception_errors(sites, entries))
        self.assertTrue(exception_errors(sites, entries[:-1]))
        self.assertTrue(exception_errors(sites[:-1], entries))
        self.assertTrue(exception_errors(sites, entries + entries[:1]))
        moved = literal_pass_sites("\n\n" + source, "src/example.py")
        self.assertEqual([], exception_errors(moved, entries))
        changed = literal_pass_sites(source.replace('"passed": True', '"passed": 1', 1), "src/example.py")
        self.assertTrue(exception_errors(changed, entries))
        self.assertEqual([], literal_pass_sites('a = {"accepted": True, "status": "READY", "passed": result == True}', "src/example.py"))


if __name__ == "__main__":
    unittest.main()
