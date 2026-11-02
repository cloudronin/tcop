#!/usr/bin/env python3
"""Run every declared fixture; intentional negative inputs are not study findings."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
from tooling import FORMAL, sha256
from trace_to_tla import validate_one

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bfs', action='store_true')
args = parser.parse_args()
expectations = json.loads((FORMAL/'traces/fixture-expectations.json').read_text())
actual_files = {p.name for p in (FORMAL/'traces/fixtures').glob('*.json')}
assert actual_files == set(expectations), 'Fixture manifest does not cover every fixture'
rows = []
for filename, expected in expectations.items():
    result = validate_one(FORMAL/'traces/fixtures'/filename,
                          FORMAL/'traces/fixture-results', bfs=args.bfs, fixture=True)
    ok = result['outcome'] == expected['outcome'] and result['first_rejected_step_index'] == expected['first_rejected_step_index']
    rows.append(dict(fixture=filename, expected=expected, actual=result['outcome'],
                     first_rejected_step_index=result['first_rejected_step_index'],
                     passed=ok, pinned_tools_record_sha256=result['pinned_tools_record_sha256']))
    print(json.dumps(rows[-1]), flush=True)
    (FORMAL/'traces/fixture-results/summary.json').write_text(json.dumps(rows,indent=2)+'\n')
    if not ok:
        print(json.dumps(result,indent=2), flush=True)
        raise SystemExit(1)
print(f'All {len(rows)} trace fixtures matched their expectations.')
