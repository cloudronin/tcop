#!/usr/bin/env python3
"""Offline TLC runs; halt immediately on any property violation/deadlock.

The sandbox disallows TLC's BFS RMI listener. DFID uses an in-process set.
No checker, tool jar, property, or state bound is modified by this runner.
"""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
import hashlib
import json
import re
import subprocess
import time
from tooling import checked_tools, tlc_stats, sha256

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bfs", action="store_true", help="BFS with auto workers outside the sandbox; default DFID")
parser.add_argument("--config", action="append", choices=["NoWidening", "AcceptOnlyValid", "EffectHolds", "LyingPeer", "MC", "TimingSlow", "TimingSlowApproval", "TimingFast", "TimingFastCredential", "BaselineDenial", "Sanity", "SanityLying", "MCApprovalBaseline"], help="run only named configuration(s)")
args = parser.parse_args()
tools_hash = checked_tools()
mode = "bfs" if args.bfs else "dfid"

ROOT = Path(__file__).resolve().parent.parent
FORMAL = ROOT / 'formal'
JAR = FORMAL / 'tools/tla2tools.jar'
EXPECTED = '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88'
assert hashlib.sha256(JAR.read_bytes()).hexdigest() == EXPECTED
NAMES = ['NoWidening', 'AcceptOnlyValid', 'EffectHolds', 'LyingPeer', 'MC',
         'TimingSlow', 'TimingSlowApproval', 'TimingFast',
         'TimingFastCredential', 'BaselineDenial', 'Sanity', 'SanityLying',
         'MCApprovalBaseline']
results = []
for name in (args.config or NAMES):
    command = ['/opt/homebrew/opt/openjdk/bin/java', '-XX:+UseParallelGC',
               '-cp', 'formal/tools/tla2tools.jar', 'tlc2.TLC',
               '-workers', 'auto' if args.bfs else '1', '-fp', '0']
    if not args.bfs:
        command += ['-dfid', '50']
    command += ['-metadir', f'formal/states/{mode}-{name}',
                '-config', f'formal/tla/{name}.cfg', 'formal/tla/MC.tla']
    start = time.monotonic()
    run = subprocess.run(command, cwd=ROOT, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    elapsed = time.monotonic() - start
    output = run.stdout
    (FORMAL / 'results' / f'{mode}-{name}.log').write_text(output)
    counts = re.findall(r'(?m)^(\d+) states generated, (\d+) distinct states found\.', output)
    levels = re.findall(r'Starting level (\d+):', output)
    ok = run.returncode == 0 and 'Model checking completed. No error has been found.' in output
    if name == 'Sanity':
        ok = ok and 'a4 |-> "executed"' in output and 'effectiveMessages |-> {1}' in output
    if name == 'SanityLying':
        ok = ok and 'lieRemovedAuthority |-> TRUE,\n  executed |-> <<>>' in output
    stats = tlc_stats(output)
    row = dict(config=name, passed=ok, exit_code=run.returncode,
               mode=mode, provenance="local_execution", pinned_tools_record_sha256=tools_hash,
               spec_sha256=sha256(FORMAL/"tla/TCOPReceiver.tla"),
               config_sha256=sha256(FORMAL/f"tla/{name}.cfg"), tlc_stats=stats,
               generated=int(counts[-1][0]) if counts else None,
               distinct=int(counts[-1][1]) if counts else None,
               dfid_level=int(levels[-1]) if levels else None,
               seconds=round(elapsed, 3), command=command)
    results.append(row)
    (FORMAL / 'results' / f'summary-{mode}.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(row), flush=True)
    if not ok:
        print(output[-16000:], flush=True)
        raise SystemExit(run.returncode or 1)
