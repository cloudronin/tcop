#!/usr/bin/env python3
"""Check real properties and require named counterexamples from isolated canaries.

Default: sandbox-compatible DFID. Use --bfs outside the sandbox. A real
violation, a canary pass, or a checker error fails the run immediately.
"""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
import json
import re
import subprocess
import time
from tooling import JAVA, checked_tools, tlc_stats, sha256

ROOT = Path(__file__).resolve().parent.parent
FORMAL = ROOT / 'formal'
REAL_NAMES = ['NoWidening', 'AcceptOnlyValid', 'EffectHolds', 'LyingPeer', 'MC',
             'TimingSlow', 'TimingSlowApproval', 'TimingFast',
             'TimingFastCredential', 'BaselineDenial', 'Sanity', 'SanityLying',
             'MCApprovalBaseline']
TRUST_NAMES = ['ReceiptBoundRestrictions', 'QuarantinedIssuerNoEffect',
               'ZeroTrustOwnDestinationsOnly', 'TrustMC', 'TrustSanity']
CANARIES = {
    'CanaryNoWidening': dict(property='NoWidening', fault='FaultReattach: adapter re-adds removed A0 authority'),
    'CanaryAcceptOnlyValid': dict(property='AcceptOnlyValid', fault='FaultValidWithoutNonce: drop only consumed-nonce validation'),
    'CanaryEffectHolds': dict(property='EffectHolds', fault='FaultHarmfulAuthorization: execute a covered action through an installed deny'),
    'CanaryLyingPeer': dict(property='LyingPeerOnlyCostsAvailability', fault='FaultReceiveCommand: execute the command field of a valid false observation'),
    'CanaryReceiptBound': dict(property='ReceiptBoundRestrictions', fault='FaultNoSessionReceipt: bypass exact issuer/session/destination receipt gate', family='trust'),
    'CanaryQuarantinedIssuer': dict(property='QuarantinedIssuerNoEffect', fault='FaultQuarantineBypass: let a quarantined issuer reach the binding effect', family='trust'),
    'CanaryZeroTrust': dict(property='ZeroTrustOwnDestinationsOnly', fault='FaultUntrustedBroadAction: allow freeze/revocation/non-owned egress without local trust', family='trust'),
}


def classify(output, exit_code, target=None):
    """Require a named property or a clause located inside that property."""
    labels = re.findall(r'Error: (?:Invariant|Action property|Temporal property) (.+?) is violated\.', output)
    violations = list(labels)
    if target is not None:
        # TLC decomposes temporal conjunctions and may print the violating
        # clause's source span rather than its enclosing property name.
        # Resolve only spans wholly inside the checked, unchanged property.
        lines = (FORMAL/'tla/TCOPReceiver.tla').read_text().splitlines()
        start = next((i for i, line in enumerate(lines, 1)
                      if re.match(r'^' + re.escape(target) + r'\s*==', line)), None)
        end = next((i-1 for i, line in enumerate(lines, 1)
                    if start is not None and i > start and re.match(r'^\w+(?:\([^)]*\))?\s*==', line)), len(lines))
        for label in labels:
            span = re.fullmatch(r'line (\d+), col \d+ to line (\d+), col \d+ of module TCOPReceiver', label)
            if span and start is not None and start <= int(span[1]) <= int(span[2]) <= end:
                violations.append(target)
    states = [int(n) for n in re.findall(r'^State (\d+):', output, re.M)]
    length = max(states) if states else None
    contiguous = states == list(range(1, (length or 0) + 1))
    if exit_code == 0 and 'Model checking completed. No error has been found.' in output:
        return 'satisfied', violations, length, labels
    if exit_code in (12, 13) and labels and contiguous and (length or 0) >= 2:
        return ('violated' if target is None or target in violations else 'other_violation'), violations, length, labels
    return 'tool_error', violations, length, labels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bfs', action='store_true', help='BFS with auto workers outside the sandbox; default DFID')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--config', action='append', choices=REAL_NAMES + TRUST_NAMES + list(CANARIES), help='run only named configuration(s)')
    selection.add_argument('--canaries-only', action='store_true', help='run all seven required-failure checks only')
    args = parser.parse_args()
    tools_hash = checked_tools()
    mode = 'bfs' if args.bfs else 'dfid'
    receiver_hash = sha256(FORMAL/'tla/TCOPReceiver.tla')
    # Run canaries first so an unexpectedly satisfied canary is reported first.
    names = args.config or (list(CANARIES) if args.canaries_only else list(CANARIES) + REAL_NAMES + TRUST_NAMES)
    results = []
    for name in names:
        canary = CANARIES.get(name)
        if canary:
            spec = FORMAL/f'tla/canaries/{name}.tla'
            config = FORMAL/f'tla/canaries/{name}.cfg'
            expected = 'violated'
        else:
            spec = FORMAL/('tla/TrustMC.tla' if name in TRUST_NAMES else 'tla/MC.tla')
            config = FORMAL/f'tla/{name}.cfg'
            expected = 'satisfied'
        trust_case = name in TRUST_NAMES or (canary and canary.get('family') == 'trust')
        fingerprint = 1 if trust_case else 0
        command = [JAVA, '-XX:+UseParallelGC', '-DTLA-Library='+str(FORMAL/'tla'),
                   '-cp', 'formal/tools/tla2tools.jar', 'tlc2.TLC',
                   '-workers', 'auto' if args.bfs else '1', '-fp', str(fingerprint)]
        if not args.bfs:
            command += ['-dfid', '50']
        command += ['-metadir', f'formal/states/{mode}-{name}',
                    '-config', str(config), str(spec)]
        start = time.monotonic()
        run = subprocess.run(command, cwd=ROOT, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        elapsed = time.monotonic() - start
        output = run.stdout
        log = FORMAL/'results'/f'{mode}-{name}.log'
        log.write_text(output)
        outcome, violations, length, labels = classify(output, run.returncode, canary['property'] if canary else None)
        ok = outcome == expected
        if name == 'Sanity':
            ok = ok and 'a4 |-> "executed"' in output and 'effectiveMessages |-> {1}' in output
        if name == 'SanityLying':
            ok = ok and 'lieRemovedAuthority |-> TRUE,\n  executed |-> <<>>' in output
        stats = tlc_stats(output)
        row = dict(config=name, passed=ok, expected_outcome=expected,
                   actual_outcome=outcome, exit_code=run.returncode,
                   mode=mode, fingerprint_polynomial=fingerprint, provenance='local_execution', pinned_tools_record_sha256=tools_hash,
                   spec_sha256=receiver_hash, checked_module_sha256=sha256(spec),
                   config_sha256=sha256(config), tlc_stats=stats,
                   generated=stats['generated'], distinct=stats['distinct'],
                   dfid_level=stats['depth'] if not args.bfs else None,
                   seconds=round(elapsed, 3), command=command,
                   violated_properties=[v for v in violations if not v.startswith("line ")],
                   tlc_violation_labels=labels, counterexample_length=length,
                   counterexample_transitions=length-1 if length is not None else None,
                   log_sha256=sha256(log))
        if canary:
            row.update(property=canary['property'], fault=canary['fault'],
                       canary_bounds_sha256=sha256(FORMAL/('tla/TrustMC.tla' if canary.get('family') == 'trust' else 'tla/canaries/CanaryBounds.tla')))
        if name in TRUST_NAMES or (canary and canary.get('family') == 'trust'):
            row['trust_spec_sha256'] = sha256(FORMAL/'tla/TCOPTrust.tla')
        if name == 'TrustSanity':
            witnesses = ['untrustedRestriction', 'trustedFreeze', 'quarantinedWarningBlocked', 'pendingWarningCancelled']
            row['reachability_witnesses'] = {w: w + ' |-> TRUE' in output for w in witnesses}
            ok = ok and all(row['reachability_witnesses'].values())
            row['passed'] = ok
        results.append(row)
        (FORMAL/'results'/f'summary-{mode}.json').write_text(json.dumps(results, indent=2)+'\n')
        if canary:
            (FORMAL/'results'/f'canaries-{mode}.json').write_text(json.dumps([r for r in results if r['expected_outcome']=='violated'], indent=2)+'\n')
        if canary and outcome == 'satisfied':
            print(f"UNEXPECTED CANARY PASS: unchanged property {canary['property']} was satisfied under {canary['fault']}. This is a property-detection failure.", flush=True)
        print(json.dumps(row), flush=True)
        if sha256(FORMAL/'tla/TCOPReceiver.tla') != receiver_hash:
            raise RuntimeError('The real receiver model changed during checking')
        if not ok:
            print(output[-24000:], flush=True)
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
