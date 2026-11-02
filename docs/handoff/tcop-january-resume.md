# TCOP: January resume handoff

Written 2026-11-01, when TCOP work paused until January 2027. A fresh
session can resume from this file and a clean clone of `main`. Read
`docs/tcop-framing-layering-and-bindings.md` first: it is the owner's
top-level framing, and every spec question is judged against it before the
amendment text.

## 1. State on `main`

`main` holds everything that existed locally on 2026-11-01, merged with
merge commits (no rebase or squash), so every sealed commit hash below is
still valid and reachable.

### Sealed specifications (never edit or rename)

| File | sha256 | Sealed in |
| --- | --- | --- |
| `spec/external-warning-adaptive-crosshost-v1.md` | `aa9659d2ef27169dd08264317327d7106a44f2ecc530ff9acc3942f879e6e752` | 3198424 |
| `spec/external-warning-adaptive-crosshost-amendment-001.md` | `b3f3df95b4833769d18dd35283999b2344d0de9a32fdf3950b4fff09df5999e7` | cf92c98 |
| `spec/external-warning-adaptive-crosshost-amendment-002.md` | `d5d73dc64bd5a95777796f59972cfeaaf0b0efcb2f071e9964f28aaff9d1cc40` | cf92c98 |
| `spec/external-warning-adaptive-crosshost-amendment-003.md` | `521ab718a6d75275f1546adf015a7e25daee0a3593fed29539a0ab61cafc3a57` | 3198424 |
| `spec/external-warning-adaptive-crosshost-amendment-004.md` | `9546e30627eab69924f47d595fa536da22acee8edd818d1b268eee8ba02b0706` | 619cb4e |
| `spec/external-warning-adaptive-crosshost-amendment-005.md` | `3b45fef22a9b00cff1a3e001db07404a10a396445620d7c8298459e672cdd22b` | 851cc6a |

The plan (`benchmark/studies/external-warning-adaptive-crosshost-v1.yaml`)
is at effective revision 1.5 and pins 004 and 005 by these hashes.
Amendment 005 also pins `formal/pinned-tools.json` (sha256
`9a96e57e11ecef2ed9303e99cbdc92092d025ec67f53a1cc2a4b42b767ab001e`).

The paper's text calls the cross-host series "CH-001" to "CH-006" to tell
it apart from the separate live-runtime series
(`spec/v0.6-agent-validation-runtime-amendment-001.md` to `-006.md`). The
files themselves are not renamed.

### Unsealed work

- `spec/external-warning-adaptive-crosshost-amendment-006.md`: **unsealed
  draft** (victim-side observer, receipts, partner and zero-trust
  conditions, hostile-victim family). The owner approved its content on
  2026-11-01 (section 2), but the decisions are not yet applied to its
  text and it is not sealed.
- `docs/amendment-006-investigations.md`: receipts can use OpenShell's
  middleware header hook; v0.3 and v0.4 are available but not wired into
  any receiver; v0.4's tip channel can open a provisional gate for a
  quarantined issuer.

### Key commits

| Commit | What |
| --- | --- |
| 8bfc9ee, 1fa0920 | Phase 0 notes and pins; Phase 1 admission record, role census, expected-pattern tooling |
| 27d5d5d | Phase 2a: plan 1.4 and one validator per 003/004 gate |
| 1b057c4 | Phase 2b: plan 1.5, receiver intake, tightening adapter and five bindings, conformance checks C1-C4 |
| 185393f, 346ee78 | Discrete-event simulator; ties go against E2 |
| 42c5cfe, dd9f546 | TLA+ model, trace validation tooling, safety-property canaries |
| c6701db | TLA+ receipt, quarantine, and zero-trust properties with canaries |
| 55ebad4 | 2026 incident case mapping (`docs/case-mapping-2026.md`) with an orchestrator verification section that governs |
| a976cdc | Repository sweep for unearned passes and the CI rule (`tests/test_no_unearned_passes.py`) |
| b04f940 | Context-value comparator v2 with executed controls |
| f5a9cfe | 006 draft and investigation notes |
| 1a15909 | 17-page consistency-revision paper source imported unchanged |
| 1a15909 to 9973980 | Preprint: controls corrections, retitle, two builds, Shared Signals related work, verified 2026 incident text, and the four must-fix edits |
| b6d068c, 9e1a4f7, 234c8ab | Merge commits for the harness branch, the preprint branch, and comparator v2 |
| 94bf95d | The eight artifact roots the paper's numbers trace to, now tracked |
| 2400cbb | LaTeX build scratch untracked and ignored |
| 165696a | Local paths scrubbed from tracked files |
| 78e2dc3 | Unearned-pass allowlist updated for the merged code (no new class A site) |

### Not on `main`, on purpose

- Branch `cloudronin/paper-controls-correction`: the controls corrections
  made on the older 10-page draft. Superseded: the same corrections were
  ported into the 17-page source on the preprint branch, which replaced the
  draft.
- `formal/tools/tla2tools.jar`, virtual environments, TLC state folders,
  and LaTeX scratch: tooling and build output, ignored by git and
  reproducible from the pins in section 6.
- The third-party NemoClaw, OpenShell, and OpenClaw checkouts: read as data
  during Phase 0 and pinned by commit in section 6.

### Formal model

`formal/`: TLA+ model `formal/tla/TCOPReceiver.tla` with safety, timing,
and trust properties. 25 checks (properties and canaries) all give their
expected outcome under breadth-first TLC: 65,136 distinct states, nothing
left on the queue. Results: `formal/results/summary-bfs.json` and
`summary-dfid.json`. 22 trace fixtures match (`formal/run_trace_fixtures.sh`).
`formal/FINDINGS.md` finding 1: the generic validators do not enforce
nonce consumption or receipt correlation (the study intake does). Finding 2:
the code has no receipt-ownership registry, trust grants, or
own-destination limit yet.

### Paper

`paper/usenix27/` builds two PDFs from one source, both 17 pages:
- `main.pdf`: anonymous USENIX build (`make paper-check`).
- `preprint/main-preprint.pdf`: arXiv build with author block and
  repository links pinned to tag `preprint-v1` (`make paper-preprint`).
  **That tag does not exist yet**, so those links do not resolve until the
  January 16 final pass creates it.

Title: "TCOP: An Agentic Early Warning and Response Protocol".

### Known sealed-file exposure

`formal/results/java-properties.txt` records the local user name, home
directory, and a working-directory path. It was left unchanged because the
sealed pinned-tools record pins its hash
(`observation_output_sha256 = dd79ee79...`). Removing it needs a new
pinned-tools record under a new amendment.

## 2. Owner decisions recorded 2026-11-01 (not yet implemented)

**v0.4 conflict: scope the rule to v0.4.**
- Restate the TLA+ quarantine property: a quarantined source can cause at
  most v0.4's short-lived provisional gate, and only on its own
  destinations; never a lasting restriction, never on anyone else's
  destinations. Rerun it with its canary.
- Code question (`src/tcop/confirmation.py:442-460` and `613-628`): does
  the gate take its scope from the receipt's own-destination binding or
  from the observation's subject? If own destinations, v0.4 runs as
  published. If subject, add a clamp to the sender's own destinations, and
  the paper reports "v0.4 plus a clamp" and why, as a finding.
- Either way, "an untrusted peer can only block traffic to its own
  destinations" must hold in the code before any hostile-victim episode
  runs.

**Amendment 006: all approved.**
- Campaign: H1 triggers the warning; H2 onward is what gets measured.
- Receipt service: OpenShell's middleware header, with two limits stated
  in 006 and the paper: HTTPS needs TLS inspection, and NemoClaw's
  middleware setup is unqualified, so it must pass admission on the
  owner's hosts.
- Hostile-family counts: real, forged, and reused receipts, plus an honest
  stranger, each with v0.3 and v0.4 on and off.
- Freeze and detach: an untrusted peer's receipt cannot authorize an
  action that hits several sessions, so those actions are blocked. This
  is deliberate.

**Earlier decisions still in force:** three machines (study runner,
MacBook Pro as host A, Mac mini as host B); D = 3000 ms simulated
operator latency; E2-native-min-a at a 1 s poll; the S-B instant egress
cut; ties go against E2 in computed outcomes only; the safety stop; no
pass recorded without an observed outcome.

## 3. Open work, in dependency order

1. **v0.4 gate scope.** Read the two `confirmation.py` ranges and decide
   whether a clamp is needed. Done when the answer, with file:line, is in
   006 and, if a clamp is needed, the paper's finding text is drafted.
2. **Restated quarantine property.** Done when the model states the
   scoped property, its canary is reported violated, and all 25 earlier
   checks keep their outcomes under breadth-first TLC.
3. **006 ready to seal.** Apply section 2's decisions to the draft and
   remove its draft banner text only when the owner seals it. Done when the
   owner seals it (planned January 5) and the plan pins its hash.
4. **Trust model in code.** Receipt ownership, trust grants, and the
   own-destination limit in the cross-host receiver, with v0.3 and v0.4
   wired in and the separate release controller for expiries. Done when
   each of the three TLA+ trust properties has a code-level test that
   fails on its canary scenario, and the unearned-pass CI rule passes.
5. **Host prerequisites.** `docs/amendment-003-host-setup.md` (move the
   synthetic targets from the runner to host A per 006), NemoClaw
   middleware admission, and TLS inspection for receipts. Done when
   admission records on both hosts pass and C1-C4 conformance records
   exist.
6. **Paper polish.**
   - Labels overflow their boxes in Figures 1 and 9.
   - Figure 4's title counts calls over a bar that counts pairs; move the
     calls number to the caption.
   - Figure 3 is unreadable at column width.
   - There is a blank gap on page 8.
   - Write "three" in the prose instead of the generated "3".
   - Make "incidents" plural in the Ethics appendix.
   - For the Kimi K3 claim, cite the AI Security Institute's own account
     if one exists.
   Done when both builds pass and the owner signs off.
7. **USENIX Cycle 2 rules** on posting and promoting a preprint during
   review. Done when the rules are confirmed and the arXiv plan fits them.

## 4. Schedule (2027)

| Date | Milestone |
| --- | --- |
| Jan 5 | Seal 006 |
| Jan 9 | Host session |
| Jan 10 | Live run |
| Jan 13 | Results review |
| Jan 16 | Final pass; create tag `preprint-v1` and verify every arXiv link |
| Jan 18 | USENIX registration |
| Jan 24 | Submission |
| Jan 28 | Artifact |
| Feb 1 | arXiv |

## 5. Ground rules

- No live efficacy episode before 006 and the predictions are sealed.
  The full order: 006 seal, role scripts and detector, conformance,
  calibration, grid finalization, expected-pattern seal, TLC pass, smoke
  and trace validation, then the live run.
- Never edit or rename a sealed file. Changes go in a new amendment.
- No tag until the January 16 final pass.
- No pass recorded without the observed outcome it passed on.
- Run tests with Python 3.11 or later that has `cryptography` and PyYAML.

## 6. How to resume from a fresh clone

```bash
git clone https://github.com/cloudronin/tcop.git && cd tcop
shasum -a 256 spec/external-warning-adaptive-crosshost-amendment-004.md spec/external-warning-adaptive-crosshost-amendment-005.md formal/pinned-tools.json
python3.11 -m venv .venv && .venv/bin/pip install -e . matplotlib pypdf
make schema PYTHON=.venv/bin/python
make test PYTHON=.venv/bin/python
```

Sealed-root checks (each must report valid):

```bash
PYTHONPATH=src .venv/bin/python -m tcop.cli study validation-value verify --artifact-dir artifacts/tcx-validation-value-v2
PYTHONPATH=src .venv/bin/python -m tcop.cli study adaptive-authorization verify --artifact-dir artifacts/adaptive-agent-authorization-v1
PYTHONPATH=src .venv/bin/python -m tcop.cli study c2e-frontier verify --artifact-dir artifacts/c2e-frontier-v1
PYTHONPATH=src .venv/bin/python -m tcop.cli study independent-warning-v2 verify --artifact-dir artifacts/independent-warning-admission-v2-external-stratified
PYTHONPATH=src .venv/bin/python -m tcop.cli study independent-warning-full verify --artifact-dir artifacts/independent-warning-admission-v3-full-population
PYTHONPATH=src .venv/bin/python -m tcop.cli artifact verify artifacts/federated-domain-v0.6-evidence --require-complete --require-replayable
PYTHONPATH=src .venv/bin/python -m tcop.cli artifact verify artifacts/v0.6-agent-validation --require-replayable
PYTHONPATH=src .venv/bin/python -m tcop.cli study comparator verify --artifact-dir artifacts/context-value-comparator-v1
PYTHONPATH=src .venv/bin/python -m tcop.cli study comparator-v2 verify --artifact-dir artifacts/context-value-comparator-v2
PYTHONPATH=src .venv/bin/python -m tcop.cli study external-adaptive run --output /tmp/tcop-xa-check
```

The last command must seal a `BLOCKED` preflight (no hosts yet); it fails
loudly if a pinned upstream root changed.

Formal model (needs a JDK and TLA+ tools v1.7.4 at
`formal/tools/tla2tools.jar`, sha256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`, from
the tlaplus GitHub release; the jar is not tracked):

```bash
python3 formal/run_checks.py --bfs
bash formal/run_trace_fixtures.sh
```

Paper (needs TeX, Matplotlib, PyYAML, pypdf):

```bash
PATH=.venv/bin:$PATH make paper-check paper-preprint PYTHON=python3
```

Third-party pins (not in the repository; fetch at these commits): NemoClaw
v0.0.140 `88fe14f3fb9a0bf72997cce19ec88b5b2ee08391`, OpenShell v0.0.116
`d1155aa70042d3e2ee49dbfa15346b108b7c1d92`, OpenClaw 2026.9.2
`3928bad9badfcb6c7d140530435e806fb8092190`.
