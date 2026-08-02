# TCOP: Receiver-Sovereign Federated Early Warning

TCOP is a receiver-sovereign federated early-warning architecture for
cross-domain agent tool use. Domains exchange signed, scoped, time-bounded
context. The receiving domain alone correlates that context with its local
state, applies its own policy, and issues any enforcement decision.

TCOP is not a remote kill switch. It does not create detections, does not send
enforcement commands across domains, and is not presented as an Internet-scale
deployment. This repository is a deterministic reference framework and an
evidence package for the accompanying paper.

The installed `tcop` command is the single interface for protocol validation,
frozen-strategy certification, deterministic study reproduction, artifact
review, safe local services, and observational administration.

```text
TCOP protocol core ── deterministic experiments / artifact replay
                   ├─ local domain services / bounded-context gateway
                   └─ read-only operational diagnostics
```

Those modes share signing, TCX validation, receipt handling, frozen strategy
adapters, local resolver behavior, and the gateway acceptance boundary. They
differ only in clock, transport, persistence, telemetry, and local enforcement
adapters.

It also contains a separate v0.2 deterministic witness profile. The profile
adds receiver-classified control-group evidence, interaction receipts,
provenance-preserving relays, passive peer witnesses, and safe active patrols
without changing the frozen v0.1 path.

The separate v0.3 reliability profile adds receiver-local, scope-specific
observer reliability, fixed-point weighted corroboration, probation,
hysteresis, compromise windows, and accusation-cycle reporting. It reuses
immutable v0.2 evidence and never creates a global reputation score.

The separate v0.4 confirmation profile adds a zero-credit investigative-tip
channel, scoped provisional protection, independently auditable direct-local
emergency evidence, source-novel confirmation, and deterministic campaign
grouping. It consumes v0.2 evidence and v0.3 reliability projections without
changing the frozen earlier profiles.

The separate v0.5 minimality profile is an analysis/composition layer over
v0.1–v0.4. It evaluates declared coherent profiles, ablations, interactions,
complexity, Pareto frontiers, and profile selection without adding a defense.

## Paper reviewer quickstart

The question protected by the paper is whether signed cross-domain context can
arrive early enough for a receiving domain to make a useful local decision,
without granting another domain enforcement authority. Review starts from the
sealed artifacts, not from a model call or a live service.

```bash
python -m pip install -e .

# Validate the strict deterministic A1:A2 evidence and frozen strategies.
tcop study verify-inputs \
  --plan benchmark/studies/v0.6-evidence.yaml \
  --source artifacts/minimality-v0.5-validation \
  --source-artifact artifacts/federated-domain-v0.6

# Verify the credential-free and certified live-replay evidence roots.
tcop artifact verify artifacts/federated-domain-v0.6-evidence \
  --require-complete --require-replayable
tcop artifact verify artifacts/v0.6-agent-validation-live-origin-certified \
  --require-complete --require-replayable

# Verify the separately rooted C0-C3 context-versus-blanket comparator.
tcop study comparator verify \
  --artifact-dir artifacts/context-value-comparator-v1
```

The expected result is a successful verification for each root. The comparator
artifact digest is `2a7c267f69aa736122de7366359983e838ba29316e142957c7e8049d63cbf421`.
For an end-to-end paper check, run `make paper-check`; the reviewer workspace
and paper-specific source verifier are in [paper/usenix27](paper/usenix27).

| Paper result | Evidence root | What to inspect |
| --- | --- | --- |
| Receiver-local authority and no remote enforcement | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/authorization-audit.json`, `reports/origin-federation-audit.json` |
| Deterministic A1:A2 containment result | `artifacts/federated-domain-v0.6-evidence` | `pairs/paired-results.jsonl`, `reports/paired-causal-comparison.json` |
| Frozen live traces and causal replay | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/trace-generation-summary.json`, `reports/paired-enforcement-results.json` |
| Availability cost | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/benign-workload-impact.json` |
| Context versus blanket restriction | `artifacts/context-value-comparator-v1` | `reports/summary.json`, `cohort/cohort-census.json`, `decision-traces/decision-traces.jsonl` |

The context comparator is explicitly separate from the original A1:A2 result.
Its frozen cohorts lacked an episode containing both a matching harmful action
and a same-capability nonmatching benign action, so its primary C1/C2 test is
a separately labeled deterministic policy-selectivity fixture. It reports the
full cohorts without pooling them into a live-agent selectivity claim.

## Scope

The first milestone implements:

- signed, scoped, expiring observations and strict validation;
- static trust-domain and observer authority configuration;
- append-only SQLite evidence storage and JSONL exports;
- deterministic five-node simulation with replay, delay, partition, and Sybil
  fault cases;
- local capability-specific trust envelopes and simulated responses; and
- CT-001–CT-020 plus deterministic B-001–B-010 benchmark artifacts;
- timing, topology, partition-posture, false-containment, and architectural
  ablation experiments.

The protocol does not receive benchmark ground truth. Protocol, resolution,
and benchmark-truth streams are stored separately to prevent oracle leakage.

## CLI quick start

Install into a Python 3.11+ environment:

```bash
python -m pip install -e .
tcop --help
```

Review the immutable strategy compatibility boundary:

```bash
tcop strategy list
tcop strategy certify --all
```

Create a deterministic v0.2 protocol fixture and verify it with the same
validator the local gateway uses:

```bash
tcop context create --observer observer-1 --trust-domain partner.example \
  --subject agent-1 --scope tool:data.export \
  --write /tmp/warning.tcx.json --receipt-write /tmp/receipt.json
tcop context verify /tmp/warning.tcx.json --receipt /tmp/receipt.json
tcop receipt verify /tmp/receipt.json --context /tmp/warning.tcx.json
```

For a practical, reviewer-scale v0.6 reproduction:

```bash
tcop study reproduce \
  --plan benchmark/studies/v0.6-federated.yaml \
  --selection core \
  --output artifacts/federated-domain-v0.6-core
tcop artifact verify artifacts/federated-domain-v0.6-core \
  --require-complete --require-replayable
```

The full pre-registered matrix uses `--selection full`. Individual stages are
available through `tcop study verify-inputs`, `matrix`, `run`, `replay`,
`validate`, and `report`; existing artifacts can be inspected or compared
without running a study through `tcop artifact`.

The v0.6 missing-evidence round is a separate, receiver-only analysis layer:
it audits strict A1/A2 causal pairs, receipt timing, the bounded central
comparator, utility cost, and post-run forensic quality while preserving the
completed federation artifact unchanged.

```bash
tcop study reproduce \
  --plan benchmark/studies/v0.6-evidence.yaml \
  --selection full \
  --source-artifact artifacts/federated-domain-v0.6 \
  --output artifacts/federated-domain-v0.6-evidence
tcop artifact verify artifacts/federated-domain-v0.6-evidence \
  --require-complete --require-replayable
```

The v0.6 agent-validation layer is also separate. It refuses to run if the
formally admitted source artifacts or frozen strategy certificates differ, and
it never rewrites those inputs. The credential-free path exercises the same
signed-context, receipt-correlation, local-authorization, causal-barrier, and
negative-control contracts without claiming external validity:

```bash
tcop study agent prepare
tcop study agent reproduce --selection smoke \
  --output artifacts/v0.6-agent-validation
tcop artifact verify artifacts/v0.6-agent-validation --require-replayable
```

The reference-gateway selection, generic local-authorization patch, and
bounded five-service deployment are documented in
`integrations/mcp-gateway/` and `deploy/agent-validation/`. A provider-neutral
LLM run requires an explicit runtime configuration and an environment-variable
credential; its captured tool trace is replayed deterministically and is never
used to alter the frozen TCOP protocol or prior artifacts.

The repository checkout supplies the frozen v0.5 validation inputs by default.
An installed CLI used elsewhere must receive the equivalent immutable input
root explicitly with `--source /path/to/minimality-v0.5-validation`.

Commands emit JSON by default and also accept `--format text|json|jsonl`.
Commands that create a file or artifact reserve `--output` for that destination
and retain `--format` for their structured stdout representation. Diagnostics
and service logs go to stderr.

## Safe local service

The checked-in [domain configuration](config/domain-local.example.yaml) is a
versioned local-service example. Inspect it before binding a listener:

```bash
tcop service domain --config config/domain-local.example.yaml --dry-run
tcop service domain --config config/domain-local.example.yaml
tcop admin health --endpoint http://127.0.0.1:8443
```

The listener accepts only context publication/receipt and observational
endpoints. Received context is validated and resolved locally; it cannot
quarantine a remote agent, disable a remote capability, or terminate a remote
workflow. `tcop admin` is read-only.

## Compatibility commands

The v0.1–v0.5 deterministic commands remain available through the CLI for
reproduction compatibility (`tcop benchmark`, `witness`, `reliability`,
`confirmation`, `minimality`, and `federated`). A Makefile remains only as a
developer shortcut that delegates to `tcop`; it is not the public interface.

## Safety and non-goals

All response adapters are simulations. The implementation intentionally omits
LLM calls, production enforcement, Kubernetes, Kafka, and external discovery.
Those integrations must not be added until this deterministic milestone is
reproducible.
