# TCOP: Receiver-Bound Runtime Evidence for Cross-Domain Agent Authorization

TCOP is a protocol for carrying signed, scoped, time-bounded runtime evidence
from an observing domain to the local authorization boundary of a receiving
domain. Before that evidence can affect a pending agent action, the receiver
validates provenance, freshness, replay state, receipt correlation, subject,
resource namespace, capability, and scope against its own state. The receiver
then creates the authorization decision under its own policy.

This repository is the reference implementation and sealed evidence package
for the final USENIX Security 2027 paper, *TCOP: Receiver-Bound Runtime
Evidence for Cross-Domain Agent Authorization*. It is organized so reviewers
can inspect the evidence-to-authorization boundary, reproduce the
credential-free results, and distinguish protocol behavior from the receiver
strategies evaluated on top of it.

TCOP is not a remote kill switch, a detector, or a mandated containment
strategy. It carries evidence. An imported TCX field never maps directly to
allow, deny, quarantine, revoke, or suspend. The receiver alone chooses
whether to reject, monitor, restrict, or otherwise handle accepted evidence.

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
adapters. The gateway consumes a Domain-B-local policy and decision, never a
remote enforcement instruction.

## Consistency-revision results and claim boundary

| Evidence | Result | What it supports |
| --- | --- | --- |
| Matched synthetic containment | Across 54 strict input-equivalent pairs, the containment-first receiver improved 30, left 24 unchanged, and worsened none. Harmful calls fell from 39 to 3, preventing 36 of 39 baseline calls. | A causal comparison under matched frozen policy and synthetic scenarios, not deployment effectiveness. |
| TCX Validation-Value v2 | Across 12 mixed actions, Exact Binding (C2) blocks 3 harmful actions and constrains none of 12 benign actions. The broad Arrival Guard (C1-class) blocks 7 harmful actions and constrains 7 benign actions; both block the 3 accepted binding-matched harmful actions. | Receiver-side semantic binding, validation, hostile-peer handling, and correlation behavior. |
| Post-denial substitution replay | Exact Binding forwards all 15 eligible substitutions. The evaluated receiver-local Campaign Correlation strategy blocks those substitutions and forwards the tested outside-campaign same-risk benign actions. | A bounded strategy tradeoff, not mandatory TCOP behavior or a general escalation policy. |
| Campaign Correlation frontier (C2E artifact identifier) | Across the predeclared 150-episode population, Campaign Correlation blocks campaign-linked harmful substitutions without restricting the tested outside-campaign benign actions. | Deterministic strategy selectivity under declared receiver-local relations. |
| Full external-warning ledger | The sealed 168-case population contains 72 attack-bearing and 96 benign source cases: 25 receiver-actionable exact bindings, 47 attack-bearing no-warning cases, and 96 benign no-warning cases. C1, C2, and Campaign Correlation block the 25 exact bindings; Standing Guard (C3) blocks all 72 attack-bearing cases and constrains all 96 benign cases. | Conditional receiver authorization outcomes, not detector quality, warning prevalence, or deployment rates. |

The protocol controls separately show that invalid signatures, wrong receipts,
expired or replayed contexts, unauthorized peers, and action-like remote
metadata create no receiver restriction. The single-environment reference path
also records Domain-B-local policy and decision provenance for every gateway
block.

These counts have different units of analysis, including strict pairs,
validation episodes, replay treatments, and gateway calls. They are reported
separately and must not be pooled.

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

The paper asks whether signed cross-domain runtime evidence can reach a
receiver in time to inform one pending local authorization decision, without
giving the observing domain enforcement authority. Review starts from sealed
artifacts, not a live model call or service.

```bash
python -m pip install -e .

# Default paper reproduction: Tier 0 source and paper checks, deterministic
# causal replay, and strict replay of frozen agent traces. No provider
# credential is read.
(cd paper/usenix27 && ./artifact/reproduce.sh --all-no-credentials)

# Verify the consistency-revision study roots directly through the public CLI.
tcop study validation-value verify --artifact-dir artifacts/tcx-validation-value-v2
tcop study adaptive-authorization verify --artifact-dir artifacts/adaptive-agent-authorization-v1
tcop study c2e-frontier verify --artifact-dir artifacts/c2e-frontier-v1
tcop study independent-warning-v2 verify \
  --artifact-dir artifacts/independent-warning-admission-v2-external-stratified
tcop study independent-warning-full verify \
  --artifact-dir artifacts/independent-warning-admission-v3-full-population
```

The default workflow is credential-free. It verifies source roots, regenerates
paper-local data, figures, and tables, builds the paper, audits claims,
numbers, and anonymity, reruns the deterministic core, and strictly replays
frozen agent traces. Tier 3 can regenerate live traces with a separately
configured provider credential, but is not needed for any causal claim and
cannot replace frozen replay evidence.

| Paper result | Evidence root | What to inspect |
| --- | --- | --- |
| Single-environment reference-path deployment | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/authorization-audit.json`, `reports/origin-federation-audit.json` |
| Deterministic A1:A2 containment result | `artifacts/federated-domain-v0.6-evidence` | `pairs/paired-results.jsonl`, `reports/paired-causal-comparison.json` |
| Frozen live traces and causal replay | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/trace-generation-summary.json`, `reports/paired-enforcement-results.json` |
| Availability cost | `artifacts/v0.6-agent-validation-live-origin-certified` | `reports/benign-workload-impact.json` |
| TCX validation-value frontier | `artifacts/tcx-validation-value-v2` | `reports/condition-summary.json`, `reports/matching-harmful-summary.json`, `hostile-peer-results.csv`, `correlation-results.csv` |
| Post-denial substitution replay | `artifacts/adaptive-agent-authorization-v1` | `reports/summary.json`, `decision-traces.jsonl` |
| Campaign Correlation frontier (C2E artifact identifier) | `artifacts/c2e-frontier-v1` | `reports/frontier-summary.json`, `escalation-lifecycle.jsonl`, `c2e-field-use-traces.jsonl` |
| Independent Warning Admission v2 | `artifacts/independent-warning-admission-v2-external-stratified` | `reports/cohort-summary.json`, `reports/substitution-summary.json`, `candidate-ledger.csv` |
| Full external-warning ledger | `artifacts/independent-warning-admission-v3-full-population` | `reports/pipeline-coverage.json`, `reports/authorization-outcomes.json`, `candidate-ledger.csv` |

Every study root contains its own plan, manifest, normalized outputs, source
or selection ledger where applicable, report, and verifier. The final paper
preserves predecessor roots and amendment lineage; review the studies as
separate evidence streams rather than pooling their denominators.

## Repository scope

The reference framework includes:

- signed, scoped, expiring runtime observations and strict receiver validation;
- static trust-domain and observer authority configuration, append-only
  evidence storage, and JSONL exports;
- deterministic simulation with replay, delay, partition, and Sybil fault
  cases, including the preserved v0.1–v0.5 regression path;
- receiver-local capability envelopes, strategy certification, and separately
  rooted studies for validation value, timing, substitution, Campaign
  Correlation selectivity (artifact identifier C2E),
  and independent-warning admission; and
- a bounded single-environment reference gateway and frozen live-trace replay
  path, alongside the credential-free deterministic evidence.

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

All evaluated tools, target systems, and enforcement actions are synthetic.
The default review workflow uses no provider credential. Optional credentialed
trace generation is bounded, separately locked, and cannot replace the frozen
replay evidence used for paper claims.

TCOP is not a production deployment, Internet-scale federation, global
consensus system, or key-lifecycle service. This repository does not expose a
cross-domain enforcement interface, attack real systems, or reverse completed
actions. Docker is needed only for the optional reference-gateway smoke path;
production enforcement, Kubernetes, Kafka, and external discovery remain out
of scope.
