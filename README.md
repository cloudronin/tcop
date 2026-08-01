# TCOP Reference Framework (TCF)

This repository contains the deterministic, test-first v0.1 reference
implementation for the Trust Context Project (TCOP). It exercises TCX message
exchange and local TCRS resolution; it is not a production security control.

It also contains a separate v0.2 deterministic witness profile. The profile
adds receiver-classified control-group evidence, interaction receipts,
provenance-preserving relays, passive peer witnesses, and safe active patrols
without changing the frozen v0.1 path.

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

## Quick start

Install the project dependency into a Python 3.11+ environment, then run:

```bash
make verify
```

The command writes per-scenario reproducibility artifacts under
`artifacts/verify/`.

To run the complete deterministic research suite, including the second
iteration of controlled experiments and the v0.2 witness suite, use:

```bash
make research
```

It also writes timing and architecture experiment artifacts to
`artifacts/experiments/`. See
[the second-iteration research note](docs/v0.2-deterministic-experiments.md)
for the interpretation limits and measured outcomes.

Use `make research-regression` to reproduce only the frozen v0.1 corpus in
`artifacts/regression-v0.1/`; use `make research-witness` for B-011–B-030,
CT-021–CT-040, and witness artifacts in `artifacts/witness-v0.2/`.
The implemented witness profile and its deterministic findings are summarized
in [the v0.2 witness report](docs/v0.3-witness-implementation-report.md).

## Safety and non-goals

All response adapters are simulations. The implementation intentionally omits
LLM calls, production enforcement, Kubernetes, Kafka, and external discovery.
Those integrations must not be added until this deterministic milestone is
reproducible.
