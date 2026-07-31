# TCOP Reference Framework (TCF)

This repository contains the deterministic, test-first v0.1 reference
implementation for the Trust Context Project (TCOP). It exercises TCX message
exchange and local TCRS resolution; it is not a production security control.

## Scope

The first milestone implements:

- signed, scoped, expiring observations and strict validation;
- static trust-domain and observer authority configuration;
- append-only SQLite evidence storage and JSONL exports;
- deterministic five-node simulation with replay, delay, partition, and Sybil
  fault cases;
- local capability-specific trust envelopes and simulated responses; and
- CT-001–CT-020 plus deterministic B-001–B-010 benchmark artifacts.

The protocol does not receive benchmark ground truth. Protocol, resolution,
and benchmark-truth streams are stored separately to prevent oracle leakage.

## Quick start

Install the project dependency into a Python 3.11+ environment, then run:

```bash
make verify
```

The command writes per-scenario reproducibility artifacts under
`artifacts/verify/`.

## Safety and non-goals

All response adapters are simulations. The implementation intentionally omits
LLM calls, production enforcement, Kubernetes, Kafka, and external discovery.
Those integrations must not be added until this deterministic milestone is
reproducible.

