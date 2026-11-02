# Environment

Tier 0 and Tier 2 require Python, PyYAML, Matplotlib, and a TeX installation for the paper PDF. Tier 1 uses the existing deterministic TCOP runtime. Docker is required only for the reference-gateway smoke path. No tier except optional live trace regeneration requires a model-provider credential.

Python version: use **CPython 3.12.2** to reproduce sealed artifact root
digests exactly. Sealed artifacts record the interpreter in
`environment.json`, which is inside the digested root; a different Python
version changes the root digest even when every result file is identical.
`artifacts/federated-domain-v0.6-evidence/environment.json` records the
full conda-forge 3.12.2 build string, so an exact root match for that
artifact needs that build. The code and tests run on Python 3.11 and later.
See `docs/KNOWN_ISSUES.md`.
