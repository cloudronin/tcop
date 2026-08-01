# TC-RFC-0026: Investigation capacity and confirmation metrics (Draft)

Investigation scheduling SHALL be deterministic, enforce a declared global
budget and per-control-group cap, and reserve declared capacity for high-risk
tips before lower-risk work. This reservation is intended to make a low-risk
tip-flood unable to starve high-risk investigation.

Benchmark output SHALL separately record provisional-protection latency,
investigation latency, confirmation latency, and damage accrued from a
requirement's activation through its confirmation deadline. These measurements
MUST NOT be collapsed into a single latency or security-loss metric.

CT-085, CT-087, B-063, B-066, and B-067 exercise these controls and measures.
