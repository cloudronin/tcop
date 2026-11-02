# Claim-Evidence Ledger

| Claim | Status | Supporting values | Caveat |
|---|---|---|---|
| C-ARCH-01 | supported | Action and enforcement metadata are ignored by the receiver evaluator. | bounded evaluation scope |
| C-AUTH-01 | supported | Every reference-deployment gateway block references a Domain-B policy and decision. | bounded evaluation scope |
| C-AUTH-02 | supported | The accepted action-semantic mutation ignores remote action and enforcement fields. | bounded evaluation scope |
| C-DETERMINISTIC-01 | supported | 54 pairs; 39 baseline calls; 3 treatment calls; 36 prevented. | 123 unmatched balanced or utility comparisons; zero worsened follows containment-first monotonicity for this metric. |
| C-VALIDATION-01 | supported with qualification | Full cohort C1-class/C2 harmful blocks 7/3; benign constraints 7/0; matching subset 3/3 each. | Synthetic credential-free cohort only; C2 rejects mismatched-warning controls rather than applying a broad class guard. |
| C-VALIDATION-02 | supported with qualification | Current 12 constraints; idempotent 1 constraint and 11 deduplications; quota-plus-monitor 3 constraints and 9 monitored. | Synthetic rate sweep; no operational-rate inference. |
| C-CORRELATION-01 | supported with qualification | 24 cases; 0 misbindings; 0 cross-session restrictions. | Synthetic concurrent-session sweep. |
| C-VALIDATOR-01 | supported with qualification | 11 mutation cases; action and enforcement fields ignored. | Mutation corpus, not a formal proof. |
| C-ADAPTIVE-01 | supported with qualification | Exact Binding: 15/15 post-denial harmful completions; Campaign Correlation: 0/15; every imported-evidence strategy: 5/5 exercised safe fallbacks forwarded. | Bounded reference runtime and predeclared branches; the safe-fallback result does not measure unrelated same-risk actions, deployment prevalence, or universal containment. |
| C-C2E-FRONTIER-01 | supported with qualification | C2E: 10/10 harmful blocked and 0/20 benign constrained; campaign-linked non-exact harmful: 5/5 blocked; outside-campaign benign: 5/5 forwarded; C1/C3: 10/20 benign constrained; 0 unrelated restrictions. | Deterministic receiver-local reference strategy only; not deployment prevalence, detector quality, universal containment, or a generally optimal escalation policy. |
| C-INDEPENDENT-V2-01 | supported with qualification | 25 attack-bearing prompt-attack candidates, 47 attack-bearing no-warning candidates, and 96 benign no-warning candidates; 12 selected external bases per principal stratum; 540 policy rows; C2/C2E 12/12 blocks and 0/12 benign constraints; C3 12/12 benign constraints; C2E 12/12 no-relation substitutions forwarded and 12/12 locally related substitutions blocked. | Hash-selected external integration cohort plus derived controls; it does not estimate detector quality, warning prevalence, arbitrary warning-source behavior, or production effectiveness. |
| C-INDEPENDENT-FULL-01 | supported with qualification | 168 source cases: 72 attack-bearing and 96 benign; 25 detector warnings, normalized TCX objects, admissions, and exact bindings; 47 attack-bearing no-warning cases; C1/C2/C2E 25/72 harmful blocks and 0/96 benign constraints; C3 72/72 harmful blocks and 96/96 benign constraints. | Uses preserved detector outputs and frozen policy semantics; it does not measure detector quality, field prevalence, arbitrary warning-source behavior, or production effectiveness. |
| C-AMENDMENT-01 | supported with qualification | 0/60 before correction; 20/20 after correction. | Post hoc eligibility correction remains visible and separately bounded. |
| C-LIVE-01 | supported | 44 eligible traces; 220 pairs. | bounded evaluation scope |
| C-UTILITY-01 | supported with qualification | 360 / 320 / 40. | Synthetic false-warning treatments and capability restriction |
| C-UTILITY-02 | supported with qualification | Inside-window: 120 / 80 / 40 calls and 0/40 workflows; remaining treatments: 240 / 240 / 0 calls and 80/80 workflows. | Synthetic workload only |
| C-FAILURE-01 | supported | 16 passed controls. | bounded evaluation scope |
| C-PERF-01 | supported with qualification | Performance-only selections with 20 samples each. | No production latency inference |
| C-CENTRAL-01 | supported with qualification | 54 fact-equivalent cells; three authority-placement and three outage regressions. | bounded evaluation scope |
| C-CENTRAL-02 | supported | Bounded comparator scope. | bounded evaluation scope |
| C-LIMIT-01 | supported with qualification | Context is actionable only before consequential actions. | bounded evaluation scope |
| C-LIMIT-02 | supported | Reference-only gateway role. | bounded evaluation scope |
| P-01 | prohibited | None; prohibited. | Do not use. |
| P-02 | prohibited | None; prohibited. | Do not use. |
| P-03 | prohibited | None; prohibited. | Do not use. |
| P-04 | prohibited | None; prohibited. | Do not use. |
| P-05 | prohibited | None; prohibited. | Do not use. |
| P-06 | prohibited | None; prohibited. | Do not use. |
| P-07 | prohibited | None; prohibited. | Do not use. |
| P-08 | prohibited | None; prohibited. | Do not use. |
| P-09 | prohibited | None; prohibited. | Do not use. |
| P-10 | prohibited | None; prohibited. | Do not use. |
