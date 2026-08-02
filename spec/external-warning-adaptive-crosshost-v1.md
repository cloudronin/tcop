# TCOP External-Warning, Adaptive-Attacker, Cross-Host Study v1

This execution surface preserves the supplied study specification's central
constraint: a result is valid only when the evaluation uses the pinned
AgentDojo source, the pinned Meta Llama Prompt Guard 2 model, and genuinely
separate hosts or VMs. A local synthetic substitute, two local processes, or
two containers on one host is not a valid replacement.

`tcop study external-adaptive run` therefore performs preflight first. It may
evaluate only after it records immutable revisions and content hashes for both
external dependencies, verifies their licenses, and receives two distinct,
non-local host identities through `TCOP_EXTERNAL_HOST_A` and
`TCOP_EXTERNAL_HOST_B`. The command otherwise writes a sealed `BLOCKED`
artifact containing the exact unmet gates and no efficacy findings.

The holdout uses the Meta Llama Prompt Guard 2 86M variant. Its official
snapshot requires a full immutable Hugging Face revision and recorded license
acceptance before acquisition or evaluation; an unpinned model cache is not an
admitted input.

The study root is `artifacts/external-warning-adaptive-crosshost-v1/`. It is
separate from all v0.1 through v0.6 and validation-value artifacts. A blocked
artifact is evidence of an unmet precondition, not an experimental result and
does not authorize a manuscript update.

Amendments 001 and 002 are incorporated in the source plan before external timestamping.
It adds a falsification comparator: S1 (standard STIX 2.1 and TAXII 2.1 with
Domain-B-local OPA), T2 (direct TCOP with that identical OPA interface), and
S2 (TCOP carried in a declared STIX extension over that same TAXII path). The
comparison must keep the gateway action-binding adapter, local request, OPA
input, cadence, and retry ladder constant. The future execution may not
conclude protocol novelty unless the standards-native baseline is represented
fairly and the capability mapping is trace-backed.

Amendment 002 replaces the generic retry ladder with five fixed adaptive
branches, makes valid-broader-risk a required gated population, and requires a
predeclared 4 by 4 two-host network-interface timing surface. Its census,
branch-coverage, timing, and outcome-partition artifacts must be complete
before any external result is reported.
