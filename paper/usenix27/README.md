# TCOP USENIX Security 2027 Paper Workspace

This workspace is an anonymous, evidence-first first draft. It consumes read-only TCOP v0.6 artifacts and produces normalized paper data, vector figures, generated tables, result macros, a PDF draft, and a compact anonymous reviewer package. It does not rerun live model sampling or modify research artifacts.

The deterministic missing-evidence source uses the admitted root 0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99. The unavailable cd26169 source is retained as a formally superseded reference in spec/v0.6-agent-validation-source-artifact-amendment.md; the verifier checks this amendment explicitly.

## Direct commands

    python3 scripts/verify_sources.py
    python3 scripts/extract_results.py
    python3 scripts/paperlib.py inventory
    python3 scripts/generate_macros.py
    python3 scripts/generate_tables.py
    MPLCONFIGDIR=.matplotlib-cache python3 scripts/generate_figures.py
    scripts/build_paper.sh
    python3 scripts/verify_claims.py
    python3 scripts/verify_manuscript_numbers.py
    python3 scripts/verify_anonymity.py
    scripts/reproduce_core.sh

The top-level Make targets provide the same workflow: paper-verify-sources, paper-extract, paper-figures, paper-tables, paper-build, paper-number-audit, paper-anonymity-audit, paper-reproduce-core, and paper-check.

## Reproduction tiers

Tier 0 verifies source roots and regenerates paper derivatives without credentials. Tier 1 reruns the deterministic causal core without credentials. Tier 2 strictly replays frozen agent traces without credentials. Tier 3, live trace regeneration, is optional and credentialed; it is not necessary to validate the paper's causal claims.

The current official USENIX template files are copied under template/ with checksums in generated/paper-metadata.json. A Security 2027-specific kit was not available when this draft was assembled; replace only the template files if and when an official kit is released, then rerun all paper checks.
