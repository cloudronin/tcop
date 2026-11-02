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

Negative-control correction: ten live conditions were executed and passed; two are covered only by executed signed-envelope mutations; four remain **Not tested**. Hostile-peer burst and concurrent-session tables are formula-computed illustrations, not measurements. See `docs/KNOWN_ISSUES.md` in the reviewer artifact.

## Anonymous and preprint builds

From the repository root, `make paper-check PYTHON=python3` builds and checks
`paper/usenix27/main.pdf` with anonymous authorship and artifact links.
`make paper-preprint PYTHON=python3` builds
`paper/usenix27/preprint/main-preprint.pdf` from the same manuscript with the
preprint author block and public repository link. It runs source stability,
number, claim, LaTeX, page-budget, bibliography, and preprint identity/link
checks; only anonymity is omitted. Reports are separate under
`preprint/evidence/`. The preprint build verifies that `main.pdf` is unchanged.
After generating shared data, figures, tables, and macros, the direct entry
point is `python3 paper/usenix27/scripts/paperlib.py build --preprint`.

Preprint repository links use the single `PREPRINT_TAG` setting in
`scripts/paperlib.py`. The build maps reader-facing paths to file or directory
URLs at that tag, leaving anonymous path text unchanged. Its
`preprint/link-manifest.json` lists every PDF URL; repository targets are
checked against git HEAD, and missing paths or other refs fail the build.
External URLs have no repository path or git-tracking claim.
