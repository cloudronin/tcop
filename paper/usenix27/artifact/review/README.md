# Anonymous Reviewer Artifact

This directory is the compact anonymous reviewer package for the TCOP paper. It contains machine-checkable expected results, normalized data, figure and table provenance, and a credential-free reproduction driver. It also includes the sealed TCX Validation-Value Study v2 used for the selective-enforcement, hostile-peer, correlation, and validator-mutation claims. It intentionally does not include provider credentials or a full raw research artifact tree.

For Tier 1 and Tier 2, distribute this directory with an anonymous TCOP source-and-artifact archive that preserves the repository-relative source paths. Tier 0 can inspect expected results and all derived paper material directly.

Negative-control correction: ten live conditions were executed and passed; two are covered only by executed signed-envelope mutations; four remain **Not tested**. Hostile-peer burst and concurrent-session tables are formula-computed illustrations, not measurements. See `docs/KNOWN_ISSUES.md` in the reviewer artifact.
