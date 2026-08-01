# TC-RFC-0028: TCOP profile composition and feature dependencies (Draft)

Composition SHALL validate dependencies before execution. A disabled feature
MUST have no active policy parameter, state record, decision contribution,
transition, or feature artifact. Dependency-preserving removals are explicit;
dead or unreachable policy paths are forbidden. Scenario identifiers MUST NOT
select profile parameters.

The v0.5 feature manifest is analysis metadata only and does not revise a
protocol message or a frozen profile's runtime behavior.
