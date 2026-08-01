# TC-RFC-0022: Tip-only investigative evidence (Draft)

A receiver MAY classify a fresh, receipted threat observation from a
restricted or quarantined issuer as an investigative tip. The classification
MUST remain receiver-local and MUST NOT add corroborative influence, alter
issuer reliability, restore an issuer state, or directly authorize a full
quarantine. Tips are input to bounded investigation only.

The reference profile records the tip, its zero corroborative credit, its
deduplication key, and the resulting scheduled or declined action. CT-065
through CT-070 and B-051 through B-055 exercise this boundary.
