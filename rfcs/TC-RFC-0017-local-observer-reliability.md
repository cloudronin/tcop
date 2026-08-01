# TC-RFC-0017: Local observer reliability and scope-specific influence (Draft)

A receiving domain SHALL maintain reliability by `(local domain, observer
control group, scope)`. A signature establishes origin, not reliability.
Reliability records are receiver-local, append-only auditable state; they are
not global truth and do not transfer automatically between scopes.

The reference model uses unknown, normal, suspicious, restricted,
quarantined, and probation states. Subject risk state remains separate from
issuer reliability state. CT-041–CT-045 and B-031, B-036, and B-038 cover this
RFC.
