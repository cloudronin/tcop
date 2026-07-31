# TC-RFC-0002: Trust Lifecycle Profile (Draft)

The externally visible states are `unknown`, `healthy`, `suspicious`,
`constrained`, `quarantined`, `recovering`, and `recovered`. Transitions are
local and capability-specific. Recovery requires a new signed recovery or
attestation observation; elapsed time alone cannot restore a capability.

