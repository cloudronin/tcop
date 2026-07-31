# TC-RFC-0001: Observation Envelope (Draft)

The immutable v0.1 observation envelope is defined in
`schemas/observation-v0.1.json`. The signed bytes are canonical JSON of the
envelope without `signature`. The reference suite uses Ed25519 and a registered
`key_id`. Invalid, expired, out-of-scope, replayed, cross-tenant, or malformed
observations are never committed.

