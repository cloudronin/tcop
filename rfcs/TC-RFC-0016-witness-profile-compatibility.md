# TC-RFC-0016: Witness profile compatibility boundary (Draft)

TCX witness profiles after v0.2 SHALL consume the original signed v0.2
observation, receipt, patrol, and relay records without changing their
canonical bytes, validation rules, scenario catalogues, or artifact roots.
Profile-local resolver records SHALL carry their own versioned schemas and
MUST NOT be represented as edits to an accepted observation.

This boundary maps to the v0.3 regression gates for v0.1 and v0.2.
