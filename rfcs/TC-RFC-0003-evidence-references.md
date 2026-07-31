# TC-RFC-0003: Evidence References (Draft)

v0.1 carries evidence digests and optional access-controlled locators. Evidence
references are provenance inputs, never evidence contents or remote verdicts.

## Signed withdrawal references

An observer can issue a `recovery.withdrawal` observation with metadata field
`withdraws` set to the observation identifier it retracts. Receivers validate
the withdrawal through the normal TCX path and retain both records in evidence
storage. A valid withdrawal removes only the referenced active observation from
local resolution; it does not delete immutable evidence or alter observations
from other observers. Profiles should set a narrow recovery envelope and record
the resulting restoration event.
