# TC-RFC-0012: Active patrol observer lifecycle and safety (Draft)

Patrols are authorized, synthetic-data-only observers. Their authorization
states target allowlist, permitted capabilities, expiry, query budget, rate
limit, concurrency bound, and challenge profile. A patrol may issue a safe
challenge and publish a signed observation; it may not enforce, revoke,
quarantine, modify production data, or use unrestricted credentials.

The receiver gives an active patrol no extra authority merely because it is a
patrol. Same-control patrols are first-party evidence.
