# TC-RFC-0014: Conflicting evidence and staged recovery (Draft)

TCX v0.2 preserves conflicting, withdrawn, and clean observations in immutable
evidence streams. The reference resolver records conflict rather than creating
a universal trust score. A withdrawal removes its target from active resolution
but not history. High-risk restoration is staged: withdrawal alone yields an
approval-gated envelope; withdrawal plus fresh clean receipt-verified evidence
may restore the normal envelope.
