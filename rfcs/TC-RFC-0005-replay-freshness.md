# TC-RFC-0005: Replay and Freshness Protection (Draft)

Receivers enforce expiration, bounded clock skew, monotonic sequence, unique
observation identifiers, and single-use challenge nonces. Synchronization never
allows expired or older observations to replace accepted newer state.

