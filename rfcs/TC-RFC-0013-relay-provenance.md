# TC-RFC-0013: Relay provenance and no evidence laundering (Draft)

Relays wrap the immutable original signed observation in a separately signed
relay record. The original observer, signature, and observation identifier are
never replaced. Relay chains are loop-checked and audit-visible, but a relay is
not a new witness and cannot add to the independent-control-group set.

After a network heal, synchronization replays the original observation through
this mechanism without manufacturing a second claim.
