# TC-RFC-0010: Evidence classes and control-group independence (Draft)

TCX v0.2 classifies evidence at the receiving domain from the static
administrative control-group registry. A subject's own claim is
`self_assertion`; an observation from the same control group is `first_party`.
Neither contributes independent corroboration. `independent_peer` and
`neutral_third_party` evidence count at most once per observer control group
and only when the reference resolver verifies its interaction receipt.

The signed envelope carries an observer declaration, but the effective class
and reason code are receiver-generated immutable classification records.
