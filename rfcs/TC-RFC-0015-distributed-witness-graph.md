# TC-RFC-0015: Distributed witness graph (Draft)

The witness graph is an immutable projection of accepted v0.2 observations,
interaction receipts, and relay records. Edges retain observer and subject
administrative/control-group identifiers, interaction identity, effective
evidence class, scope, receipt state, and relay chain. Local resolvers emit the
distinct admissible independent control groups used for each decision.

The graph exchanges evidence; final operating envelopes remain local sovereign
decisions.
