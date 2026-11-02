---------------- MODULE FrozenTrace ----------------
EXTENDS TCOPTrace
InputEvents == <<
[kind |-> "receive", t |-> 0, m |-> 1, decision |-> "accepted", selected |-> <<"deny_egress", "d0">>, action |-> 0, cap |-> <<"none", "none">>, authorized |-> FALSE, denied |-> FALSE, executed |-> FALSE, authority |-> {<<"egress", "d0">>, <<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "submit", t |-> 0, m |-> 1, decision |-> "", selected |-> <<"none", "none">>, action |-> 0, cap |-> <<"none", "none">>, authorized |-> FALSE, denied |-> FALSE, executed |-> FALSE, authority |-> {<<"egress", "d0">>, <<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "effect", t |-> 0, m |-> 1, decision |-> "", selected |-> <<"none", "none">>, action |-> 0, cap |-> <<"none", "none">>, authorized |-> FALSE, denied |-> FALSE, executed |-> FALSE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "receive", t |-> 0, m |-> 2, decision |-> "accepted", selected |-> <<"deny_egress", "d0">>, action |-> 0, cap |-> <<"none", "none">>, authorized |-> FALSE, denied |-> FALSE, executed |-> FALSE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "attempt", t |-> 2, m |-> 0, decision |-> "", selected |-> <<"none", "none">>, action |-> 0, cap |-> <<"egress", "d0">>, authorized |-> FALSE, denied |-> TRUE, executed |-> FALSE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "attempt", t |-> 4, m |-> 0, decision |-> "", selected |-> <<"none", "none">>, action |-> 1, cap |-> <<"credential", "c0">>, authorized |-> TRUE, denied |-> FALSE, executed |-> TRUE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "attempt", t |-> 4, m |-> 0, decision |-> "", selected |-> <<"none", "none">>, action |-> 4, cap |-> <<"work", "benign">>, authorized |-> TRUE, denied |-> FALSE, executed |-> TRUE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}],
[kind |-> "end", t |-> 4, m |-> 0, decision |-> "", selected |-> <<"none", "none">>, action |-> 0, cap |-> <<"none", "none">>, authorized |-> FALSE, denied |-> FALSE, executed |-> FALSE, authority |-> {<<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}]
>>
InputEnvelopes == <<[id |-> "observation1", nonce |-> "nonce1", signed |-> TRUE, authorized |-> TRUE, correlated |-> TRUE, expires |-> 20, lie |-> FALSE], [id |-> "observation1", nonce |-> "nonce2", signed |-> TRUE, authorized |-> TRUE, correlated |-> TRUE, expires |-> 20, lie |-> FALSE]>>
InputInitialAuthority == {<<"egress", "d0">>, <<"egress", "d1">>, <<"credential", "c0">>, <<"credential", "c1">>, <<"work", "benign">>}
InputDestinations == {"d0", "d1"}
InputCredentials == {"c0", "c1"}
InputPrimaryDest == "d0"
InputPrimaryCredential == "c0"
InputMinLag == (("deny_egress" :> 0) @@ ("revoke_credential" :> 0) @@ ("freeze" :> 0))
InputMaxLag == (("deny_egress" :> 1) @@ ("revoke_credential" :> 1) @@ ("freeze" :> 1))
InputActionInterval == 2
InputApprovalDelay == 0
InputBaselineDeniesA0 == FALSE
InputA0Kind == "egress"
InputReadyAtEmission == FALSE
InputMaxMessages == 2
InputReceiveUntil == 0
====================================================
