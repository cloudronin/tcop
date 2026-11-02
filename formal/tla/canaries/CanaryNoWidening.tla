----------------------- MODULE CanaryNoWidening -----------------------
EXTENDS CanaryBounds
\* FAULT: the adapter can reattach authority already removed by an effect.
FaultReattach ==
    /\ effective # {} /\ A0Capability \notin Authority
    /\ Authority' = Authority \cup {A0Capability}
    /\ UNCHANGED <<now, status, choice, submitAt, effectAt, seenIds,
                    seenNonces, accepted, delivered, Covered, effective,
                    attempt, nextAttempt, result, a4, Executed>>
CanaryNext == Next \/ FaultReattach
CanarySpec == Init /\ [][CanaryNext]_vars /\ WF_vars(Progress)
=======================================================================
