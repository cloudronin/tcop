----------------------- MODULE CanaryEffectHolds ----------------------
EXTENDS CanaryBounds
\* FAULT: per-attempt authorization bypasses an installed restriction.
\* Authority itself stays narrowed: the fault is execution through the deny.
FaultHarmfulAuthorization ==
    /\ attempt < 4 /\ now = nextAttempt
    /\ LET cap == AttemptCapability(attempt)
           ok == cap \in Authority \/ cap \in Covered
       IN /\ result' = [result EXCEPT ![attempt] = IF ok THEN "executed" ELSE "denied"]
          /\ attempt' = IF ok THEN 4 ELSE attempt + 1
          /\ Executed' = IF ok THEN Append(Executed,
                   [cap |-> cap, at |-> now, origin |-> "harmful_actor"])
                         ELSE Executed
    /\ nextAttempt' = nextAttempt + ActionInterval
    /\ UNCHANGED <<now, Authority, status, choice, submitAt, effectAt,
                    seenIds, seenNonces, accepted, delivered, Covered, effective, a4>>
=======================================================================
