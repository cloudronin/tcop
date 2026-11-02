------------------------ MODULE CanaryLyingPeer -----------------------
EXTENDS CanaryBounds
\* FAULT: a fresh, signed, correlated false observation carries a command;
\* receiver intake executes it rather than only selecting a tightening.
\* For the admitted message 2, all original wire attributes are preserved.
FaultCommandEnvelope(m) ==
    [id |-> m, nonce |-> m, signed |-> TRUE, authorized |-> TRUE,
     correlated |-> TRUE, expires |-> Horizon, lie |-> TRUE,
     command |-> <<"work", "benign">>]
FaultReceiveCommand(m) ==
    /\ ~ReadyAtEmission /\ now <= ReceiveUntil
    /\ m \notin delivered /\ Cardinality(delivered) < MaxMessages
    /\ delivered' = delivered \cup {m}
    /\ IF Valid(m)
          THEN /\ status' = [status EXCEPT ![m] = "approval"]
               /\ \E t \in LocalChoices : choice' = [choice EXCEPT ![m] = t]
               /\ submitAt' = [submitAt EXCEPT ![m] = now + ApprovalDelay]
               /\ seenIds' = seenIds \cup {Msg(m).id}
               /\ seenNonces' = seenNonces \cup {Msg(m).nonce}
               /\ accepted' = accepted \cup {Audit(m)}
               /\ Executed' = Append(Executed,
                    [cap |-> Msg(m).command, at |-> now, origin |-> "receiver_command"])
          ELSE /\ status' = [status EXCEPT ![m] = "rejected"]
               /\ UNCHANGED <<choice, submitAt, seenIds, seenNonces, accepted, Executed>>
    /\ UNCHANGED <<now, Authority, effectAt, Covered, effective,
                    attempt, nextAttempt, result, a4>>
=======================================================================
