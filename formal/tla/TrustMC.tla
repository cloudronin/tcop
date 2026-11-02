---------------------------- MODULE TrustMC ---------------------------
EXTENDS TCOPTrust
CONSTANTS PeerA, PeerB, OtherSession, AlternateDest
MCTrustMessages == {1, 2}
MCTrustSingleMessage == {1}
MCTrustMin == [k \in Kinds |-> 0]
MCTrustMax == [k \in Kinds |-> 1]
MCTrustRoutes == {<<PeerA, BoundSession, PrimaryDest>>,
                  <<PeerB, OtherSession, AlternateDest>>}
MCTrustSingleRoute == {<<PeerA, BoundSession, PrimaryDest>>}
MCWarnings == [m \in {1, 2} |->
                 [issuer |-> IF m = 1 THEN PeerA ELSE PeerB,
                  session |-> BoundSession,
                  destination |-> IF m = 1 THEN PrimaryDest ELSE AlternateDest]]
MCTrustChoices == Tightenings
TrustWitnessReport ==
    IF Terminal THEN PrintT([trustTerminal |-> TRUE,
         untrustedRestriction |-> (\E a \in effectAudit : ~a.trusted),
         trustedFreeze |-> (\E a \in effectAudit : a.trusted /\ a.action[1] = "freeze"),
         quarantinedWarningBlocked |-> (\E b \in blocked : b.quarantined),
         pendingWarningCancelled |-> (\E m \in delivered : m \notin effective /\ status[m] = "rejected")])
    ELSE TRUE
=======================================================================
