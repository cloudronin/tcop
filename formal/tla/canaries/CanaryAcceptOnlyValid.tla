-------------------- MODULE CanaryAcceptOnlyValid ---------------------
EXTENDS CanaryBounds
\* FAULT: identical to Valid except the consumed-nonce check is absent.
\* The unchanged Receive still records the actual prior nonce set in Audit.
FaultValidWithoutNonce(m) ==
    /\ Msg(m).signed /\ Msg(m).authorized /\ Msg(m).correlated
    /\ Msg(m).expires >= now /\ Msg(m).id \notin seenIds
=======================================================================
