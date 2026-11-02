---------------- MODULE CanaryZeroTrust ----------------
EXTENDS TrustMC
\* FAULT: bypass only OwnPolicyGate; the checked property is unchanged.
FaultUntrustedBroadAction(p, t) == TRUE
============================================================
