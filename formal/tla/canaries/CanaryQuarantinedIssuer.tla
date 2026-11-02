---------------- MODULE CanaryQuarantinedIssuer ----------------
EXTENDS TrustMC
\* FAULT: bypass only QuarantineGate; the checked property is unchanged.
FaultQuarantineBypass(p) == TRUE
============================================================
