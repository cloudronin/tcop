---------------- MODULE CanaryReceiptBound ----------------
EXTENDS TrustMC
\* FAULT: bypass only ReceiptGate; the checked property is unchanged.
FaultNoSessionReceipt(m) == TRUE
============================================================
