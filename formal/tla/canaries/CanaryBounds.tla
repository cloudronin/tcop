------------------------- MODULE CanaryBounds -------------------------
EXTENDS TCOPReceiver
\* Fixture constants only. Faults are defined by the four sibling modules.
ZeroLag == [k \in Kinds |-> 0]
OneEgressChoice == {<<"deny_egress", PrimaryDest>>}
SingleMessage == {1}
ReplayNonceMessages == {1, 4}
LyingMessage == {2}
=======================================================================
