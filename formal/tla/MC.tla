------------------------------ MODULE MC ------------------------------
EXTENDS TCOPReceiver
\* The primary targets are distinguished by A0. Swapping them would be
\* unsound. With two targets there is no nontrivial residual symmetry.
MCMin == [k \in Kinds |-> 0]
MCMax == [k \in Kinds |-> 1]
SlowMin == [k \in Kinds |-> 2]
SlowMax == [k \in Kinds |-> 3]
FastMin == [k \in Kinds |-> 0]
FastMax == [k \in Kinds |-> 1]
AllChoices == Tightenings
A0Choices == CoveringChoices
EgressChoice == {<<"deny_egress", PrimaryDest>>}
FreezeChoice == {<<"freeze", "sandbox">>}
SanityAtHorizon == Terminal => (a4 = "executed" /\ effective # {})
WitnessReport == IF Terminal
                 THEN PrintT([reachable |-> "terminal", tick |-> now,
                              a0 |-> result[0], a4 |-> a4,
                              effectiveMessages |-> effective,
                              lieRemovedAuthority |-> LyingCostWitness,
                              executed |-> Executed])
                 ELSE TRUE
=======================================================================
