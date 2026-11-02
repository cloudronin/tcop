------------------------- MODULE TCOPReceiver -------------------------
EXTENDS Naturals, Integers, FiniteSets, Sequences, TLC

CONSTANTS Destinations, Credentials, PrimaryDest, PrimaryCredential,
          MinLag, MaxLag, ActionInterval, ApprovalDelay, BaselineDeniesA0,
          A0Kind, LocalChoices, ReadyAtEmission, MaxMessages, ReceiveUntil

Kinds == {"deny_egress", "revoke_credential", "freeze"}
Capabilities == ({"egress"} \X Destinations)
                \cup ({"credential"} \X Credentials)
                \cup {<<"work", "benign">>}
Tightenings == ({"deny_egress"} \X Destinations)
              \cup ({"revoke_credential"} \X Credentials)
              \cup {<<"freeze", "sandbox">>}
A0Capability == IF A0Kind = "egress" THEN <<"egress", PrimaryDest>>
                ELSE <<"credential", PrimaryCredential>>
Baseline == IF BaselineDeniesA0 THEN Capabilities \ {A0Capability}
            ELSE Capabilities
Covers(t) == CASE t[1] = "deny_egress" -> {<<"egress", t[2]>>}
              [] t[1] = "revoke_credential" -> {<<"credential", t[2]>>}
              [] OTHER -> Capabilities
CoveringChoices == {t \in Tightenings : A0Capability \in Covers(t)}
NoChoice == <<"none", "none">>
MaxBound == CHOOSE n \in {MaxLag[k] : k \in Kinds} :
                         \A k \in Kinds : n >= MaxLag[k]
Horizon == 4 * ActionInterval + ReceiveUntil + ApprovalDelay + MaxBound + 1

ASSUME /\ PrimaryDest \in Destinations /\ PrimaryCredential \in Credentials
       /\ A0Kind \in {"egress", "credential"}
       /\ MinLag \in [Kinds -> Nat] /\ MaxLag \in [Kinds -> Nat]
       /\ \A k \in Kinds : MinLag[k] <= MaxLag[k]
       /\ ActionInterval > 0 /\ ApprovalDelay \in Nat
       /\ MaxMessages \in 1..7 /\ ReceiveUntil \in Nat
       /\ LocalChoices # {} /\ LocalChoices \subseteq Tightenings
       /\ ReadyAtEmission \in BOOLEAN /\ BaselineDeniesA0 \in BOOLEAN

\* Finite wire variants. Truth is evaluator-only; it is never read by Valid
\* or by the receiver's nondeterministic local action selection.
Messages == 1..7
Msg(m) == [id |-> CASE m = 3 -> 1 [] OTHER -> m,
           nonce |-> CASE m = 4 -> 1 [] OTHER -> m,
           signed |-> m # 5, authorized |-> m # 5,
           correlated |-> m # 7,
           expires |-> IF m = 6 THEN -1 ELSE Horizon,
           lie |-> m = 2]

VARIABLES now, Authority, status, choice, submitAt, effectAt,
          seenIds, seenNonces, accepted, delivered,
          Covered, effective, attempt, nextAttempt, result, a4, Executed
vars == <<now, Authority, status, choice, submitAt, effectAt,
          seenIds, seenNonces, accepted, delivered,
          Covered, effective, attempt, nextAttempt, result, a4, Executed>>

Valid(m) == /\ Msg(m).signed /\ Msg(m).authorized /\ Msg(m).correlated
            /\ Msg(m).expires >= now
            /\ Msg(m).id \notin seenIds /\ Msg(m).nonce \notin seenNonces
Audit(m) == [message |-> m, at |-> now, id |-> Msg(m).id,
             nonce |-> Msg(m).nonce, priorIds |-> seenIds,
             priorNonces |-> seenNonces]
SeedAudit == [message |-> 1, at |-> 0, id |-> 1, nonce |-> 1,
              priorIds |-> {}, priorNonces |-> {}]

Init == /\ now = 0 /\ Authority = Baseline
        /\ status = [m \in Messages |-> IF ReadyAtEmission /\ m = 1
                                            THEN "approval" ELSE "unreceived"]
        /\ choice \in [Messages -> {NoChoice} \cup LocalChoices]
        /\ \A m \in Messages :
             IF ReadyAtEmission /\ m = 1 THEN choice[m] \in LocalChoices
             ELSE choice[m] = NoChoice
        /\ submitAt = [m \in Messages |-> IF ReadyAtEmission /\ m = 1
                                               THEN ApprovalDelay ELSE 0]
        /\ effectAt = [m \in Messages |-> 0]
        /\ seenIds = IF ReadyAtEmission THEN {1} ELSE {}
        /\ seenNonces = IF ReadyAtEmission THEN {1} ELSE {}
        /\ accepted = IF ReadyAtEmission THEN {SeedAudit} ELSE {}
        /\ delivered = IF ReadyAtEmission THEN {1} ELSE {}
        /\ Covered = {} /\ effective = {}
        /\ attempt = 0 /\ nextAttempt = ActionInterval
        /\ result = [i \in 0..3 |-> "unattempted"]
        /\ a4 = "waiting" /\ Executed = <<>>

Receive(m) ==
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
          ELSE /\ status' = [status EXCEPT ![m] = "rejected"]
               /\ UNCHANGED <<choice, submitAt, seenIds, seenNonces, accepted>>
    /\ UNCHANGED <<now, Authority, effectAt, Covered, effective,
                    attempt, nextAttempt, result, a4, Executed>>

Submit(m) ==
    /\ status[m] = "approval" /\ now = submitAt[m]
    /\ status' = [status EXCEPT ![m] = "pending"]
    /\ \E lag \in MinLag[choice[m][1]]..MaxLag[choice[m][1]] :
          effectAt' = [effectAt EXCEPT ![m] = now + lag]
    /\ UNCHANGED <<now, Authority, choice, submitAt, seenIds, seenNonces,
                    accepted, delivered, Covered, effective,
                    attempt, nextAttempt, result, a4, Executed>>

TakeEffect(m) ==
    /\ status[m] = "pending" /\ now = effectAt[m]
    /\ status' = [status EXCEPT ![m] = "effective"]
    /\ Authority' = Authority \ Covers(choice[m])
    /\ Covered' = Covered \cup Covers(choice[m])
    /\ effective' = effective \cup {m}
    /\ UNCHANGED <<now, choice, submitAt, effectAt, seenIds, seenNonces,
                    accepted, delivered, attempt, nextAttempt, result, a4, Executed>>

\* A1 uses another admitted capability, A2 a fresh session, A3 a fresh
\* subject. Session/subject changes do not escape this single sandbox.
AttemptCapability(i) == IF i = 1 THEN <<"credential", PrimaryCredential>>
                        ELSE A0Capability
HarmfulAttempt ==
    /\ attempt < 4 /\ now = nextAttempt
    /\ LET cap == AttemptCapability(attempt)
           ok == cap \in Authority
       IN /\ result' = [result EXCEPT ![attempt] = IF ok THEN "executed" ELSE "denied"]
          /\ attempt' = IF ok THEN 4 ELSE attempt + 1
          /\ Executed' = IF ok THEN Append(Executed,
                   [cap |-> cap, at |-> now, origin |-> "harmful_actor"])
                         ELSE Executed
    /\ nextAttempt' = nextAttempt + ActionInterval
    /\ UNCHANGED <<now, Authority, status, choice, submitAt, effectAt,
                    seenIds, seenNonces, accepted, delivered, Covered, effective, a4>>

BenignAttempt ==
    /\ attempt = 4 /\ a4 = "waiting"
    /\ a4' = IF <<"work", "benign">> \in Authority THEN "executed" ELSE "denied"
    /\ Executed' = IF a4' = "executed" THEN Append(Executed,
             [cap |-> <<"work", "benign">>, at |-> now, origin |-> "benign_actor"])
                   ELSE Executed
    /\ UNCHANGED <<now, Authority, status, choice, submitAt, effectAt,
                    seenIds, seenNonces, accepted, delivered, Covered, effective,
                    attempt, nextAttempt, result>>

Urgent == (\E m \in Messages :
               (status[m] = "approval" /\ now = submitAt[m])
               \/ (status[m] = "pending" /\ now = effectAt[m]))
          \/ (attempt < 4 /\ now = nextAttempt)
          \/ (attempt = 4 /\ a4 = "waiting")
Tick == /\ now < Horizon /\ ~Urgent /\ now' = now + 1
        /\ UNCHANGED <<Authority, status, choice, submitAt, effectAt,
                       seenIds, seenNonces, accepted, delivered, Covered, effective,
                       attempt, nextAttempt, result, a4, Executed>>
Terminal == now = Horizon /\ a4 # "waiting"
            /\ \A m \in Messages : status[m] \notin {"approval", "pending"}
ReceiverStep == \E m \in Messages : Receive(m) \/ Submit(m) \/ TakeEffect(m)
Progress == ReceiverStep \/ HarmfulAttempt \/ BenignAttempt \/ Tick
Next == Progress \/ (Terminal /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars /\ WF_vars(Progress)

TypeOK == /\ Authority \subseteq Capabilities /\ Covered \subseteq Capabilities
          /\ now \in 0..Horizon /\ attempt \in 0..4
          /\ status \in [Messages -> {"unreceived", "rejected", "approval", "pending", "effective"}]
          /\ choice \in [Messages -> Tightenings \cup {NoChoice}]
          /\ a4 \in {"waiting", "executed", "denied"}
NoWidening == [][Authority' \subseteq Authority]_vars
AcceptOnlyValid == \A a \in accepted :
    LET m == a.message IN
      /\ Msg(m).signed /\ Msg(m).authorized /\ Msg(m).correlated
      /\ Msg(m).expires >= a.at
      /\ a.id \notin a.priorIds /\ a.nonce \notin a.priorNonces
EffectInstalled == Covered \cap Authority = {}
EffectHolds == /\ []EffectInstalled
               /\ [][\A i \in (Len(Executed)+1)..Len(Executed') :
                        Executed'[i].cap \notin Covered]_vars
NoCommandPath == [][ReceiverStep => Executed' = Executed]_vars
LyingPeerOnlyCostsAvailability ==
    /\ NoWidening /\ NoCommandPath
    /\ [](\A i \in 1..Len(Executed) :
           Executed[i].origin \in {"harmful_actor", "benign_actor"})
LadderOrder == \A i \in 1..3 : result[i] # "unattempted" => result[i-1] = "denied"
A4Independent == a4 # "waiting" => attempt = 4
SlowAssumption == ~BaselineDeniesA0 /\
                 (\A t \in LocalChoices : MinLag[t[1]] > ActionInterval)
FastAssumption == /\ ReadyAtEmission /\ LocalChoices \subseteq CoveringChoices
                  /\ \A t \in LocalChoices : MaxLag[t[1]] + ApprovalDelay < ActionInterval
TimingClaim == SlowAssumption =>
               (result[0] # "unattempted" => result[0] = "executed")
FastTimingClaim == FastAssumption =>
                   (result[0] # "unattempted" => result[0] = "denied")
BoundedCompletion == now = Horizon => Terminal
Completes == <>Terminal
A4Completes == <>(a4 = "executed")
EffectReached == <>(effective # {})
\* Positive reachability predicates, reported by MC without failing a check.
LyingCostWitness == 2 \in effective /\ Authority # Baseline
=======================================================================
