---------------------------- MODULE TCOPTrust --------------------------
EXTENDS TCOPReceiver
CONSTANTS Peers, Sessions, BoundSession, TrafficRoutes, WarningData, AuxUntil

\* Authority is the original single sandbox/session context. Other sessions
\* distinguish receipts for unrelated traffic; they are not extra runtimes.
ASSUME /\ BoundSession \in Sessions /\ AuxUntil \in 0..Horizon
       /\ TrafficRoutes \subseteq (Peers \X Sessions \X Destinations)
       /\ ~ReadyAtEmission
       /\ \A m \in Messages :
            /\ WarningData[m].issuer \in Peers
            /\ WarningData[m].session \in Sessions
            /\ WarningData[m].destination \in Destinations

VARIABLES trusted, trustBy, quarantined, traffic, minted, held,
          examined, blocked, effectAudit
extraVars == <<trusted, trustBy, quarantined, traffic, minted, held,
               examined, blocked, effectAudit>>
trustVars == <<vars, extraVars>>

TrustInit == /\ Init
             /\ trusted = {} /\ trustBy = [p \in Peers |-> "none"]
             /\ quarantined = {} /\ traffic = {} /\ minted = {} /\ held = {}
             /\ examined = {} /\ blocked = {} /\ effectAudit = {}

\* Only receiver/operator transitions raise trust. A warning never does.
RaiseTrust(p, actor) ==
    /\ now <= AuxUntil /\ p \notin trusted /\ p \notin quarantined
    /\ actor \in {"receiver", "operator"}
    /\ trusted' = trusted \cup {p}
    /\ trustBy' = [trustBy EXCEPT ![p] = actor]
    /\ UNCHANGED <<vars, quarantined, traffic, minted, held, examined, blocked, effectAudit>>
QuarantinePeer(p) ==
    /\ now <= AuxUntil /\ p \notin quarantined
    /\ quarantined' = quarantined \cup {p}
    /\ UNCHANGED <<vars, trusted, trustBy, traffic, minted, held, examined, blocked, effectAudit>>

\* A route triple is actual arrival at peer p of session s traffic to d.
\* Minting is a receiver-side operation; delivery only gives it to that p.
TrafficArrival(r) ==
    /\ now <= AuxUntil /\ r \notin traffic
    /\ traffic' = traffic \cup {r}
    /\ UNCHANGED <<vars, trusted, trustBy, quarantined, minted, held, examined, blocked, effectAudit>>
MintReceipt(r) ==
    /\ now <= AuxUntil /\ r \in traffic /\ r \notin minted
    /\ minted' = minted \cup {r}
    /\ UNCHANGED <<vars, trusted, trustBy, quarantined, traffic, held, examined, blocked, effectAudit>>
DeliverReceipt(r) ==
    /\ now <= AuxUntil /\ r \in minted /\ r \notin held
    /\ held' = held \cup {r}
    /\ UNCHANGED <<vars, trusted, trustBy, quarantined, traffic, minted, examined, blocked, effectAudit>>
ValidReceipts == held \cap minted \cap traffic
OwnDestinations(p) == {d \in Destinations :
                        \E s \in Sessions : <<p, s, d>> \in ValidReceipts}
ReceiptGate(m) ==
    /\ WarningData[m].session = BoundSession
    /\ <<WarningData[m].issuer, BoundSession, WarningData[m].destination>> \in ValidReceipts
QuarantineGate(p) == p \notin quarantined
OwnPolicyGate(p, t) == p \in trusted \/
                      (t[1] = "deny_egress" /\ t[2] \in OwnDestinations(p))
IntakeGate(m) == ReceiptGate(m) /\ QuarantineGate(WarningData[m].issuer)
EffectGate(m) == IntakeGate(m) /\ OwnPolicyGate(WarningData[m].issuer, choice[m])

TrustReceive(m) ==
    /\ m \notin examined /\ Cardinality(examined) < MaxMessages
    /\ Receive(m)
    /\ Valid(m) => (IntakeGate(m) /\ OwnPolicyGate(WarningData[m].issuer, choice'[m]))
    /\ examined' = examined \cup {m}
    /\ UNCHANGED <<trusted, trustBy, quarantined, traffic, minted, held, blocked, effectAudit>>
\* Policy refusal is a base-spec stutter: no TCX acceptance, write or command.
TrustReject(m) ==
    /\ now <= ReceiveUntil /\ m \notin examined
    /\ Cardinality(examined) < MaxMessages /\ ~IntakeGate(m)
    /\ examined' = examined \cup {m}
    /\ blocked' = blocked \cup {[message |-> m, issuer |-> WarningData[m].issuer,
                                 at |-> now, quarantined |-> (WarningData[m].issuer \in quarantined)]}
    /\ UNCHANGED <<vars, trusted, trustBy, quarantined, traffic, minted, held, effectAudit>>
TrustSubmit(m) == /\ EffectGate(m) /\ Submit(m) /\ UNCHANGED extraVars
EffectRecord(m) ==
    [message |-> m, issuer |-> WarningData[m].issuer,
     session |-> BoundSession, warningSession |-> WarningData[m].session,
     destination |-> WarningData[m].destination, action |-> choice[m],
     at |-> now, trusted |-> (WarningData[m].issuer \in trusted),
     quarantined |-> (WarningData[m].issuer \in quarantined),
     held |-> held, minted |-> minted, traffic |-> traffic,
     removed |-> (Authority \cap Covers(choice[m]))]
TrustTakeEffect(m) ==
    /\ EffectGate(m) /\ TakeEffect(m)
    /\ effectAudit' = effectAudit \cup {EffectRecord(m)}
    /\ UNCHANGED <<trusted, trustBy, quarantined, traffic, minted, held, examined, blocked>>
\* Recheck before installation. A quarantined issuer cannot retain a queued
\* path to a new restriction. This never rolls back an installed effect.
CancelBlocked(m) ==
    /\ status[m] \in {"approval", "pending"} /\ ~EffectGate(m)
    /\ status' = [status EXCEPT ![m] = "rejected"]
    /\ UNCHANGED <<now, Authority, choice, submitAt, effectAt, seenIds,
                    seenNonces, accepted, delivered, Covered, effective,
                    attempt, nextAttempt, result, a4, Executed, extraVars>>

TrustReceiverStep == \E m \in Messages :
    TrustReceive(m) \/ TrustReject(m) \/ TrustSubmit(m) \/ TrustTakeEffect(m) \/ CancelBlocked(m)
TrustAuxStep == (\E p \in Peers, actor \in {"receiver", "operator"} : RaiseTrust(p, actor))
               \/ (\E p \in Peers : QuarantinePeer(p))
               \/ (\E r \in TrafficRoutes : TrafficArrival(r) \/ MintReceipt(r) \/ DeliverReceipt(r))
TrustProgress == TrustReceiverStep \/ TrustAuxStep
                 \/ ((HarmfulAttempt \/ BenignAttempt \/ Tick) /\ UNCHANGED extraVars)
TrustNext == TrustProgress \/ (Terminal /\ UNCHANGED trustVars)
TrustSpec == TrustInit /\ [][TrustNext]_trustVars /\ WF_trustVars(TrustProgress)

TrustTypeOK == /\ TypeOK /\ trusted \subseteq Peers /\ quarantined \subseteq Peers
               /\ trustBy \in [Peers -> {"none", "receiver", "operator"}]
               /\ traffic \subseteq TrafficRoutes /\ minted \subseteq TrafficRoutes
               /\ held \subseteq TrafficRoutes /\ examined \subseteq Messages
TrustRaisedLocally == \A p \in Peers :
                       (p \in trusted) = (trustBy[p] \in {"receiver", "operator"})
ReceiptProvenance == held \subseteq minted /\ minted \subseteq traffic
ReceiptBoundRestrictions == \A a \in effectAudit :
    /\ a.session = a.warningSession
    /\ <<a.issuer, a.session, a.destination>> \in (a.held \cap a.minted \cap a.traffic)
QuarantinedIssuerNoEffect == \A a \in effectAudit : ~a.quarantined
ZeroTrustOwnDestinationsOnly == \A a \in effectAudit :
    ~a.trusted =>
       /\ a.action[1] = "deny_egress"
       /\ \E s \in Sessions : <<a.issuer, s, a.action[2]>> \in (a.held \cap a.minted \cap a.traffic)
=======================================================================
