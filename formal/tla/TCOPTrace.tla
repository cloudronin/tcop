--------------------------- MODULE TCOPTrace ---------------------------
EXTENDS TCOPReceiver
CONSTANTS TraceEvents, TraceEnvelopes, TraceInitialAuthority
VARIABLE traceIndex
traceVars == <<vars, traceIndex>>

\* Only the bounded wire fixture table is replaced with the supplied wire
\* records. The receiver's validation, actions and properties are unchanged.
TraceMessageSet == 1..Len(TraceEnvelopes)
TraceMsg(m) == TraceEnvelopes[m]
TraceInit == Init /\ Authority = TraceInitialAuthority /\ traceIndex = 0

ReceiveEvent(e) ==
    /\ Receive(e.m)
    /\ status'[e.m] = IF e.decision = "accepted" THEN "approval" ELSE "rejected"
    /\ choice'[e.m] = e.selected
AttemptEvent(e) ==
    /\ e.authorized = (e.cap \in Authority)
    /\ e.denied = ~e.authorized /\ e.executed = e.authorized
    /\ IF e.action < 4
          THEN /\ attempt = e.action /\ e.cap = AttemptCapability(e.action)
               /\ HarmfulAttempt
               /\ result'[e.action] = IF e.executed THEN "executed" ELSE "denied"
          ELSE /\ e.cap = <<"work", "benign">> /\ BenignAttempt
               /\ a4' = IF e.executed THEN "executed" ELSE "denied"
EndEvent == /\ a4 # "waiting" /\ delivered = Messages
            /\ \A m \in Messages : status[m] \notin {"approval", "pending"}
            /\ UNCHANGED vars
EventStep(e) ==
    /\ now = e.t /\ now' = e.t /\ Authority' = e.authority
    /\ CASE e.kind = "receive" -> ReceiveEvent(e)
         [] e.kind = "submit" -> Submit(e.m)
         [] e.kind = "effect" -> TakeEffect(e.m)
         [] e.kind = "attempt" -> AttemptEvent(e)
         [] e.kind = "authority" -> UNCHANGED vars
         [] e.kind = "end" -> EndEvent
         [] OTHER -> FALSE
Advance == /\ traceIndex < Len(TraceEvents)
           /\ EventStep(TraceEvents[traceIndex + 1])
           /\ traceIndex' = traceIndex + 1
HiddenTick == /\ traceIndex < Len(TraceEvents)
              /\ now < TraceEvents[traceIndex + 1].t /\ Tick
              /\ UNCHANGED traceIndex
\* Nonmatching branches may stutter. Acceptance is existential end
\* reachability after exhaustive search, never merely absence of an error.
TraceNext == Advance \/ HiddenTick \/ UNCHANGED traceVars
TraceSpec == TraceInit /\ [][TraceNext]_traceVars
TraceReport == PrintT(<<"TCOP_TRACE_REACHED", traceIndex>>)
=======================================================================
