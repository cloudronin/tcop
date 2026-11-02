# TCOP framing: protocol layering and runtime bindings

Owner framing, 2026-11-01. Read this before drafting amendment 004. Judge
every spec question against it first, and the amendment text second.

## The model

TCOP is to agent sandbox runtimes what TCP is to IP. OpenClaw, NemoClaw and
OpenShell are the IP layer: they run and confine an agent's actions, but they
have no semantics for acting on another domain's signed evidence. TCOP adds
those semantics on top.

## Bindings

TCOP defines its abstract tightening actions once, each with a guarantee. A
binding maps each abstract action onto one runtime's primitives. OpenShell at
the pinned version is the first binding. A different sandbox runtime gets a
different binding, the same way a transport protocol needs a different
mapping on a different network layer.

Draft guarantees, to be finalized in 004:

- Remove egress destination: new connections to that destination fail.
- Revoke credential: the credential stops resolving for new requests.
  Requests already in flight may finish.
- Freeze: nothing further runs in the sandbox until it is released.
- Snapshot: sandbox state is captured. It restricts nothing.

## What the experiment compares

E0, the bare agent, is IP. E1, the sandbox with its own policy, is secured
IP. E2, TCOP bound to that sandbox, is TCP over secured IP. The frontier
metrics map to network performance: useful work is goodput, damage prevented
is reliability, and time to detect and time to block are latency. E2 sits on
E1 because TCOP needs an enforcement point to bind to.

## Where the runtime lacks a primitive

Build it in the harness, reaching below the runtime if needed (for example,
freeze via docker pause). Each such piece is a temporary layering violation.
It is a finding, not a gap to hide. The precedent is the 1974 Transmission
Control Program, which did internetworking and transport in one protocol. It
was split into TCP and IP around 1978, once it was clear what belonged in the
lower layer. TCOP plus the harness is the 1974 version, and the binding table
is the argument for where the split should go.

## What this means for 004 and the outputs

- Split E2 into E2-native (runtime primitives only) and E2-extended (native
  plus harness-built). The gap between them measures what each missing
  primitive is worth.
- Tag every tightening action as native or harness. Never pool them.
- A harness-built result shows what a primitive would buy if the runtime had
  it. It is not a measurement of the runtime.
- Build a binding table with one row per abstract action. Each row records
  the guarantee, whether the action is native at the pinned version, how it
  is bound (native operation or harness implementation), whether the binding
  meets the guarantee, meets it more coarsely, or does not meet it, and its
  measured frontier effect. Mark each row as pure layering (built from what
  the runtime exposes) or extension (had to reach below the runtime).

## Extension proposals

Each proposal states the primitive's measured value (E2-extended minus
E2-native: damage prevented gained and work cost paid), the interface the
runtime should expose, and the guarantee it must meet. The check the harness
version passed becomes the acceptance test. When the runtime ships the
primitive natively and passes that check, the binding drops the workaround.

## Goal

Expose the gaps with measured evidence so runtimes build these primitives
natively, and leave a binding template plus conformance checks that let TCOP
bind to any secure sandbox runtime.
