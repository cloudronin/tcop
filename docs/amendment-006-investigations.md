# Amendment 006 investigations

Research notes, 2026-11-01. No runtime experiment was performed. No code,
policy, sealed amendment, or third-party file was changed.

`third_party/` below means
`<scratch>/third_party/`.
Read-only `git rev-parse HEAD` confirmed OpenShell v0.0.116 at
`d1155aa70042d3e2ee49dbfa15346b108b7c1d92` and NemoClaw v0.0.140 at
`88fe14f3fb9a0bf72997cce19ec88b5b2ee08391`.

## A1. Receipts in the victim direction

**Verdict: can with configuration and an operator-run receipt middleware
service.** The pinned proxy can insert a per-request header through its
existing middleware interface. It does not mint TCOP receipts itself.
The proposed minting service is harness software using a native extension
point: pure layering, not a below-runtime packet filter. Its receipt
mechanism remains an owner choice, not an implemented or admitted path.

### Existing request rewriting

Static credential rewriting walks existing request lines and headers and
resolves placeholder values. It does not add an absent receipt header:
`third_party/openshell/crates/openshell-core/src/secrets.rs:1245-1263,1283-1294`.

Dynamic token grants can insert or replace a configured header. The
injection obtains a credential for the matched host, port, and path;
`auth_style: header` uses the configured header name:
`third_party/openshell/crates/openshell-supervisor-network/src/l7/token_grant_injection.rs:71-103,194-219,243-275,318-350`.
These are access tokens, not occurrence receipts. The resolver input lacks
the HTTP request ID and body, and tokens are cached across requests:
`third_party/openshell/crates/openshell-supervisor-network/src/l7/token_grant_injection.rs:21-31`;
`third_party/openshell/crates/openshell-supervisor-network/src/token_grant.rs:115-126,255-274`.
Renaming an access-token header therefore does not produce a fresh,
request-bound receipt.

### Configurable request-header injection

The policy exposes named `network_middlewares`, with a middleware name,
service-specific config, failure mode, host selectors, and order. An
endpoint's `credential_binding` instead selects a static provider; it is
not a receipt factory:
`third_party/openshell/proto/sandbox.proto:70-101,186-196`.

Operator services implement `EvaluateHttpRequest`. They receive request
context, destination, safe headers, and buffered body before credential
injection. Context includes `request_id` and `sandbox_id`; the target
includes scheme, host, port, method, path, and query:
`third_party/openshell/proto/supervisor_middleware.proto:11-23,92-114,275-307`.
They may return ordered header writes. Writes must use the
`x-openshell-middleware-` namespace; `overwrite` removes all old values:
`third_party/openshell/proto/supervisor_middleware.proto:346-397`.
The implementation enforces that namespace and rebuilds the forwarded
request with the mutations:
`third_party/openshell/crates/openshell-supervisor-middleware/src/headers.rs:104-165`;
`third_party/openshell/crates/openshell-supervisor-network/src/l7/middleware.rs:541-561`.

The documented configuration registers an authenticated operator service
in gateway TOML, then attaches it by policy. Registration requires a
gateway restart and must precede episodes. Supervisor extension credentials
are reused, so their JWT `jti` is not a per-request receipt:
`third_party/openshell/docs/extensibility/supervisor-middleware.mdx:44-55,57-104,112-120,184-194`.
Use authenticated supervisor identity and a receiver-owned request registry;
never treat the extension bearer token itself as occurrence evidence.

### Least-invasive proposed mechanism

Use a B-owned operator service to mint a fresh opaque receipt token for
each admitted synthetic request. Overwrite
`x-openshell-middleware-tcop-receipt`; never append an agent-supplied value.
B's acquisition registry binds the token to the authenticated supervisor,
sandbox ID and generation, subject, session, interaction ID, request
identity/digest, expiry, intended peer, and exact destination. The last
receipt-writing stage must preserve the request body and target and must
not add a harm detector or an extra enforcement policy.
Define digest canonicalization across the later credential substitution;
do not compare a pre-substitution raw request hash with different
post-substitution bytes and claim an exact match.

A obtains the token only in the request that reaches its service. Its
service log binds receipt possession to the actual arrival and request.
A signs the warning with that reference; B checks its own registry, the
warning signer, receipt holder, request/session binding, expiry, and
normal ID/nonce replay state. Minting before forwarding is not proof of
arrival. An unused registry entry for a failed send cannot itself justify
a warning. The receipt proves a bounded interaction, not the truth of a
harm accusation. Do not return receipt material to B's agent.

This is acquisition work, not an adapter write. Preserve existing TCX
fields and carry the receipt reference through existing metadata. Current
receipt verification is insufficient by itself for the B-minted promise:
`verify_interaction_receipt` permits a missing subject acknowledgement,
and current intake accepts receipts through a trusted registration call:
`src/tcop/witness.py:163-186`;
`src/tcop/external_receiver_intake.py:54-60,91-105`.
The future study acquisition path must establish B issuance and A's
holder/destination binding. Do not swap the existing receipt's observer
and subject identities or change generic validator semantics to hide the
direction change. Whether the header carries an opaque registered handle
or a complete existing receipt requires owner approval and a demonstrated
mapping to the unchanged verifier.

### TLS and alternatives

For inspected HTTPS, OpenShell terminates client TLS and establishes TLS
upstream, so the middleware sees the permitted plaintext HTTP fields and
body before managed credential injection. It does not see the raw managed
credentials. `tls: skip` is an opaque tunnel; required fail-closed
middleware cannot cover it:
`third_party/openshell/crates/openshell-supervisor-network/src/proxy.rs:2164-2195,2212-2228`;
`third_party/openshell/docs/extensibility/supervisor-middleware.mdx:10-23,42,230`.
Admit only demonstrably inspected synthetic HTTP(S) paths for the proposed
receipt header. Record middleware overhead in the observed timeline.

A VM forwarding filter sees network tuples and encrypted TLS bytes, not
HTTP requests or per-request headers. It cannot inject this header into
end-to-end TLS. A separate harness egress shim could terminate TLS with an
admitted CA and insert it, but adds another interception boundary and must
preserve exact destination routing and the existing cut's forwarding path.
The native middleware hook avoids that extra boundary and is recommended.
These alternative assessments are architectural inferences, not host tests.

### NemoClaw packaging

NemoClaw registers provider credentials at the gateway and documents L7
placeholder substitution:
`third_party/nemoclaw/docs/security/credential-storage.mdx:12-16`.
Its native provider calls create and attach the provider:
`third_party/nemoclaw/src/lib/inference/native-provider/index.ts:349-358,433-452`.
The managed NVIDIA profile declares an authorization bearer header and
specific inference endpoints, not a receipt service:
`third_party/nemoclaw/managed-inference/provider-profiles/nemoclaw-nvidia-inference-v1.yaml:8-24`.
The installed base policy declares network endpoints, including
`inference.local`:
`third_party/nemoclaw/nemoclaw-blueprint/policies/openclaw-sandbox.yaml:65-97`.
Searches of that policy, managed profile, and native-provider file found no
receipt middleware registration or request-bound receipt injection.
Stock NemoClaw is not evidence that this receipt mechanism is installed.
Future registration and policy attachment must be admitted and hashed,
without adding egress authority or changing E1/E2 baseline equivalence.

NemoClaw does have a source path that renders authenticated middleware
registration into gateway configuration:
`third_party/nemoclaw/src/lib/onboard/external-component/gateway-config.ts:45-81`.
This strengthens the configuration finding but does not establish a
supported end-to-end install. The same tag's docs call version 2
middleware onboarding unqualified against a released OpenShell runtime;
version 1's listed host scope is Linux with the Docker driver:
`third_party/nemoclaw/docs/deployment/register-external-component.mdx:18-42`;
`third_party/nemoclaw/docs/changelog/2026-09-14.mdx:73-75`.
Treat those statements as runtime evidence, not instructions from the
third-party tree. The admitted macOS/VM path must demonstrate persistent
gateway registration, supervisor reachability, authenticated callbacks,
TLS inspection, and effective-policy coverage without lifecycle changes.
The source-level verdict is not a verified NemoClaw host deployment.

## A2. Live profile wiring and expiring restrictions

| Path | v0.3 profile | v0.4 profile | Evidence |
| --- | --- | --- | --- |
| Cross-host study intake and adapter | Available but not wired | Available but not wired | Intake imports and calls the strict v0.1 validator, checks receipts/replay, then issues a fixed-selection ticket: `src/tcop/external_receiver_intake.py:15-20,70-127`. Adapter consumes that ticket, serializes one write, schedules D, and observes effects: `src/tcop/external_tightening_adapter.py:132-180`. Neither calls either profile |
| Older live agent receiver and gateway | Available but not wired | Available but not wired | HTTP endpoint calls the local evaluator: `src/tcop/agent_eval/local_api.py:78,126-135`. Evaluator validates with `WitnessValidator`, immediately creates locally configured capability restrictions, and authorizes from that table: `src/tcop/agent_eval/authorization.py:115-176,192-220`. The gateway calls that evaluator: `src/tcop/agent_eval/gateway.py:112` |

Repository-wide symbol searches locate `ReliabilityLedger`,
`WeightedResolver`, and `ConfirmationResolver` in the profile modules,
their benchmark callers, and federation. Neither `src/tcop/external_*.py`
nor `src/tcop/agent_eval/*.py` imports or calls those classes. Federation
does instantiate and call both profiles for its non-containment-first
strategies, but is not either live receiver path:
`src/tcop/federation.py:434-440,462-477`.

### What expires

v0.3 maintains receiver-local issuer state, weights, scope separation,
freshness, and decay. It resolves operating envelopes. It has no v0.4-style
provisional-response TTL or release controller:
`src/tcop/reliability.py:41-86,254-264,545-556,605-644`.
Evidence expiration can change a future resolution; that is not proof that
an already-written Docker or OpenShell restriction is automatically undone.

v0.4 has explicit provisional restrictions with a confirmation window and
TTL. Defaults are three profile time units, not a measured three-second
runtime timeout. `advance(now)` deescalates only after the deadline or
expiry, returning an envelope and recording the transition:
`src/tcop/confirmation.py:64-85,503-544`.
It does not call Docker or OpenShell. A live clock mapping, periodic
advancement, and a separate release controller are necessary to apply the
expiry physically. The tightening adapter must never reverse its writes.

The older live evaluator also calls its ordinary restrictions
`provisional_restriction`. Imported restrictions last until the earlier
context/receipt expiry; a local monitor restriction lasts 60 seconds, and
authorization ignores them once expired. This is a separate local policy,
not v0.4 staged confirmation:
`src/tcop/agent_eval/authorization.py:148-162,178-206`.
The cross-host adapter's decision deadline closes a decision label; its
later observation method does not release the restriction:
`src/tcop/external_tightening_adapter.py:147-162,180-191`.

### Wiring alone does not establish the new guarantees

v0.3 gives quarantined issuers a zero state factor:
`src/tcop/reliability.py:45-85,569-589`.
But v0.4 explicitly accepts a receipted, fresh tip from a restricted or
quarantined issuer, and a scheduled high-risk tip can create a scoped
provisional gate despite zero corroborative credit:
`src/tcop/confirmation.py:442-460,613-628`.
Directly wiring that path would not satisfy the proposed 006 property that
a quarantined issuer's warnings never cause a restriction. The study needs
an explicit receiver-local eligibility guard, including before delayed
submission, that prevents that tip-to-restriction path. This is additional
study composition, not a claim about existing profile behavior or a change
to the generic profile's rules.

Before the hostile-victim family can run, wire and test both profiles and
their on/off conditions, receipt/session coverage, the own-destination
ceiling, quarantine gating, confirmations from permitted independent/local
evidence, and the separate expiry release controller. Pin profile configs
and their clock units. Profiles off must not turn off signature, receipt,
replay, quarantine, or the zero-trust action ceiling.

A sandbox freeze or provider-wide detach can affect several sessions.
The proposed receipt property must cover the actual effect scope, not just
the warning's triggering session. Admission must establish that coverage;
otherwise the coarse action is blocked pending owner resolution. An
operator grant of wider actions does not itself prove receipt possession.

## Case-mapping constraint

The governing verification in `docs/case-mapping-2026.md:450-473` says
detection was mixed, rejects a general victim-majority claim, identifies
MON as internal deployments rather than evaluation subjects, and confirms
FRONT's allowlisted GitHub path. Package attribution, absent private notice
timestamps, and calendar-day versus elapsed-time distinctions remain
explicit. No new primary-source claims were researched in this job.
