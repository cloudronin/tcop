# Amendment 004 conformance on admitted hosts

These commands have not run on OpenShell, Docker or a VM in Phase 2b.
Unit tests use fake transports. They do not admit a binding or calibrate the
real study. No real prediction, grid or frozen-input record was sealed.

## Before running

Use OpenClaw 2026.9.2, NemoClaw 88fe14f3fb9a0bf72997cce19ec88b5b2ee08391,
and OpenShell 0.0.116 at d1155aa70042d3e2ee49dbfa15346b108b7c1d92.
Use the admitted Docker daemon/context. The snapshot driver calls Docker
29.5.2's `docker commit --no-pause FULL_ID`. It never pauses first.

Have the verified three-machine base admission seal. Prepare a disposable
synthetic conformance fixture, a control destination and a second sandbox.
Start progress counters and stage the credential connection/in-flight request
before the applicable check. The fixture controller is a trusted test
controller, separate from the tightening adapter. Its interface is below.
It must drive the workload through B's actual enforcement boundary. A bare
`docker exec` in the outer supervisor namespace is not a substitute.

Each check starts from the admitted effective baseline. Reset or reprovision
fixtures only through the separate study controller between checks. The
adapter cannot reset them. Record the resulting sandbox/container generation.
Use separate host configurations for the 10 s and 1 s supervisors. Do not
change a running supervisor's poll setting through the adapter.

The instant-cut service must already be installed in the Docker Linux VM's
initial network namespace. It owns an empty deny-only forwarding set. Its
write API adds exactly the admitted bridge/source-IP/destination-IP/TCP-port
tuple atomically. Its read API reads that tuple. It exposes no deletion,
accept, route or execution method. Provisioning that VM service is an
admission prerequisite; the client does not install or launch it. Colima
needs VM root access. Docker Desktop needs VM root access and ECI disabled.
If those conditions cannot be established, record this binding unavailable.
The target is a dedicated routed synthetic address off B's bridge. The
controller verifies the bridge hook and container continuity across polls
and reconciliation. Never use a production endpoint or real credential.

Prepare an authenticated local gateway connection for `grpcurl`. This code
puts no bearer token in arguments, files or logs. It does not obtain
credentials. A missing local connection fails the check.

## Host configuration

Copy the synthetic shape and fill it with measured admission values:

```sh
mkdir -p /private/tmp/tcop-on-hosts
cp tests/fixtures/amendment-005-host-config.json /private/tmp/tcop-on-hosts/host-10.json
```

Set `synthetic_fixture` to false only after replacing every synthetic identity,
address, baseline authority entry and resource version. Set the admission
seal path, pinned proto directory, local gateway endpoint and common-clock
origin. Set the staged fixture controller command, capture journal and VM
worker socket. Create `host-1.json` for the separately admitted 1 s fixture.
The example contains no real host attestation or credential.

`family_targets` fixes S-A's absent relay, S-B's allowed target and S-C's
leaked credential before any TCX arrives. A destination's `initially_allowed`
must agree with the admitted baseline authority. The provider lists every
credential it holds and has no policy credential binding. No TCX controls
these values.

Read the exact Docker identity without printing its environment:

```sh
docker version --format '{{.Client.Version}}'
PYTHONPATH=src python3.11 -m tcop.external_conformance identity --config /private/tmp/tcop-on-hosts/host-10.json
PYTHONPATH=src python3.11 -m tcop.external_conformance identity --config /private/tmp/tcop-on-hosts/host-1.json
```

The identity reader checks the full container ID, managed-by, sandbox ID,
name and workspace labels and the admitted IP. Generation is the canonical
hash of container ID, creation time, start time and restart count. Copy that
measured generation into the matching configuration. Never use a short ID
or select the first of multiple containers. Preserve the Docker context and
exclusive lifecycle control during a check.

## C1-C4 commands

Run from the repository root on the admitted host. Each output is new and
unsealed. Existing outputs are refused. Restore the baseline through the
separate controller before each command, then update its measured identity.
The commands deliberately do not install software or reset fixtures.

```sh
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-10.json --check C1 --binding native-egress-10 --output /private/tmp/tcop-on-hosts/C1-native-10.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-1.json --check C1 --binding native-egress-1 --output /private/tmp/tcop-on-hosts/C1-native-1.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-10.json --check C1 --binding instant-egress --output /private/tmp/tcop-on-hosts/C1-instant.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-10.json --check C2 --binding provider-detach-10 --output /private/tmp/tcop-on-hosts/C2-native-10.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-1.json --check C2 --binding provider-detach-1 --output /private/tmp/tcop-on-hosts/C2-native-1.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-10.json --check C3 --binding freeze --output /private/tmp/tcop-on-hosts/C3-freeze.json
PYTHONPATH=src python3.11 -m tcop.external_conformance run --config /private/tmp/tcop-on-hosts/host-10.json --check C4 --binding snapshot --output /private/tmp/tcop-on-hosts/C4-snapshot.json
```

The default observation window is 20000 ms. Fix any different conformance
window before running; it never changes an efficacy decision deadline.
C3 calls the separate fixture controller's release operation after this
window. No adapter or binding transport has an unpause operation.

## Controller and worker interfaces

The executable in `fixture_controller_command` receives `--stage STAGE
--binding BINDING --config CONFIG`. It writes one JSON object to stdout.
The controller must already be staged for the admitted workload. It is an
injected host fixture, not a supplied fake or an inferred pass flag.

| Check/stage | Required measured response |
| --- | --- |
| C1 before/after | Fresh `target`, `control`, `other_sandbox`, `inference`, `supervisor` connection outcomes and `fresh: true`. All succeed before; only target fails after. Use fresh sockets through the workload proxy, never pooled connections. |
| C2 before/after | `target_resolves`, `group_peer_resolves`, `unrelated_resolves`, `new_request_existing_connection_resolves`, `in_flight_staged`, `in_flight_may_finish`. Target and group peer resolve before; new target requests fail after, including on the existing connection. Unrelated keys still resolve. Completion of the already-staged request is allowed. |
| C3 before/after/released | Two integer `counters`, integer `outside_counter`, fixed `window_ms`, `restarted: false`. Both bound counters stop throughout the window; the outside counter advances; both resume only after the separate `release_fixture` stage. |
| C4 before/after | Nonempty stable `markers`; matching `captured_markers`, source container/generation and `artifact_sha256` from the returned image; `coverage: [filesystem]`, omissions including memory and mounted volumes; `paused: false`, continued execution/access and an unaffected other sandbox. Inspect the image outside B. Never restore it through the adapter. |
| provider_fingerprint | A current post-detach config readback with `provider_absent: true`, `ambiguous: false`, and `provider_env_revision`. This is the expected secret-free fingerprint, not a fabricated monotonic revision. |

The receiver-owned journal contains JSON lines of actual readbacks and
failures on the common clock. `at_ms` is receiver observation time after
correlation. Keep source timestamps separately as `effect_at_ms` and
`poll_at_ms`; keep raw acquisition logs. Do not backdate a newly correlated
observation. Old journal entries are excluded when the driver starts.

Native policy readback queries the exact returned policy version. Detach
needs an enforcing-supervisor `Provider environment refreshed` event,
loaded status, exact fingerprint, named provider absence and matching sandbox
identity/generation. A log line alone does not establish acceptance. The
source exposes this fingerprint signal; it does not supply the study's
collector or a monotonic detach-ack revision. The staged controller must
supply the current config readback and the correlated event.

The VM client sends newline-delimited JSON over the admitted local Unix
socket. Writes are `{operation: add_bound_tuple, tuple: ...}`; reads use
`read_bound_tuple`. Readback returns `installed` and the exact tuple. The
transport reconstructs that tuple from admission and rejects altered bytes.
The VM service itself must enforce this bound tuple and deny-only API.

## Calibration and frozen inputs

Record measured detection, signing and validation samples in a separate
`timings.json`: `status: measured`, `samples_ms` with those three nonempty
arrays, and the source `evidence_sha256`. No placeholder value is filled in.
Native captures must also identify persistence, supervisor poll, actual
effect and observation barriers. A local RPC-return time cannot replace
those measurements. Import fails if any barrier or required check is absent.

```sh
PYTHONPATH=src python3.11 -m tcop.external_conformance import-calibration --record /private/tmp/tcop-on-hosts/C1-native-10.json --record /private/tmp/tcop-on-hosts/C1-native-1.json --record /private/tmp/tcop-on-hosts/C1-instant.json --record /private/tmp/tcop-on-hosts/C2-native-10.json --record /private/tmp/tcop-on-hosts/C2-native-1.json --record /private/tmp/tcop-on-hosts/C3-freeze.json --timings /private/tmp/tcop-on-hosts/timings.json --seed 20260801 --output /private/tmp/tcop-on-hosts/calibration.json
```

C4 is capability only and is not a calibration input. The importer recomputes
C1-C3 pass conditions and evidence commitments. It retains native persistence,
processing and observation distributions per binding and poll configuration.
The simulator adds polling separately. No distribution is fitted or tuned
from efficacy outcomes. One record per binding/configuration is accepted by
this importer; repeated measurements must be aggregated before admission.

Run real smoke trace validation first. Resolve every rejected/malformed smoke
trace with the owner. Then, before the first live episode, freeze the model
inputs with the owner's reviewed source tree:

```sh
PYTHONPATH=src python3.11 -m tcop.external_conformance freeze-inputs --output /private/tmp/tcop-on-hosts/frozen-inputs
```

This is a content seal, not an external timestamp. Do not rerun it to revise
inputs after live execution. The writer reads the formal tree and writes
outside it. It hashes all declared modules/configurations, converter, schema
and pinned-tools record. Property and trace result records must reference
that same frozen set. Real trace checking remains the formal converter's
command in `formal/TRACE_SCHEMA.md`; these drivers never run TLC implicitly.

The live runner remains blocked until the other study admissions close.
These host commands are checks, not efficacy episodes.
