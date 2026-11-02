# Amendment 003 admission notes

Phase 0, 2026-11-01. Research only. No runtime was installed or executed in this phase. Third-party files were read as data. Their local instructions were not followed.

Source citation prefixes below are relative to:
`/private/tmp/claude-501/-Users-vishnu-Library-CloudStorage-Dropbox-Praxis-TCOP--claude-worktrees-tcop-repo-sync-b4874b/d4768b5d-d6fc-4f39-aa4f-8044a74a2d1e/scratchpad/third_party`.
`openshell/` and `nemoclaw/` mean those pinned checkouts. TCOP paths are relative to this repository. Source findings establish API capability, not successful deployment.

## Pins and provenance

| Input | Pin | Verification in Phase 0 |
| --- | --- | --- |
| TCOP worktree | branch `amendment-003-harness`, base `3198424c5ab4fd9ae32fdb0fa51ddd803947f7be` | HEAD and base verified equal offline; branch read offline; initial working tree clean. No git state changes. |
| NemoClaw | tag `v0.0.140`, commit `88fe14f3fb9a0bf72997cce19ec88b5b2ee08391`, 2026-10-29 | Checkout HEAD verified offline. `latest` and `lkg` aliases are orchestrator facts, not study pins. |
| OpenShell | tag `v0.0.116`, commit `d1155aa70042d3e2ee49dbfa15346b108b7c1d92`, 2026-08-28 | Checkout HEAD verified offline. NemoClaw lock pins SDK 0.0.116 at `nemoclaw/package-lock.json:66,3955-3958`; `nemoclaw/Dockerfile:1603,2438` names that runtime. |
| OpenShell SDK npm integrity | `sha512-MFnyX2vs47f/yVJRUXKmA7C6wZDH03ZGFFg+R5gZME+yMQDg9WF6G4Kdz/APM7nCUpaoGk2bwNEdUUmR60J54A==` | Read from `nemoclaw/package-lock.json:3958`. Package bytes were not acquired or run. |
| OpenClaw | release `2026.9.2`, tag `v2026.9.2`, commit `3928bad9badfcb6c7d140530435e806fb8092190`, tag object `87d32a44ab9744903d36a33b399c26cfc2b078d6` | Commit and tag object are orchestrator-established facts. No OpenClaw checkout was supplied. Release choice verified at `nemoclaw/Dockerfile.base:396`. |
| OpenClaw npm integrity | `sha512-M6C7UsnX815nv26qBJFYGe6aGzv+ftZLRzV6S9oRXUtXg2Yn67eVntpssT94kgkquKVSeUxerUg0j1ONp4WYQg==` | Verified as committed value at `nemoclaw/Dockerfile.base:397`. Tarball bytes were not acquired. |
| Install-test image | `node:22-bookworm`, `sha256:18a6d90fd60542269850c80ca03b29b1d9b14d6b221ac7ee8e35b0d33ef904bd` | Existing install log records digest. No image operation in Phase 0. |

### b. OpenClaw publisher and release

The orchestrator established the publisher as the `openclaw` GitHub organization, repository `https://github.com/openclaw/openclaw`, run by the OpenClaw Foundation. It established that openclaw.ai links only to that organization, and that npm package `openclaw` declares repository `git+https://github.com/openclaw/openclaw.git` and maintainers `steipete` and `vincentkoc`. These registry, website, and foundation facts were not re-fetched offline.

Use 2026.9.2 for E0 and E1/E2. This is the release in NemoClaw's image, not the orchestrator-observed npm latest 2026.10.9. The blueprint minimum 2026.3.11 (`nemoclaw/nemoclaw-blueprint/blueprint.yaml:8`) is not the installed release. The image validates the minimum and the installed target (`nemoclaw/Dockerfile.base:487-491,563-564`). Admission must verify actual agent bytes/version in both deployments, not only the build ARG.

## a. OpenShell policy-change API

### Submission and revision outcomes

`UpdateConfig` is the policy RPC (`openshell/proto/openshell.proto:384-386`). A sandbox-scoped request names the sandbox and workspace. Only network policies and inference can change; static fields must match creation policy. It accepts full policy replacement or incremental merge operations, and has an optimistic resource-version guard and immutable annotations (`openshell/proto/openshell.proto:1957-1995`). Keep `global=false`. Bind the client to one verified sandbox ID, name, workspace, and gateway. Never expose a global-write route.

`RemoveNetworkEndpoint` names rule, host, port. `RemoveNetworkRule` names the rule (`openshell/proto/openshell.proto:1998-2028`). The response returns policy version, policy hash, settings revision, deletion flag, and annotations (`openshell/proto/openshell.proto:2040-2053`). A successful RPC means submitted, not loaded.

A changed policy/provenance receives a monotonically increasing sandbox revision. Identical policy hash plus identical provenance returns the existing revision, not a new one (`openshell/crates/openshell-server/src/grpc/policy.rs:3720-3770`). Rejected submissions need not have a revision. Thus not every invocation creates its own revision. Record request ID, exact candidate hash, base revision, returned revision, and timestamps. Use unique non-secret request annotations if distinct submission provenance is required. Do not label a no-op as a fresh effective change. Serialize adapter writes and guard against stale policy replacement.

Read the exact returned version with `GetSandboxPolicyStatus(name, version, workspace)`. Version 0 means latest and must not be used to attribute a particular request. It returns the revision and active version. `ListSandboxPolicies` returns revision history. `ReportPolicyStatus` is the runtime-to-gateway load report, not a report the adapter should fabricate (`openshell/proto/openshell.proto:2056-2139`). Each persisted revision has its own hash, status, error, created time, loaded time, and provenance. CLI `policy set --policy FILE --wait SANDBOX` polls the submitted version; timeout exits 124, failed and superseded exit nonzero (`openshell/crates/openshell-cli/src/run.rs:6190-6256`). Its one-second polling is unsuitable as the measurement clock for the 25 ms cells. Use runtime events/timestamps and revision reads, not CLI return time, for timing attribution.

### Proposed study mapping

| Runtime evidence by fixed deadline | Study decision | Retained detail |
| --- | --- | --- |
| Exact revision LOADED with matching candidate hash and target | `accepted` | created/loaded/observed timestamps, active version, policy hash; distinguish later replacement |
| Explicit RPC validation/authorization/concurrency rejection | `rejected` | sanitized error and request identity; revision may be absent |
| Exact revision FAILED | `rejected` | load_error; last known good policy remains active |
| Exact revision SUPERSEDED before load | `rejected` | `superseded_before_load`; a newer revision is not acceptance of this request |
| PENDING past deadline, approval pending, or no conclusive response | `timed_out` | last raw status and deadline; no claim of non-application |

Unspecified/malformed status is never accepted. Preserve it as environment failure, with `timed_out` if no conclusive response arrives by deadline. A late load remains a late event; it does not rewrite the deadline decision. Separate runtime acceptance, approval, and actual denial. An accepted change does not prove it caused a block. Preserve rejected/timed_out plus harm as distinct rows as required by amendment 003:102-107.

### Approval paths and E2a/E2b

`GetDraftPolicy` returns chunks, draft version, and analysis time. `ApproveDraftChunk` takes a reviewed chunk ID and review token and returns policy version/hash. `ApproveAllDraftChunks` validates exact reviewed tokens, stages compatible operations, and writes once; multiple approved chunks share that revision (`openshell/proto/openshell.proto:2500-2582`). Rejection is explicit through `RejectDraftChunk`.

`proposal_approval_mode=auto` enables automatic draft approval only when the current prover delta has no new findings and no security notes. Gateway scope overrides sandbox scope. Unset mode is manual (`openshell/crates/openshell-server/src/grpc/policy.rs:1209-1240,1433-1499,4536-4563`). Auto is not a guarantee to accept every tightening.

Crucially, draft approval merges `PolicyMergeOp::AddRule`, not `RemoveEndpoint` (`openshell/crates/openshell-server/src/grpc/policy.rs:6547-6575`; batch path at 5084). This is not an operator gate around arbitrary `UpdateConfig` removals. Direct operator policy updates do not acquire that draft gate merely by setting approval mode.

Proposed E2a: validated endpoint-removal submission through sandbox `UpdateConfig`, with no human wait. Record it as direct operator submission, with actual runtime settings. This is not proof of a native auto-accept-tightening mode. Proposed E2b: an explicit receiver-local human review of the exact candidate/base hash before that same native write. That is a harness approval gate, not the runtime's draft-approval setting. Neither mapping fully meets the spec's native operator-setting wording. Native E2a/E2b admission stays blocked until the study owner resolves this gap. A further investigation route exists: OpenShell can intercept UpdateConfig (`openshell/crates/openshell-gateway-interceptors/src/routes.rs:35`) and a validate-phase interceptor can deny before side effects (`openshell/proto/gateway_interceptor.proto:67-90,118-129`). This is an extension hook, not evidence of a packaged human-review queue. Confirm any NemoClaw governance service, configured binding, timeout, and review semantics before recommending it as E2b. Do not conclude that no native extension could gate removals. Do not call a draft AddRule proposal a removal.

### Four permitted actions

| Spec action | Native mechanism at 0.0.116 | Admission implication |
| --- | --- | --- |
| Remove named egress destination(s) | `UpdateConfig.merge_operations.remove_endpoint` or `remove_rule`; native policy path, versioned load status | Supported. Remove all matching authorities for the named host/port, including overlapping rules and binary grants. Verify effective policy has no alternate allow path. |
| Revoke one named credential scope | None with that semantic contract in policy RPC/schema. Network credential bindings identify providers; they are not a named credential-scope revocation API (`openshell/proto/sandbox.proto:96-104,186-196`). Provider detach/credential rotation are separate operations (`openshell/proto/openshell.proto:90-100,319`). | Unsupported as written. Do not relabel destination denial or provider detach as scope revocation. S-C admission blocked pending an exact supported mapping. |
| Freeze sandbox | None through policy change. `StopSandbox` retains persistent state but is a separate lifecycle RPC; not a policy revision or a process-freeze guarantee (`openshell/proto/openshell.proto:110-125`). | Unsupported as written. No stop/delete/sandbox-exec substitute. |
| Request snapshot | None in the gateway RPC service. Status snapshots are status messages, not forensic sandbox snapshots (`openshell/proto/openshell.proto:1343-1384`). | Unsupported as written. No driver-level or in-sandbox substitute. |

Negative findings are bounded to the pinned public gateway schema and policy implementation. These findings do not claim that another OpenShell release has no such feature. The full four-action adapter cannot be admitted at this revision as written.

### NemoClaw's packaged path

NemoClaw pins the SDK but does not use a policy-mutation SDK call on the inspected path. The typed `setSandboxPolicy` writer validates a document, writes a temporary mode-0600 YAML file, invokes the native CLI, classifies the result, then removes the file (`nemoclaw/src/lib/adapters/openshell/sandbox-policy-cli.ts:297-363`). Its shared argument builder emits `policy set [-g GATEWAY] --policy FILE --wait SANDBOX` (`nemoclaw/nemoclaw/src/shared/openshell-policy-boundary.cts:72-84`). The blueprint's `setSandboxPolicy` uses that same builder and classifier (`nemoclaw/nemoclaw/src/blueprint/openshell-policy.ts:82-92`; call at `nemoclaw/nemoclaw/src/blueprint/runner.ts:1041`).

The SDK does supply read calls: `connectManagedOpenShellSdk`, then `client.raw.getSandboxConfig({sandboxId}, {signal})` (`nemoclaw/src/lib/adapters/openshell/sdk-read.ts:21-38`; `sandbox-config.ts:43`). Do not invent a NemoClaw SDK policy-write call from the dependency pin. For the harness, exact-revision RPC status reads can supplement the packaged CLI path. Their deployed behavior remains to be confirmed.

ACCEPT_REJECT_PER_CHANGE: yes
Persisted sandbox policy revisions expose independent LOADED/FAILED/SUPERSEDED/PENDING status and exact-version lookup; duplicate no-ops reuse a revision and rejected submissions may have none (proto:2040-2139; server policy.rs:3720-3770).

## Baseline policy

The shipped OpenClaw base is `nemoclaw/nemoclaw-blueprint/policies/openclaw-sandbox.yaml`. It states deny by default at lines 4-7. It is selected as the default base at `nemoclaw/src/lib/onboard.ts:2359`. This is a source file hash, not a verified installed effective policy hash.

The onboarding tier defaults to **balanced**, including in non-interactive mode (`nemoclaw/src/lib/onboard/policy-selection-prompts.ts:150-163`). `tiers.yaml:23-32` adds npm, pypi, huggingface, brew-balanced, and brave. OpenClaw adds pricing support (`nemoclaw/src/lib/onboard/policy-tier-suppression.ts:38-43`). Restricted removes those agent additions. Therefore base-only must not be silently described as the default installed policy. No policy was installed by the license-gated test.

Hashes below were computed with `shasum -a 256`, on the pinned files. Paths in this table are under `nemoclaw/nemoclaw-blueprint/policies/`.

| File | SHA-256 |
| --- | --- |
| `openclaw-sandbox.yaml` | `fdc7b4fceb0b5b7f32472c581013a7edd25ffecc24f7b7dc1d34dd096d937425` |
| `tiers.yaml` | `0aa72e561b5219c0294eaef6c9d1d477151921f8f886389f0ad2329b4127e1dc` |
| `presets/npm.yaml` | `ae5409475de2b4b718b0aa10a90df41d4932c92c71ca4319048d6437d270ded7` |
| `presets/pypi.yaml` | `be4aa22f8e26c5cffca5da413b60f87af4f6a77a8e31f0419b2207632debfe67` |
| `presets/huggingface.yaml` | `ead1547c54f3a41e6f7d08173ce9bfb12ae3ade090975e1c9bdcac66e22f54b2` |
| `presets/brew-balanced.yaml` | `7f3990a8398765ba19bd56d31960074add985d9d22bfb18eb1869c089a687e74` |
| `presets/brave.yaml` | `69e16f24410460477a92d39618f0116cc8cbfe7ae7d1c248ff3a1a7c997eeef1` |
| `presets/openclaw-pricing.yaml` | `bbf285cd5248e0b03a4d998026e7e3f2ed9de71f2bd634a7fab77d0af7427836` |

All listed base endpoints use port 443, REST enforcement:

| Base rule and source lines | Destination and allowed request |
| --- | --- |
| nvidia, 66-80 | integrate.api.nvidia.com; POST /v1/chat/completions, /v1/completions, /v1/embeddings; GET /v1/models and /v1/models/**; openclaw binary |
| managed_inference, 88-103 | inference.local; GET/POST /**; openclaw, node in /usr/local/bin and /usr/bin, curl, python3 |
| clawhub, 118-135 | clawhub.ai; GET/POST /**, encoded slash opt-in; openclaw and /usr/local/bin/node |
| openclaw_api, 137-156 | openclaw.ai GET/POST /**; catalog.openclaw.ai GET /**; openclaw and /usr/local/bin/node |
| openclaw_docs, 158-168 | docs.openclaw.ai GET /**; openclaw |
| npm_registry, 174-184 | registry.npmjs.org GET /**; openclaw |

Balanced adds the following allowlist entries. Binary restrictions in each source file still apply. Ports are all 443. This tier retains allowlist-based egress, but includes broad transport grants to some named hosts.

| Preset, source lines | Additional access |
| --- | --- |
| npm.yaml:10-30 | registry.npmjs.org, registry.yarnpkg.com; full access for listed npm/npx/node/yarn binaries |
| pypi.yaml:10-37 | pypi.org, files.pythonhosted.org; GET/HEAD /** for listed curl/python/pip/uv binaries |
| huggingface.yaml:10-41 | huggingface.co and cdn-lfs.huggingface.co GET /**; router.huggingface.co GET/POST /**; /usr/local/bin/python3 and node |
| brew-balanced.yaml:14-52 | formulae.brew.sh, github.com, ghcr.io, pkg-containers.githubusercontent.com, objects.githubusercontent.com full access; raw.githubusercontent.com GET/HEAD /**; listed curl and Homebrew binaries; several endpoints skip TLS inspection |
| brave.yaml:10-22 | api.search.brave.com GET/POST /**; listed node/curl binaries |
| openclaw-pricing.yaml:16-39 | raw.githubusercontent.com GET /BerriAI/litellm/main/model_prices_and_context_window.json; openrouter.ai GET /api/v1/models; listed node binaries |

The npm preset also skips TLS inspection on its named hosts (`presets/npm.yaml:16-23`). Provider composition and optional messaging/observability selections can add more rules. The future admission record must capture every selected preset, global/effective policy, provider-derived authority, and hash of the actual baseline bytes. Reject undocumented additions or overrides. Keep E1/E2 baselines identical. Choose synthetic targets without enabling real external targets or credentials.

## c. Install findings

Verdict: **NOT VERIFIED past the Docker prerequisite**. The first Linux arm64 container test exited 1 at the third-party software license gate. The study owner then approved accepting the notice (notice version `2026-04-01b`, `nemoclaw/bin/lib/usage-notice.json`). A second throwaway-container run with `--yes-i-accept-third-party-software` passed that gate and exited 1 at the next step: "Docker is not installed", then `sudo: command not found` while running Docker's convenience installer (installer SHA-256 `7f966774378d94acf1817eb1aba213c21b576d01d1ee2f0656fe36e75ffa1258`). The test was stopped there on purpose: going further would mean giving the container the host's Docker socket. Log: `THIRD_PARTY/../nemoclaw-install-linux-arm64-accepted.log`. No inference credentials were supplied. Each real host must accept the notice itself; the admission record should capture the accepted notice version per host.

The full log is `THIRD_PARTY/../nemoclaw-install-linux-arm64.log`, where THIRD_PARTY is the absolute directory above. Read back offline: image digest at line 39, Linux 6.12.76-linuxkit aarch64 and Node v22.23.4 at lines 41-42, pinned NemoClaw banner at line 51, license error and EXIT=1 at lines 53-54. The log does not prove gateway startup, sandbox creation, inference, policy load, or two-host execution. Host macOS/Apple Silicon and Docker 29.5.2 are orchestrator-established environment facts.

Native Apple Silicon macOS is supported in source with limitations. `nemoclaw/install.sh:326-332` says the gateway build is aarch64 and rejects Intel macOS. The installer delegates platform work; `nemoclaw/scripts/install-openshell.sh:640-714,1032,1055` handles the macOS VM driver's hypervisor entitlement/signing. These helper paths do not make the VM driver the standard onboarding backend. The documentation explicitly selects the Docker-driver gateway and says no separately signed VM helper is needed for standard macOS onboarding (`nemoclaw/docs/get-started/prerequisites.mdx:73-74`). This is support evidence, not a successful native install. The documented path needs a running container runtime such as Docker Desktop or Colima (`nemoclaw/docs/get-started/prerequisites.mdx:73-80,111`). A VM on this Mac does not supply two separately administered study hosts.

For the tested Linux container route, Node >=22.19.0, reachable Docker, an OpenShell gateway, and an inference provider are required (`nemoclaw/docs/get-started/prerequisites.mdx:35-46`). Qualified rootless Podman routes also exist at lines 48-52; Docker is the default, not the only Linux runtime. Docker is checked before onboarding (`nemoclaw/src/lib/advisories/checks/host/docker.ts:81`). The container test had neither gateway Docker access nor a provider key. An install inside a container does not establish those prerequisites. No installation, third-party script, gateway mutation, or paid inference was performed in Phase 0.

## Open risks and stop conditions

Full runtime admission is blocked by missing native scope revocation, freeze/snapshot policy paths, and the E2b native-approval mismatch. The install is unverified beyond the notice gate. The actual installed effective baseline hash and two-host attestations do not exist in this phase. Role scripts remain drafts until public-source mapping exists. The existing preflight does not prove pins or topology from names alone. These are admission blockers, not permission to fabricate successful runtime responses. Offline harness construction can proceed with explicit unsupported-capability blockers, but cannot deliver the complete admitted study until the runtime/spec conflicts are resolved.
