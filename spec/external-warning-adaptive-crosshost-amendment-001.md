# Amendment 001: STIX/TAXII Composition Comparator

## Question protected

Can a competent standard STIX 2.1 and TAXII 2.1 composition, with Domain-B
local OPA policy, reproduce TCOP's receiver-side acceptance semantics? This is
a falsification test. A result that weakens TCOP's protocol-novelty claim is a
complete result.

## Effective conditions

The base E0, E1, E2, E2M, E2E, and E3 conditions remain. The combined plan
adds the following paired conditions using identical corpus case, detector
output, Host-A observation, Host-B action binding, initial local state, retry
ladder, protected tool, gateway adapter, and normalized OPA policy interface.

| Condition | Path | Purpose |
| --- | --- | --- |
| S1 | Schema-valid native STIX 2.1 objects through a pinned real TAXII 2.1 client/server to B-local OPA | Faithful standards-native composition baseline |
| T2 | Direct TCOP/TCX transport to the same receiver and OPA interface | Holds the decision engine constant while testing TCOP acceptance semantics |
| S2 | Declared TCX STIX extension through the same TAXII path, then the T2 acceptance state machine and OPA interface | Transport and serialization equivalence check |

S1 may use any reasonable standard STIX object, relationship, normative field,
and B-local state. It may not include a TCOP extension or opaque receipt/action
binding field, a hidden TCOP side channel, benchmark truth, future actions,
remote policy, or a remote enforcement command. If standard fields plus B-local
state can build a correlation mechanism, it is permitted and must be recorded.

## Build order

| Order | Deliverable | Done gate |
| --- | --- | --- |
| 1 | `stix_native_mapping.py` and `stix-native-mapping.md` | Every TCOP-relevant concept is marked `standard`, `local-composition`, or `absent` with a field/relationship reference. |
| 2 | Pinned STIX schema validator, TAXII 2.1 client/server, OPA adapter, and dependency lock | Exact revisions or image digests, schema-validation proof, and OPA policy digest are captured before held-out execution. |
| 3 | Shared gateway action-binding adapter and normalized OPA input | The same local action input reaches S1, T2, and S2 in each paired fixture; field-use traces exclude truth, remote action, and hidden branches. |
| 4 | S1 native-object fixtures and custom-property audit | Every S1 object is schema-valid and contains no custom extension/property. |
| 5 | S2 STIX extension and T2/S2 fixtures | Semantic-equivalence tests pass except for declared, measured transport behavior. |
| 6 | Two-host external preflight and combined-plan seal | Existing roots are unchanged; external source/license/revision/topology gates and A1-A8 pass. |
| 7 | Held-out execution and replayable report | Full cohort, strata, single-attempt, adaptive, timing, mapping, and paired comparison outputs are complete. |

## Policy and audit contract

The versioned OPA adapter accepts only receiver-local action facts, receiver
local state, permitted message state, and receiver-local time. It receives no
remote enforcement field, benchmark label, detector ground truth, future
action, or hidden policy branch. S1 exposes standard STIX fields only; T2 and
S2 expose the receiver's TCOP acceptance result plus allowed local binding
facts. A field-use trace is required for every decision.

The future artifact must write `semantic-capability-matrix.csv` with these
rows: authenticated provenance, receiver-issued correlation, exact local
subject and resource binding, capability/scope binding, freshness/expiry,
replay, receiver-local action-time decision, prevention of remote enforcement,
and end-to-end transport. Each cell must be `standard`, `local-composition`,
`TCOP-profile`, `absent`, or `not-applicable`, with a source or trace reference.

## Integrity and interpretation gates

A1 through A8 require schema-valid native objects, real TAXII traversal, a
shared adapter and OPA interface, passing custom-property and side-channel
audits, complete trace-backed matrix and cohort rows, T2/S2 equivalence, and
unchanged existing artifact digests plus verified amendment/effective-plan
hashes. No outcome direction is a gate.

If S1 reproduces T2 with standards plus B-local composition, TCOP is an
architecture/profile and evaluation methodology rather than a distinct
protocol semantic. If S1 requires a local receipt/action-binding contract
absent from exchanged standard fields, TCOP's contribution is that explicit
receiver-side contract. If S2 equals T2 apart from measured transport behavior,
transport encoding is not the novelty claim. A broader S1 block rate with worse
availability is reported as a frontier, not as universal superiority.

## Sealing rule

The base plan has no external timestamp proof. Amendment 001 is therefore
incorporated into the source plan before a future combined-plan canonical hash
is made. The already-created `BLOCKED` preflight artifact remains untouched as
evidence of the earlier missing external inputs and topology. A later admitted
execution must create a distinct successor artifact or combined execution
manifest that references both the unchanged blocked predecessor and this
effective plan.
