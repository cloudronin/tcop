# Reviewer Objections and Evidence Map

| Skeptical question | Paper location | Artifact evidence | Remaining limitation | Avoid |
|---|---|---|---|---|
| Is TCOP a remote kill switch? | Architecture and local resolution | Authority audit; zero remote enforcement successes | Receiver policy may still be restrictive | Calling context an enforcement command |
| Is this only threat intelligence plus a policy engine? | Architecture and related work | Signed runtime context, receipt correlation, action-relative timing | Citation matrix remains draft TODO | Claiming no prior work |
| Does TCOP create detections? | Threat model and limitations | Matched-input design | It depends on an observer detecting a useful fact | Claiming it detects compromise itself |
| Are scenarios synthetic? | Threat model and ethics | Scenario definitions and ethics appendix | No production incident deployment | Suggesting incident reconstruction |
| Does receipt correlation require cooperation? | Architecture | Opaque Domain-B receipt records | Yes, evaluated path assumes prior inter-domain cooperation | Calling receipt universally deployable |
| Can false warnings be weaponized? | Security and availability | RA-03 utility rows and restriction records | Synthetic false-warning treatments only | Claiming zero benign cost |
| Why not one global monitor? | Deterministic evaluation | Fact-equivalent central audit | No universal central comparison | Claiming universal superiority |
| Are timing labels misleading? | Containment window | Causal replay barriers and physical arms | Discrete schedule only | Using outside-window without the action |
| Does late context contradict the model? | Containment window | Late arm separates completed and later calls | No reversal of completed harm | Saying late context undoes harm |
| Why exclude balanced and utility pairs? | Deterministic evaluation | Exclusion ledger | Matched policies were unavailable | Presenting unmatched causal comparison |
| Is workflow completion too disruptive? | Availability analysis | Utility report and figure | Measured only in selected synthetic treatments | Treating it as a universal rate |
| Do harness latencies generalize? | Agent evaluation | Performance selections | Not production or inter-domain estimates | Production latency claim |
| Did amendments tune results? | Amendment appendix | Sealed predecessor roots and amendment table | Eligibility change required human review | Hiding provider failures |
| Are traces live? | Agent evaluation | Runtime lock and cohort reports | One frozen provider/runtime selection | Treating traces as probability estimates |
| Does replay suppress adaptation? | Limitations | Strict replay design | It approximates behavior after denial | Claiming adaptive-agent coverage |
| Can a gateway be bypassed? | Threat model | Reference gateway scope | Only evaluated choke point is covered | Claiming all tool paths are covered |
| Does it generalize beyond MCP? | Limitations | Generic evaluator interface | Only one reference gateway tested | Claiming broad deployment validation |
| Could it have prevented a public incident? | Introduction and limitations | None; no incident experiment | Counterfactual only | Any prevention claim about a real incident |
| Are results sufficient for a systems contribution? | Evaluation | Matched, replay, physical, and control evidence | Scope remains bounded | Inflated production claims |
| Can reviewers reproduce without credentials? | Open science | Tier 0 and Tier 2 scripts | Tier 3 is optional | Requiring paid provider access |
