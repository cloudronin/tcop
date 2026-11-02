# Agent-Action Framing Revision

This revision narrows the manuscript's contribution from generic cross-domain context exchange to receiver-bound runtime evidence for authorization of pending agent actions.

## Principal changes

- The abstract and introduction now lead with cross-domain agent tool and capability actions.
- The protocol contract is described as runtime evidence bound to receiver-local session, subject, resource, capability, scope, and expiry before local authorization.
- The introduction distinguishes threat-intelligence exchange, SOAR or response orchestration, and TCOP by decision location.
- Related work treats STIX/TAXII and MISP as possible evidence sources, and CACAO/SOAR as possible response mechanisms. TCOP is not presented as a replacement for either class.
- The agent-protocol comparison now distinguishes MCP tool access, A2A agent collaboration, and ANP networking from TCOP's receiver-local evidence-to-authorization boundary.
- The threat model, architecture, containment-window model, evaluation, availability analysis, and conclusion use agent-action authorization terminology.
- The receiver contract now exposes exact, partial, and invalid binding branches, gives compact receiver pseudocode, and maps its security goals to the evaluated controls and claim boundaries.
- The evaluation is explicitly labeled matched causal and conformance evidence. Two separately sealed follow-up studies now bound adaptive post-denial authorization and independent-warning admission.

## Follow-up evidence

- The adaptive authorization study contains 100 strict policy-conditioned replay episodes and 12 bounded runtime episodes. Exact binding alone permits all 15 eligible harmful post-denial substitutions in the frozen branch set; C2E's receiver-local campaign relation permits none. C1, C2, C2E, and C3 each forward all 5 of 5 exercised in-campaign benign fallbacks. This is evidence about the declared reference model, not deployment prevalence, unrelated same-risk actions, or universal containment.
- The independent-warning normalizer successor preserves v1 unchanged and retains its 30-entry AgentDojo slice, raw Prompt Guard outputs, receipt construction, and policy rows. A separate sealed amendment maps the pinned model configuration's labels before inference: 29 `LABEL_0` outputs map to no warning and one `LABEL_1` output maps to an exact binding. The resulting warning is admitted, and C1 through C3 each block its matched action. The paper presents this as a detector-to-TCX integration case study, separates normalization from authorization, and does not treat it as detector-quality or field-prevalence evidence.
- The C2E Frontier Study v1 adds a deterministic receiver-local strategy comparison. C2E blocks 10 of 10 harmful actions, including 5 campaign-linked non-exact substitutions, while constraining 0 of 20 benign actions. C1 and C3 block the same harmful actions but constrain 10 benign actions each. The manuscript treats this as selectivity evidence for the declared receiver-local campaign strategy, not as a mandatory TCOP policy or deployment-effectiveness claim.
- Both new roots are copied into the paper workspace, verified by their sealed digests, and included in the evidence inventory and claim ledger.

## Preserved boundaries

No sealed data, policy, result, figure, table, source digest, or claim denominator changed. The revision makes no claim from the blocked v1.2 holdout admission run.
