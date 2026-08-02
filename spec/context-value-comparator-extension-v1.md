# TCOP Context-Value Comparator Extension v1

This sealed extension evaluates C0 local-only, C1 arrival-only blanket, C2
validated context-matched, and C3 always-restrict policies over read-only v0.6
inputs. C1 receives only a validity, arrival, and TTL token. C2 evaluates the
validated issuer, receipt, capability class, receiver-local subject, resource
namespace, scope, and expiry. C3 receives no TCOP message.

The original A1:A2 evidence remains an input dependency and is not modified.
The frozen cohorts contain no episode with both a matching harmful action and a
same-capability nonmatching benign action; the separately reported deterministic
policy-selectivity fixture supplies that controlled comparison. Results are
reported by cohort and are never pooled into a live-agent claim.
