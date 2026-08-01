# TC-RFC-0025: Deterministic evidence-campaign grouping (Draft)

Each receiver SHALL group evidence locally by subject, normalized scope, claim
family, and declared virtual-time window. When more than one compatible
campaign matches, the lexicographically smallest campaign identifier SHALL be
the merge target and each absorbed campaign SHALL retain a `merged_into`
reference. Incompatible scope, claim family, or window membership SHALL create
a deterministic split linked to its predecessor. A compatible append SHALL
create an append-only revision.

All campaign decisions retain the original observation IDs, control groups,
interaction IDs, relay provenance, and revision history. CT-076, CT-082, and
CT-083 cover relay equivalence, merge/split, and timing behavior.
