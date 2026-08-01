# TC-RFC-0021: Accusation graphs and circular reliability dependencies (Draft)

Accusations about observers SHALL be retained as immutable directed edges. The
resolver SHALL identify unresolved cycles and SHALL NOT propagate a reliability
decision transitively through control groups or force certainty from a cycle.
Only independently validated local input can change a record.

The required artifact is `observer-accusation-graph.json`. CT-058 and B-039
cover cycle detection and non-propagation.
