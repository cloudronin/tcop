# TC-RFC-0009: Trust-context connectivity postures (Draft)

When a domain cannot obtain fresh remote trust context, it must choose and log
a local operating posture rather than treat the condition as an implicit
protocol success or failure.

- `fail_open` preserves the normal envelope.
- `fail_constrained` removes high-impact capabilities such as external export,
  persistent memory writes, and financial transfer.
- `fail_closed` quarantines the external subject until connectivity is restored.
- `risk_sensitive` keeps low-risk capabilities available while denying the
  profile's high-impact capabilities.

The selected posture is a local policy decision, not a remote verdict. A
profile must state the capability mapping, maximum duration, restoration rule,
and audit event. TC-RFC-0009 does not prescribe which posture a deployment must
choose.
