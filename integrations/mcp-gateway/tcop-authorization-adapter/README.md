# Generic local authorization adapter

This directory contains the source patch used to give the selected reference
MCP gateway one deliberately narrow hook:

```text
MCP tool call -> local authorization evaluator -> local decision -> forward or block
```

The patch is generic. It has no TCOP imports or branching, does not inspect a
remote context, and does not infer a policy from tool arguments. The receiver
owns all policy. The gateway sends only its locally available session/client
information and the server/tool being invoked. It performs one evaluation per
call and has no authorization cache.

`POST /v1/authorize` contract:

```json
{
  "session_id": "gateway-local-session",
  "client_name": "gateway-local-client",
  "server": "configured-server",
  "tool": "configured-tool"
}
```

The response is receiver-local and must contain `allowed`, `decision_id`,
`policy_id`, and `authority_domain`. A denial is returned to MCP as a tool
error that cites that local policy and decision. A network error is fail
closed at the hook. The adapter does not accept a remotely supplied action,
decision, enforcement, block, or deny field.

In the TCOP harness, the Domain-B endpoint binds the gateway session to the
B-private, opaque receipt-reference map during context admission. The public
receipt digest is never used as an enforcement command.
