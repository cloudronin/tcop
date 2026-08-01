# MCP gateway selection record

## Rejected candidate: Microsoft MCP Gateway

- Repository: `https://github.com/microsoft/mcp-gateway`
- Inspected revision: `1a66c421fb9df7c81649b3f7da264d089e1c8423`
- License: MIT
- Build instructions inspected: repository README, Docker Desktop Kubernetes and `kubectl` workflow.

The candidate is not selected for this study. Its Foundry tool path builds a
cluster-DNS address of the form
`http://{tool}-service.adapter.svc.cluster.local/...` in
`dotnet/Microsoft.McpGateway.Management/src/Foundry/AgentToolRegistry.cs`.
That deployment assumption and its Kubernetes build instructions violate the
study's bounded Docker-Compose topology. No custom replacement of its tool
path is permitted: that would cease to be a clean reference-gateway
integration.

## Selected candidate: Docker MCP Gateway

- Repository: `https://github.com/docker/mcp-gateway`
- Pinned revision: `2bd20fe83dd04870e8d87dc1ed059d4d19fc7c68`
- License: MIT (repository `LICENSE`)
- Build baseline: `go build ./cmd/docker-mcp`; run the resulting
  `docker-mcp gateway run` command with the study's local configuration.
- Hook point: `pkg/gateway/handlers.go`, immediately before the delegated MCP
  server `CallTool` invocation.
- Local patch: `tcop-authorization-adapter/patches/0001-local-authorization-evaluator.patch`

The selected gateway is a reference enforcement point only. It is not a
literal reproduction of the OpenAI--Hugging Face defensive architecture, and
the study makes no such claim. Its only study-specific modification is an
otherwise generic local authorization-evaluator interface. The gateway passes
the local session, client identity, server, and tool to the receiver-local
evaluator. It neither parses TCX nor knows any TCOP strategy, receipt,
resolver, evidence, or enforcement vocabulary.

## Patch acceptance conditions

Before a live run, `tcop study agent run-live` must record this selection
record, the exact source revision, the patch SHA-256, a successful clean patch
application, the unmodified-gateway baseline result, and the patched-gateway
result. The local evaluator endpoint is intentionally cache-free; any cache
experiment is a distinct `gateway-overhead` selection and cannot alter the
correctness or counterfactual runs.
