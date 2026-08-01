# v0.6 agent-validation reference deployment

The Compose definition has five study units: `tcopd-a`, `agent-runner-a`,
`tcopd-b`, `mcp-gateway-b`, and `partner-tool-service-b`. The internal network
is isolated; only the optional live agent receives a separate model-egress
network. All tools and state are synthetic.

The MCP gateway is a reference enforcement point. It is not a literal
reproduction of the OpenAI--Hugging Face defensive architecture.

The gateway enables its documented development-only insecure-remote URL flag
solely because the synthetic MCP service is an HTTP endpoint on the isolated
Compose network. The flag is prohibited outside this test topology.

Before starting the live profile:

1. Run `tcop study agent prepare` to verify the admitted frozen inputs.
2. Verify the selected gateway source and patch with
   `tcop study agent gateway verify --source /path/to/docker-mcp-gateway`.
3. Build and tag the patched source with
   `tcop study agent gateway build --source /path/to/docker-mcp-gateway --tag tcop-reference-mcp-gateway:2bd20fe83dd04870e8d87dc1ed059d4d19fc7c68`.
4. Copy `live-runtime.example.yaml` outside the repository, replace only
   provider/model/endpoint values, and set the named environment variable.
5. Start `docker compose -f deploy/agent-validation/compose.yaml --profile live up`.

For the credential-free gateway wiring check, start just the three
receiver-side services and run the `tcop study agent probe-gateway` command
inside the `tcopd-b` container. The fixed Compose bearer token is a
non-sensitive synthetic test value; do not reuse this pattern for a deployed
gateway.

No study artifact is complete merely because the containers start. Completion
requires the captured trace, signed context/receipt admissions, the strict
A1/A2 replay pairs, negative controls, gateway integration result, and a
successful `tcop artifact verify --require-complete` result.
