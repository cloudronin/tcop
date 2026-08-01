# Quick Start

From the paper workspace:

    ./artifact/reproduce.sh --verify-only
    ./artifact/reproduce.sh --agent-replay
    ./artifact/reproduce.sh --all-no-credentials

The default command performs Tier 0 verification and Tier 2 strict replay. No environment variable for a model provider is read by these commands.

The optional reference-gateway smoke check verifies a separately supplied pinned Git checkout and does not contact a model provider:

    TCOP_GATEWAY_SOURCE=relative/path/to/pinned-gateway ./artifact/reproduce.sh --gateway-smoke
