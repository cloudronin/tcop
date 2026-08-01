"""Shared command-line presentation, errors, and declarative configuration."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping


EXIT_SUCCESS = 0
EXIT_CLI = 2
EXIT_FROZEN_INPUT = 3
EXIT_STRATEGY = 4
EXIT_PROTOCOL = 5
EXIT_INVARIANT = 6
EXIT_REPLAY = 7
EXIT_ARTIFACT = 8
EXIT_SERVICE = 9


class TCOPCommandError(RuntimeError):
    """Expected CLI failure with a documented machine-stable exit status."""

    def __init__(self, message: str, code: int = EXIT_CLI) -> None:
        super().__init__(message)
        self.code = code


def jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [jsonable(item) for item in value]
    return value


def emit(value: Any, output: str = "json") -> None:
    """Write structured command data to stdout and keep diagnostics separate."""

    payload = jsonable(value)
    if output == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif output == "jsonl":
        records = payload if isinstance(payload, list) else [payload]
        for record in records:
            print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    elif output == "text":
        if isinstance(payload, Mapping):
            for key, item in payload.items():
                if isinstance(item, (dict, list)):
                    print(f"{key}: {json.dumps(item, sort_keys=True)}")
                else:
                    print(f"{key}: {item}")
        else:
            print(str(payload))
    else:
        raise TCOPCommandError(f"unsupported output format: {output}")


def diagnostic(message: str) -> None:
    print(f"tcop: {message}", file=sys.stderr)


def load_config(path: Path) -> dict[str, Any]:
    """Load JSON or YAML configuration, rejecting non-object documents."""

    if not path.is_file():
        raise TCOPCommandError(f"configuration not found: {path}")
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(path.read_text(encoding="utf-8"))
        else:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - package dependency supplies it
                raise TCOPCommandError("YAML configuration requires PyYAML", EXIT_CLI) from exc
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TCOPCommandError(f"invalid configuration: {exc}") from exc
    if not isinstance(value, dict):
        raise TCOPCommandError("configuration root must be an object")
    return value


def require_domain_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Check the shared v0.6 Domain configuration boundary.

    Services only use this model for identity, peers, state, and local policy;
    forbidden remote-enforcement keys are rejected before a listener starts.
    """

    if config.get("apiVersion") != "tcop.io/v0.6" or config.get("kind") not in {"Domain", "Gateway", "Resolver", "Observer", "Enforcement"}:
        raise TCOPCommandError("configuration requires apiVersion tcop.io/v0.6 and a supported kind")
    metadata, spec = config.get("metadata"), config.get("spec")
    if not isinstance(metadata, Mapping) or not str(metadata.get("domainId", "")):
        raise TCOPCommandError("configuration metadata.domainId is required")
    if not isinstance(spec, Mapping):
        raise TCOPCommandError("configuration spec is required")
    forbidden = {"quarantineRemoteAgent", "disableRemoteCapability", "terminateRemoteWorkflow", "remoteEnforcement"}
    found = sorted(forbidden & set(spec))
    if found:
        raise TCOPCommandError(f"remote enforcement is not a TCOP service operation: {', '.join(found)}", EXIT_SERVICE)
    return {"domain_id": str(metadata["domainId"]), "kind": str(config["kind"]), "spec": dict(spec)}
