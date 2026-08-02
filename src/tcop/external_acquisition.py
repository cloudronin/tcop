"""Seal the externally acquired source closure without bypassing gated inputs."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .cli_support import TCOPCommandError, load_config


DEFAULT_BUNDLE = Path("artifacts/external-warning-adaptive-crosshost-v1-inputs")


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _files(root: Path) -> list[dict[str, str]]:
    return [{"path": str(path.relative_to(root)), "sha256": sha256(path.read_bytes()).hexdigest()} for path in sorted(root.rglob("*")) if path.is_file() and ".git" not in path.relative_to(root).parts]


def _git_commit(root: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TCOPCommandError(f"acquired repository is not a readable Git checkout: {root}") from exc


def seal_acquisition_bundle(bundle: Path = DEFAULT_BUNDLE, plan_path: Path = Path("benchmark/studies/external-warning-adaptive-crosshost-v1.yaml")) -> dict[str, Any]:
    """Write file manifests and an input lock for previously acquired inputs."""

    if (bundle / "inputs.lock.json").exists():
        raise TCOPCommandError("acquisition bundle is already sealed; create a successor bundle rather than overwrite it")
    plan = load_config(plan_path)
    vendor = bundle / "vendor"
    expected = {
        "agentdojo": "agentdojo", "stix_schema": "cti-stix2-json-schemas", "taxii_client": "cti-taxii-client",
        "taxii_server": "cti-taxii-server", "opa_source": "opa",
    }
    missing = [name for name, directory in expected.items() if not (vendor / directory).is_dir()]
    if missing:
        raise TCOPCommandError("acquisition bundle is missing public inputs: " + ",".join(missing))
    source_locks = {name: {"directory": directory, "commit": _git_commit(vendor / directory), "files": _files(vendor / directory)} for name, directory in expected.items()}
    corpus_root = vendor / "agentdojo" / "src" / "agentdojo" / "default_suites"
    corpus_manifest = _files(corpus_root)
    opa_binary = vendor / "opa_darwin_arm64_static"
    opa_checksum = vendor / "opa_darwin_arm64_static.sha256"
    opa_lock = {"version": plan["composition_dependencies"]["opa"]["tag"], "source_commit": source_locks["opa_source"]["commit"], "binary": {"path": str(opa_binary.relative_to(bundle)), "sha256": sha256(opa_binary.read_bytes()).hexdigest()} if opa_binary.is_file() else None, "published_checksum": opa_checksum.read_text(encoding="utf-8").strip() if opa_checksum.is_file() else None}
    model = plan["external_sources"]["llama_prompt_guard_2"]
    model_root = vendor / "prompt_guard_2_86m"
    required_model_files = {"config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "LICENSE", "USE_POLICY.md"}
    present_model_files = {path.name for path in model_root.rglob("*") if path.is_file()} if model_root.is_dir() else set()
    snapshot_complete = required_model_files.issubset(present_model_files)
    model_lock = {"repo": model["url"], "variant": model["variant"], "revision": "a8ded8e697ce7c355e395a0df51f94adb4a2fd27", "access": "available" if snapshot_complete else "awaiting_author_review", "license_terms_acknowledgement": "user_accepted_pending_provider_authorization" if model_root.exists() else "not_recorded", "snapshot": "acquired" if snapshot_complete else "not_acquired", "present_files": sorted(present_model_files), "missing_required_files": sorted(required_model_files - present_model_files)}
    lock = {
        "schema": "tcop.external-inputs-lock/1.0", "acquired_at": datetime.now(timezone.utc).isoformat(), "plan_revision": plan["effective_plan_revision"],
        "agentdojo": {"url": plan["external_sources"]["agentdojo"]["url"], "release_tag": plan["external_sources"]["agentdojo"]["release_tag"], "commit": source_locks["agentdojo"]["commit"], "selected_suites": plan["external_sources"]["agentdojo"]["selected_suites"], "selected_tasks": plan["external_sources"]["agentdojo"]["selected_tasks"], "corpus_file_count": len(corpus_manifest)},
        "prompt_guard_2": model_lock, "sources": source_locks, "opa": opa_lock,
        "inference_library": {"transformers": "4.44.0", "torch": "2.2.2"},
        "two_host_topology": {"status": "not_provisioned", "host_attestations": []},
        "complete": False, "blockers": (["Prompt Guard 2 authorization is awaiting review by the model publisher"] if not snapshot_complete else []) + ["two separate cloud VM attestations have not been supplied"],
    }
    _write(bundle / "agentdojo-corpus-file-manifest.json", corpus_manifest)
    _write(bundle / "inputs.lock.json", lock)
    _write(bundle / "inputs.lock.sha256.json", {"sha256": sha256(canonical_bytes(lock)).hexdigest()})
    return {"bundle": str(bundle), "complete": False, "public_source_count": len(source_locks), "agentdojo_corpus_file_count": len(corpus_manifest), "model_status": model_lock["snapshot"], "blockers": lock["blockers"], "lock_digest": sha256(canonical_bytes(lock)).hexdigest()}
