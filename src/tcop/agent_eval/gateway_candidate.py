"""Pinned-reference-gateway verification and explicit local image build."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..cli_support import EXIT_INVARIANT, TCOPCommandError


INTEGRATION_ROOT = Path("integrations/mcp-gateway")
MANIFEST_PATH = INTEGRATION_ROOT / "gateway-selection-manifest.json"


def _manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TCOPCommandError(f"reference gateway selection manifest is unreadable: {exc}", EXIT_INVARIANT) from exc
    if not isinstance(value, dict) or not isinstance(value.get("selected"), dict):
        raise TCOPCommandError("reference gateway selection manifest is malformed", EXIT_INVARIANT)
    return value


def _run(command: list[str], *, cwd: Path) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)  # noqa: S603 - fixed executable/arguments
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise TCOPCommandError(f"reference gateway command failed: {' '.join(command)}: {detail.strip()}", EXIT_INVARIANT) from exc
    return result.stdout.strip()


def verify_gateway_source(source: Path) -> dict[str, Any]:
    """Verify the exact candidate and test patch applicability without editing it."""

    document, selected = _manifest(), _manifest()["selected"]
    patch = INTEGRATION_ROOT / str(selected["patch"])
    if not source.is_dir() or not (source / ".git").is_dir():
        raise TCOPCommandError("reference gateway source must be a Git checkout", EXIT_INVARIANT)
    revision = _run(["git", "rev-parse", "HEAD"], cwd=source)
    if revision != selected["revision"]:
        raise TCOPCommandError(f"reference gateway revision mismatch: expected {selected['revision']}, got {revision}", EXIT_INVARIANT)
    if sha256(patch.read_bytes()).hexdigest() != selected["patch_sha256"]:
        raise TCOPCommandError("reference gateway patch digest mismatch", EXIT_INVARIANT)
    license_text = (source / "LICENSE").read_text(encoding="utf-8", errors="replace")
    if "MIT" not in license_text.upper():
        raise TCOPCommandError("reference gateway license did not verify as MIT", EXIT_INVARIANT)
    _run(["git", "apply", "--check", str(patch.resolve())], cwd=source)
    return {
        "repository": selected["repository"],
        "revision": revision,
        "license": selected["license"],
        "patch": str(patch),
        "patch_sha256": selected["patch_sha256"],
        "patch_applies_cleanly": True,
        "gateway_contains_tcop_logic": selected["gateway_contains_tcop_logic"],
        "authorization_cache": selected["authorization_cache"],
        "selection_scope": document["scope"],
    }


def build_gateway_image(source: Path, *, tag: str) -> dict[str, Any]:
    """Build a tagged patched image only when the user explicitly invokes it."""

    verified = verify_gateway_source(source)
    patch = INTEGRATION_ROOT / str(_manifest()["selected"]["patch"])
    with tempfile.TemporaryDirectory(prefix="tcop-reference-gateway-") as temporary:
        worktree = Path(temporary) / "source"
        shutil.copytree(source, worktree, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        _run(["git", "init"], cwd=worktree)
        _run(["git", "apply", str(patch.resolve())], cwd=worktree)
        _run(["docker", "build", "--target", "mcp-gateway", "--tag", tag, "."], cwd=worktree)
    return {**verified, "image": tag, "built": True}
