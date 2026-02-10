"""Agent auto-update — check for new versions and self-update.

The update flow:
1. Agent calls GET /api/agents/version on the cloud API
2. If server version > local version, trigger update
3. Run ``git pull && pip install -e .`` in the install directory
4. Restart the daemon process
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from importlib.metadata import version as get_version
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


def get_local_version() -> str:
    """Get the locally installed bigr-discovery version."""
    try:
        return get_version("bigr-discovery")
    except Exception:
        return "0.0.0"


def check_for_update(api_url: str, token: str) -> dict | None:
    """Check the cloud API for a newer agent version.

    Returns dict with ``latest_version`` and ``update_available`` if newer
    version exists, or None if up to date or check fails.
    """
    try:
        resp = httpx.get(
            f"{api_url.rstrip('/')}/api/agents/version",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
        latest = data.get("latest_version", "0.0.0")
        local = get_local_version()

        if _compare_versions(latest, local) > 0:
            return {
                "update_available": True,
                "local_version": local,
                "latest_version": latest,
                "message": data.get("message", ""),
            }
        return None
    except Exception as exc:
        logger.debug("Version check failed: %s", exc)
        return None


def perform_update(install_dir: Path | None = None) -> bool:
    """Pull latest code and reinstall.

    Parameters
    ----------
    install_dir:
        Root of the bigr-discovery repo. Defaults to the package location.

    Returns True on success, False on failure.
    """
    if install_dir is None:
        # Infer from package location
        install_dir = Path(__file__).resolve().parent.parent.parent

    if not (install_dir / ".git").is_dir():
        logger.warning("Not a git repo: %s — cannot auto-update", install_dir)
        return False

    try:
        # Pull latest
        result = subprocess.run(
            ["git", "pull", "--ff-only"],
            cwd=install_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.error("git pull failed: %s", result.stderr)
            return False
        logger.info("git pull: %s", result.stdout.strip())

        # Reinstall
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", str(install_dir), "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.error("pip install failed: %s", result.stderr)
            return False
        logger.info("Reinstalled bigr-discovery")

        return True
    except Exception as exc:
        logger.error("Auto-update failed: %s", exc)
        return False


def _compare_versions(a: str, b: str) -> int:
    """Compare two semver-ish version strings.

    Returns positive if a > b, 0 if equal, negative if a < b.
    """
    def parse(v: str) -> tuple[int, ...]:
        parts = []
        for p in v.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    pa, pb = parse(a), parse(b)
    # Pad shorter tuple
    max_len = max(len(pa), len(pb))
    pa = pa + (0,) * (max_len - len(pa))
    pb = pb + (0,) * (max_len - len(pb))

    for x, y in zip(pa, pb):
        if x != y:
            return x - y
    return 0
