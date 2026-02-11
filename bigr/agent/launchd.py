"""macOS LaunchAgent management for BİGR Discovery agent.

Provides install/uninstall commands to run the agent as a background
service that starts automatically at login.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

LABEL = "com.bigr.discovery.agent"
PLIST_DIR = Path.home() / "Library" / "LaunchAgents"
PLIST_PATH = PLIST_DIR / f"{LABEL}.plist"
LOG_DIR = Path.home() / ".bigr" / "logs"


def _python_path() -> str:
    """Return the path to the current Python interpreter."""
    return sys.executable


def _bigr_cli_module() -> list[str]:
    """Return the command to invoke bigr CLI as a module."""
    return [_python_path(), "-m", "bigr.cli"]


def generate_plist(api_url: str = "http://127.0.0.1:9978") -> str:
    """Generate launchd plist XML content."""
    python = _python_path()
    log_dir = str(LOG_DIR)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>bigr.cli</string>
        <string>agent</string>
        <string>start</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>60</integer>

    <key>StandardOutPath</key>
    <string>{log_dir}/agent.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>{log_dir}/agent.stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:{os.path.dirname(python)}</string>
    </dict>
</dict>
</plist>
"""


def install() -> tuple[bool, str]:
    """Install the LaunchAgent and load it."""
    if platform.system() != "Darwin":
        return False, "LaunchAgent is only supported on macOS."

    PLIST_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    plist_content = generate_plist()
    PLIST_PATH.write_text(plist_content, encoding="utf-8")

    # Load the agent
    try:
        subprocess.run(
            ["launchctl", "unload", str(PLIST_PATH)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass  # May not be loaded yet

    result = subprocess.run(
        ["launchctl", "load", str(PLIST_PATH)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return False, f"launchctl load failed: {result.stderr}"

    return True, str(PLIST_PATH)


def uninstall() -> tuple[bool, str]:
    """Unload and remove the LaunchAgent."""
    if not PLIST_PATH.exists():
        return False, "LaunchAgent is not installed."

    try:
        subprocess.run(
            ["launchctl", "unload", str(PLIST_PATH)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass

    PLIST_PATH.unlink(missing_ok=True)
    return True, "LaunchAgent removed."


def is_installed() -> bool:
    """Check if the LaunchAgent plist exists."""
    return PLIST_PATH.exists()


def is_running() -> bool:
    """Check if the LaunchAgent is currently loaded and running."""
    try:
        result = subprocess.run(
            ["launchctl", "list", LABEL],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False
