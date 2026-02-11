"""macOS Menu Bar app for BİGR Discovery agent.

Provides a system tray icon with agent status, quick actions,
and dashboard access. Uses rumps for native macOS menu bar integration.

The menu bar app is a lightweight monitor — the agent daemon runs as
a separate process (via ``bigr agent start`` or LaunchAgent).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import webbrowser
from pathlib import Path

import httpx
import rumps

from bigr.agent.config import AgentConfig
from bigr.agent.daemon import _is_process_alive

_PID_PATH = Path.home() / ".bigr" / "agent.pid"
_DASHBOARD_URL = "http://localhost:19978"


class BigrMenuBarApp(rumps.App):
    """macOS menu bar status monitor for BİGR Discovery agent."""

    def __init__(self) -> None:
        super().__init__(name="BİGR Discovery", title="\U0001f6e1", quit_button=None)
        self._cfg = AgentConfig.load()
        self._api_url = self._cfg.api_url or "http://127.0.0.1:9978"

        # Menu items we need to update dynamically
        self._status_item = rumps.MenuItem("Durum: kontrol ediliyor...")
        self._scan_item = rumps.MenuItem("Son Tarama: -")
        self._asset_item = rumps.MenuItem("Cihazlar: -")
        self._shield_item = rumps.MenuItem("Bulgular: -")
        self._toggle_item = rumps.MenuItem("Agent Baslat")

        try:
            from bigr import __version__
            version_str = __version__
        except Exception:
            version_str = "?"

        self.menu = [
            rumps.MenuItem(f"BIGR Discovery v{version_str}"),
            None,
            self._status_item,
            self._scan_item,
            self._asset_item,
            self._shield_item,
            None,
            rumps.MenuItem("Simdi Tara", callback=self._on_scan_now),
            rumps.MenuItem("Dashboard Ac", callback=self._on_dashboard),
            None,
            self._toggle_item,
            rumps.MenuItem("Log Dosyasini Ac", callback=self._on_open_log),
            None,
            rumps.MenuItem("Cikis", callback=self._on_quit),
        ]
        self._toggle_item.set_callback(self._on_toggle)

        # Initial refresh
        self._refresh(None)

        # Periodic refresh every 30 seconds
        self._timer = rumps.Timer(self._refresh, 30)
        self._timer.start()

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_agent_pid() -> int | None:
        """Return agent PID if running, else None."""
        if not _PID_PATH.exists():
            return None
        try:
            pid = int(_PID_PATH.read_text().strip())
            return pid if _is_process_alive(pid) else None
        except (ValueError, OSError):
            return None

    def _api_get(self, path: str, timeout: float = 5.0) -> dict | None:
        """GET helper with auth header. Returns JSON dict or None on error."""
        try:
            headers: dict[str, str] = {}
            if self._cfg.token:
                headers["Authorization"] = f"Bearer {self._cfg.token}"
            resp = httpx.get(
                f"{self._api_url}{path}",
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def _refresh(self, _timer: rumps.Timer | None) -> None:
        """Periodic status refresh — updates all menu items."""
        pid = self._get_agent_pid()
        running = pid is not None

        # Agent status
        if running:
            self.title = "\U0001f6e1"
            self._status_item.title = f"Durum: Calisiyor (PID {pid})"
            self._toggle_item.title = "Agent Durdur"
        else:
            self.title = "\u26a0\ufe0f"
            self._status_item.title = "Durum: Durdu"
            self._toggle_item.title = "Agent Baslat"

        # Fetch asset count (longer timeout for Neon DB)
        data = self._api_get("/api/data?limit=0", timeout=15.0)
        if data:
            self._asset_item.title = f"Cihazlar: {data.get('total_assets', '-')}"

        # Last scan time
        scans = self._api_get("/api/scans?limit=1", timeout=15.0)
        if scans:
            scan_list = scans.get("scans", [])
            if scan_list:
                started = scan_list[0].get("started_at")
                if started:
                    self._scan_item.title = f"Son Tarama: {_format_ago(started)}"

        # Shield findings count
        findings = self._api_get("/api/shield-findings?limit=1", timeout=15.0)
        if findings and "total" in findings:
            self._shield_item.title = f"Bulgular: {findings['total']}"

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_scan_now(self, _sender: rumps.MenuItem) -> None:
        """Trigger an immediate scan via the cloud API."""
        if not self._cfg.agent_id:
            rumps.notification(
                "BIGR Discovery", "Hata",
                "Agent kayitli degil. Oncelikle 'bigr agent start' calistirin.",
            )
            return

        try:
            headers: dict[str, str] = {}
            if self._cfg.token:
                headers["Authorization"] = f"Bearer {self._cfg.token}"

            resp = httpx.post(
                f"{self._api_url}/api/agents/{self._cfg.agent_id}/commands",
                json={
                    "command_type": "scan_now",
                    "targets": self._cfg.targets,
                    "shield": self._cfg.shield,
                },
                headers=headers,
                timeout=10.0,
            )
            if resp.status_code in (200, 201):
                rumps.notification(
                    "BIGR Discovery", "Tarama Baslatildi",
                    "Agent yeni bir tarama dongusu baslatacak.",
                )
            else:
                rumps.notification(
                    "BIGR Discovery", "Hata",
                    f"Tarama istegi basarisiz: HTTP {resp.status_code}",
                )
        except Exception as exc:
            rumps.notification(
                "BIGR Discovery", "Baglanti Hatasi",
                str(exc)[:120],
            )

    def _on_dashboard(self, _sender: rumps.MenuItem) -> None:
        """Open the web dashboard in the default browser."""
        webbrowser.open(_DASHBOARD_URL)

    def _on_open_log(self, _sender: rumps.MenuItem) -> None:
        """Open the agent log file in Console.app."""
        log_path = Path.home() / ".bigr" / "agent.log"
        if log_path.exists():
            subprocess.Popen(["open", "-a", "Console", str(log_path)])
        else:
            rumps.notification(
                "BIGR Discovery", "Log Bulunamadi",
                "Agent henuz calistirilmamis.",
            )

    def _on_toggle(self, _sender: rumps.MenuItem) -> None:
        """Start or stop the agent daemon."""
        pid = self._get_agent_pid()
        if pid:
            self._stop_agent(pid)
        else:
            self._start_agent()
        # Refresh immediately after toggle
        self._refresh(None)

    def _start_agent(self) -> None:
        """Start agent daemon as a detached subprocess."""
        try:
            subprocess.Popen(
                [sys.executable, "-m", "bigr.cli", "agent", "start"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            rumps.notification(
                "BIGR Discovery", "Agent Baslatildi",
                "Arka planda tarama basliyor.",
            )
        except Exception as exc:
            rumps.notification(
                "BIGR Discovery", "Baslatma Hatasi",
                str(exc)[:120],
            )

    def _stop_agent(self, pid: int) -> None:
        """Gracefully stop the agent daemon."""
        # Send offline heartbeat (best-effort)
        if self._cfg.api_url and self._cfg.token:
            try:
                httpx.post(
                    f"{self._cfg.api_url}/api/agents/heartbeat",
                    json={"status": "offline"},
                    headers={"Authorization": f"Bearer {self._cfg.token}"},
                    timeout=5.0,
                )
            except Exception:
                pass

        try:
            os.kill(pid, signal.SIGTERM)
            rumps.notification(
                "BIGR Discovery", "Agent Durduruldu",
                f"PID {pid} sonlandirildi.",
            )
        except OSError as exc:
            rumps.notification(
                "BIGR Discovery", "Durdurma Hatasi",
                str(exc)[:120],
            )

    def _on_quit(self, _sender: rumps.MenuItem) -> None:
        """Quit the menu bar app (agent keeps running)."""
        rumps.quit_application()


def _format_ago(iso_str: str) -> str:
    """Convert ISO datetime string to Turkish relative time."""
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = (now - dt).total_seconds()
        if diff < 60:
            return "az once"
        if diff < 3600:
            return f"{int(diff / 60)}dk once"
        if diff < 86400:
            return f"{int(diff / 3600)}sa once"
        return f"{int(diff / 86400)}g once"
    except Exception:
        return iso_str[:19]


def run_menubar() -> None:
    """Entry point for the menu bar app."""
    app = BigrMenuBarApp()
    app.run()
