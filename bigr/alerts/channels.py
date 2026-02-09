"""Notification channels for BİGR alert delivery."""

from __future__ import annotations

import json
import logging
import platform
import subprocess
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path

from bigr.alerts.models import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class AlertChannel(ABC):
    """Base class for alert delivery channels."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send an alert through this channel. Returns True on success."""
        ...


class LogChannel(AlertChannel):
    """Append alerts to a local log file."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)

    def send(self, alert: Alert) -> bool:
        """Append a formatted alert line to the log file."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            line = (
                f"{alert.timestamp.isoformat()} "
                f"[{alert.severity.value.upper()}] "
                f"{alert.alert_type.value} | "
                f"{alert.ip} | "
                f"{alert.message}\n"
            )
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            return True
        except OSError:
            logger.warning("Failed to write alert to %s", self.log_path, exc_info=True)
            return False


class WebhookChannel(AlertChannel):
    """POST alert JSON to an HTTP endpoint using stdlib urllib."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def send(self, alert: Alert) -> bool:
        """POST the alert dict as JSON to the configured URL."""
        try:
            data = json.dumps(alert.to_dict()).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=self.timeout)
            return True
        except Exception:
            logger.warning("Webhook delivery to %s failed", self.url, exc_info=True)
            return False


class DesktopChannel(AlertChannel):
    """Send OS-level desktop notification (macOS osascript / Linux notify-send)."""

    def send(self, alert: Alert) -> bool:
        """Trigger a desktop notification."""
        title = f"BİGR Alert: {alert.severity.value.upper()}"
        body = f"{alert.alert_type.value} | {alert.ip} | {alert.message}"

        try:
            system = platform.system()
            if system == "Darwin":
                subprocess.run(
                    [
                        "osascript",
                        "-e",
                        f'display notification "{body}" with title "{title}"',
                    ],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
            elif system == "Linux":
                subprocess.run(
                    ["notify-send", title, body],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
            else:
                logger.warning("Desktop notifications not supported on %s", system)
                return False
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning("Desktop notification failed", exc_info=True)
            return False


def dispatch_alerts(
    alerts: list[Alert],
    channels: list[AlertChannel],
    min_severity: AlertSeverity | None = None,
) -> int:
    """Send alerts to all configured channels.

    Parameters
    ----------
    alerts:
        List of alerts to dispatch.
    channels:
        List of channels to deliver to.
    min_severity:
        If set, alerts below this severity level are skipped.

    Returns
    -------
    Total number of successful sends (alerts x channels).
    """
    success_count = 0
    for alert in alerts:
        if min_severity is not None and alert.severity.level < min_severity.level:
            continue
        for channel in channels:
            if channel.send(alert):
                success_count += 1
    return success_count
