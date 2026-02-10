"""Alert service for agent events — stale agents, critical findings.

Sends alerts via webhook (Slack/Discord/generic JSON POST).
Also provides an in-memory alert log accessible via API.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from bigr.core.settings import settings

logger = logging.getLogger(__name__)

_MAX_ALERT_LOG = 200


@dataclass
class Alert:
    """An alert event."""

    level: str  # "critical", "warning", "info"
    category: str  # "stale_agent", "critical_finding", etc.
    title: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


class AlertService:
    """Manages alert emission and logging."""

    def __init__(self) -> None:
        self._log: deque[Alert] = deque(maxlen=_MAX_ALERT_LOG)

    def emit(self, alert: Alert) -> None:
        """Log an alert and optionally send to webhook."""
        self._log.appendleft(alert)
        logger.warning("ALERT [%s] %s: %s — %s", alert.level, alert.category, alert.title, alert.detail)
        self._send_webhook(alert)

    def recent(self, limit: int = 50) -> list[dict]:
        """Return recent alerts as dicts."""
        return [a.to_dict() for a in list(self._log)[:limit]]

    def _send_webhook(self, alert: Alert) -> None:
        """Fire-and-forget webhook POST. Non-blocking."""
        url = settings.ALERT_WEBHOOK_URL
        if not url:
            return
        try:
            # Use a short timeout since this is best-effort
            httpx.post(
                url,
                json={
                    "text": f"[{alert.level.upper()}] {alert.title}\n{alert.detail}",
                    **alert.to_dict(),
                },
                timeout=5.0,
            )
        except Exception as exc:
            logger.debug("Webhook send failed: %s", exc)


# Global singleton
alert_service = AlertService()


def alert_critical_finding(
    finding_title: str,
    target: str,
    site_name: str | None,
    agent_name: str | None,
) -> None:
    """Emit alert for a critical-severity shield finding."""
    detail = f"Target: {target}"
    if site_name:
        detail += f", Site: {site_name}"
    if agent_name:
        detail += f", Agent: {agent_name}"
    alert_service.emit(Alert(
        level="critical",
        category="critical_finding",
        title=f"Critical finding: {finding_title}",
        detail=detail,
    ))


def alert_stale_agent(agent_name: str, agent_id: str, last_seen: str | None) -> None:
    """Emit alert when an agent goes stale (no heartbeat > 5min)."""
    alert_service.emit(Alert(
        level="warning",
        category="stale_agent",
        title=f"Agent stale: {agent_name}",
        detail=f"Agent {agent_id} last seen: {last_seen or 'never'}",
    ))
