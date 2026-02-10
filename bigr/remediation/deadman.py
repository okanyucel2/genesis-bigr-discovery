"""Dead Man Switch — monitors agent heartbeats and triggers alerts on silence."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.models_db import AgentDB
from bigr.remediation.models import DeadManSwitchConfig, DeadManSwitchStatus

logger = logging.getLogger(__name__)


class DeadManSwitch:
    """Monitors agent heartbeats and triggers alerts on silence.

    Turkish-warm messaging philosophy:
    - Alive: "Her sey yolunda, {agent_name} aktif."
    - Dead: "Dikkat! {agent_name} son {minutes} dakikadir sessiz."
    """

    def __init__(self, config: DeadManSwitchConfig | None = None) -> None:
        self._config = config or DeadManSwitchConfig()
        self._alerts_sent: dict[str, str] = {}  # agent_id -> last_alert_time

    @property
    def config(self) -> DeadManSwitchConfig:
        return self._config

    async def check_agents(
        self, db: AsyncSession
    ) -> list[DeadManSwitchStatus]:
        """Check all active agents and return their status."""
        stmt = select(AgentDB).where(AgentDB.is_active == 1)
        result = await db.execute(stmt)
        agents = result.scalars().all()

        statuses: list[DeadManSwitchStatus] = []
        now = datetime.now(timezone.utc)

        for agent in agents:
            status = self._evaluate_agent(agent, now)
            statuses.append(status)

            # Trigger alert if needed
            if status.alert_triggered:
                minutes = status.minutes_since_heartbeat or 0
                await self.trigger_alert(agent.id, minutes)

        return statuses

    async def get_status(
        self, agent_id: str, db: AsyncSession
    ) -> DeadManSwitchStatus | None:
        """Get status for a specific agent."""
        stmt = select(AgentDB).where(AgentDB.id == agent_id)
        result = await db.execute(stmt)
        agent = result.scalar_one_or_none()

        if agent is None:
            return None

        now = datetime.now(timezone.utc)
        return self._evaluate_agent(agent, now)

    async def update_config(self, config: DeadManSwitchConfig) -> None:
        """Update Dead Man Switch configuration."""
        self._config = config
        logger.info(
            "Dead Man Switch config updated: timeout=%d min, enabled=%s",
            config.timeout_minutes,
            config.enabled,
        )

    async def trigger_alert(
        self, agent_id: str, minutes_silent: float
    ) -> dict:
        """Send alert when agent goes dark.

        For now: log warning + return alert dict.
        Future: email, webhook, push notification.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Avoid spamming: only alert once per agent per 10-minute window
        last_alert = self._alerts_sent.get(agent_id)
        if last_alert:
            try:
                last_dt = datetime.fromisoformat(last_alert)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                if (now_dt - last_dt).total_seconds() < 600:
                    return {
                        "status": "suppressed",
                        "agent_id": agent_id,
                        "message": "Uyari zaten gonderildi, bekleniyor.",
                    }
            except (ValueError, TypeError):
                pass

        self._alerts_sent[agent_id] = now_iso

        message = f"Dikkat! Ajan son {minutes_silent:.0f} dakikadir sessiz."
        logger.warning("DEAD MAN SWITCH: agent=%s silent_minutes=%.1f", agent_id, minutes_silent)

        return {
            "status": "alert_sent",
            "agent_id": agent_id,
            "minutes_silent": minutes_silent,
            "message_tr": message,
            "message": f"Alert: Agent {agent_id} has been silent for {minutes_silent:.0f} minutes.",
            "alerted_at": now_iso,
        }

    def _evaluate_agent(
        self, agent: AgentDB, now: datetime
    ) -> DeadManSwitchStatus:
        """Evaluate a single agent's dead-man-switch status."""
        if not agent.last_seen:
            # Agent registered but never reported
            return DeadManSwitchStatus(
                agent_id=agent.id,
                agent_name=agent.name,
                last_heartbeat=None,
                minutes_since_heartbeat=None,
                is_alive=False,
                alert_triggered=self._config.enabled,
                config=self._config,
            )

        try:
            last_seen_dt = datetime.fromisoformat(agent.last_seen)
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return DeadManSwitchStatus(
                agent_id=agent.id,
                agent_name=agent.name,
                last_heartbeat=agent.last_seen,
                minutes_since_heartbeat=None,
                is_alive=False,
                alert_triggered=self._config.enabled,
                config=self._config,
            )

        delta = now - last_seen_dt
        minutes_since = delta.total_seconds() / 60.0
        is_alive = minutes_since <= self._config.timeout_minutes
        alert_triggered = (
            self._config.enabled
            and not is_alive
        )

        return DeadManSwitchStatus(
            agent_id=agent.id,
            agent_name=agent.name,
            last_heartbeat=agent.last_seen,
            minutes_since_heartbeat=round(minutes_since, 1),
            is_alive=is_alive,
            alert_triggered=alert_triggered,
            config=self._config,
        )
