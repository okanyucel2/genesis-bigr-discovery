"""Pydantic schemas for remediation and dead man switch."""

from __future__ import annotations

from pydantic import BaseModel


class RemediationAction(BaseModel):
    """A single remediation action the user can take."""

    id: str
    title: str
    title_tr: str
    description: str
    description_tr: str
    severity: str  # "critical", "high", "medium", "low"
    action_type: str  # "firewall_rule", "service_disable", "config_change", "manual"
    target_ip: str | None = None
    target_port: int | None = None
    auto_fixable: bool = False
    estimated_impact: str = ""


class RemediationPlan(BaseModel):
    """Full remediation plan for a device or network."""

    asset_ip: str | None = None
    total_actions: int = 0
    critical_count: int = 0
    auto_fixable_count: int = 0
    actions: list[RemediationAction] = []
    generated_at: str = ""
    ai_tier_used: str = "heuristic"


class DeadManSwitchConfig(BaseModel):
    """Configuration for the Dead Man Switch."""

    enabled: bool = True
    timeout_minutes: int = 30
    alert_email: str | None = None
    alert_webhook: str | None = None


class DeadManSwitchStatus(BaseModel):
    """Current status of the Dead Man Switch."""

    agent_id: str
    agent_name: str = ""
    last_heartbeat: str | None = None
    minutes_since_heartbeat: float | None = None
    is_alive: bool = True
    alert_triggered: bool = False
    config: DeadManSwitchConfig = DeadManSwitchConfig()
