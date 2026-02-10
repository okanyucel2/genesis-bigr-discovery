"""Pydantic models for the BİGR Product Language Engine."""

from __future__ import annotations

from pydantic import BaseModel


class HumanNotification(BaseModel):
    """A human-friendly notification ready for display."""

    id: str
    title: str  # Short title (Turkish)
    body: str  # Main message (Turkish, warm tone)
    severity: str  # "info", "warning", "critical"
    icon: str  # Emoji/icon suggestion
    action_label: str | None = None  # CTA button text if applicable
    action_type: str | None = None  # "fix_it", "dismiss", "investigate"
    original_alert_type: str  # The raw AlertType value
    original_message: str  # The technical message
    generated_by: str  # "rules", "L0", "L1", "L2"
    created_at: str


class HumanizeRequest(BaseModel):
    """Request to humanize a technical alert."""

    alert_type: str
    severity: str
    ip: str | None = None
    message: str
    details: dict | None = None  # port, device name, etc.
    device_name: str | None = None  # Friendly device name if known


class NotificationPreferences(BaseModel):
    """User preferences for notification style."""

    language: str = "tr"  # "tr", "en"
    tone: str = "warm"  # "warm", "professional", "minimal"
    include_technical: bool = False  # Show original tech message too?
