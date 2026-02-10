"""Pydantic schemas for the Family Shield dashboard API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FamilyDevice(BaseModel):
    """A device in the family group."""

    id: str
    name: str  # Friendly name ("Okan'in iPhone")
    device_type: str  # "phone", "laptop", "tablet", "desktop", "other"
    icon: str  # Device type icon
    owner_name: str | None = None  # "Okan", "Ayse", etc.
    is_online: bool = False
    last_seen: str | None = None
    safety_score: float = 0.5  # 0.0-1.0
    safety_level: str = "warning"  # "safe", "warning", "danger"
    open_threats: int = 0
    ip: str | None = None
    network_name: str | None = None  # Which network this device is on


class FamilyOverview(BaseModel):
    """Family Shield overview for the parent dashboard."""

    family_name: str = "Ailem"
    plan_id: str = "family"
    devices: list[FamilyDevice] = Field(default_factory=list)
    max_devices: int = 5
    total_threats: int = 0
    avg_safety_score: float = 0.0
    safety_level: str = "safe"  # Overall family safety
    devices_online: int = 0
    last_scan: str | None = None


class FamilyAlert(BaseModel):
    """An alert across any family device."""

    id: str
    device_id: str
    device_name: str
    alert_type: str
    severity: str
    message: str  # Human-friendly (from Language Engine)
    timestamp: str
    is_read: bool = False


class FamilyTimelineEntry(BaseModel):
    """A timeline entry for activity across family devices."""

    id: str
    device_id: str
    device_name: str
    device_icon: str
    event_type: str  # "scan", "threat_detected", "device_added", "device_removed"
    message: str
    timestamp: str


class AddDeviceRequest(BaseModel):
    """Request to add a device to the family group."""

    device_name: str = Field(..., min_length=1, max_length=100)
    device_type: str = "other"
    owner_name: str | None = None


class UpdateDeviceRequest(BaseModel):
    """Request to update device info."""

    name: str | None = None
    device_type: str | None = None
    owner_name: str | None = None
