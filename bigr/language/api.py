"""FastAPI routes for the BİGR Product Language Engine.

Provides endpoints to humanize technical alerts, preview notifications
in different tones, and retrieve sample notifications for demo/testing.
"""

from __future__ import annotations

from fastapi import APIRouter

from bigr.language.humanizer import NotificationHumanizer
from bigr.language.models import (
    HumanizeRequest,
    HumanNotification,
    NotificationPreferences,
)
from bigr.language.templates import TEMPLATES, FALLBACK_TEMPLATE

router = APIRouter(prefix="/api/language", tags=["language-engine"])

# Module-level humanizer (no AI router by default -- injected at startup if available)
_humanizer = NotificationHumanizer()


def set_humanizer(humanizer: NotificationHumanizer) -> None:
    """Replace the module-level humanizer (e.g. with one that has an AI router)."""
    global _humanizer  # noqa: PLW0603
    _humanizer = humanizer


@router.post("/humanize")
async def humanize_alert(request: HumanizeRequest) -> dict:
    """Transform a technical alert into a human-friendly notification."""
    notification = await _humanizer.humanize(request)
    return {"notification": notification.model_dump()}


@router.post("/humanize/batch")
async def humanize_batch(requests: list[HumanizeRequest]) -> dict:
    """Transform multiple alerts at once."""
    notifications = await _humanizer.humanize_batch(requests)
    return {
        "notifications": [n.model_dump() for n in notifications],
        "count": len(notifications),
    }


@router.get("/templates")
async def list_templates() -> dict:
    """List all available notification templates."""
    return {
        "templates": TEMPLATES,
        "fallback": FALLBACK_TEMPLATE,
        "alert_types": list(TEMPLATES.keys()),
    }


@router.post("/preview")
async def preview_notification(
    request: HumanizeRequest,
    tone: str = "warm",
) -> dict:
    """Preview how a notification would look with a given tone.

    Currently only ``warm`` is fully implemented. ``professional``
    and ``minimal`` will produce the same template output until
    tone-aware AI generation is added.
    """
    prefs = NotificationPreferences(tone=tone)
    notification = await _humanizer.humanize(request, prefs)
    return {
        "preview": notification.model_dump(),
        "tone": tone,
    }


@router.get("/sample-notifications")
async def sample_notifications() -> dict:
    """Return sample notifications for all alert types (for demo/testing).

    Generates one notification per alert-type / severity combination
    that has a template entry, using dummy data.
    """
    samples: list[dict] = []

    sample_data: dict[str, dict] = {
        "new_device": {
            "ip": "192.168.1.23",
            "message": "New device detected: 192.168.1.23 (MAC: aa:bb:cc:dd:ee:ff)",
        },
        "port_change": {
            "ip": "192.168.1.5",
            "message": "Port 445 (SMB) open on 192.168.1.5 - EternalBlue risk",
            "device_name": "Oturma Odasi PC",
            "details": {"port": 445},
        },
        "rogue_device": {
            "ip": "192.168.1.99",
            "message": "Unauthorized device 192.168.1.99 not in whitelist",
        },
        "device_missing": {
            "ip": "192.168.1.10",
            "message": "Device 192.168.1.10 no longer responding",
        },
        "mass_change": {
            "ip": "0.0.0.0",
            "message": "Mass change: 15 new devices detected in last scan",
        },
        "category_change": {
            "ip": "192.168.1.7",
            "message": "Device 192.168.1.7 category changed from IoT to Tasinabilir",
            "device_name": "Yazici",
        },
        "threat_detected": {
            "ip": "10.0.0.1",
            "message": "Threat score 0.85 for subnet 10.0.0.0/24",
        },
    }

    for alert_type, severities in TEMPLATES.items():
        data = sample_data.get(alert_type, {})
        for severity in severities:
            req = HumanizeRequest(
                alert_type=alert_type,
                severity=severity,
                ip=data.get("ip", "192.168.1.1"),
                message=data.get("message", f"Technical alert: {alert_type}"),
                device_name=data.get("device_name"),
                details=data.get("details"),
            )
            notification = await _humanizer.humanize(req)
            samples.append(notification.model_dump())

    return {
        "samples": samples,
        "count": len(samples),
    }
