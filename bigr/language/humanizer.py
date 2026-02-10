"""Core humanizer engine for the BİGR Product Language Engine.

Transforms technical security alerts into warm, human-friendly Turkish
notifications suitable for consumer display.

Strategy:
    1. For warning/critical alerts, try AI-based humanization first.
    2. Fall back to rule-based templates if AI is unavailable or fails.
    3. Templates use ``{ip}``, ``{device_name}``, ``{port}`` placeholders.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from bigr.language.models import (
    HumanizeRequest,
    HumanNotification,
    NotificationPreferences,
)
from bigr.language.templates import FALLBACK_TEMPLATE, TEMPLATES

if TYPE_CHECKING:
    from bigr.ai.router import InferenceRouter

logger = logging.getLogger(__name__)


class NotificationHumanizer:
    """Transforms technical alerts into human-friendly notifications.

    Parameters
    ----------
    ai_router:
        Optional :class:`InferenceRouter` instance.  When provided, the
        humanizer will attempt AI-based text generation for warning and
        critical alerts before falling back to rule-based templates.
    """

    def __init__(self, ai_router: InferenceRouter | None = None) -> None:
        self._router = ai_router

    async def humanize(
        self,
        request: HumanizeRequest,
        preferences: NotificationPreferences | None = None,
    ) -> HumanNotification:
        """Transform a technical alert into a human notification.

        For warning/critical alerts with an available AI router, the
        engine first tries AI generation. On failure (timeout, error,
        etc.) it transparently falls back to templates.
        """
        prefs = preferences or NotificationPreferences()

        # For warning/critical alerts, try AI if router is available
        if self._router and request.severity in ("warning", "critical"):
            try:
                return await self._humanize_with_ai(request, prefs)
            except Exception:
                logger.debug(
                    "AI humanization failed for %s/%s, falling back to templates",
                    request.alert_type,
                    request.severity,
                    exc_info=True,
                )

        return self._humanize_with_templates(request, prefs)

    async def humanize_batch(
        self,
        requests: list[HumanizeRequest],
        preferences: NotificationPreferences | None = None,
    ) -> list[HumanNotification]:
        """Humanize multiple alerts concurrently."""
        tasks = [self.humanize(req, preferences) for req in requests]
        return await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # AI-based humanization
    # ------------------------------------------------------------------

    async def _humanize_with_ai(
        self,
        request: HumanizeRequest,
        prefs: NotificationPreferences,
    ) -> HumanNotification:
        """Use AI router to generate human-friendly text."""
        assert self._router is not None  # noqa: S101 - guarded by caller

        from bigr.ai.router_models import InferenceQuery

        system_prompt = (
            "Sen BIGR guvenlik asistanisin. Teknik guvenlik uyarilarini "
            "sicak, samimi Turkce ile yeniden yaz. Kullanici teknik bilgi "
            "sahibi degil. Korkutma, guven ver. Kisa tut (max 2 cumle). "
            "Emoji kullanma."
        )

        device = request.device_name or request.ip or "bilinmeyen"
        prompt = (
            f"Teknik uyari: {request.message}\n"
            f"Uyari turu: {request.alert_type}\n"
            f"Cihaz: {device}\n"
            f"Onem: {request.severity}\n\n"
            f"Bu uyariyi sicak, insani Turkce ile yeniden yaz."
        )

        result = await self._router.route(
            InferenceQuery(
                query_type="text_gen",
                prompt=prompt,
                system_prompt=system_prompt,
                preferred_tier="auto",
                max_tier="l1",  # Don't waste L2 on notifications
            )
        )

        # Determine tier label
        tier_label = result.tier_used
        if "L0" in tier_label or "local" in tier_label.lower():
            generated_by = "L0"
        elif "L1" in tier_label or "haiku" in tier_label.lower():
            generated_by = "L1"
        elif "L2" in tier_label or "opus" in tier_label.lower():
            generated_by = "L2"
        else:
            generated_by = tier_label

        # Use template for structural fields (icon, action) but AI for text
        template = TEMPLATES.get(request.alert_type, {}).get(request.severity)
        if not template:
            template = FALLBACK_TEMPLATE.get(
                request.severity, FALLBACK_TEMPLATE["info"]
            )

        ai_body = result.content.strip()
        # Clean up common AI artefacts
        if ai_body.startswith('"') and ai_body.endswith('"'):
            ai_body = ai_body[1:-1]

        return HumanNotification(
            id=str(uuid.uuid4()),
            title=template["title"],
            body=ai_body,
            severity=request.severity,
            icon=template.get("icon", "\u2139\ufe0f"),
            action_label=template.get("action_label"),
            action_type=template.get("action_type"),
            original_alert_type=request.alert_type,
            original_message=request.message,
            generated_by=generated_by,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # Template-based humanization
    # ------------------------------------------------------------------

    def _humanize_with_templates(
        self,
        request: HumanizeRequest,
        prefs: NotificationPreferences,
    ) -> HumanNotification:
        """Use rule-based templates for humanization."""
        template = TEMPLATES.get(request.alert_type, {}).get(request.severity)
        if not template:
            template = FALLBACK_TEMPLATE.get(
                request.severity, FALLBACK_TEMPLATE["info"]
            )

        # Build placeholder values with safe defaults
        ip = request.ip or "bilinmeyen"
        device_name = request.device_name or request.ip or "bir cihaz"
        port = ""
        if request.details:
            port = str(request.details.get("port", ""))

        # Fill placeholders, handling missing keys gracefully
        try:
            body = template["body"].format(
                ip=ip,
                device_name=device_name,
                port=port,
            )
        except KeyError:
            # If template has an unexpected placeholder, just use raw body
            body = template["body"]

        return HumanNotification(
            id=str(uuid.uuid4()),
            title=template["title"],
            body=body,
            severity=request.severity,
            icon=template.get("icon", "\u2139\ufe0f"),
            action_label=template.get("action_label"),
            action_type=template.get("action_type"),
            original_alert_type=request.alert_type,
            original_message=request.message,
            generated_by="rules",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
