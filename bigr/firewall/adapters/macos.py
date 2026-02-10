"""macOS Network Extension (NEFilterDataProvider) adapter.

NOTE: Full NEFilterDataProvider implementation requires:
- Apple Developer Program membership
- com.apple.developer.networking.networkextension entitlement
- System Extension approval via MDM or user consent
- Swift/Objective-C Network Extension target

This adapter provides the Python-side integration layer.
The actual Swift extension communicates via XPC/IPC.
"""

from __future__ import annotations

import platform

from bigr.firewall.adapters.base import FirewallAdapter
from bigr.firewall.models import FirewallRule


class MacOSFirewallAdapter(FirewallAdapter):
    """macOS NEFilterDataProvider adapter (stubbed).

    In production, the Swift Network Extension process handles actual
    packet filtering. This Python adapter manages the rule push via
    XPC and reads status from the extension.
    """

    def __init__(self) -> None:
        self._is_installed: bool = False
        self._rules_applied: int = 0

    async def install(self) -> dict:
        """Attempt to activate the Network Extension.

        In production, this triggers:
        1. NEFilterManager.shared().loadFromPreferences()
        2. User approval dialog
        3. System Extension activation
        """
        if platform.system() != "Darwin":
            return {"status": "error", "message": "macOS only"}

        # Stub: In production, communicate with Swift extension via XPC
        self._is_installed = True
        return {
            "status": "stub",
            "message": (
                "NEFilterDataProvider stub activated. "
                "Full implementation requires Apple Developer entitlements."
            ),
            "platform": "macos",
            "engine": "ne_filter_stub",
        }

    async def uninstall(self) -> dict:
        """Deactivate the adapter."""
        self._is_installed = False
        self._rules_applied = 0
        return {"status": "ok", "message": "Adapter deactivated"}

    async def apply_rules(self, rules: list[FirewallRule]) -> dict:
        """Push rules to the NE filter.

        In production, serializes rules to JSON and sends
        via XPC to the Swift Network Extension process.
        """
        self._rules_applied = len(rules)
        return {
            "status": "stub",
            "rules_pushed": len(rules),
            "message": "Rules queued for NEFilterDataProvider (stub mode)",
        }

    async def get_status(self) -> dict:
        """Get adapter status."""
        return {
            "platform": "macos",
            "engine": "ne_filter",
            "is_installed": self._is_installed,
            "rules_applied": self._rules_applied,
            "requires_entitlement": True,
            "entitlement": "com.apple.developer.networking.networkextension",
        }

    def platform_name(self) -> str:
        """Return platform identifier."""
        return "macos"
