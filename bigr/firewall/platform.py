"""Platform detection and firewall adapter factory.

This module provides a single entry-point --
:func:`get_adapter` -- for obtaining the correct
:class:`~bigr.firewall.adapters.base.FirewallAdapter`
for the host operating system.

Usage::

    from bigr.firewall.platform import get_adapter

    adapter = get_adapter()            # auto-detect
    adapter = get_adapter("windows")   # force specific platform
"""

from __future__ import annotations

import logging
import platform as _platform

from bigr.firewall.adapters.base import FirewallAdapter

logger = logging.getLogger(__name__)


def detect_platform() -> str:
    """Detect the current operating system.

    Returns:
        One of ``"macos"``, ``"windows"``, ``"linux"``, or ``"unknown"``.
    """
    system = _platform.system()
    mapping: dict[str, str] = {
        "Darwin": "macos",
        "Windows": "windows",
        "Linux": "linux",
    }
    return mapping.get(system, "unknown")


def get_adapter(platform_override: str | None = None) -> FirewallAdapter:
    """Return the appropriate :class:`FirewallAdapter` for the current (or
    overridden) platform.

    Args:
        platform_override: Force a specific platform adapter instead of
            auto-detecting.  Useful for testing and for admin UIs that
            display information about other platforms.

    Returns:
        An instance of the platform-specific adapter.

    Raises:
        ValueError: If the platform string is not recognised.
    """
    target = platform_override or detect_platform()
    logger.debug("Resolving firewall adapter for platform=%s", target)

    if target == "macos":
        from bigr.firewall.adapters.macos import MacOSFirewallAdapter

        return MacOSFirewallAdapter()

    if target == "windows":
        from bigr.firewall.adapters.windows import WindowsFirewallAdapter

        return WindowsFirewallAdapter()

    if target == "linux":
        from bigr.firewall.adapters.linux import LinuxFirewallAdapter

        return LinuxFirewallAdapter()

    raise ValueError(
        f"Unsupported platform: {target!r}. "
        "Supported values are 'macos', 'windows', 'linux'."
    )


def get_all_adapters() -> dict:
    """Return descriptive metadata about every supported adapter.

    This is intended for dashboard / admin UIs that show which adapters
    are available and what the host is currently running.

    Returns:
        A dict with ``current_platform`` and an ``adapters`` mapping
        keyed by platform name.
    """
    current = detect_platform()

    return {
        "current_platform": current,
        "adapters": {
            "macos": {
                "name": "macOS NEFilterDataProvider",
                "engine": "ne_filter",
                "is_current": current == "macos",
                "requires": "Apple Developer entitlement (com.apple.developer.networking.networkextension)",
                "min_version": "macOS 10.15+ (Catalina)",
            },
            "windows": {
                "name": "Windows Filtering Platform (WFP)",
                "engine": "wfp",
                "is_current": current == "windows",
                "requires": "Administrator privileges",
                "min_version": "Windows Vista / Server 2008+",
            },
            "linux": {
                "name": "Linux nftables / iptables",
                "engine": "nftables",
                "is_current": current == "linux",
                "requires": "Root privileges (CAP_NET_ADMIN)",
                "min_version": "Linux 3.13+ (nftables) or any kernel (iptables)",
            },
        },
    }
