"""Abstract base class for platform-specific firewall adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bigr.firewall.models import FirewallRule


class FirewallAdapter(ABC):
    """Abstract base class for platform-specific firewall adapters."""

    @abstractmethod
    async def install(self) -> dict:
        """Install/activate the firewall adapter."""

    @abstractmethod
    async def uninstall(self) -> dict:
        """Uninstall/deactivate the firewall adapter."""

    @abstractmethod
    async def apply_rules(self, rules: list[FirewallRule]) -> dict:
        """Push rules to the platform firewall."""

    @abstractmethod
    async def get_status(self) -> dict:
        """Get adapter-specific status."""

    @abstractmethod
    def platform_name(self) -> str:
        """Return platform identifier."""
