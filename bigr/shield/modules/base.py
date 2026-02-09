"""Base scan module interface."""

from __future__ import annotations

import abc

from bigr.shield.models import ShieldFinding


class ScanModule(abc.ABC):
    """Abstract base class for Shield scan modules."""

    name: str = ""
    weight: int = 0  # Score weight (percentage contribution to overall score)

    @abc.abstractmethod
    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run module scan against target. Returns list of findings."""
        ...

    @abc.abstractmethod
    def check_available(self) -> bool:
        """Check if module dependencies are available."""
        ...
