"""Common threat types shared between Shield and Guardian modules."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class ThreatReputation(str, Enum):
    """Reputation level for a domain or IP."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ThreatEntry(BaseModel):
    """A single threat indicator (domain, IP, etc.)."""

    indicator: str
    indicator_type: str  # "domain", "ip", "url"
    reputation: ThreatReputation = ThreatReputation.UNKNOWN
    source: str = ""
    category: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float = 0.0
