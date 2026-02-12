"""Common rule categories shared between Shield and Guardian modules."""

from __future__ import annotations

from enum import Enum


class RuleCategory(str, Enum):
    """Category of a blocking/filtering rule."""

    MALWARE = "malware"
    AD = "ad"
    TRACKER = "tracker"
    PHISHING = "phishing"
    CUSTOM = "custom"


class RuleAction(str, Enum):
    """Action to take when a rule matches."""

    BLOCK = "block"
    ALLOW = "allow"
