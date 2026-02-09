"""DHCP fingerprinting via Option 55 (Parameter Request List)."""

from __future__ import annotations

import re

from bigr.classifier.fingerprint_v2 import DhcpFingerprint

# Known Option 55 signatures -> OS
# These are the DHCP options that different OSes request.
# Stored as frozenset for efficient subset matching.
DHCP_FINGERPRINTS: dict[tuple[int, ...], str] = {
    # Windows 10/11
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): "Windows 10/11",
    # macOS
    (1, 3, 6, 15, 119, 252): "macOS",
    # Android
    (1, 3, 6, 15, 26, 28, 51, 58, 59): "Android",
    # Linux (dhclient)
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121): "Linux (dhclient)",
    # ChromeOS
    (1, 121, 33, 3, 6, 12, 15, 26, 28): "ChromeOS",
}

# Vendor class identifier patterns
_VENDOR_CLASS_PATTERNS: list[tuple[str, str]] = [
    (r"^MSFT\b", "Windows"),
    (r"^android-dhcp-(\d+)", "Android {0}"),
    (r"dhcpcd.*Linux|Linux", "Linux"),
    (r"^udhcpc", "Linux (embedded)"),
]


def guess_os_by_dhcp_options(option55: list[int]) -> str | None:
    """Match DHCP Option 55 against known fingerprints.

    Uses subset/superset matching since clients may have variations.
    First tries exact match, then best overlap ratio.
    """
    if not option55:
        return None

    input_set = set(option55)

    # Exact match first
    input_tuple = tuple(option55)
    if input_tuple in DHCP_FINGERPRINTS:
        return DHCP_FINGERPRINTS[input_tuple]

    # Overlap-based matching: find the signature with best Jaccard similarity
    best_match: str | None = None
    best_score: float = 0.0
    min_threshold = 0.5  # At least 50% overlap required

    for sig_tuple, os_name in DHCP_FINGERPRINTS.items():
        sig_set = set(sig_tuple)
        intersection = input_set & sig_set
        union = input_set | sig_set
        if not union:
            continue
        jaccard = len(intersection) / len(union)
        if jaccard > best_score and jaccard >= min_threshold:
            best_score = jaccard
            best_match = os_name

    return best_match


def parse_vendor_class(option60: str | None) -> str | None:
    """Parse DHCP Option 60 (Vendor Class Identifier).

    Examples:
    - "MSFT 5.0" -> "Windows"
    - "android-dhcp-14" -> "Android 14"
    - "dhcpcd-9.4.1:Linux-6.1" -> "Linux"
    """
    if option60 is None:
        return None

    for pattern, template in _VENDOR_CLASS_PATTERNS:
        match = re.search(pattern, option60, re.IGNORECASE)
        if match:
            # If template has placeholders, fill them with groups
            if "{0}" in template and match.groups():
                return template.format(match.group(1))
            return template

    return None
