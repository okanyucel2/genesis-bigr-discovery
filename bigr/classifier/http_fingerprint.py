"""HTTP User-Agent parsing and device classification."""

from __future__ import annotations

import re

from bigr.classifier.fingerprint_v2 import HttpFingerprint

# User-Agent -> device type mapping
# Each tuple: (regex_pattern, device_type, os_name, browser_vendor)
UA_PATTERNS = [
    # Mobile devices
    (r"iPhone", "mobile", "iOS", "Apple"),
    (r"iPad", "tablet", "iPadOS", "Apple"),
    (r"Android.*Mobile", "mobile", "Android", None),
    (r"Android(?!.*Mobile)", "tablet", "Android", None),
    # Desktop
    (r"Macintosh", "desktop", "macOS", "Apple"),
    (r"Windows NT", "desktop", "Windows", None),
    (r"X11.*Linux|Linux.*X11", "desktop", "Linux", None),
    (r"CrOS", "desktop", "ChromeOS", "Google"),
    # IoT / Embedded
    (r"SmartTV|SMART-TV|NetCast|Tizen", "smart_tv", None, None),
    (r"PlayStation|Xbox", "game_console", None, None),
    # Bots / Servers
    (r"curl/|wget/|python-requests|Go-http-client", "server", None, None),
]

# OS version extraction patterns
_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "iOS": re.compile(r"iPhone OS (\d+[_\.]\d+(?:[_\.]\d+)?)"),
    "iPadOS": re.compile(r"CPU OS (\d+[_\.]\d+(?:[_\.]\d+)?)"),
    "Windows": re.compile(r"Windows NT (\d+\.\d+)"),
    "Android": re.compile(r"Android (\d+(?:\.\d+)*)"),
    "macOS": re.compile(r"Mac OS X (\d+[_\.]\d+(?:[_\.]\d+)*)"),
    "Linux": re.compile(r"Linux (\d+\.\d+(?:\.\d+)*)"),
    "ChromeOS": re.compile(r"CrOS \w+ (\d+\.\d+(?:\.\d+)*)"),
}


def parse_user_agent(ua: str | None) -> HttpFingerprint:
    """Parse User-Agent string to extract device info."""
    if ua is None:
        return HttpFingerprint()

    for pattern, device_type, os_name, vendor in UA_PATTERNS:
        if re.search(pattern, ua):
            os_version = extract_os_version(ua, os_name) if os_name else None
            return HttpFingerprint(
                user_agent=ua,
                device_type=device_type,
                os_name=os_name,
                os_version=os_version,
                browser=vendor,
            )

    # No match - still store the UA
    return HttpFingerprint(user_agent=ua)


def extract_os_version(ua: str, os_name: str) -> str | None:
    """Extract OS version from User-Agent.

    Examples:
    - "iPhone OS 17_0" -> "17.0"
    - "Windows NT 10.0" -> "10"
    - "Android 14" -> "14"
    - "Mac OS X 14_1_1" -> "14.1.1"
    """
    pattern = _VERSION_PATTERNS.get(os_name)
    if pattern is None:
        return None

    match = pattern.search(ua)
    if not match:
        return None

    version = match.group(1).replace("_", ".")

    # For Windows NT, map the NT version to marketing version
    if os_name == "Windows":
        nt_map = {
            "10.0": "10",
            "6.3": "8.1",
            "6.2": "8",
            "6.1": "7",
            "6.0": "Vista",
            "5.1": "XP",
        }
        return nt_map.get(version, version)

    return version
