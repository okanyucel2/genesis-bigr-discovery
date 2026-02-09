"""MAC address OUI vendor lookup."""

from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

# Well-known vendor prefixes for quick classification
# Used as fallback when OUI database is not available
KNOWN_VENDORS: dict[str, str] = {
    # Network equipment
    "00:1a:1e": "Aruba Networks",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:1b:44": "SanDisk",
    "00:17:c5": "SonicWall",
    "00:1e:bd": "Cisco",
    "00:26:cb": "Cisco",
    "00:1f:9e": "Cisco",
    "00:23:69": "Cisco",
    "00:25:84": "Cisco",
    "28:c6:3f": "Cisco Meraki",
    "00:18:0a": "Juniper",
    "00:05:85": "Juniper",
    "00:1f:12": "Juniper",
    "d4:04:ff": "Juniper",
    "70:b3:d5": "MikroTik",
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "e4:8d:8c": "MikroTik",
    "64:d1:54": "MikroTik",
    # IoT / Cameras
    "a4:14:37": "Hikvision",
    "c0:56:e3": "Hikvision",
    "44:19:b6": "Hikvision",
    "54:c4:15": "Hikvision",
    "bc:ad:28": "Hikvision",
    "40:ed:98": "Hikvision",
    "c4:2f:90": "Dahua",
    "3c:ef:8c": "Dahua",
    "a0:bd:1d": "Dahua",
    # Printers
    "00:00:48": "Seiko Epson",
    "00:1b:a9": "Brother",
    "00:1e:8f": "Canon",
    "00:15:99": "HP Printing",
    "a4:5d:36": "HP Printing",
    # Consumer / Laptops
    "ac:de:48": "Apple",
    "3c:22:fb": "Apple",
    "f0:18:98": "Apple",
    "a8:60:b6": "Apple",
    "00:1a:a0": "Dell",
    "14:fe:b5": "Dell",
    "f8:b1:56": "Dell",
    "54:bf:64": "Dell",
    "00:21:cc": "Lenovo",
    "58:20:b1": "Lenovo",
    "7c:7a:91": "Lenovo",
    "e8:6a:64": "Samsung",
    "a0:82:1f": "Samsung",
    "00:26:37": "Samsung",
}

# Category hints by vendor name keywords
VENDOR_CATEGORY_HINTS: dict[str, str] = {
    "cisco": "ag_ve_sistemler",
    "juniper": "ag_ve_sistemler",
    "aruba": "ag_ve_sistemler",
    "mikrotik": "ag_ve_sistemler",
    "sonicwall": "ag_ve_sistemler",
    "meraki": "ag_ve_sistemler",
    "vmware": "ag_ve_sistemler",
    "hikvision": "iot",
    "dahua": "iot",
    "axis": "iot",
    "epson": "iot",
    "brother": "iot",
    "canon": "iot",
    "hp printing": "iot",
    "xerox": "iot",
    "apple": "tasinabilir",
    "dell": "tasinabilir",
    "lenovo": "tasinabilir",
    "samsung": "tasinabilir",
    "intel": "tasinabilir",
    "realtek": "tasinabilir",
}


@lru_cache(maxsize=1)
def _load_oui_database() -> dict[str, str]:
    """Load OUI database from CSV file."""
    oui_path = Path(__file__).parent.parent.parent / "data" / "oui.csv"
    if not oui_path.exists():
        return {}

    db: dict[str, str] = {}
    with oui_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if len(row) >= 2:
                prefix = row[0].strip().lower()
                vendor = row[1].strip()
                db[prefix] = vendor
    return db


def lookup_vendor(mac: str | None) -> str | None:
    """Look up vendor by MAC address prefix (first 3 octets)."""
    if not mac:
        return None

    # Normalize MAC
    mac_clean = mac.lower().replace("-", ":")
    prefix = mac_clean[:8]  # "aa:bb:cc"

    # Try known vendors first (fast path)
    if prefix in KNOWN_VENDORS:
        return KNOWN_VENDORS[prefix]

    # Try OUI database
    oui_db = _load_oui_database()
    if prefix in oui_db:
        return oui_db[prefix]

    return None


def get_vendor_category_hint(vendor: str | None) -> str | None:
    """Get BİGR category hint from vendor name."""
    if not vendor:
        return None

    vendor_lower = vendor.lower()
    for keyword, category in VENDOR_CATEGORY_HINTS.items():
        if keyword in vendor_lower:
            return category

    return None
