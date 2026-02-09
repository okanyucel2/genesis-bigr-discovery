"""TLS certificate analysis for device identification."""

from __future__ import annotations

import re

from bigr.classifier.fingerprint_v2 import TlsFingerprint

# Known self-signed cert patterns -> device type
CERT_DEVICE_PATTERNS = {
    r"HP\s*(LaserJet|OfficeJet|ENVY|DeskJet)": "printer",
    r"Hikvision|DS-\d": "ip_camera",
    r"Dahua|DH-": "ip_camera",
    r"AXIS\s*[A-Z]\d": "ip_camera",
    r"Synology|DiskStation": "nas",
    r"QNAP|TS-\d": "nas",
    r"Ubiquiti|UniFi": "network_equipment",
    r"MikroTik|RouterOS": "network_equipment",
    r"VMware|ESXi": "hypervisor",
}


def extract_device_from_cert(cn: str | None, san: list[str] | None = None) -> str | None:
    """Extract device type from certificate CN or SAN fields.

    Checks the Common Name and Subject Alternative Names against
    known device vendor/model patterns.
    """
    if cn is None and not san:
        return None

    # Check CN first
    if cn:
        for pattern, device_type in CERT_DEVICE_PATTERNS.items():
            if re.search(pattern, cn, re.IGNORECASE):
                return device_type

    # Check SAN entries
    if san:
        for name in san:
            for pattern, device_type in CERT_DEVICE_PATTERNS.items():
                if re.search(pattern, name, re.IGNORECASE):
                    return device_type

    return None


def analyze_certificate(
    cn: str | None = None,
    san: list[str] | None = None,
    issuer: str | None = None,
    is_self_signed: bool = False,
    expiry_days: int | None = None,
) -> TlsFingerprint:
    """Analyze TLS certificate for device identification hints.

    Self-signed certificates are common on IoT devices, network equipment,
    and other embedded systems. The CN and SAN fields often contain
    device model information.
    """
    device_hint = extract_device_from_cert(cn, san)

    return TlsFingerprint(
        cn=cn,
        san=san or [],
        issuer=issuer,
        is_self_signed=is_self_signed,
        expiry_days=expiry_days,
        device_hint=device_hint,
    )
