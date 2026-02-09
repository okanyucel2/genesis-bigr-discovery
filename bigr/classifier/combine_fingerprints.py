"""Combine multiple fingerprint sources into a unified device fingerprint."""

from __future__ import annotations

from bigr.classifier.fingerprint_v2 import (
    DeviceFingerprint,
    DhcpFingerprint,
    HttpFingerprint,
    TcpFingerprint,
    TlsFingerprint,
)


# Device type -> BİGR category mapping
_DEVICE_TYPE_TO_CATEGORY = {
    "mobile": "tasinabilir",
    "tablet": "tasinabilir",
    "desktop": "tasinabilir",
    "game_console": "tasinabilir",
    "smart_tv": "iot",
    "printer": "iot",
    "ip_camera": "iot",
    "nas": "iot",
    "hypervisor": "ag_ve_sistemler",
    "network_equipment": "ag_ve_sistemler",
    "server": "uygulamalar",
}

# Scoring weights per device type
_DEVICE_TYPE_SCORES: dict[str, dict[str, float]] = {
    "mobile": {"tasinabilir": 0.4},
    "tablet": {"tasinabilir": 0.4},
    "desktop": {"tasinabilir": 0.3},
    "game_console": {"tasinabilir": 0.3},
    "smart_tv": {"iot": 0.3},
    "printer": {"iot": 0.5},
    "ip_camera": {"iot": 0.5},
    "nas": {"iot": 0.3},
    "hypervisor": {"ag_ve_sistemler": 0.3},
    "network_equipment": {"ag_ve_sistemler": 0.4},
    "server": {"uygulamalar": 0.4},
}


def combine_fingerprints(
    tcp: TcpFingerprint | None = None,
    http: HttpFingerprint | None = None,
    tls: TlsFingerprint | None = None,
    dhcp: DhcpFingerprint | None = None,
) -> DeviceFingerprint:
    """Combine all fingerprint sources into a unified result.

    Weight hierarchy for OS detection:
    1. DHCP Option 55 (most reliable for OS detection)
    2. User-Agent (most reliable for device type)
    3. TLS Certificate (reliable for IoT devices)
    4. TCP Stack (least specific but always available)
    """
    # Collect OS hints from all sources
    os_votes: list[str] = []
    device_type_votes: list[str] = []
    source_count = 0

    if tcp is not None:
        source_count += 1
        if tcp.os_guess:
            os_votes.append(tcp.os_guess)

    if http is not None:
        source_count += 1
        if http.os_name:
            os_votes.append(http.os_name)
        if http.device_type:
            device_type_votes.append(http.device_type)

    if tls is not None:
        source_count += 1
        if tls.device_hint:
            device_type_votes.append(tls.device_hint)

    if dhcp is not None:
        source_count += 1
        if dhcp.os_guess:
            os_votes.append(dhcp.os_guess)

    # Determine combined OS (priority: DHCP > HTTP > TCP)
    combined_os: str | None = None
    if dhcp and dhcp.os_guess:
        combined_os = dhcp.os_guess
    elif http and http.os_name:
        combined_os = http.os_name
    elif tcp and tcp.os_guess:
        combined_os = tcp.os_guess

    # Determine combined device type (priority: HTTP > TLS > infer from OS)
    combined_device_type: str | None = None
    if http and http.device_type:
        combined_device_type = http.device_type
    elif tls and tls.device_hint:
        combined_device_type = tls.device_hint
    elif combined_os:
        # Infer device type from OS
        os_lower = combined_os.lower()
        if "network equipment" in os_lower:
            combined_device_type = "network_equipment"
        elif "windows" in os_lower or "macos" in os_lower or "linux" in os_lower:
            combined_device_type = "desktop"

    # Calculate confidence based on source count and agreement
    confidence = 0.0
    if source_count > 0:
        # Base confidence from number of sources
        base = min(source_count * 0.25, 1.0)  # 0.25 per source, max 1.0

        # Agreement bonus: if multiple OS votes agree
        if len(os_votes) >= 2:
            # Normalize OS names for comparison
            normalized = [_normalize_os(v) for v in os_votes]
            unique = set(normalized)
            if len(unique) == 1:
                # All agree
                agreement_bonus = 0.2
            else:
                agreement_bonus = 0.0
            base = min(base + agreement_bonus, 1.0)

        confidence = round(base, 2)

    return DeviceFingerprint(
        tcp=tcp,
        http=http,
        tls=tls,
        dhcp=dhcp,
        combined_os=combined_os,
        combined_device_type=combined_device_type,
        confidence=confidence,
    )


def _normalize_os(os_name: str) -> str:
    """Normalize OS name for agreement comparison."""
    os_lower = os_name.lower()
    if "linux" in os_lower:
        return "linux"
    if "windows" in os_lower:
        return "windows"
    if "android" in os_lower:
        return "android"
    if "ios" in os_lower or "ipad" in os_lower:
        return "ios"
    if "macos" in os_lower or "mac os" in os_lower:
        return "macos"
    if "chromeos" in os_lower:
        return "chromeos"
    if "network" in os_lower:
        return "network"
    return os_lower


def score_by_fingerprint_v2(fingerprint: DeviceFingerprint, scores: object) -> None:
    """Apply fingerprint-based scoring to ClassificationScores.

    Weight hierarchy:
    1. DHCP Option 55 (most reliable for OS detection)
    2. User-Agent (most reliable for device type)
    3. TLS Certificate (reliable for IoT devices)
    4. TCP Stack (least specific but always available)
    """
    device_type = fingerprint.combined_device_type
    if not device_type:
        return

    score_deltas = _DEVICE_TYPE_SCORES.get(device_type, {})
    for category, delta in score_deltas.items():
        current = getattr(scores, category, 0.0)
        setattr(scores, category, current + delta)
