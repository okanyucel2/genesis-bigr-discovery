"""Alert evaluation engine - converts scan diffs into actionable alerts."""

from __future__ import annotations

from bigr.alerts.models import Alert, AlertSeverity, AlertType
from bigr.diff import DiffResult


# Map diff change_type strings to AlertType enum members.
_CHANGE_TYPE_MAP: dict[str, tuple[AlertType, AlertSeverity]] = {
    "port_change": (AlertType.PORT_CHANGE, AlertSeverity.INFO),
    "category_change": (AlertType.CATEGORY_CHANGE, AlertSeverity.WARNING),
    "vendor_change": (AlertType.PORT_CHANGE, AlertSeverity.INFO),  # minor, reuse INFO
    "hostname_change": (AlertType.PORT_CHANGE, AlertSeverity.INFO),
}


def evaluate_diff(
    diff_result: DiffResult,
    rules: list[dict] | None = None,
    mass_threshold: int = 10,
) -> list[Alert]:
    """Evaluate a scan diff and generate alerts.

    Parameters
    ----------
    diff_result:
        The DiffResult from comparing two scans.
    rules:
        Optional custom rules for rogue device detection etc.
    mass_threshold:
        Number of new devices that triggers a CRITICAL mass_change alert.

    Returns
    -------
    List of Alert objects, one per detected event.
    """
    alerts: list[Alert] = []

    # --- New devices ---
    for asset in diff_result.new_assets:
        ip = asset.get("ip", "unknown")
        mac = asset.get("mac")

        alerts.append(
            Alert(
                alert_type=AlertType.NEW_DEVICE,
                severity=AlertSeverity.WARNING,
                ip=ip,
                mac=mac,
                message=f"New device detected: {ip}",
                details={"asset": asset},
            )
        )

        # Check rogue device rules against new devices
        if rules:
            for rule in rules:
                if rule.get("trigger") == "rogue_device":
                    if _matches_rogue_rule(asset, rule):
                        sev = _parse_severity(rule.get("severity", "critical"))
                        alerts.append(
                            Alert(
                                alert_type=AlertType.ROGUE_DEVICE,
                                severity=sev,
                                ip=ip,
                                mac=mac,
                                message=f"Rogue device detected: {ip}",
                                details={"asset": asset, "rule": rule},
                            )
                        )

    # --- Mass change detection ---
    if len(diff_result.new_assets) >= mass_threshold:
        alerts.append(
            Alert(
                alert_type=AlertType.MASS_CHANGE,
                severity=AlertSeverity.CRITICAL,
                ip="0.0.0.0",
                mac=None,
                message=f"Mass change: {len(diff_result.new_assets)} new devices detected",
                details={"count": len(diff_result.new_assets)},
            )
        )

    # --- Removed devices ---
    for asset in diff_result.removed_assets:
        ip = asset.get("ip", "unknown")
        mac = asset.get("mac")
        alerts.append(
            Alert(
                alert_type=AlertType.DEVICE_MISSING,
                severity=AlertSeverity.INFO,
                ip=ip,
                mac=mac,
                message=f"Device missing: {ip}",
                details={"asset": asset},
            )
        )

    # --- Changed assets ---
    for change in diff_result.changed_assets:
        mapping = _CHANGE_TYPE_MAP.get(change.change_type)
        if mapping:
            alert_type, severity = mapping
            alerts.append(
                Alert(
                    alert_type=alert_type,
                    severity=severity,
                    ip=change.ip,
                    mac=change.mac,
                    message=f"{change.change_type} on {change.ip}: {change.old_value} -> {change.new_value}",
                    details={
                        "field": change.field,
                        "old_value": change.old_value,
                        "new_value": change.new_value,
                    },
                )
            )

    return alerts


def _matches_rogue_rule(asset: dict, rule: dict) -> bool:
    """Check whether a new asset matches a rogue-device rule's condition."""
    condition = rule.get("condition", {})
    ip = asset.get("ip", "")

    ip_prefix = condition.get("ip_prefix")
    if ip_prefix and ip.startswith(ip_prefix):
        return True

    mac_prefix = condition.get("mac_prefix")
    mac = asset.get("mac", "") or ""
    if mac_prefix and mac.startswith(mac_prefix):
        return True

    return False


def _parse_severity(value: str) -> AlertSeverity:
    """Parse a severity string to enum, defaulting to WARNING."""
    try:
        return AlertSeverity(value)
    except ValueError:
        return AlertSeverity.WARNING
