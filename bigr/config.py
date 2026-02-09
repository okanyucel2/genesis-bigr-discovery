"""Configuration loader for BİGR Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


_DEFAULT_DIR = Path.home() / ".bigr"


@dataclass
class TargetConfig:
    """A single scan target definition."""

    subnet: str
    interval: str = "5m"
    label: str = ""


@dataclass
class BigrConfig:
    """Top-level BİGR configuration."""

    targets: list[TargetConfig] = field(default_factory=list)
    alerts_enabled: bool = True
    alert_channels: list[dict] = field(default_factory=list)
    db_path: str | None = None


def get_config_path() -> Path:
    """Return the default config file path: ~/.bigr/config.yaml."""
    return _DEFAULT_DIR / "config.yaml"


def parse_interval(interval: str) -> int:
    """Parse an interval string like '5m', '2h', '30s' into seconds.

    Raises ValueError for invalid formats.
    """
    if not interval:
        raise ValueError(f"Invalid interval: '{interval}'")

    suffix = interval[-1].lower()
    multipliers = {"s": 1, "m": 60, "h": 3600}

    if suffix not in multipliers:
        raise ValueError(f"Invalid interval: '{interval}'. Use s/m/h suffix (e.g. '5m', '2h', '30s').")

    try:
        value = int(interval[:-1])
    except ValueError:
        raise ValueError(
            f"Invalid interval: '{interval}'. Numeric part must be an integer."
        ) from None

    return value * multipliers[suffix]


def load_config(config_path: Path | None = None) -> BigrConfig:
    """Load configuration from a YAML file.

    If the file does not exist or is empty, returns a default BigrConfig.
    """
    path = config_path or get_config_path()

    if not path.exists():
        return BigrConfig()

    with path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        return BigrConfig()

    # Parse targets
    targets: list[TargetConfig] = []
    for t in raw.get("targets", []):
        if isinstance(t, dict) and "subnet" in t:
            targets.append(
                TargetConfig(
                    subnet=t["subnet"],
                    interval=t.get("interval", "5m"),
                    label=t.get("label", ""),
                )
            )

    # Parse alerts
    alerts_section = raw.get("alerts", {})
    if not isinstance(alerts_section, dict):
        alerts_section = {}

    alerts_enabled = alerts_section.get("enabled", True)
    alert_channels = alerts_section.get("channels", [])

    # Parse optional db_path
    db_path = raw.get("db_path")

    return BigrConfig(
        targets=targets,
        alerts_enabled=alerts_enabled,
        alert_channels=alert_channels,
        db_path=db_path,
    )
