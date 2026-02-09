"""Tests for config loader."""

from pathlib import Path

import pytest
import yaml

from bigr.config import (
    BigrConfig,
    TargetConfig,
    get_config_path,
    load_config,
    parse_interval,
)


class TestConfigLoader:
    def test_load_default_config_when_no_file(self, tmp_path):
        """Should return default config if ~/.bigr/config.yaml missing."""
        config = load_config(config_path=tmp_path / "nonexistent" / "config.yaml")
        assert isinstance(config, BigrConfig)
        assert config.targets == []
        assert config.alerts_enabled is True

    def test_load_config_from_yaml(self, tmp_path):
        """Should parse YAML config file correctly."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "targets": [
                {"subnet": "192.168.1.0/24", "interval": "5m", "label": "Ana LAN"},
            ],
            "alerts": {"enabled": False, "channels": []},
        }))

        config = load_config(config_path=config_file)
        assert isinstance(config, BigrConfig)
        assert len(config.targets) == 1
        assert config.targets[0].subnet == "192.168.1.0/24"
        assert config.alerts_enabled is False

    def test_config_targets_list(self, tmp_path):
        """Should return list of target dicts with subnet, interval, label."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "targets": [
                {"subnet": "192.168.1.0/24", "interval": "5m", "label": "Ana LAN"},
                {"subnet": "10.0.0.0/24", "interval": "30m", "label": "Sunucu VLAN"},
            ],
        }))

        config = load_config(config_path=config_file)
        assert len(config.targets) == 2
        assert config.targets[0].subnet == "192.168.1.0/24"
        assert config.targets[0].interval == "5m"
        assert config.targets[0].label == "Ana LAN"
        assert config.targets[1].subnet == "10.0.0.0/24"
        assert config.targets[1].interval == "30m"
        assert config.targets[1].label == "Sunucu VLAN"

    def test_config_default_interval(self, tmp_path):
        """Missing interval should default to '5m'."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "targets": [
                {"subnet": "10.0.0.0/8"},
            ],
        }))

        config = load_config(config_path=config_file)
        assert config.targets[0].interval == "5m"

    def test_parse_interval_minutes(self):
        """'5m' should return 300 seconds."""
        assert parse_interval("5m") == 300

    def test_parse_interval_hours(self):
        """'2h' should return 7200 seconds."""
        assert parse_interval("2h") == 7200

    def test_parse_interval_seconds(self):
        """'30s' should return 30 seconds."""
        assert parse_interval("30s") == 30

    def test_parse_interval_invalid(self):
        """Invalid interval should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid interval"):
            parse_interval("abc")

    def test_config_alerts_section(self, tmp_path):
        """Should parse alerts configuration."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "targets": [],
            "alerts": {
                "enabled": True,
                "channels": [
                    {"type": "webhook", "url": "https://hooks.slack.com/test"},
                    {"type": "log", "path": "~/.bigr/alerts.log"},
                ],
            },
        }))

        config = load_config(config_path=config_file)
        assert config.alerts_enabled is True
        assert len(config.alert_channels) == 2
        assert config.alert_channels[0]["type"] == "webhook"
        assert config.alert_channels[1]["type"] == "log"

    def test_get_config_path(self):
        """Should return ~/.bigr/config.yaml path."""
        path = get_config_path()
        assert path == Path.home() / ".bigr" / "config.yaml"

    def test_config_db_path_override(self, tmp_path):
        """Should parse db_path override from config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "targets": [],
            "db_path": "/custom/path/bigr.db",
        }))

        config = load_config(config_path=config_file)
        assert config.db_path == "/custom/path/bigr.db"

    def test_config_db_path_default_none(self, tmp_path):
        """db_path should default to None when not specified."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"targets": []}))

        config = load_config(config_path=config_file)
        assert config.db_path is None

    def test_target_config_defaults(self):
        """TargetConfig should have sensible defaults."""
        target = TargetConfig(subnet="10.0.0.0/24")
        assert target.interval == "5m"
        assert target.label == ""

    def test_parse_interval_plain_number(self):
        """Plain number without suffix should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid interval"):
            parse_interval("300")

    def test_parse_interval_zero(self):
        """'0s' should return 0."""
        assert parse_interval("0s") == 0

    def test_load_config_empty_yaml(self, tmp_path):
        """Empty YAML file should return default config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        config = load_config(config_path=config_file)
        assert isinstance(config, BigrConfig)
        assert config.targets == []
