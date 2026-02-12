"""Tests for the agent CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from bigr.cli import app

runner = CliRunner()


class TestAgentRegister:
    def test_register_success(self, tmp_path):
        config_path = tmp_path / "agent.yaml"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "agent_id": "agent-123",
            "token": "a" * 64,
            "message": "Registered.",
        }

        with patch("httpx.post", return_value=mock_resp):
            result = runner.invoke(app, [
                "agent", "register",
                "--api-url", "http://localhost:9978",
                "--name", "test-scanner",
                "--site", "HQ",
                "--config", str(config_path),
            ])
        assert result.exit_code == 0
        assert "Registered" in result.output
        assert config_path.exists()

        # Verify saved config
        import yaml
        saved = yaml.safe_load(config_path.read_text())
        assert saved["agent_id"] == "agent-123"
        assert saved["api_url"] == "http://localhost:9978"

    def test_register_api_error(self, tmp_path):
        import httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=mock_resp,
        )

        with patch("httpx.post", return_value=mock_resp):
            result = runner.invoke(app, [
                "agent", "register",
                "--api-url", "http://localhost:9978",
                "--name", "bad",
                "--config", str(tmp_path / "agent.yaml"),
            ])
        assert result.exit_code == 1
        assert "failed" in result.output.lower()


class TestAgentStop:
    def test_stop_no_agent(self):
        with patch("bigr.cli.Path") as mock_path_cls:
            mock_pid = MagicMock()
            mock_pid.exists.return_value = False
            mock_path_cls.home.return_value.__truediv__ = MagicMock(return_value=mock_pid)
            # Just test the command runs without crashing
            result = runner.invoke(app, ["agent", "stop"])
            # Either shows "not running" or proceeds
            assert result.exit_code == 0


class TestAgentStatus:
    def test_status_not_running(self):
        result = runner.invoke(app, ["agent", "status"])
        # Agent PID file won't exist in test env
        assert result.exit_code == 0


class TestAgentConfig:
    def test_config_load_save_roundtrip(self, tmp_path):
        from bigr.agent.config import AgentConfig

        cfg = AgentConfig(
            api_url="https://example.com",
            token="tok123",
            agent_id="agent-abc",
            name="scanner",
            site_name="HQ",
            targets=["192.168.1.0/24", "10.0.0.0/16"],
            interval_seconds=120,
            shield=True,
        )
        path = tmp_path / "agent.yaml"
        cfg.save(path)

        loaded = AgentConfig.load(path)
        assert loaded.api_url == "https://example.com"
        assert loaded.token == "tok123"
        assert loaded.agent_id == "agent-abc"
        assert loaded.targets == ["192.168.1.0/24", "10.0.0.0/16"]
        assert loaded.interval_seconds == 120
        assert loaded.shield is True

    def test_config_load_missing_file(self, tmp_path):
        from bigr.agent.config import AgentConfig

        cfg = AgentConfig.load(tmp_path / "nonexistent.yaml")
        assert cfg.api_url == ""
        assert cfg.token == ""
        assert cfg.targets == []
