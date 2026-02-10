"""Agent configuration — load/save from ~/.bigr/agent.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_DEFAULT_DIR = Path.home() / ".bigr"
_CONFIG_PATH = _DEFAULT_DIR / "agent.yaml"


@dataclass
class AgentConfig:
    """Persistent configuration for the local agent daemon."""

    api_url: str = ""
    token: str = ""
    agent_id: str = ""
    name: str = ""
    site_name: str = ""
    targets: list[str] = field(default_factory=list)
    interval_seconds: int = 300
    shield: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> AgentConfig:
        """Load config from YAML file. Returns defaults if file missing."""
        p = path or _CONFIG_PATH
        if not p.exists():
            return cls()
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(
            api_url=data.get("api_url", ""),
            token=data.get("token", ""),
            agent_id=data.get("agent_id", ""),
            name=data.get("name", ""),
            site_name=data.get("site_name", ""),
            targets=data.get("targets", []),
            interval_seconds=data.get("interval_seconds", 300),
            shield=data.get("shield", False),
        )

    def save(self, path: Path | None = None) -> Path:
        """Persist config to YAML file. Creates parent dirs if needed."""
        p = path or _CONFIG_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "api_url": self.api_url,
            "token": self.token,
            "agent_id": self.agent_id,
            "name": self.name,
            "site_name": self.site_name,
            "targets": self.targets,
            "interval_seconds": self.interval_seconds,
            "shield": self.shield,
        }
        p.write_text(yaml.safe_dump(data, default_flow_style=False), encoding="utf-8")
        return p
