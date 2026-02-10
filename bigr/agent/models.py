"""Pydantic schemas for the agent API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AgentRegisterRequest(BaseModel):
    """POST /api/agents/register body."""

    name: str = Field(..., min_length=1, max_length=128)
    site_name: str = Field(default="", max_length=128)
    location: str | None = Field(default=None, max_length=256)
    subnets: list[str] = Field(default_factory=list)
    secret: str | None = Field(default=None)


class AgentRegisterResponse(BaseModel):
    """Returned once on successful registration (token shown only here)."""

    agent_id: str
    token: str
    message: str = "Agent registered. Store the token securely — it cannot be retrieved again."


class AgentHeartbeatRequest(BaseModel):
    """POST /api/agents/heartbeat body."""

    status: str = Field(default="online", max_length=32)
    version: str | None = Field(default=None, max_length=32)
    subnets: list[str] | None = None


class IngestDiscoveryRequest(BaseModel):
    """POST /api/ingest/discovery body — mirrors save_scan_async dict shape."""

    target: str
    scan_method: str = "hybrid"
    started_at: str
    completed_at: str | None = None
    is_root: bool = False
    assets: list[dict] = Field(default_factory=list)


class IngestShieldRequest(BaseModel):
    """POST /api/ingest/shield body — shield scan results."""

    target: str
    started_at: str
    completed_at: str | None = None
    modules_run: list[str] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
