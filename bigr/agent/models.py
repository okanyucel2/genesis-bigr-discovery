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


class NetworkFingerprintPayload(BaseModel):
    """Network fingerprint sent by agent alongside scan results."""

    fingerprint_hash: str = Field(..., min_length=1, max_length=128)
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    ssid: str | None = None


class IngestDiscoveryRequest(BaseModel):
    """POST /api/ingest/discovery body — mirrors save_scan_async dict shape."""

    target: str
    scan_method: str = "hybrid"
    started_at: str
    completed_at: str | None = None
    is_root: bool = False
    assets: list[dict] = Field(default_factory=list)
    network_fingerprint: NetworkFingerprintPayload | None = None


class IngestShieldRequest(BaseModel):
    """POST /api/ingest/shield body — shield scan results."""

    target: str
    started_at: str
    completed_at: str | None = None
    modules_run: list[str] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)


class CreateCommandRequest(BaseModel):
    """POST /api/agents/{agent_id}/commands — dashboard triggers a remote scan."""

    command_type: str = Field(default="scan_now", max_length=64)
    targets: list[str] = Field(default_factory=list, description="Subnet CIDRs to scan. Empty = use agent's registered subnets.")
    shield: bool = Field(default=True, description="Run shield security modules after discovery.")


class CommandStatusUpdate(BaseModel):
    """PATCH /api/agents/commands/{command_id} — agent reports progress."""

    status: str = Field(..., pattern="^(ack|running|completed|failed)$")
    result: dict | None = None


class UpdateNetworkRequest(BaseModel):
    """PUT /api/networks/{id} — rename a network."""

    friendly_name: str = Field(..., min_length=1, max_length=256)
