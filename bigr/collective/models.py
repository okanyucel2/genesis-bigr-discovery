"""Pydantic schemas for the collective intelligence module.

These models define the data structures for anonymized threat signal
sharing across the BİGR agent network ("Waze Effect").
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatSignal(BaseModel):
    """An anonymized threat signal from a single agent."""

    subnet_hash: str = Field(..., description="HMAC-SHA256 of /24 subnet")
    signal_type: str = Field(
        ...,
        description="Signal category: port_scan, malware_c2, brute_force, suspicious",
    )
    severity: float = Field(..., ge=0.0, le=1.0, description="Severity 0.0-1.0")
    port: int | None = Field(default=None, description="Target port if applicable")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    agent_hash: str = Field(..., description="HMAC of agent ID (anonymized)")


class CollectiveSignalReport(BaseModel):
    """Aggregated signal visible to all users.

    Only published when k-anonymity threshold is met.
    """

    subnet_hash: str
    signal_type: str
    reporter_count: int = Field(
        ..., description="How many unique agents reported this"
    )
    avg_severity: float
    first_seen: str
    last_seen: str
    confidence: float = Field(
        ..., description="Based on reporter_count and consistency"
    )
    is_verified: bool = Field(
        ..., description="Meets k-anonymity threshold"
    )


class CollectiveStats(BaseModel):
    """Network-wide collective intelligence statistics."""

    total_signals: int
    active_agents: int = Field(
        ..., description="Agents contributing in last 24h"
    )
    verified_threats: int = Field(
        ..., description="Signals meeting k-anonymity"
    )
    subnets_monitored: int
    community_protection_score: float = Field(
        ..., ge=0.0, le=100.0, description="Community protection 0-100"
    )
    last_updated: str


class ContributionStatus(BaseModel):
    """This agent's contribution to the collective."""

    signals_contributed: int
    signals_received: int
    is_contributing: bool
    opt_in: bool
    privacy_level: str = Field(
        ..., description="standard, strict, or paranoid"
    )
