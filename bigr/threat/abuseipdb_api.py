"""AbuseIPDB API endpoints for direct IP reputation queries."""

from __future__ import annotations

import ipaddress
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db, get_session_factory
from bigr.core.settings import settings
from bigr.threat.feeds.abuseipdb import AbuseIPDBClient
from bigr.threat.ingestor import ThreatIngestor

router = APIRouter(prefix="/api/threat/abuseipdb", tags=["abuseipdb"])

# Module-level client singleton (lazily created)
_client: AbuseIPDBClient | None = None


def _get_client() -> AbuseIPDBClient:
    """Return the shared AbuseIPDBClient instance."""
    global _client
    if _client is None:
        _client = AbuseIPDBClient(
            api_key=settings.ABUSEIPDB_API_KEY,
            daily_limit=settings.ABUSEIPDB_DAILY_LIMIT,
        )
    return _client


def _require_api_key() -> AbuseIPDBClient:
    """Get client and raise 503 if API key is not configured."""
    client = _get_client()
    if not client.api_key:
        raise HTTPException(
            status_code=503,
            detail="AbuseIPDB API anahtari yapilandirilmamis. "
            "ABUSEIPDB_API_KEY ortam degiskenini ayarlayin.",
        )
    return client


def _validate_ip(ip: str) -> None:
    """Validate an IP address string, raising 400 on failure."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Gecersiz IP adresi: {ip}",
        )


def _get_ingestor() -> ThreatIngestor:
    """Create a ThreatIngestor instance with current settings."""
    import hashlib

    hmac_key = settings.THREAT_HMAC_KEY
    if not hmac_key:
        hmac_key = hashlib.sha256(b"bigr-threat-default-key").hexdigest()

    return ThreatIngestor(
        session_factory=get_session_factory(),
        hmac_key=hmac_key,
        otx_api_key=settings.OTX_API_KEY or None,
        expiry_days=settings.THREAT_EXPIRY_DAYS,
        abuseipdb_api_key=settings.ABUSEIPDB_API_KEY or None,
        abuseipdb_daily_limit=settings.ABUSEIPDB_DAILY_LIMIT,
    )


@router.get("/check/{ip}")
async def check_ip(ip: str) -> dict:
    """Check IP reputation against AbuseIPDB.

    Args:
        ip: The IP address to check.

    Returns:
        AbuseIPDB reputation data with BIGR normalized score.
    """
    _validate_ip(ip)
    client = _require_api_key()

    result = await client.check_ip(ip)
    if result is None:
        raise HTTPException(
            status_code=429,
            detail="AbuseIPDB gunluk istek limiti asildi veya istek basarisiz oldu.",
        )

    return result


@router.get("/blacklist")
async def get_blacklist(
    confidence_minimum: int = 90,
    limit: int = 1000,
) -> dict:
    """Get AbuseIPDB blacklist entries.

    Args:
        confidence_minimum: Minimum abuse confidence score (0-100).
        limit: Maximum number of entries to return.

    Returns:
        Dict with blacklist entries and count.
    """
    client = _require_api_key()

    entries = await client.get_blacklist(
        confidence_minimum=confidence_minimum,
        limit=limit,
    )

    return {
        "entries": entries,
        "count": len(entries),
        "confidence_minimum": confidence_minimum,
    }


@router.get("/status")
async def abuseipdb_status() -> dict:
    """Get API key status, rate limit remaining, cache stats."""
    client = _get_client()

    return {
        "enabled": bool(client.api_key),
        "api_key_set": bool(client.api_key),
        "remaining_calls": client.remaining_calls,
        "daily_limit": client.daily_limit,
        "cache_size": client.cache_size,
    }


@router.get("/enrichment/{ip}")
async def enrich_asset(ip: str, db: AsyncSession = Depends(get_db)) -> dict:
    """Enrich an asset with AbuseIPDB data + existing threat data.

    Combines AbuseIPDB reputation check with the existing ThreatIngestor
    subnet lookup to provide a comprehensive threat assessment.

    Args:
        ip: IP address to enrich.
        db: Database session.

    Returns:
        Combined threat intelligence from both AbuseIPDB and local feeds.
    """
    _validate_ip(ip)

    # AbuseIPDB data (may be None if no API key or rate limited)
    abuseipdb_client = _get_client()
    abuseipdb_data = None
    if abuseipdb_client.api_key:
        abuseipdb_data = await abuseipdb_client.check_ip(ip)

    # Local threat data from existing feeds
    ingestor = _get_ingestor()
    local_threat = await ingestor.lookup_subnet(ip)

    # Calculate combined score
    combined_score = 0.0
    sources = []

    if local_threat:
        combined_score = local_threat["threat_score"]
        sources.extend(local_threat.get("source_feeds", []))

    if abuseipdb_data:
        abuseipdb_score = abuseipdb_data["bigr_threat_score"]
        if local_threat:
            # Weighted average: 60% local feeds, 40% AbuseIPDB
            combined_score = round(combined_score * 0.6 + abuseipdb_score * 0.4, 4)
        else:
            combined_score = abuseipdb_score
        sources.append("abuseipdb")

    return {
        "ip": ip,
        "combined_threat_score": combined_score,
        "sources": sorted(set(sources)),
        "abuseipdb": abuseipdb_data,
        "local_threat": local_threat,
        "status": "flagged" if combined_score > 0.0 else "clean",
    }
