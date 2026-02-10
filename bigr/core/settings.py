"""Application settings via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///~/.bigr/bigr.db"
    DEBUG: bool = False
    AGENT_REGISTRATION_SECRET: str = ""
    ALERT_WEBHOOK_URL: str = ""  # Optional webhook for agent/finding alerts

    # Threat Intelligence settings
    THREAT_HMAC_KEY: str = ""  # Secret key for IP hashing (auto-generated if empty)
    THREAT_EXPIRY_DAYS: int = 90  # Auto-expiry for threat indicators (GDPR/KVKK)
    OTX_API_KEY: str = ""  # AlienVault OTX API key (optional, free registration)

    # AbuseIPDB settings (commercial threat intelligence)
    ABUSEIPDB_API_KEY: str = ""  # AbuseIPDB API key (free tier: 1000/day)
    ABUSEIPDB_DAILY_LIMIT: int = 1000  # Daily API call limit (free=1000, basic=10000)

    # Family Shield settings
    FAMILY_MAX_DEVICES: int = 5  # Max devices for Family Shield plan

    # Collective Intelligence ("Waze Effect") settings
    COLLECTIVE_ENABLED: bool = True  # Enable collective signal sharing
    COLLECTIVE_EPSILON: float = 1.0  # Differential privacy budget (lower = more private)
    COLLECTIVE_K_ANONYMITY: int = 3  # Min reporters before signal is shared
    COLLECTIVE_SIGNAL_TTL_HOURS: int = 72  # Auto-expiry for collective signals

    model_config = {"env_prefix": "", "case_sensitive": True}


settings = Settings()
