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

    model_config = {"env_prefix": "", "case_sensitive": True}


settings = Settings()
