"""Application settings via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///~/.bigr/bigr.db"
    DEBUG: bool = False

    model_config = {"env_prefix": "", "case_sensitive": True}


settings = Settings()
