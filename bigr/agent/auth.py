"""Agent authentication — token generation, hashing, and FastAPI dependency."""

from __future__ import annotations

import hashlib
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.core.database import get_db
from bigr.core.models_db import AgentDB

_bearer_scheme = HTTPBearer()


def generate_token() -> str:
    """Generate a cryptographically secure 32-byte hex token."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """SHA-256 hash of a plaintext token (stored in DB)."""
    return hashlib.sha256(token.encode()).hexdigest()


async def verify_agent_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AgentDB:
    """FastAPI dependency: validate Bearer token and return the agent row.

    Raises 401 if token is invalid or agent is deactivated.
    """
    token_digest = hash_token(credentials.credentials)
    stmt = select(AgentDB).where(
        AgentDB.token_hash == token_digest,
        AgentDB.is_active == 1,
    )
    agent = (await db.execute(stmt)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked agent token.",
        )
    return agent
