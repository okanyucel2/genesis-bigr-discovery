"""add friendly_name, device_model, device_manufacturer columns to assets

Revision ID: i3a4b5c6d7e8
Revises: h2a3b4c5d6e7
Create Date: 2026-02-12 18:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "i3a4b5c6d7e8"
down_revision: Union[str, None] = "h2a3b4c5d6e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("friendly_name", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("device_model", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("device_manufacturer", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "device_manufacturer")
    op.drop_column("assets", "device_model")
    op.drop_column("assets", "friendly_name")
