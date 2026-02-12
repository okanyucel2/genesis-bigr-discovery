"""add sensitivity_level column and safety_streaks table

Revision ID: h2a3b4c5d6e7
Revises: g1a2b3c4d5e6
Create Date: 2026-02-12 16:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "h2a3b4c5d6e7"
down_revision: Union[str, None] = "g1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from sqlalchemy import inspect as sa_inspect
    conn = op.get_bind()
    inspector = sa_inspect(conn)
    existing = set(inspector.get_table_names())

    # Add sensitivity_level to assets table
    assets_cols = {c["name"] for c in inspector.get_columns("assets")}
    if "sensitivity_level" not in assets_cols:
        op.add_column(
            "assets",
            sa.Column("sensitivity_level", sa.String(), nullable=True),
        )

    # Create safety_streaks table
    if "safety_streaks" not in existing:
        op.create_table(
            "safety_streaks",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("subscription_id", sa.String(), nullable=False),
            sa.Column("current_streak_days", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("longest_streak_days", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("streak_start_date", sa.String(), nullable=True),
            sa.Column("last_check_date", sa.String(), nullable=True),
            sa.Column("streak_broken_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("total_safe_days", sa.Integer(), nullable=False, server_default="0"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_safety_streaks_subscription_id",
            "safety_streaks",
            ["subscription_id"],
        )


def downgrade() -> None:
    op.drop_index("ix_safety_streaks_subscription_id", table_name="safety_streaks")
    op.drop_table("safety_streaks")
    op.drop_column("assets", "sensitivity_level")
