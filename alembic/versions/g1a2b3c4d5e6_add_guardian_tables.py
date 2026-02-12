"""add guardian tables

Revision ID: g1a2b3c4d5e6
Revises: 7aab0cde7dd5
Create Date: 2026-02-12 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "g1a2b3c4d5e6"
down_revision: Union[str, None] = "7aab0cde7dd5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "guardian_blocklists",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("format", sa.String(), nullable=False, server_default="hosts"),
        sa.Column("category", sa.String(), nullable=False, server_default="malware"),
        sa.Column("domain_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_enabled", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_updated", sa.String(), nullable=True),
        sa.Column("etag", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "guardian_blocked_domains",
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("blocklist_id", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False, server_default="malware"),
        sa.PrimaryKeyConstraint("domain"),
        sa.ForeignKeyConstraint(["blocklist_id"], ["guardian_blocklists.id"]),
    )
    op.create_index(
        "ix_guardian_blocked_domains_domain",
        "guardian_blocked_domains",
        ["domain"],
    )

    op.create_table(
        "guardian_custom_rules",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False, server_default="custom"),
        sa.Column("reason", sa.String(), nullable=False, server_default=""),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_guardian_custom_rules_domain",
        "guardian_custom_rules",
        ["domain"],
    )

    op.create_table(
        "guardian_query_stats",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("date", sa.String(), nullable=False),
        sa.Column("hour", sa.Integer(), nullable=False),
        sa.Column("total_queries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocked_queries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("allowed_queries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_hits", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("date", "hour", name="uq_guardian_stats_date_hour"),
    )

    op.create_table(
        "guardian_top_domains",
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("block_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("category", sa.String(), nullable=False, server_default=""),
        sa.Column("last_blocked", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("domain"),
    )


def downgrade() -> None:
    op.drop_table("guardian_top_domains")
    op.drop_table("guardian_query_stats")
    op.drop_index("ix_guardian_custom_rules_domain", table_name="guardian_custom_rules")
    op.drop_table("guardian_custom_rules")
    op.drop_index(
        "ix_guardian_blocked_domains_domain", table_name="guardian_blocked_domains"
    )
    op.drop_table("guardian_blocked_domains")
    op.drop_table("guardian_blocklists")
