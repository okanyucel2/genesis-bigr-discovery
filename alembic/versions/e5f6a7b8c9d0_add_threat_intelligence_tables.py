"""add threat intelligence tables

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-02-10 23:30:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create threat_feeds table
    op.create_table(
        'threat_feeds',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('feed_url', sa.String(), nullable=False),
        sa.Column('feed_type', sa.String(), nullable=False),
        sa.Column('enabled', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('last_synced_at', sa.String(), nullable=True),
        sa.Column('entries_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.Column('updated_at', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_threat_feed_name'),
    )

    # 2. Create threat_indicators table
    op.create_table(
        'threat_indicators',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('subnet_hash', sa.String(), nullable=False),
        sa.Column('subnet_prefix', sa.String(), nullable=True),
        sa.Column('threat_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('source_feeds', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('indicator_types', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('cve_refs', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.String(), nullable=False),
        sa.Column('last_seen', sa.String(), nullable=False),
        sa.Column('report_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('expires_at', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # 3. Create indexes for performance
    op.create_index(
        'ix_threat_indicators_subnet_hash',
        'threat_indicators',
        ['subnet_hash'],
    )
    op.create_index(
        'ix_threat_indicators_expires_at',
        'threat_indicators',
        ['expires_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_threat_indicators_expires_at', table_name='threat_indicators')
    op.drop_index('ix_threat_indicators_subnet_hash', table_name='threat_indicators')
    op.drop_table('threat_indicators')
    op.drop_table('threat_feeds')
