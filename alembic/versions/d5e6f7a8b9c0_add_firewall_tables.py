"""add firewall_rules and firewall_events tables

Revision ID: d5e6f7a8b9c0
Revises: f6a7b8c9d0e1
Create Date: 2026-02-10 18:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from sqlalchemy import inspect as sa_inspect
    conn = op.get_bind()
    existing = set(sa_inspect(conn).get_table_names())

    if 'firewall_rules' not in existing:
        op.create_table(
            'firewall_rules',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('rule_type', sa.String(), nullable=False),
            sa.Column('target', sa.String(), nullable=False),
            sa.Column('direction', sa.String(), nullable=False, server_default='both'),
            sa.Column('protocol', sa.String(), nullable=False, server_default='any'),
            sa.Column('source', sa.String(), nullable=False, server_default='user'),
            sa.Column('reason', sa.String(), nullable=False, server_default=''),
            sa.Column('reason_tr', sa.String(), nullable=False, server_default=''),
            sa.Column('is_active', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('created_at', sa.String(), nullable=False),
            sa.Column('expires_at', sa.String(), nullable=True),
            sa.Column('hit_count', sa.Integer(), nullable=False, server_default='0'),
            sa.PrimaryKeyConstraint('id'),
        )

    if 'firewall_events' not in existing:
        op.create_table(
            'firewall_events',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('timestamp', sa.String(), nullable=False),
            sa.Column('action', sa.String(), nullable=False),
            sa.Column('rule_id', sa.String(), nullable=True),
            sa.Column('source_ip', sa.String(), nullable=False),
            sa.Column('dest_ip', sa.String(), nullable=False),
            sa.Column('dest_port', sa.Integer(), nullable=False),
            sa.Column('protocol', sa.String(), nullable=False, server_default='tcp'),
            sa.Column('process_name', sa.String(), nullable=True),
            sa.Column('direction', sa.String(), nullable=False, server_default='outbound'),
            sa.PrimaryKeyConstraint('id'),
        )


def downgrade() -> None:
    op.drop_table('firewall_events')
    op.drop_table('firewall_rules')
