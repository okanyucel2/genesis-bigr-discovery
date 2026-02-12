"""add remediation_actions table

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-02-10 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from sqlalchemy import inspect as sa_inspect
    conn = op.get_bind()
    existing = set(sa_inspect(conn).get_table_names())

    if 'remediation_actions' not in existing:
        op.create_table(
            'remediation_actions',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('asset_ip', sa.String(), nullable=False),
            sa.Column('action_type', sa.String(), nullable=False),
            sa.Column('title', sa.String(), nullable=False),
            sa.Column('severity', sa.String(), nullable=False, server_default='medium'),
            sa.Column('status', sa.String(), nullable=False, server_default='pending'),
            sa.Column('executed_at', sa.String(), nullable=True),
            sa.Column('result', sa.Text(), nullable=True),
            sa.Column('created_at', sa.String(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
        )


def downgrade() -> None:
    op.drop_table('remediation_actions')
