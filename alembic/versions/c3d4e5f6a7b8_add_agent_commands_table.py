"""add agent_commands table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-02-10 22:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from sqlalchemy import inspect as sa_inspect
    conn = op.get_bind()
    existing = set(sa_inspect(conn).get_table_names())

    if 'agent_commands' not in existing:
        op.create_table(
            'agent_commands',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('agent_id', sa.String(), nullable=False),
            sa.Column('command_type', sa.String(), nullable=False),
            sa.Column('params', sa.Text(), nullable=True),
            sa.Column('status', sa.String(), nullable=False, server_default='pending'),
            sa.Column('created_at', sa.String(), nullable=False),
            sa.Column('started_at', sa.String(), nullable=True),
            sa.Column('completed_at', sa.String(), nullable=True),
            sa.Column('result', sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(['agent_id'], ['agents.id']),
            sa.PrimaryKeyConstraint('id'),
        )


def downgrade() -> None:
    op.drop_table('agent_commands')
