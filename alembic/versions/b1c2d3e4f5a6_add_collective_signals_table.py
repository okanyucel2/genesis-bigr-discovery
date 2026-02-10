"""add collective_signals table

Revision ID: b1c2d3e4f5a6
Revises: f6a7b8c9d0e1
Create Date: 2026-02-10 23:45:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'collective_signals',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('subnet_hash', sa.String(), nullable=False),
        sa.Column('signal_type', sa.String(), nullable=False),
        sa.Column('severity', sa.Float(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('agent_hash', sa.String(), nullable=False),
        sa.Column('reported_at', sa.String(), nullable=False),
        sa.Column('is_noised', sa.Integer(), nullable=False, server_default='1'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_collective_signals_subnet_hash',
        'collective_signals',
        ['subnet_hash'],
    )
    op.create_index(
        'ix_collective_signals_reported_at',
        'collective_signals',
        ['reported_at'],
    )
    op.create_index(
        'ix_collective_signals_agent_hash',
        'collective_signals',
        ['agent_hash'],
    )


def downgrade() -> None:
    op.drop_index('ix_collective_signals_agent_hash', table_name='collective_signals')
    op.drop_index('ix_collective_signals_reported_at', table_name='collective_signals')
    op.drop_index('ix_collective_signals_subnet_hash', table_name='collective_signals')
    op.drop_table('collective_signals')
