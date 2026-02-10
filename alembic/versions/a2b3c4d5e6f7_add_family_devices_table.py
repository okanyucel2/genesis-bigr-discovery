"""add family_devices table

Revision ID: a2b3c4d5e6f7
Revises: f6a7b8c9d0e1
Create Date: 2026-02-10 14:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'family_devices',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('subscription_id', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('device_type', sa.String(), nullable=False, server_default='other'),
        sa.Column('owner_name', sa.String(), nullable=True),
        sa.Column('added_at', sa.String(), nullable=False),
        sa.Column('is_active', sa.Integer(), nullable=False, server_default='1'),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id']),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id']),
    )
    op.create_index(
        'ix_family_devices_subscription_id',
        'family_devices',
        ['subscription_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_family_devices_subscription_id', table_name='family_devices')
    op.drop_table('family_devices')
