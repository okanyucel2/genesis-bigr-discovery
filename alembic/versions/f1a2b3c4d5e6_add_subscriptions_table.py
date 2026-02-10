"""add subscriptions table

Revision ID: f1a2b3c4d5e6
Revises: e5f6a7b8c9d0
Create Date: 2026-02-10 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'subscriptions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('plan_id', sa.String(), nullable=False, server_default='free'),
        sa.Column('activated_at', sa.String(), nullable=False),
        sa.Column('expires_at', sa.String(), nullable=True),
        sa.Column('is_active', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('stripe_customer_id', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_subscriptions_device_id',
        'subscriptions',
        ['device_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_subscriptions_device_id', table_name='subscriptions')
    op.drop_table('subscriptions')
