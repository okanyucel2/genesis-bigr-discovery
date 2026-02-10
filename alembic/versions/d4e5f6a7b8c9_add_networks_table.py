"""add networks table and network_id FK on scans/assets

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-02-10 23:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create networks table
    op.create_table(
        'networks',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('fingerprint_hash', sa.String(), nullable=False),
        sa.Column('gateway_mac', sa.String(), nullable=True),
        sa.Column('gateway_ip', sa.String(), nullable=True),
        sa.Column('ssid', sa.String(), nullable=True),
        sa.Column('friendly_name', sa.String(), nullable=True),
        sa.Column('agent_id', sa.String(), nullable=True),
        sa.Column('first_seen', sa.String(), nullable=False),
        sa.Column('last_seen', sa.String(), nullable=False),
        sa.Column('asset_count', sa.Integer(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('fingerprint_hash', name='uq_network_fingerprint'),
    )

    # 2. Add network_id FK to scans
    op.add_column('scans', sa.Column('network_id', sa.String(), nullable=True))
    op.create_foreign_key(
        'fk_scans_network_id', 'scans', 'networks',
        ['network_id'], ['id'],
    )

    # 3. Add network_id FK to assets
    op.add_column('assets', sa.Column('network_id', sa.String(), nullable=True))
    op.create_foreign_key(
        'fk_assets_network_id', 'assets', 'networks',
        ['network_id'], ['id'],
    )


def downgrade() -> None:
    # Drop FKs and columns in reverse order
    op.drop_constraint('fk_assets_network_id', 'assets', type_='foreignkey')
    op.drop_column('assets', 'network_id')

    op.drop_constraint('fk_scans_network_id', 'scans', type_='foreignkey')
    op.drop_column('scans', 'network_id')

    op.drop_table('networks')
