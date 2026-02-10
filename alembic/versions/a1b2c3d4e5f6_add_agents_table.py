"""add agents table and site columns

Revision ID: a1b2c3d4e5f6
Revises: f782f2b25b23
Create Date: 2026-02-10 14:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f782f2b25b23'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create agents table
    op.create_table(
        'agents',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('site_name', sa.String(), nullable=False, server_default=''),
        sa.Column('location', sa.String(), nullable=True),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('is_active', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('registered_at', sa.String(), nullable=False),
        sa.Column('last_seen', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='offline'),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('subnets', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    # Add nullable agent_id and site_name columns to scans
    with op.batch_alter_table('scans') as batch_op:
        batch_op.add_column(sa.Column('agent_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('site_name', sa.String(), nullable=True))
        batch_op.create_foreign_key(
            'fk_scans_agent_id', 'agents', ['agent_id'], ['id']
        )

    # Add nullable agent_id and site_name columns to assets
    with op.batch_alter_table('assets') as batch_op:
        batch_op.add_column(sa.Column('agent_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('site_name', sa.String(), nullable=True))
        batch_op.create_foreign_key(
            'fk_assets_agent_id', 'agents', ['agent_id'], ['id']
        )


def downgrade() -> None:
    with op.batch_alter_table('assets') as batch_op:
        batch_op.drop_constraint('fk_assets_agent_id', type_='foreignkey')
        batch_op.drop_column('site_name')
        batch_op.drop_column('agent_id')

    with op.batch_alter_table('scans') as batch_op:
        batch_op.drop_constraint('fk_scans_agent_id', type_='foreignkey')
        batch_op.drop_column('site_name')
        batch_op.drop_column('agent_id')

    op.drop_table('agents')
