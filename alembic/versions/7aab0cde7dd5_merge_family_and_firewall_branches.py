"""merge family and firewall branches

Revision ID: 7aab0cde7dd5
Revises: a2b3c4d5e6f7, d5e6f7a8b9c0
Create Date: 2026-02-11 06:30:56.807124
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7aab0cde7dd5'
down_revision: Union[str, None] = ('a2b3c4d5e6f7', 'd5e6f7a8b9c0')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
