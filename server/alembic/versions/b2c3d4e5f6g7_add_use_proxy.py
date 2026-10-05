"""add use_proxy column

Revision ID: b2c3d4e5f6g7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-04 16:05:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6g7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column('scan_job', sa.Column('use_proxy', sa.Boolean(), server_default='false', nullable=False))

def downgrade() -> None:
    op.drop_column('scan_job', 'use_proxy')
