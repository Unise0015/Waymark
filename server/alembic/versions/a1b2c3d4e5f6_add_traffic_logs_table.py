"""Add traffic logs table

Revision ID: a1b2c3d4e5f6
Revises: 1932313fcc57
Create Date: 2026-10-04 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '1932313fcc57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('traffic_logs',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('method', sa.String(), nullable=False),
    sa.Column('url', sa.String(), nullable=False),
    sa.Column('path', sa.String(), nullable=False),
    sa.Column('query_params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('request_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('request_body', sa.String(), nullable=True),
    sa.Column('response_status', sa.Integer(), nullable=True),
    sa.Column('response_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('response_body', sa.String(), nullable=True),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_traffic_logs_created_at'), 'traffic_logs', ['created_at'], unique=False)
    op.create_index(op.f('ix_traffic_logs_method'), 'traffic_logs', ['method'], unique=False)
    op.create_index(op.f('ix_traffic_logs_path'), 'traffic_logs', ['path'], unique=False)
    op.create_index(op.f('ix_traffic_logs_response_status'), 'traffic_logs', ['response_status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_traffic_logs_response_status'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_path'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_method'), table_name='traffic_logs')
    op.drop_index(op.f('ix_traffic_logs_created_at'), table_name='traffic_logs')
    op.drop_table('traffic_logs')
