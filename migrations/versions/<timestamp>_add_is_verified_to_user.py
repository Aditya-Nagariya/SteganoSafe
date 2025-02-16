"""Add is_verified column to user table

Revision ID: <timestamp>
Revises: xyz789ghi012  # Replace with your actual previous revision id
Create Date: YYYY-MM-DD HH:MM:SS

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '<timestamp>'
down_revision = 'acc8485d5954'  # Updated with actual previous revision id
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('user', sa.Column('is_verified', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.alter_column('user', 'is_verified', server_default=None)

def downgrade():
    op.drop_column('user', 'is_verified')
