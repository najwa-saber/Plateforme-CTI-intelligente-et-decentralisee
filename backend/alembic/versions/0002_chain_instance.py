"""report.chain_instance: identity of the chain instance a report is anchored on (non-destructive)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("chain_instance", sa.String(length=66), nullable=True))


def downgrade() -> None:
    op.drop_column("reports", "chain_instance")
