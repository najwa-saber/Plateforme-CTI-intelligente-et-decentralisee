"""On-chain anchor identity: unique (chain_instance, chain_report_id) + chain_instance on transactions.

Non-destructive: a PARTIAL unique index (rows with a NULL chain_instance, i.e. historical reports anchored
before migration 0002, are excluded) and a new nullable column. No existing row is modified.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-17
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

WHERE = "chain_instance IS NOT NULL AND chain_report_id IS NOT NULL"


def upgrade() -> None:
    op.create_index("uq_reports_chain_anchor", "reports", ["chain_instance", "chain_report_id"], unique=True,
                    postgresql_where=sa.text(WHERE), sqlite_where=sa.text(WHERE))
    op.add_column("chain_transactions", sa.Column("chain_instance", sa.String(length=66), nullable=True))
    op.create_index("ix_chain_transactions_chain_instance", "chain_transactions", ["chain_instance"])


def downgrade() -> None:
    op.drop_index("ix_chain_transactions_chain_instance", table_name="chain_transactions")
    op.drop_column("chain_transactions", "chain_instance")
    op.drop_index("uq_reports_chain_anchor", table_name="reports")
