"""Module 2 reliability schema updates: attempt uniqueness and performance indexes

Revision ID: 002_reliability
Revises: 001_initial
Create Date: 2026-11-07 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "002_reliability"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Unique constraint preventing duplicate attempt numbers for the same delivery
    with op.batch_alter_table("delivery_attempts") as batch_op:
        batch_op.create_unique_constraint(
            "uq_delivery_attempts_delivery_attempt_number",
            ["delivery_id", "attempt_number"],
        )

    # 2. Composite index on deliveries for crash reaper: (status, lease_expires_at)
    op.create_index(
        "ix_deliveries_status_lease_expires",
        "deliveries",
        ["status", "lease_expires_at"],
        unique=False,
    )

    # 3. Composite index on deliveries for retry sweeper: (status, next_retry_at)
    op.create_index(
        "ix_deliveries_status_next_retry",
        "deliveries",
        ["status", "next_retry_at"],
        unique=False,
    )

    # 4. Index on delivery_attempts(status) to accelerate finding unfinished STARTED attempts
    op.create_index(
        op.f("ix_delivery_attempts_status"),
        "delivery_attempts",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_delivery_attempts_status"), table_name="delivery_attempts")
    op.drop_index("ix_deliveries_status_next_retry", table_name="deliveries")
    op.drop_index("ix_deliveries_status_lease_expires", table_name="deliveries")
    with op.batch_alter_table("delivery_attempts") as batch_op:
        batch_op.drop_constraint(
            "uq_delivery_attempts_delivery_attempt_number",
            type_="unique",
        )
