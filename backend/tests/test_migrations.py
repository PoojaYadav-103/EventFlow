import os
import tempfile
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config


def test_alembic_migration_upgrade_and_downgrade():
    """
    Verifies that the initial Alembic migration applies cleanly to a fresh database,
    creates all expected tables, columns, indexes, and constraints, and can be
    cleanly downgraded and re-upgraded.
    """
    # 1. Create a clean isolated temporary SQLite database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_test.db")
    db_url = f"sqlite:///{db_path}"

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    config = Config(alembic_ini)
    config.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)

    engine = sa.create_engine(db_url)

    try:
        # 2. Run alembic upgrade head
        command.upgrade(config, "head")

        # 3. Inspect schema to verify tables and columns
        inspector = sa.inspect(engine)
        table_names = set(inspector.get_table_names())
        expected_tables = {"endpoints", "events", "deliveries", "delivery_attempts", "outbox_events", "alembic_version"}
        assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"

        # Verify endpoints table columns
        endpoint_cols = {col["name"]: col for col in inspector.get_columns("endpoints")}
        assert "is_deleted" in endpoint_cols, "Missing 'is_deleted' in endpoints table"
        assert endpoint_cols["is_deleted"]["nullable"] is False

        # Verify deliveries table columns and nullability
        delivery_cols = {col["name"]: col for col in inspector.get_columns("deliveries")}
        assert "endpoint_id" in delivery_cols
        assert delivery_cols["endpoint_id"]["nullable"] is True, "deliveries.endpoint_id must be nullable"

        # Verify indexes on deliveries
        delivery_indexes = {idx["name"]: idx for idx in inspector.get_indexes("deliveries")}
        assert any("lease_expires_at" in idx["column_names"] for idx in delivery_indexes.values()), \
            "Missing index on deliveries.lease_expires_at"

        # 4. Downgrade to base
        command.downgrade(config, "base")
        inspector_after_down = sa.inspect(engine)
        tables_after_down = set(inspector_after_down.get_table_names())
        assert not {"endpoints", "events", "deliveries", "delivery_attempts", "outbox_events"}.intersection(tables_after_down)

        # 5. Re-upgrade to head (verify re-run idempotence)
        command.upgrade(config, "head")
        inspector_reup = sa.inspect(engine)
        assert expected_tables.issubset(set(inspector_reup.get_table_names()))

    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass

