"""Migrations 0001 -> 0003 on an empty database must produce exactly the schema of the SQLAlchemy models."""
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

BACKEND = Path(__file__).resolve().parents[1]


def test_alembic_head_matches_models(tmp_path, monkeypatch):
    from app.core.config import get_settings
    from app.database.session import Base
    from app.models import entities  # noqa: F401

    url = f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    monkeypatch.setattr(get_settings(), "database_url", url)
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    command.upgrade(cfg, "head")

    engine = create_engine(url)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("select version_num from alembic_version").scalar() == "0003"
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff
    idx = {i["name"]: i for i in inspect(engine).get_indexes("reports")}
    assert idx["uq_reports_chain_anchor"]["unique"]
    assert "chain_instance" in {c["name"] for c in inspect(engine).get_columns("chain_transactions")}
