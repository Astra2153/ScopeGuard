from sqlalchemy import inspect, text

from app.db import engine


def test_database_connects():
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


def test_expected_tables_exist():
    names = set(inspect(engine).get_table_names())
    assert {"users", "engagements", "targets", "findings", "audit_log"} <= names
