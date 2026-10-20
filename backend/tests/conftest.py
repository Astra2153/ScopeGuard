import base64
import os

import psycopg
import pytest

TEST_DB = "scopeguard_test"
_PW = "change_me_dev_only"  # throwaway dev password, same as .env.example
ADMIN_URL = f"postgresql://scopeguard:{_PW}@127.0.0.1:5433/postgres?connect_timeout=5"

# Must be set BEFORE any app module is imported, so the app talks to the test database.
os.environ["DATABASE_URL"] = (
    f"postgresql+psycopg://scopeguard:{_PW}@127.0.0.1:5433/{TEST_DB}?connect_timeout=5"
)

from app.config import settings  # noqa: E402
from app.ratelimit import reset_limits  # noqa: E402

# A fixed, obviously-fake key: the append-only audit chain persists between test runs,
# so the key has to stay the same from run to run.
TEST_MASTER_KEY = base64.b64encode(b"T" * 32).decode()


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    assert settings.database_url.split("?")[0].endswith("/" + TEST_DB), (
        "tests must never run against the dev database"
    )
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (TEST_DB,)).fetchone()
        if not exists:
            conn.execute(f"CREATE DATABASE {TEST_DB}")
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")  # run pytest from the backend folder


@pytest.fixture(autouse=True)
def _test_settings(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    monkeypatch.setattr(settings, "master_key", TEST_MASTER_KEY)
    reset_limits()
    yield
    reset_limits()
