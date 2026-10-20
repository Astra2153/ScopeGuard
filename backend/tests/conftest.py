import pytest

from app.config import settings
from app.ratelimit import reset_limits


@pytest.fixture(autouse=True)
def _rate_limit_off_by_default(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    reset_limits()
    yield
    reset_limits()
