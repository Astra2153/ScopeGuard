import base64
import os

import pytest

from app.config import settings
from app.ratelimit import reset_limits

TEST_MASTER_KEY = base64.b64encode(os.urandom(32)).decode()


@pytest.fixture(autouse=True)
def _test_settings(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    monkeypatch.setattr(settings, "master_key", TEST_MASTER_KEY)
    reset_limits()
    yield
    reset_limits()
