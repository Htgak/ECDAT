"""Keep developer .env credentials out of test accounts and test startup."""
import pytest
from ecdat.apps.api.config import get_settings

@pytest.fixture(autouse=True)
def isolated_environment_credentials(monkeypatch):
    monkeypatch.setenv('AUTH_USERNAME','')
    monkeypatch.setenv('AUTH_PASSWORD','')
    monkeypatch.setenv('AUTH_USERS','')
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
