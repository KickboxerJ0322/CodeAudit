import pytest
from app.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, database_path=tmp_path / "audits.sqlite3", work_root=tmp_path / "work", gemini_api_key="", identity_salt="test-salt", max_file_bytes=1000)
