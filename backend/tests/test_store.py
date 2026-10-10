import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from app.store import AdmissionError, SQLiteStore


def test_concurrent_admission_and_single_claim(settings):
    store = SQLiteStore(settings)
    def create(i):
        try:
            return store.create("https://github.com/a/b", str(i))[0]
        except AdmissionError:
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = [r for r in pool.map(create, range(6)) if r]
    assert len(rows) == 2
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(lambda _: store.claim(rows[0]["id"]), range(4))) == 1


def test_daily_quota_survives_restart(settings):
    store = SQLiteStore(settings)
    for _ in range(3):
        row, _ = store.create("https://github.com/a/b", "identity")
        store.update(row["id"], status="partial")
    with pytest.raises(AdmissionError) as error:
        SQLiteStore(settings).create("https://github.com/a/b", "identity")
    assert error.value.status == 429


def test_budget_reservation_and_no_refund_on_failure(settings):
    from pydantic import SecretStr
    settings.gemini_api_key = SecretStr("test-key")
    settings.daily_budget_usd = 1.3
    store = SQLiteStore(settings)
    row, _ = store.create("https://github.com/a/b", "first")
    store.update(row["id"], status="failed")
    with pytest.raises(AdmissionError) as error:
        store.create("https://github.com/a/b", "second")
    assert error.value.status == 503


def test_stale_job_is_failed_and_cannot_resurrect(settings):
    store = SQLiteStore(settings)
    row, _ = store.create("https://github.com/a/b", "first")
    store.update(row["id"], deadline=time.time() - 1)
    store.cleanup()
    assert store.get(row["id"])["status"] == "failed"
    store.update(row["id"], status="completed")
    assert store.get(row["id"])["status"] == "failed"
