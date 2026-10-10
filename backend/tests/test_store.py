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
    for _ in range(settings.daily_limit):
        row, _ = store.create("https://github.com/a/b", "identity")
        store.update(row["id"], status="partial")
    with pytest.raises(AdmissionError) as error:
        SQLiteStore(settings).create("https://github.com/a/b", "identity")
    assert error.value.status == 429


def test_budget_reservation_and_no_refund_on_failure(settings):
    from pydantic import SecretStr
    settings.gemini_api_key = SecretStr("test-key")
    settings.daily_budget_usd = 3.0
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


def test_usage_reflects_admission_limit(settings):
    from app.store import usage_status
    settings.daily_limit = 10
    settings.daily_budget_usd = 10
    settings.concurrency = 2
    from pydantic import SecretStr
    settings.gemini_api_key = SecretStr("test-key")
    result = usage_status(settings, 1, 0.6, 0)
    assert result["can_start"] is True
    assert result["remaining_today"] == 9
    assert result["identity_scope"] == "server_network"
    assert result["budget_scope"] == "all_users"

    assert usage_status(settings, 10, 0, 0)["block_code"] == "daily_limit"
    assert usage_status(settings, 1, 0, 2)["block_code"] == "concurrency"
    assert usage_status(settings, 1, 10, 0)["block_code"] == "daily_budget"
    settings.accepting_audits = False
    assert usage_status(settings, 1, 0, 0)["block_code"] == "intake_closed"


def test_usage_shares_quota_across_sqlite_instances(settings):
    first = SQLiteStore(settings)
    assert first.usage("same-network")["used_today"] == 0
    row, _ = first.create("https://github.com/a/b", "same-network")
    first.update(row["id"], status="partial")
    second = SQLiteStore(settings)
    assert second.usage("same-network")["used_today"] == 1
    assert second.usage("other-network")["used_today"] == 0
