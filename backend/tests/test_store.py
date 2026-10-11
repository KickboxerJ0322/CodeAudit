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
    for _ in range(settings.effective_limits()[0]):
        row, _ = store.create("https://github.com/a/b", "identity")
        store.update(row["id"], status="partial")
    with pytest.raises(AdmissionError) as error:
        SQLiteStore(settings).create("https://github.com/a/b", "identity")
    assert error.value.status == 429


def test_budget_reservation_and_no_refund_on_failure(settings):
    from pydantic import SecretStr
    settings.gemini_api_key = SecretStr("test-key")
    settings.daily_budget_usd = settings.reservation()
    settings.temporary_limit_date_jst = "2099-01-01"
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
    settings.temporary_limit_date_jst = "2099-01-01"
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

def test_temporary_allowance_is_jst_calendar_day(settings):
    from datetime import datetime, timezone, timedelta
    jst = timezone(timedelta(hours=9))
    before = datetime(2026, 10, 10, 23, 59, 59, tzinfo=jst).timestamp()
    during = datetime(2026, 10, 11, 0, 0, 0, tzinfo=jst).timestamp()
    ending = datetime(2026, 10, 11, 23, 59, 59, tzinfo=jst).timestamp()
    after = datetime(2026, 10, 12, 0, 0, 0, tzinfo=jst).timestamp()
    assert settings.effective_limits(before) == (20, 80.0)
    assert settings.effective_limits(during) == (20, 60.0)
    assert settings.effective_limits(ending) == (20, 60.0)
    assert settings.effective_limits(after) == (20, 80.0)


def test_expanded_daily_budget_allows_twenty_reservations_and_stops_at_limit(settings):
    from pydantic import SecretStr
    settings.gemini_api_key = SecretStr("test-key")
    settings.temporary_limit_date_jst = "2099-01-01"
    assert settings.daily_budget_usd == 80.0
    assert settings.daily_limit == 20
    assert settings.reservation() == 4.0
    store = SQLiteStore(settings)
    for index in range(20):
        row, _ = store.create("https://github.com/a/b", str(index))
        store.update(row["id"], status="completed")
    usage = store.usage("another-network")
    assert usage["reserved_budget_usd"] == 80.0
    assert usage["block_code"] == "daily_budget"
    with pytest.raises(AdmissionError) as error:
        store.create("https://github.com/a/b", "another-network")
    assert error.value.status == 503


def test_cloud_price_expanded_budget_accepts_after_previous_stop(settings):
    from pydantic import SecretStr
    from app.store import usage_status
    settings.gemini_api_key = SecretStr("test-key")
    settings.temporary_limit_date_jst = "2099-01-01"
    settings.ai_price_ceiling_per_million = 5
    assert settings.reservation() == 3.6
    assert usage_status(settings, 1, 7.2, 0)["can_start"]
    assert not usage_status(settings, 1, 79.2, 0)["can_start"]
