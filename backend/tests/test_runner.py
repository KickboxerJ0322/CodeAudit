import asyncio
import pytest
from app.repository import AuditError, Repository
from app.runner import run_audit
from app.store import SQLiteStore


async def fake_fetch(url, work, settings):
    root = work / 'source'
    root.mkdir()
    return Repository(url, 'a' * 40, root, {'a.py': 'print(1)\n'}, [], 10, 10)


async def failed_tools(repo, work, settings):
    return [], [{'tool': name, 'status': 'unavailable', 'message': '未導入', 'rule_scope': '', 'scanned_files': [], 'unscanned_files': ['a.py']} for name in ['gitleaks', 'semgrep', 'trivy']], []


def test_missing_tools_and_key_are_partial_and_workspace_removed(settings):
    store = SQLiteStore(settings)
    row, _ = store.create('https://github.com/a/b', 'test')
    asyncio.run(run_audit(row['id'], store, settings, fetcher=fake_fetch, scanner=failed_tools))
    result = store.get(row['id'])
    assert result['status'] == 'partial'
    assert result['report']['commit_sha'] == 'a' * 40
    assert result['report']['ai']['unanalysed_files'] == ['a.py']
    assert not list(settings.work_root.iterdir())


def test_fetch_failure_is_failed_and_cleans_workspace(settings):
    async def fail(url, work, settings):
        raise AuditError('取得失敗')
    store = SQLiteStore(settings)
    row, _ = store.create('https://github.com/a/b', 'test')
    asyncio.run(run_audit(row['id'], store, settings, fetcher=fail))
    assert store.get(row['id'])['status'] == 'failed'
    assert not list(settings.work_root.iterdir())


def test_static_full_but_ai_missing_stays_partial(settings):
    async def tools(repo, work, settings):
        values, statuses, secrets = await failed_tools(repo, work, settings)
        for status in statuses:
            status['status'] = 'completed'
        return values, statuses, secrets
    store = SQLiteStore(settings)
    row, _ = store.create('https://github.com/a/b', 'test')
    asyncio.run(run_audit(row['id'], store, settings, fetcher=fake_fetch, scanner=tools))
    assert store.get(row['id'])['status'] == 'partial'


@pytest.mark.parametrize('cross_file,missing,expected', [(True, [], 'completed'), (False, [], 'partial'), (True, ['a.py'], 'partial')])
def test_completion_requires_cross_file_and_full_coverage(settings, cross_file, missing, expected):
    async def tools(repo, work, config):
        values, statuses, secrets = await failed_tools(repo, work, config)
        for status in statuses:
            status['status'] = 'completed'
        return values, statuses, secrets
    async def ai(repo, static, secrets, config):
        return [], {'status': 'completed', 'message': '分析終了', 'cross_file_completed': cross_file, 'unanalysed_files': missing}
    store = SQLiteStore(settings)
    row, _ = store.create('https://github.com/a/b', 'test')
    asyncio.run(run_audit(row['id'], store, settings, fetcher=fake_fetch, scanner=tools, analyzer=ai))
    result = store.get(row['id'])
    assert result['status'] == expected
    assert result['report']['status'] == expected
    assert result['steps']['report'] == 'completed'


def test_stale_orphan_removed_but_active_work_preserved(settings):
    import os
    import time
    from app.runner import cleanup_orphans
    settings.work_root.mkdir()
    stale = settings.work_root / 'audit-old'
    active = settings.work_root / 'audit-active'
    stale.mkdir(); active.mkdir()
    old = time.time() - settings.timeout_seconds - 120
    os.utime(stale, (old, old))
    cleanup_orphans(settings)
    assert not stale.exists() and active.exists()
