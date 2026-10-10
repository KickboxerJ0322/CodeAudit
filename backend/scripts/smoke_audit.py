"""Real public-repository smoke test, with AI always disabled. Never prints tokens/code."""
import argparse
import asyncio
import json
import tempfile
from pathlib import Path
from app.config import Settings
from app.runner import run_audit
from app.store import SQLiteStore


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', nargs='?', default='https://github.com/KickboxerJ0322/rain-map')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='codeaudit-smoke-') as work:
        settings = Settings(_env_file=None, database_path=Path(work) / 'audits.sqlite3', work_root=Path(work) / 'tmp', gemini_api_key='', ai_enabled=False, store='sqlite', dispatcher='local')
        store = SQLiteStore(settings)
        row, _ = store.create(args.url, 'smoke-test')
        await run_audit(row['id'], store, settings)
        result = store.get(row['id'])
        report = result['report'] or {}
        print(json.dumps({'status': result['status'], 'message': result['message'], 'sha': report.get('commit_sha'), 'files': report.get('analyzed_file_count'), 'excluded': report.get('excluded_file_count'), 'tools': [{k: t[k] for k in ('tool', 'status', 'message')} for t in report.get('tools', [])], 'ai_status': report.get('ai', {}).get('status'), 'findings': len(report.get('findings', []))}, ensure_ascii=True, indent=2))
        if result['status'] == 'failed':
            raise SystemExit(1)


asyncio.run(main())
