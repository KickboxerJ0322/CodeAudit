import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path

from app.gemini import analyze
from app.redaction import scrub
from app.report import finish_report, report_base
from app.repository import AuditError, fetch_repository
from app.scanners import scan


def cleanup_orphans(settings):
    root = settings.work_root.resolve()
    if not root.is_dir():
        return
    cutoff = time.time() - settings.timeout_seconds - 60
    for child in root.glob("audit-*"):
        if child.is_symlink() or not child.is_dir() or not child.resolve().is_relative_to(root):
            continue
        if child.stat().st_mtime < cutoff:
            shutil.rmtree(child, ignore_errors=True)


async def run_audit(audit_id, store, settings, fetcher=fetch_repository, scanner=scan, analyzer=analyze):
    if not store.claim(audit_id):
        return
    row = store.get(audit_id)
    started = time.monotonic()
    report = report_base(row)
    steps = row["steps"].copy()
    work = None
    def progress(step, state, message):
        steps[step] = state
        store.update(audit_id, steps=steps.copy(), message=message)
    try:
        settings.work_root.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="audit-", dir=settings.work_root)).resolve()
        seconds = min(settings.timeout_seconds, row["deadline"] - time.time())
        if seconds <= 0:
            raise AuditError("監査時間上限を超えました")
        async with asyncio.timeout(seconds):
            progress("github", "running", "公開リポジトリを安全に取得しています")
            repo = await fetcher(row["repository_url"], work, settings)
            report.update(commit_sha=repo.sha, files=sorted(repo.files), excluded_files=repo.excluded,
                          analyzed_file_count=len(repo.files), excluded_file_count=len(repo.excluded),
                          archive_bytes=repo.archive_bytes, expanded_bytes=repo.expanded_bytes,
                          target_line_count=sum(len(t.splitlines()) for t in repo.files.values()))
            progress("github", "completed", "GitHub取得が完了しました")
            progress("static", "running", "静的解析ツールで検査しています")
            static, tools, secrets = await scanner(repo, work, settings)
            report.update(findings=static, tools=tools)
            static_ok = all(tool["status"] == "completed" for tool in tools) and len(tools) == 3
            progress("static", "completed" if static_ok else "partial", "静的解析を終了しました。未検査項目はレポートに記録します")
            progress("gemini", "running", "全対象ファイルのAI分析と横断統合を確認しています")
            ai_findings, ai = await analyzer(repo, static, secrets, settings)
            report["findings"] += ai_findings
            report["ai"] = ai
            progress("gemini", ai["status"], ai["message"])
            progress("report", "running", "日本語レポートを生成しています")
            report["status"] = "completed" if static_ok and ai["status"] == "completed" and ai["cross_file_completed"] and not ai["unanalysed_files"] else "partial"
            report["summary"] = ai.get("summary", "静的解析とAI分析の実行状況を確認してください。未検査があるため安全性を判断できません。")
            report["warnings"] = [tool["tool"] + "：" + tool["message"] for tool in tools if tool["status"] != "completed"]
            if ai["status"] != "completed":
                report["warnings"].append(ai["message"])
            if repo.excluded:
                report["warnings"].append("除外ファイルは監査対象外です。ファイル一覧と除外理由を確認してください。")
            report["warnings"].append("秘密情報のマスキングは可能な範囲で行っています。未知の秘密形式を完全には検出できません。")
            # Store only masked strings, never source files, raw tool JSON or credentials.
            report = scrub(report, secrets)
            report["duration_seconds"] = round(time.monotonic() - started, 3)
            finish_report(report)
            if len(json.dumps(report, ensure_ascii=False).encode()) > settings.max_report_bytes:
                raise AuditError("レポート容量の上限を超えました。監査結果を省略して完了扱いにはしません")
            progress("report", "completed", "レポートを作成しました")
            store.update(audit_id, status=report["status"], report=report, steps=steps, message="監査完了" if report["status"] == "completed" else "部分監査：未検査項目があります")
    except (AuditError, TimeoutError) as exc:
        message = str(exc) if isinstance(exc, AuditError) else "監査時間上限を超えたため全体監査は未完了です"
        report.update(status="failed", summary=message)
        report["warnings"].append(message)
        steps = {k: "failed" if v in {"pending", "running"} else v for k, v in steps.items()}
        # Already collected findings are safe, but never preserve a huge partial report.
        if len(json.dumps(report, ensure_ascii=False).encode()) > settings.max_report_bytes:
            report = report_base(row)
            report.update(summary=message, warnings=[message])
        report["duration_seconds"] = round(time.monotonic() - started, 3)
        store.update(audit_id, status="failed", message=message, steps=steps, report=finish_report(report))
    except asyncio.CancelledError:
        store.update(audit_id, status="failed", message="ワーカーが中断されました。監査は未完了です", steps={k: "failed" if v in {"pending", "running"} else v for k, v in steps.items()})
        raise
    except Exception:
        # No raw exception logging: it could contain tokens/source or tool output.
        store.update(audit_id, status="failed", message="内部処理に失敗しました。監査は未完了です", report=report_base(row), steps={k: "failed" if v in {"pending", "running"} else v for k, v in steps.items()})
    finally:
        if work and work.is_relative_to(settings.work_root.resolve()):
            shutil.rmtree(work, ignore_errors=True)


class LocalDispatcher:
    def __init__(self, store, settings):
        self.store, self.settings, self.tasks = store, settings, set()

    async def submit(self, audit_id):
        task = asyncio.create_task(run_audit(audit_id, self.store, self.settings))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def close(self):
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class CloudDispatcher:
    def __init__(self, settings):
        self.settings = settings

    async def submit(self, audit_id):
        import google.auth
        from google.auth.transport.requests import Request
        import httpx
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        await asyncio.to_thread(credentials.refresh, Request())
        s = self.settings
        endpoint = f"https://run.googleapis.com/v2/projects/{s.project}/locations/{s.region}/jobs/{s.job_name}:run"
        async with httpx.AsyncClient(timeout=15, trust_env=False) as client:
            response = await client.post(endpoint, headers={"Authorization": "Bearer " + credentials.token}, json={"overrides": {"containerOverrides": [{"env": [{"name": "CODEAUDIT_AUDIT_ID", "value": audit_id}]}]}})
            if response.status_code not in {200, 201, 202}:
                raise AuditError("Cloud Run Jobsの起動に失敗しました")

    async def close(self):
        pass
