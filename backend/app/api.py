import asyncio
import hmac
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import ROOT, Settings
from app.models import AuditRequest
from app.report import markdown
from app.runner import CloudDispatcher, LocalDispatcher, cleanup_orphans
from app.store import AdmissionError, TERMINAL, authorize, make_store


def create_app(settings=None, store=None, dispatcher=None):
    settings = settings or Settings()
    store = store or make_store(settings)
    dispatcher = dispatcher or (CloudDispatcher(settings) if settings.dispatcher == "cloud_run" else LocalDispatcher(store, settings))

    @asynccontextmanager
    async def lifespan(app):
        async def housekeeping():
            while True:
                store.cleanup()
                cleanup_orphans(settings)
                await asyncio.sleep(60)
        cleaner = asyncio.create_task(housekeeping())
        store.cleanup()
        cleanup_orphans(settings)
        if isinstance(dispatcher, LocalDispatcher):
            for audit_id in store.queued():
                await dispatcher.submit(audit_id)
        yield
        cleaner.cancel()
        await asyncio.gather(cleaner, return_exceptions=True)
        await dispatcher.close()

    app = FastAPI(title="CodeAudit API", version="0.2.0", lifespan=lifespan)
    app.state.store = store

    @app.middleware("http")
    async def headers(request, call_next):
        if request.method == "POST" and request.url.path == "/api/audits":
            # Bound requests before JSON parsing, including chunked requests.
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    return Response(status_code=413, content="入力容量上限を超えました")
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        # Vite dev uses inline HMR scripts, so strict CSP only on the packaged production UI.
        if (ROOT / "frontend" / "dist").exists() and not request.url.path.startswith("/docs"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "0.2.0"}

    @app.get("/api/limits")
    async def limits():
        import shutil
        return {**settings.public_limits(), "ai_configured": settings.ai_enabled and (bool(settings.gemini_api_key.get_secret_value()) or settings.dispatcher == "cloud_run"), "tools_available": {name: bool(shutil.which(getattr(settings, name + "_bin"))) for name in ("gitleaks", "semgrep", "trivy")}, "tools_scope": "worker" if settings.dispatcher == "cloud_run" else "local"}

    @app.get("/api/usage")
    async def usage(request: Request):
        identity = request.client.host if request.client else "unknown"
        return store.usage(identity)

    @app.post("/api/admin/reset-daily-limits")
    async def reset_daily_limits(request: Request, authorization: str | None = Header(default=None)):
        # Disabled until a high-entropy admin credential is configured in Secret Manager.
        secret = settings.admin_reset_token.get_secret_value()
        candidate = authorization.removeprefix("Bearer ") if authorization and authorization.startswith("Bearer ") else ""
        if len(secret) < 32:
            raise HTTPException(503, "管理者リセットは未設定です")
        if len(candidate) > 512 or not hmac.compare_digest(candidate, secret):
            raise HTTPException(403, "管理者認証に失敗しました")
        day = store.reset_daily_limits()
        return {"day_jst": day, "message": "本日の回数とAI予算予約額をリセットしました"}

    @app.post("/api/audits", status_code=202)
    async def start_audit(payload: AuditRequest, request: Request):
        # Ignore user supplied X-Forwarded-For. Trust is configured at the ASGI server only.
        identity = request.client.host if request.client else "unknown"
        try:
            row, token = store.create(payload.repository_url, identity)
        except AdmissionError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        try:
            await dispatcher.submit(row["id"])
        except Exception as exc:
            store.update(row["id"], status="failed", message="ジョブ起動に失敗しました")
            raise HTTPException(503, "監査ジョブを起動できませんでした") from exc
        return {"id": row["id"], "view_token": token, "status": row["status"], "expires_at": row["expires_at"]}

    def accessible(audit_id, authorization):
        if not authorization or not authorization.startswith("Bearer ") or len(authorization) > 200:
            raise HTTPException(404, "監査が見つかりません")
        row = store.get(audit_id)
        if not authorize(row, authorization[7:]):
            raise HTTPException(404, "監査が見つかりません")
        if row["status"] not in TERMINAL and row["deadline"] <= time.time():
            store.update(audit_id, status="failed", message="監査時間上限またはワーカー中断により未完了です", steps={k: "failed" if v in {"pending", "running"} else v for k, v in row["steps"].items()})
            row = store.get(audit_id)
        return row

    @app.get("/api/audits/{audit_id}")
    async def status(audit_id: str, authorization: str | None = Header(default=None)):
        row = accessible(audit_id, authorization)
        return {key: row[key] for key in ("id", "repository_url", "status", "created_at", "expires_at", "steps", "message")}

    @app.get("/api/audits/{audit_id}/report")
    async def report(audit_id: str, authorization: str | None = Header(default=None)):
        row = accessible(audit_id, authorization)
        if row["report"] is None:
            raise HTTPException(409, row["message"] if row["status"] == "failed" else "レポートを準備中です")
        return row["report"]

    @app.get("/api/audits/{audit_id}/download")
    async def download(audit_id: str, format: str = Query(default="json", pattern="^(json|markdown)$"), authorization: str | None = Header(default=None)):
        row = accessible(audit_id, authorization)
        if row["report"] is None:
            raise HTTPException(409, "レポートを準備中です")
        content = markdown(row["report"]) if format == "markdown" else json.dumps(row["report"], ensure_ascii=False, indent=2)
        ext, mime = ("md", "text/markdown") if format == "markdown" else ("json", "application/json")
        return Response(content, media_type=mime, headers={"Content-Disposition": f'attachment; filename="codeaudit-{audit_id}.{ext}"'})

    dist = ROOT / "frontend" / "dist"
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
        @app.get("/")
        async def home():
            return FileResponse(dist / "index.html")
    return app
