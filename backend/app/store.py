import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from app.config import Settings

TERMINAL = {"completed", "partial", "failed", "rejected"}


class AdmissionError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


def day_key(now: float) -> str:
    return datetime.fromtimestamp(now, timezone(timedelta(hours=9))).strftime("%Y-%m-%d")


def new_audit(url: str, token: str, settings: Settings, now: float) -> dict:
    return {"id": secrets.token_urlsafe(24), "token_hash": hashlib.sha256(token.encode()).hexdigest(), "repository_url": url,
            "status": "queued", "created_at": now, "expires_at": now + settings.retention_hours * 3600,
            "deadline": now + settings.timeout_seconds + 30, "steps": {name: "pending" for name in ("github", "static", "gemini", "report")},
            "message": "監査を受け付けました", "report": None}


def authorize(row: dict | None, token: str, now: float | None = None) -> bool:
    return bool(row and row["expires_at"] > (now if now is not None else time.time()) and hmac.compare_digest(row["token_hash"], hashlib.sha256(token.encode()).hexdigest()))


def usage_status(settings, used_today, reserved_budget_usd, active_audits):
    """Advisory snapshot using the same ordering and thresholds as admission."""
    reservation = settings.reservation()
    daily_limit, daily_budget_usd = settings.effective_limits()
    if not settings.accepting_audits:
        reason = "監査受付を停止しています"
        code = "intake_closed"
    elif used_today >= daily_limit:
        reason = "本日の利用回数上限に達しました"
        code = "daily_limit"
    elif active_audits >= settings.concurrency:
        reason = "同時監査の上限に達しています。しばらくしてからお試しください"
        code = "concurrency"
    elif reserved_budget_usd + reservation > daily_budget_usd + 1e-9:
        reason = "サービス全体の本日のAI予算上限に達しました"
        code = "daily_budget"
    else:
        reason, code = "", "ready"
    return {
        "used_today": used_today,
        "remaining_today": max(0, daily_limit - used_today),
        "reserved_budget_usd": round(reserved_budget_usd, 4),
        "active_audits": active_audits,
        "next_audit_reservation_usd": round(reservation, 4),
        "can_start": code == "ready",
        "block_reason": reason,
        "block_code": code,
        "day_jst": day_key(time.time()),
        "identity_scope": "server_network",
        "budget_scope": "all_users",
        "budget_is_reservation": True,
    }


class SQLiteStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS audits(id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS quotas(key TEXT PRIMARY KEY, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS budgets(day TEXT PRIMARY KEY, amount REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);""")
            db.execute("INSERT OR IGNORE INTO metadata VALUES('identity_salt', ?)", (secrets.token_hex(32),))
            self.salt = settings.identity_salt.get_secret_value() or db.execute("SELECT value FROM metadata WHERE key='identity_salt'").fetchone()[0]

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.settings.database_path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def identity(self, value: str) -> str:
        return hmac.new(self.salt.encode(), value.encode(), hashlib.sha256).hexdigest()

    def _prune(self, db, now):
        for audit_id, data in db.execute("SELECT id,data FROM audits").fetchall():
            row = json.loads(data)
            if row["expires_at"] <= now:
                db.execute("DELETE FROM audits WHERE id=?", (audit_id,))
            elif row["status"] not in TERMINAL and row["deadline"] <= now:
                row.update(status="failed", message="監査時間上限またはワーカー中断により未完了です")
                row["steps"] = {k: ("failed" if v in {"pending", "running"} else v) for k, v in row["steps"].items()}
                db.execute("UPDATE audits SET data=? WHERE id=?", (json.dumps(row, ensure_ascii=False), audit_id))
        cutoff = day_key(now - 2 * 86400)
        db.execute("DELETE FROM quotas WHERE key < ?", (cutoff,))
        db.execute("DELETE FROM budgets WHERE day < ?", (cutoff,))

    def cleanup(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune(db, time.time())

    def create(self, url: str, identity: str) -> tuple[dict, str]:
        now, token = time.time(), secrets.token_urlsafe(32)
        row = new_audit(url, token, self.settings, now)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune(db, now)
            if not self.settings.accepting_audits:
                raise AdmissionError(503, "現在、監査の受付を停止しています")
            key = day_key(now) + ":" + self.identity(identity)
            quota = db.execute("SELECT count FROM quotas WHERE key=?", (key,)).fetchone()
            daily_limit, daily_budget_usd = self.settings.effective_limits(now)
            if quota and quota[0] >= daily_limit:
                raise AdmissionError(429, "本日の利用回数上限に達しました（日本時間の午前0時に更新）")
            active = sum(json.loads(data)["status"] not in TERMINAL for (data,) in db.execute("SELECT data FROM audits"))
            if active >= self.settings.concurrency:
                raise AdmissionError(429, "同時監査の上限に達しています。少し待ってからお試しください")
            day, reservation = day_key(now), self.settings.reservation()
            budget = db.execute("SELECT amount FROM budgets WHERE day=?", (day,)).fetchone()
            if (budget[0] if budget else 0) + reservation > daily_budget_usd:
                raise AdmissionError(503, "本日のAI予算上限に達したため受付を停止しています")
            db.execute("INSERT INTO quotas VALUES(?,1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key,))
            db.execute("INSERT INTO budgets VALUES(?,?) ON CONFLICT(day) DO UPDATE SET amount=amount+excluded.amount", (day, reservation))
            db.execute("INSERT INTO audits VALUES(?,?)", (row["id"], json.dumps(row, ensure_ascii=False)))
        return row, token

    def reset_daily_limits(self):
        """Administrator-only operation: clear today's quota and budget atomically."""
        today = day_key(time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM quotas WHERE key LIKE ?", (today + ":%",))
            db.execute("DELETE FROM budgets WHERE day=?", (today,))
        return today

    def usage(self, identity: str):
        now = time.time()
        day = day_key(now)
        with self.connection() as db:
            key = day + ':' + self.identity(identity)
            count = db.execute('SELECT count FROM quotas WHERE key=?', (key,)).fetchone()
            budget = db.execute('SELECT amount FROM budgets WHERE day=?', (day,)).fetchone()
            active = sum(json.loads(data)['status'] not in TERMINAL and json.loads(data)['deadline'] > now for (data,) in db.execute('SELECT data FROM audits'))
        return usage_status(self.settings, count[0] if count else 0, budget[0] if budget else 0.0, active)

    def get(self, audit_id: str):
        with self.connection() as db:
            result = db.execute("SELECT data FROM audits WHERE id=?", (audit_id,)).fetchone()
        return json.loads(result[0]) if result else None

    def update(self, audit_id: str, **changes):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            record = db.execute("SELECT data FROM audits WHERE id=?", (audit_id,)).fetchone()
            if not record:
                return
            row = json.loads(record[0])
            # A late worker cannot resurrect a terminal/expired audit.
            if row["status"] in TERMINAL or row["expires_at"] <= time.time():
                return
            row.update(changes)
            db.execute("UPDATE audits SET data=? WHERE id=?", (json.dumps(row, ensure_ascii=False), audit_id))

    def claim(self, audit_id: str) -> bool:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            record = db.execute("SELECT data FROM audits WHERE id=?", (audit_id,)).fetchone()
            row = json.loads(record[0]) if record else None
            if not row or row["status"] != "queued" or row["deadline"] <= time.time():
                return False
            row["status"] = "running"
            db.execute("UPDATE audits SET data=? WHERE id=?", (json.dumps(row, ensure_ascii=False), audit_id))
            return True

    def queued(self):
        with self.connection() as db:
            return [json.loads(data)["id"] for (data,) in db.execute("SELECT data FROM audits") if json.loads(data)["status"] == "queued"]


def make_store(settings: Settings):
    if settings.store == "firestore":
        from app.firestore_store import FirestoreStore
        return FirestoreStore(settings)
    return SQLiteStore(settings)
