import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from google.cloud import firestore
from app.store import AdmissionError, TERMINAL, day_key, new_audit, usage_status


class FirestoreStore:
    """Admission is serialized by one tiny coordinator document, across API instances."""
    def __init__(self, settings):
        self.settings = settings
        self.client = firestore.Client(project=settings.project, database=settings.firestore_database)
        self.audits = self.client.collection("audits")
        self.coordinator = self.client.collection("control").document("admission")

    def create(self, url, identity):
        now, token = time.time(), secrets.token_urlsafe(32)
        row = new_audit(url, token, self.settings, now)
        ident = hmac.new(self.settings.identity_salt.get_secret_value().encode(), identity.encode(), hashlib.sha256).hexdigest()
        day = day_key(now)
        quota_ref = self.client.collection("quotas").document(day + "-" + ident)
        audit_ref = self.audits.document(row["id"])

        @firestore.transactional
        def admit(tx):
            control = self.coordinator.get(transaction=tx).to_dict() or {}
            quota = quota_ref.get(transaction=tx).to_dict() or {}
            active = {k: v for k, v in control.get("active", {}).items() if v > now}
            budget = control.get("budget", 0) if control.get("day") == day else 0
            daily_limit, daily_budget_usd = self.settings.effective_limits(now)
            if not self.settings.accepting_audits:
                raise AdmissionError(503, "現在、監査の受付を停止しています")
            if quota.get("count", 0) >= daily_limit:
                raise AdmissionError(429, "本日の利用回数上限に達しました")
            if len(active) >= self.settings.concurrency:
                raise AdmissionError(429, "同時監査の上限に達しています")
            if budget + self.settings.reservation() > daily_budget_usd:
                raise AdmissionError(503, "本日のAI予算上限に達しました")
            active[row["id"]] = row["deadline"]
            tx.set(self.coordinator, {"active": active, "day": day, "budget": budget + self.settings.reservation()})
            tx.set(quota_ref, {"count": quota.get("count", 0) + 1, "delete_at": datetime.now(timezone.utc) + timedelta(days=2)})
            tx.set(audit_ref, {**row, "delete_at": datetime.fromtimestamp(row["expires_at"], timezone.utc)})
        admit(self.client.transaction())
        return row, token

    def reset_daily_limits(self):
        """Reset current JST day's counters; never modify active audit records."""
        day = day_key(time.time())
        # Firestore quota docs are keyed by YYYY-MM-DD + '-' + hashed network.
        refs = list(self.client.collection("quotas").list_documents())
        # Only today's documents. Batch to respect Firestore write limits.
        today_refs = [ref for ref in refs if ref.id.startswith(day + "-")]
        for start in range(0, len(today_refs), 400):
            batch = self.client.batch()
            for ref in today_refs[start:start + 400]:
                batch.delete(ref)
            batch.commit()
        @firestore.transactional
        def reset(tx):
            current = self.coordinator.get(transaction=tx).to_dict() or {}
            if current.get("day") == day:
                tx.update(self.coordinator, {"budget": 0})
        reset(self.client.transaction())
        return day

    def usage(self, identity):
        now = time.time()
        day = day_key(now)
        ident = hmac.new(self.settings.identity_salt.get_secret_value().encode(), identity.encode(), hashlib.sha256).hexdigest()
        quota = self.client.collection('quotas').document(day + '-' + ident).get().to_dict() or {}
        control = self.coordinator.get().to_dict() or {}
        reserved = control.get('budget', 0) if control.get('day') == day else 0
        active = sum(deadline > now for deadline in control.get('active', {}).values())
        return usage_status(self.settings, quota.get('count', 0), reserved, active)

    def get(self, audit_id):
        row = self.audits.document(audit_id).get().to_dict()
        if row:
            row.pop("delete_at", None)
        return row

    def update(self, audit_id, **changes):
        ref = self.audits.document(audit_id)
        @firestore.transactional
        def change(tx):
            row = ref.get(transaction=tx).to_dict()
            control = self.coordinator.get(transaction=tx).to_dict() or {}
            if not row or row["status"] in TERMINAL or row["expires_at"] <= time.time():
                return
            tx.update(ref, changes)
            if changes.get("status") in TERMINAL:
                active = control.get("active", {})
                active.pop(audit_id, None)
                tx.update(self.coordinator, {"active": active})
        change(self.client.transaction())

    def claim(self, audit_id):
        ref = self.audits.document(audit_id)
        @firestore.transactional
        def claim(tx):
            row = ref.get(transaction=tx).to_dict()
            if not row or row["status"] != "queued" or row["deadline"] <= time.time():
                return False
            tx.update(ref, {"status": "running"})
            return True
        return claim(self.client.transaction())

    def cleanup(self):
        # Firestore TTL deletes expired records; access independently validates expires_at.
        pass
