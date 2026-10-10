import time
import pytest
from fastapi.testclient import TestClient
from app.api import create_app
from app.report import report_base

URL = "https://github.com/KickboxerJ0322/rain-map"


class NoopDispatcher:
    async def submit(self, audit_id):
        pass
    async def close(self):
        pass


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings, dispatcher=NoopDispatcher())) as client:
        yield client


def test_limits_never_expose_keys(settings):
    settings.gemini_api_key = __import__('pydantic').SecretStr("very-secret-api-key")
    client = TestClient(create_app(settings, dispatcher=NoopDispatcher()))
    response = client.get("/api/limits")
    assert "very-secret" not in response.text
    assert response.json()["ai_configured"] is True
    assert response.headers["cache-control"] == "no-store"


def test_usage_tracks_accepted_requests(client):
    before = client.get('/api/usage')
    assert before.status_code == 200
    assert before.json()['used_today'] == 0
    response = client.post('/api/audits', json={'repository_url': URL})
    assert response.status_code == 202
    after = client.get('/api/usage')
    assert after.status_code == 200
    assert after.json()['used_today'] == 1
    assert after.json()['active_audits'] == 1
    assert after.headers['cache-control'] == 'no-store'


def test_create_and_token_access(client):
    response = client.post("/api/audits", json={"repository_url": URL})
    assert response.status_code == 202
    ticket = response.json()
    endpoint = f"/api/audits/{ticket['id']}"
    for suffix in ["", "/report", "/download"]:
        assert client.get(endpoint + suffix).status_code == 404
        assert client.get(endpoint + suffix, headers={"Authorization": "Bearer wrong"}).status_code == 404
    valid = {"Authorization": "Bearer " + ticket["view_token"]}
    result = client.get(endpoint, headers=valid)
    assert result.status_code == 200
    assert "token_hash" not in result.text and "view_token" not in result.text
    assert client.get(endpoint + "/report", headers=valid).status_code == 409
    row = client.app.state.store.get(ticket["id"])
    client.app.state.store.update(ticket["id"], status="partial", report=report_base(row))
    for format in ["json", "markdown"]:
        download = client.get(endpoint + "/download?format=" + format, headers=valid)
        assert download.status_code == 200
        assert "attachment" in download.headers["content-disposition"]
    assert client.get(endpoint + "/download?format=html", headers=valid).status_code == 422


def test_expired_audit_is_invisible_before_cleanup(client):
    ticket = client.post("/api/audits", json={"repository_url": URL}).json()
    client.app.state.store.update(ticket["id"], expires_at=time.time() - 1)
    assert client.get(f"/api/audits/{ticket['id']}", headers={"Authorization": "Bearer " + ticket["view_token"]}).status_code == 404
    client.app.state.store.cleanup()
    assert client.app.state.store.get(ticket["id"]) is None


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://github.com.evil/a/b", "https://github.com/a/b/tree/main", "https://github.com/a/b?x=1", "https://user@github.com/a/b", "https://github.com/a/..", "https://127.0.0.1/a/b"])
def test_invalid_urls(client, url):
    assert client.post("/api/audits", json={"repository_url": url}).status_code == 422


def test_large_body_rejected(client):
    assert client.post("/api/audits", content='x' * 5000, headers={"Content-Type": "application/json"}).status_code == 413


def test_intake_switch(settings):
    settings.accepting_audits = False
    client = TestClient(create_app(settings, dispatcher=NoopDispatcher()))
    assert client.post("/api/audits", json={"repository_url": URL}).status_code == 503


def test_packaged_ui(client):
    from app.config import ROOT
    if not (ROOT / 'frontend/dist/index.html').exists():
        pytest.skip('Run frontend build first')
    response = client.get('/')
    assert response.status_code == 200
    assert 'CodeAudit' in response.text
    assert "script-src 'self'" in response.headers['content-security-policy']
