import asyncio
import re
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from app.config import Settings
from app.gemini import Gemini, analyze
from app.models import AIResponse
from app.repository import AuditError, Repository


def test_deployed_limits_match_defaults():
    settings = Settings(_env_file=None)
    assert settings.ai_max_total_tokens == 720000
    assert settings.ai_max_cost_usd == 4.0
    root = Path(__file__).resolve().parents[2]
    for name in ("job.yaml", "service.yaml"):
        text = (root / "deploy" / name).read_text()
        daily = re.search(r"CODEAUDIT_DAILY_LIMIT, value: '([^']+)'", text)
        assert daily is not None and int(daily.group(1)) == settings.daily_limit
        for key, expected in (("TOTAL_TOKENS", settings.ai_max_total_tokens),
                              ("COST_USD", settings.ai_max_cost_usd)):
            value = re.search(r"CODEAUDIT_AI_MAX_" + key + r", value: '([^']+)'", text)
            assert value is not None
            assert float(value.group(1)) == expected


@pytest.mark.parametrize("kind,delta,allowed", [
    ("tokens", -1, True), ("tokens", 0, True), ("tokens", 1, False),
    ("cost", -1, True), ("cost", 0, True), ("cost", 1, False),
])
def test_cumulative_preflight_boundaries(settings, kind, delta, allowed):
    settings.gemini_api_key = SecretStr("test-key")
    settings.ai_price_ceiling_per_million = 5
    # Isolate token and cost constraints, including the new configured limits.
    boundary = 720000 if kind == "tokens" else 800000
    settings.ai_max_total_tokens = 720000 if kind == "tokens" else 1000000
    settings.ai_max_cost_usd = 4
    settings.ai_max_output_tokens = 6000
    paths = []

    def respond(request):
        paths.append(request.url.path)
        if request.url.path.endswith(":countTokens"):
            return httpx.Response(200, json={"totalTokens": 1000})
        value = AIResponse(summary="分析完了", analyzed_segments=[], findings=[]).model_dump_json()
        return httpx.Response(200, json={
            "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": value}]}}],
            "usageMetadata": {"totalTokenCount": 2000},
        })

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = Gemini(settings, client)
            previous = boundary - 7000 + delta
            engine.used_tokens = previous
            if allowed:
                await engine.request("code")
                assert engine.used_tokens == previous + 2000
                assert engine.calls == 1
            else:
                with pytest.raises(AuditError, match="上限"):
                    await engine.request("code")
                assert engine.used_tokens == previous
                assert engine.calls == 0
    asyncio.run(run())
    assert len(paths) == (2 if allowed else 1)
    assert paths[0].endswith(":countTokens")


def test_call_limit_blocks_before_any_http_request(settings):
    settings.gemini_api_key = SecretStr("test-key")
    paths = []

    def respond(request):
        paths.append(request.url.path)
        if request.url.path.endswith(":countTokens"):
            return httpx.Response(200, json={"totalTokens": 10})
        value = AIResponse(summary="分析完了", analyzed_segments=[], findings=[]).model_dump_json()
        return httpx.Response(200, json={
            "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": value}]}}],
            "usageMetadata": {"totalTokenCount": 20},
        })

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = Gemini(settings, client)
            engine.calls = settings.ai_max_calls - 1
            await engine.request("code")
            assert engine.calls == settings.ai_max_calls
            with pytest.raises(AuditError, match="呼び出し回数上限"):
                await engine.request("code")
            assert engine.used_tokens == 20
    asyncio.run(run())
    assert len(paths) == 2


def test_failed_generation_keeps_reservation_and_call(settings):
    settings.gemini_api_key = SecretStr("test-key")

    def respond(request):
        return (httpx.Response(200, json={"totalTokens": 1000})
                if request.url.path.endswith(":countTokens")
                else httpx.Response(503))

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = Gemini(settings, client)
            with pytest.raises(AuditError, match="応答に失敗"):
                await engine.request("code")
            assert engine.calls == 1
            assert engine.used_tokens == 1000 + settings.ai_max_output_tokens
    asyncio.run(run())


def test_cross_file_call_is_included_in_preflight(settings, tmp_path):
    settings.gemini_api_key = SecretStr("test-key")
    settings.ai_max_calls = 2
    settings.ai_chunk_chars = 1000
    target = Repository("https://github.com/a/b", "a" * 40, tmp_path,
                        {"a.py": "x = 1\n" * 500}, [], 3000, 3000)

    class NeverCalled:
        calls = 0
        used_tokens = 0

        async def request(self, prompt):
            pytest.fail("Preflight must reject before generation")

    _, metadata = asyncio.run(analyze(target, [], [], settings, NeverCalled()))
    assert metadata["status"] != "completed"
    assert not metadata["cross_file_completed"]
    assert metadata["calls"] == 0


def test_daily_reservation_uses_new_per_audit_ceiling(settings):
    settings.gemini_api_key = SecretStr("test-key")
    assert settings.reservation() == 4.0
    assert settings.daily_limit == 20
    assert settings.daily_budget_usd == 80.0
    settings.ai_enabled = False
    assert settings.reservation() == 0.0
