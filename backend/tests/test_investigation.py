import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr

from app.gemini import Gemini, analyze, validate_finding
from app.models import AIResponse, AIFinding
from app.repository import Repository


def target(tmp_path):
    return Repository("https://github.com/a/b", "a" * 40, tmp_path,
                      {"a.py": "value = input()\neval(value)\n", "b.py": "from a import value\n"}, [], 50, 50)


def item():
    return AIFinding(severity="high", category="configuration", title="入力の実行",
                     file="a.py", start_line=2, end_line=2, evidence="eval(value)",
                     reason="入力経路を確認", impact="コード実行", remediation="evalを除去",
                     confidence=.8)


class ResearchEngine:
    def __init__(self, mode="withdraw"):
        self.calls = self.used_tokens = 0
        self.mode = mode
        self.prompts = []

    async def request(self, prompt):
        data = json.loads(prompt)
        self.prompts.append(data)
        self.calls += 1
        self.used_tokens += 100
        if "segments" in data:
            return AIResponse(summary="分割分析", analyzed_segments=data["expected_segment_ids"], findings=[item()])
        if "analysis" in data:
            path = "../secret" if self.mode == "path" else "a.py"
            end = 999 if self.mode == "range" else 2
            return AIResponse(summary="統合", analyzed_segments=data["expected_segment_ids"], findings=[],
                              research_requests=[{"target_id": "c000001", "question": "入力の生成元は？",
                                                  "ranges": [{"file": path, "start_line": 1, "end_line": end}]}])
        question = data["questions"][0]
        return AIResponse(summary="再確認", analyzed_segments=[], findings=[],
                          research_decisions=[] if self.mode == "missing" else [{
                              "request_id": question["request_id"],
                              "verdict": "uncertain" if self.mode == "repeat" else "withdraw",
                              "explanation": "根拠を確認しました",
                              "evidence": [{"file": "a.py", "start_line": 1, "end_line": 1,
                                            "quote": "invented" if self.mode == "quote" else "value = input()"}]}],
                          research_requests=[{"target_id": "c000001", "question": "再確認",
                                              "ranges": [{"file": "a.py", "start_line": 1, "end_line": 2}]}]
                          if self.mode == "repeat" else [])


def test_research_reads_selected_code_and_retracts_only_ai(settings, tmp_path):
    settings.gemini_api_key = SecretStr("test-key")
    engine = ResearchEngine()
    findings, metadata = asyncio.run(analyze(target(tmp_path), [], [], settings, engine))
    assert not findings
    assert metadata["status"] == "completed"
    assert metadata["research_completed"] and metadata["research_rounds"] == 1
    assert engine.calls == 3
    assert engine.prompts[-1]["questions"][0]["ranges"][0]["code"] == "value = input()\neval(value)"
    assert metadata["decision_history"][-1]["action"] == "AI指摘を取り下げ"


@pytest.mark.parametrize("mode", ["path", "range", "quote", "missing", "repeat"])
def test_unsafe_or_incomplete_research_cannot_complete(settings, tmp_path, mode):
    settings.gemini_api_key = SecretStr("test-key")
    engine = ResearchEngine(mode)
    findings, metadata = asyncio.run(analyze(target(tmp_path), [], [], settings, engine))
    assert metadata["status"] == "partial"
    assert not metadata["cross_file_completed"]
    assert not metadata["research_completed"]
    assert findings
    assert engine.calls <= 5  # two original calls plus three bounded research rounds
    if mode in {"path", "range"}:
        assert engine.calls == 2


def test_static_finding_is_not_deleted_by_ai(settings, tmp_path):
    settings.gemini_api_key = SecretStr("test-key")
    repo = target(tmp_path)
    static = validate_finding(item(), repo, repo.files, [])
    static["source"] = "semgrep"
    static["rule_id"] = "test-rule"
    _, metadata = asyncio.run(analyze(repo, [static], [], settings, ResearchEngine()))
    assert static["source"] == "semgrep"
    assert metadata["status"] == "completed"
    assert metadata["decision_history"][-1]["action"] == "静的指摘は保持"


def test_research_uses_existing_call_limit(settings, tmp_path):
    settings.gemini_api_key = SecretStr("test-key")
    settings.ai_max_calls = 2
    engine = ResearchEngine()
    _, metadata = asyncio.run(analyze(target(tmp_path), [], [], settings, engine))
    assert engine.calls == 2
    assert metadata["status"] == "partial"


@pytest.mark.parametrize("complete", [True, False])
def test_measured_input_output_cost_and_coverage(settings, tmp_path, complete):
    settings.gemini_api_key = SecretStr("test-key")

    def respond(request):
        if request.url.path.endswith(":countTokens"):
            return httpx.Response(200, json={"totalTokens": 10})
        body = json.loads(request.content)
        data = json.loads(body["contents"][0]["parts"][0]["text"])
        value = AIResponse(summary="完了", analyzed_segments=data["expected_segment_ids"], findings=[])
        usage = {"totalTokenCount": 20}
        if complete:
            usage["promptTokenCount"] = 10
        return httpx.Response(200, json={"usageMetadata": usage, "candidates": [
            {"finishReason": "STOP", "content": {"parts": [{"text": value.model_dump_json()}]}}]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await analyze(target(tmp_path), [], [], settings, Gemini(settings, client))
    _, metadata = asyncio.run(run())
    assert metadata["status"] == "completed"
    assert metadata["calls"] == 2
    assert metadata["target_lines"] == 3
    assert metadata["research_rounds"] == 0
    assert metadata["research_completed"]
    if complete:
        assert metadata["input_tokens"] == metadata["output_tokens"] == 20
        assert metadata["estimated_api_cost_usd"] == pytest.approx(.000056)
    else:
        assert metadata["input_tokens"] is None
        assert metadata["estimated_api_cost_usd"] is None


def test_research_masks_source_and_decision_text(settings, tmp_path):
    settings.gemini_api_key = SecretStr("test-key")
    repo = target(tmp_path)
    repo.files["a.py"] += 'password="private-value"\n'
    engine = ResearchEngine()
    _, metadata = asyncio.run(analyze(repo, [], ["private-value"], settings, engine))
    assert "private-value" not in json.dumps(engine.prompts)
    assert "private-value" not in json.dumps(metadata)
