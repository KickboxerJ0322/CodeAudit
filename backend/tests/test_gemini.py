import asyncio
import json
import httpx
import pytest
from pydantic import SecretStr
from app.gemini import Gemini, analyze, generation_schema, segments, validate_finding
from app.models import AIFinding, AIResponse
from app.redaction import mask, scrub
from app.repository import AuditError, Repository


def repo(tmp_path):
    return Repository('https://github.com/a/b', 'a' * 40, tmp_path, {'a.py': 'value = input()\neval(value)\n', 'b.py': 'from a import value\n'}, [], 50, 50)


def test_redaction_preserves_lines_and_json():
    secret = 'ghp_' + 'A' * 30
    text = f'password="dangerous-value"\nkey="{secret}"\n'
    result = mask(text)
    assert 'dangerous-value' not in result and secret not in result
    assert text.count('\n') == result.count('\n')
    assert '[REDACTED]' in scrub({'evidence': '{"password": "dangerous-value"}'})['evidence']
    assert json.loads(json.dumps(scrub({'evidence': text})))['evidence'] == result


def test_all_segments_preserve_every_line():
    files = {'a.py': 'one\ntwo\nthree\n', 'b.py': 'x\n'}
    parts = segments(files, 8)
    for file, code in files.items():
        assert ''.join(p['code'] for p in parts if p['file'] == file) == code


def test_oversized_single_line_is_losslessly_segmented():
    source = 'x' * 26001 + '\\n' + 'tail\\n'
    parts = segments({'long.js': source}, 24000)
    assert ''.join(part['code'] for part in parts) == source
    assert all(len(part['code']) <= 24000 for part in parts)
    assert parts[0]['start_line'] == 1 == parts[0]['end_line']
    assert parts[1]['start_line'] == 1
    assert parts[-1]['end_line'] == 2


def finding(**changes):
    return AIFinding(severity='high', category='confirmed', title='入力のコード実行', file=changes.get('file', 'a.py'), start_line=changes.get('start_line', 2), end_line=changes.get('end_line', 2), evidence=changes.get('evidence', 'eval(value)'), reason='外部入力が実行されます', impact='コード実行', remediation='evalを除去してください', confidence=.8)


def test_ai_location_is_not_exploit_confirmation(tmp_path):
    target = repo(tmp_path)
    result = validate_finding(finding(), target, target.files, [])
    assert result['category'] == 'configuration' and result['evidence_verified'] is True
    assert target.sha in result['github_url']
    for item in [finding(file='missing.py'), finding(end_line=99), finding(evidence='invented')]:
        assert validate_finding(item, target, target.files, []) is None


class FakeGemini:
    def __init__(self, omit=False, fail_integration=False):
        self.used_tokens, self.calls = 0, 0
        self.omit, self.fail_integration = omit, fail_integration
        self.prompts = []
    async def request(self, prompt):
        data = json.loads(prompt)
        self.prompts.append(data)
        self.calls += 1
        self.used_tokens += 100
        if 'segments' in data:
            ids = [p['id'] for p in data['segments']]
        else:
            if self.fail_integration:
                raise AuditError('integration failed')
            ids = [i for a in data['analysis'] for i in a['segments']]
        return AIResponse(summary='ファイル間の入力経路を確認しました', analyzed_segments=[] if self.omit else ids, findings=[])


def test_complete_analysis_and_cross_file(settings, tmp_path):
    settings.gemini_api_key = SecretStr('test-key')
    engine = FakeGemini()
    _, metadata = asyncio.run(analyze(repo(tmp_path), [], [], settings, engine))
    assert metadata['status'] == 'completed' and metadata['cross_file_completed'] is True
    assert metadata['analyzed_files'] == ['a.py', 'b.py']
    assert len(engine.prompts) == 2
    assert {p['file'] for p in engine.prompts[0]['segments']} == {'a.py', 'b.py'}


@pytest.mark.parametrize('omit,fail', [(True, False), (False, True)])
def test_incomplete_ai_cannot_be_complete(settings, tmp_path, omit, fail):
    settings.gemini_api_key = SecretStr('test-key')
    _, result = asyncio.run(analyze(repo(tmp_path), [], [], settings, FakeGemini(omit, fail)))
    assert result['status'] != 'completed' and result['cross_file_completed'] is False


def test_preflight_budget_rejects_before_generation(settings):
    settings.gemini_api_key = SecretStr('test-key')
    settings.ai_max_total_tokens = 3000
    calls = []
    def respond(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={'totalTokens': 5000})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(AuditError, match='上限'):
                await Gemini(settings, client).request('code')
    asyncio.run(run())
    assert len(calls) == 1 and calls[0].endswith(':countTokens')


def test_truncated_output_is_not_complete(settings):
    settings.gemini_api_key = SecretStr('test-key')
    def respond(request):
        if request.url.path.endswith(':countTokens'):
            return httpx.Response(200, json={'totalTokens': 10})
        return httpx.Response(200, json={'candidates': [{'finishReason': 'MAX_TOKENS'}]})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(AuditError, match='打ち切'):
                await Gemini(settings, client).request('code')
    asyncio.run(run())

def test_structured_json_config_matches_count_and_generation(settings):
    settings.gemini_api_key = SecretStr('test-key')
    configs = []
    def respond(request):
        payload = json.loads(request.content)
        body = payload.get('generateContentRequest', payload)
        config = body['generationConfig']
        assert config['responseMimeType'] == 'application/json'
        assert config['responseJsonSchema'] == generation_schema()
        assert 'responseFormat' not in config
        configs.append(config)
        if request.url.path.endswith(':countTokens'):
            return httpx.Response(200, json={'totalTokens': 10})
        value = AIResponse(summary='分析完了', analyzed_segments=[], findings=[]).model_dump_json()
        return httpx.Response(200, json={'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'text': value}]}}], 'usageMetadata': {'totalTokenCount': 20}})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = Gemini(settings, client)
            result = await engine.request('code')
            assert result.summary == '分析完了' and engine.used_tokens == 20
    asyncio.run(run())
    assert len(configs) == 2 and configs[0] == configs[1]

def test_generation_schema_keeps_title_field_and_local_bounds():
    from pydantic import ValidationError
    schema = generation_schema()
    finding_schema = schema['$defs']['AIFinding']
    assert 'title' in finding_schema['properties'] and 'title' in finding_schema['required']
    assert 'maxItems' not in json.dumps(schema) and 'maxLength' not in json.dumps(schema)
    with pytest.raises(ValidationError):
        AIResponse.model_validate({'summary': 'x' * 5001, 'analyzed_segments': [], 'findings': []})
    values = finding().model_dump()
    values['title'] = 'x' * 301
    with pytest.raises(ValidationError):
        AIFinding.model_validate(values)

def test_rejected_finding_does_not_mean_unanalysed_code(settings, tmp_path):
    settings.gemini_api_key = SecretStr('test-key')
    class Rejected(FakeGemini):
        async def request(self, prompt):
            result = await super().request(prompt)
            result.findings = [finding(evidence='invented')]
            return result
    _, metadata = asyncio.run(analyze(repo(tmp_path), [], [], settings, Rejected()))
    assert metadata['status'] == 'completed'
    assert metadata['cross_file_completed'] and metadata['rejected_findings'] == 2
    assert metadata['unanalysed_files'] == []


def test_coverage_diagnostics_do_not_store_unknown_text(settings, tmp_path):
    settings.gemini_api_key = SecretStr('test-key')
    class WrongIntegration(FakeGemini):
        async def request(self, prompt):
            result = await super().request(prompt)
            if 'analysis' in json.loads(prompt):
                result.analyzed_segments = ['untrusted-secret-text']
            return result
    _, metadata = asyncio.run(analyze(repo(tmp_path), [], [], settings, WrongIntegration()))
    assert metadata['status'] == 'partial' and not metadata['cross_file_completed']
    assert metadata['unanalysed_files'] == []
    diagnostic = metadata['coverage_diagnostics'][-1]
    assert diagnostic['missing_ids'] and diagnostic['unexpected_id_hashes']
    assert 'untrusted-secret-text' not in json.dumps(metadata)
    assert all(p['id'].startswith('s') for p in metadata['segment_manifest'])

def test_generation_schema_limits_response_ids_to_sent_segments():
    schema = generation_schema(['s000006', 's000002'])
    assert schema['properties']['analyzed_segments']['items']['enum'] == ['s000002', 's000006']
    assert 'enum' not in generation_schema()['properties']['analyzed_segments']['items']
