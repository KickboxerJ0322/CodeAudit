import asyncio
import json
from pathlib import Path
from app.repository import Repository
from app.scanners import scan


def test_three_tool_formats_redact_and_merge(settings, tmp_path, monkeypatch):
    secret = 'secret-value-12345'
    files = {'a.py': f'token="{secret}"\neval(value)\n', 'package-lock.json': '{"some-package": "1.0.0"}\n', '.gitleaks.toml': '[extend]\nuseDefault = false\n'}
    repo = Repository('https://github.com/a/b', 'a' * 40, tmp_path / 'source', files, [], 100, 100)
    monkeypatch.setattr('app.scanners.shutil.which', lambda name: name)
    async def process(args, work, timeout, report):
        if args[0] == 'gitleaks':
            trusted_config = Path(args[args.index('--config') + 1])
            assert trusted_config.parent == work
            assert trusted_config.read_text(encoding='utf-8') == '[extend]\nuseDefault = true\n'
            value = [{'RuleID': 'key', 'File': 'a.py', 'StartLine': 1, 'EndLine': 1, 'Secret': secret}]
        elif args[0] == 'semgrep':
            value = {'results': [{'check_id': 'eval', 'path': 'a.py', 'start': {'line': 2}, 'end': {'line': 2}, 'extra': {'message': 'evalを確認', 'severity': 'WARNING'}}], 'paths': {'scanned': ['a.py']}, 'errors': []}
        else:
            value = {'SchemaVersion': 2, 'Results': [{'Target': 'package-lock.json', 'Vulnerabilities': [{'VulnerabilityID': 'CVE-example', 'PkgName': 'some-package', 'InstalledVersion': '1.0.0', 'FixedVersion': '2.0.0', 'Severity': 'HIGH'}]}]}
        report.write_text(json.dumps(value), encoding='utf-8')
        return 10 if args[0] == 'gitleaks' else 0
    monkeypatch.setattr('app.scanners.run_process', process)
    findings, tools, secrets = asyncio.run(scan(repo, tmp_path, settings))
    assert len(findings) == 3 and all(tool['status'] == 'completed' for tool in tools)
    assert secret not in json.dumps(findings) and secrets == [secret]
    assert not list(tmp_path.glob('gitleaks.json'))


def test_tool_failure_never_success(settings, tmp_path, monkeypatch):
    repo = Repository('https://github.com/a/b', 'a' * 40, tmp_path / 'source', {'a.py': 'x\n'}, [], 1, 1)
    monkeypatch.setattr('app.scanners.shutil.which', lambda name: name)
    async def fail(*args):
        return 2
    monkeypatch.setattr('app.scanners.run_process', fail)
    findings, tools, _ = asyncio.run(scan(repo, tmp_path, settings))
    assert not findings and all(tool['status'] == 'failed' for tool in tools)

def test_filewide_absence_requires_independent_evidence(tmp_path):
    from app.scanners import file_configuration_finding
    target = Repository('https://github.com/a/b', 'a' * 40, tmp_path,
                        {'Dockerfile': 'FROM node:22-alpine\nCMD ["node", "app.js"]\n'}, [], 10, 10)
    item = file_configuration_finding(target, 'AVD-DS-0002', 'high', 'Dockerfile', [])
    assert item['evidence_scope'] == 'file' and item['evidence_verified']
    assert '#L' not in item['github_url']
    assert file_configuration_finding(target, 'UNKNOWN', 'high', 'Dockerfile', []) is None
    assert file_configuration_finding(target, 'AVD-DS-0002', 'high', '../Dockerfile', []) is None
    target.files['Dockerfile'] += 'USER node\n'
    assert file_configuration_finding(target, 'AVD-DS-0002', 'high', 'Dockerfile', []) is None
