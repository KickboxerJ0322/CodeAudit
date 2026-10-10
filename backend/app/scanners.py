import asyncio
import json
from urllib.parse import quote
import os
import shutil
import signal
import subprocess
import re
from pathlib import Path

from app.config import Settings
from app.models import Finding
from app.redaction import mask, scrub
from app.repository import Repository


async def run_process(args: list[str], work: Path, timeout: int, report: Path | None = None):
    home = work / "home"
    home.mkdir(exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "SystemRoot", "WINDIR", "PATHEXT", "COMSPEC", "LANG", "LC_ALL"}}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CACHE_HOME=str(home / "cache"), SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    process = await asyncio.create_subprocess_exec(*args, cwd=work, env=env, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, **options)
    waiter = asyncio.create_task(process.wait())
    try:
        async with asyncio.timeout(timeout):
            while process.returncode is None:
                if report and report.exists() and report.stat().st_size > 8_000_000:
                    raise ValueError("解析出力が上限を超えました")
                try:
                    await asyncio.wait_for(asyncio.shield(waiter), .2)
                except TimeoutError:
                    pass
            if report and report.exists() and report.stat().st_size > 8_000_000:
                raise ValueError("解析出力が上限を超えました")
            return process.returncode
    finally:
        if process.returncode is None:
            if os.name == "nt":
                killer = await asyncio.create_subprocess_exec("taskkill", "/PID", str(process.pid), "/T", "/F", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await killer.wait()
                if process.returncode is None:
                    process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        await waiter


def relative_file(value: str, root: Path) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return ""
    name = value.replace("\\", "/").removeprefix("./")
    if name.startswith(root.name + "/"):
        name = name[len(root.name) + 1:]
    return name


def constant_innerhtml_assignment(code: str) -> bool:
    """Recognize only direct constant HTML literals, not variable input."""
    match = re.search(r"\.innerHTML\s*=\s*(['\"\x60])([\s\S]*?)\1\s*;?\s*$", code)
    return bool(match and (match.group(1) != chr(96) or "${" not in match.group(2)))


def make_finding(repo, source, rule, severity, category, title, file, start, end, reason, impact, remediation, secrets):
    if file not in repo.files:
        return None
    lines = repo.files[file].splitlines()
    if not lines or start < 1 or end < start or end > len(lines):
        return None
    if source == "semgrep" and rule.endswith("javascript-innerhtml") and constant_innerhtml_assignment("\n".join(lines[start - 1:end])):
        return None
    evidence = mask("\n".join(lines[start - 1:end]), secrets)[:2000]
    from urllib.parse import quote
    return Finding(source=source, rule_id=mask(rule, secrets)[:200], severity=severity, category=category,
                   title=mask(title, secrets)[:300], file=file, start_line=start, end_line=end, evidence=evidence,
                   reason=mask(reason, secrets)[:2000], impact=mask(impact, secrets)[:2000], remediation=mask(remediation, secrets)[:3000],
                   evidence_verified=True, github_url=f"{repo.url}/blob/{repo.sha}/{quote(file, safe='/')}#L{start}-L{end}").model_dump()


def file_configuration_finding(repo, rule, severity, file, secrets):
    # Only trusted absence rules whose absence we can independently verify.
    instruction = {"AVD-DS-0002": "USER", "DS002": "USER", "DS-0002": "USER",
                   "AVD-DS-0026": "HEALTHCHECK", "DS026": "HEALTHCHECK", "DS-0026": "HEALTHCHECK"}.get(rule)
    if not instruction or file not in repo.files or Path(file).name.lower() != "dockerfile":
        return None
    code = repo.files[file]
    if re.search(r"(?im)^\s*" + instruction + r"\b", code):
        return None
    values = dict(source="trivy", rule_id=rule, severity=severity, category="configuration",
                  title=f"Dockerfileに{instruction}設定がありません", file=file,
                  start_line=1, end_line=max(1, len(code.splitlines())), evidence_scope="file",
                  evidence=f"ファイル全体を確認：{instruction}命令なし（特定行の指摘ではありません）",
                  reason=f"Trivyの欠如ルールと照合し、ファイル全体に{instruction}命令がないことを確認しました。ベースイメージや実行環境の設定は別途確認が必要です。",
                  impact="実効ユーザーや稼働状態の確認が不足する可能性があります。悪用可能性は未確認です。",
                  remediation=f"{instruction}の明示設定を検討し、ベースイメージとCloud Run側の設定も確認してください。",
                  evidence_verified=True, github_url=f"{repo.url}/blob/{repo.sha}/" + quote(file, safe="/"))
    return Finding.model_validate(scrub(values, secrets)).model_dump()


async def scan(repo: Repository, work: Path, settings: Settings) -> tuple[list[dict], list[dict], list[str]]:
    findings, statuses, secrets = [], [], []
    root = work / "scan-source"
    root.mkdir()
    for name, text in repo.files.items():
        # Do not let repository ignore/config files suppress our trusted rules.
        if Path(name).name in {".semgrepignore", ".gitleaksignore", ".trivyignore", ".trivyignore.yaml"}:
            continue
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8", newline="")
    ignore = work / "empty-ignore"
    ignore.write_text("", encoding="utf-8")
    trivy_config = work / "trivy-safe.yaml"
    trivy_config.write_text("{}", encoding="utf-8")
    gitleaks_config = work / "gitleaks-safe.toml"
    gitleaks_config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    rules = Path(__file__).parent / "rules" / "security.yml"
    for tool, binary in [("gitleaks", settings.gitleaks_bin), ("semgrep", settings.semgrep_bin), ("trivy", settings.trivy_bin)]:
        executable = shutil.which(binary)
        status = {"tool": tool, "status": "failed", "message": "", "scanned_files": [], "unscanned_files": [], "rule_scope": "", "rejected_findings": 0, "location_diagnostics": []}
        statuses.append(status)
        if not executable:
            status.update(status="unavailable", message="ツール未導入のため未検査です")
            continue
        output = work / f"{tool}.json"
        if tool == "gitleaks":
            # Keep raw secrets only in the isolated report long enough to redact all subsequent outputs.
            args = [executable, "dir", str(root), "--config", str(gitleaks_config), "--no-banner", "--no-color", "--report-format", "json", "--report-path", str(output), "--exit-code", "10", "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow", "--timeout", str(settings.tool_timeout_seconds)]
            status["rule_scope"] = "Gitleaks組み込みルール（Git履歴は対象外）"
        elif tool == "semgrep":
            args = [executable, "scan", "--jobs", "2", "--config", str(rules), "--json", "--output", str(output), "--metrics", "off", "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--max-target-bytes", str(settings.max_file_bytes), str(root)]
            status["rule_scope"] = "CodeAudit同梱ルール7種 / Python・JavaScript・TypeScript。一般的な全ルール監査ではありません"
        else:
            args = [executable, "fs", "--config", str(trivy_config), "--ignorefile", str(ignore), "--scanners", "vuln,misconfig", "--format", "json", "--output", str(output), "--exit-code", "0", "--timeout", f"{settings.tool_timeout_seconds}s", "--skip-version-check", str(root)]
            status["rule_scope"] = "ロックファイルの依存脆弱性・IaC構成。コンテナイメージ実体は未検査"
        try:
            code = await run_process(args, work, settings.tool_timeout_seconds, output)
            if code not in ({0, 10} if tool == "gitleaks" else {0}) or not output.exists():
                raise ValueError()
            data = json.loads(output.read_text(encoding="utf-8"))
            raw_findings = []
            if tool == "gitleaks":
                if not isinstance(data, list):
                    raise ValueError()
                for item in data:
                    value = item.get("Secret", "")
                    if isinstance(value, str) and len(value) >= 4:
                        secrets.append(value)
                for item in data:
                    raw_findings.append((item.get("RuleID", "secret"), "high", "confirmed", "秘密情報と思われる値がソースに含まれています", item.get("File", ""), int(item.get("StartLine", 0)), int(item.get("EndLine", 0)), "秘密情報のパターンと一致しました。値の有効性は未確認です。公開済みの場合は漏えいとして対応してください。", "第三者にキーが利用され、データ漏えいや課金につながる可能性があります。", "該当キーを失効・再発行し、環境変数やSecret Managerへ移してください。削除だけではGit履歴から消えません。"))
            elif tool == "semgrep":
                if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                    raise ValueError()
                status["scanned_files"] = [relative_file(x, root) for x in data.get("paths", {}).get("scanned", [])]
                status["unscanned_files"] = sorted(set(repo.files) - set(status["scanned_files"]))
                if data.get("errors"):
                    status.update(status="partial", message="解析エラーがあり、全ファイルの検査は完了していません")
                for item in data["results"]:
                    extra = item.get("extra", {})
                    raw_findings.append((item.get("check_id", "pattern"), "high" if extra.get("severity") == "ERROR" else "medium", "configuration", "危険な処理パターンの設定確認が必要です", item.get("path", ""), int(item.get("start", {}).get("line", 0)), int(item.get("end", {}).get("line", 0)), extra.get("message", "入力値と設定を確認してください"), "外部入力の到達経路によって、コード実行や情報漏えいの可能性があります。悪用可能性は未確認です。", extra.get("message", "外部入力を検証してください")))
            else:
                if not isinstance(data, dict) or not isinstance(data.get("Results", []), list) or "SchemaVersion" not in data:
                    raise ValueError()
                for result in data.get("Results", []):
                    file = result.get("Target", "").split(" (")[0]
                    for item in result.get("Vulnerabilities", []) or []:
                        rule = item.get("VulnerabilityID", "dependency")
                        package = item.get("PkgName", "")
                        # Locate actual manifest evidence rather than inventing a dependency line.
                        name = relative_file(file, root)
                        lines = repo.files.get(name, "").splitlines()
                        version = str(item.get("InstalledVersion", ""))
                        line = next((i for i, text in enumerate(lines, 1) if package and package in text and version and re.search(r'(?<![\w.])' + re.escape(version) + r'(?![\w.])', '\n'.join(lines[i-1:i+7]))), 0)
                        if not line:
                            status["rejected_findings"] += 1
                            status["location_diagnostics"].append({"rule_id": mask(rule, secrets)[:200], "reason": "dependency_location_unverified"})
                            status["message"] = "行番号の根拠を確認できない依存検出はレポートから除外しました"
                            status["status"] = "partial"
                            continue
                        raw_findings.append((rule, str(item.get("Severity", "MEDIUM")).lower(), "confirmed", f"依存ライブラリに既知の脆弱性：{rule}", name, line, line, f"{package} の検出バージョン {item.get('InstalledVersion', '')} は脆弱性DBに掲載されています。コードから到達するかは未確認です。", "脆弱な機能を利用している場合、情報漏えいやサービス停止につながる可能性があります。", f"修正版 {item.get('FixedVersion') or '未提供'} を確認し、更新後に互換性をテストしてください。"))
                    for item in result.get("Misconfigurations", []) or []:
                        cause = item.get("CauseMetadata", {})
                        raw_findings.append((item.get("ID", "configuration"), str(item.get("Severity", "MEDIUM")).lower(), "configuration", "構成ファイルのセキュリティ設定を確認してください", file, int(cause.get("StartLine", 0)), int(cause.get("EndLine", 0)), "Trivyの構成ルールに一致しました。運用環境への適用状況を確認してください。", "公開範囲や権限の設定により、アクセス範囲が広がる可能性があります。", "該当設定を最小権限・最小公開範囲に見直してください。"))
            for rule, severity, category, title, file, start, end, reason, impact, remediation in raw_findings:
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "info"
                finding = make_finding(repo, tool, rule, severity, category, title, relative_file(file, root), start, end, reason, impact, remediation, secrets)
                if not finding and tool == "trivy" and start == 0 and end == 0:
                    finding = file_configuration_finding(repo, rule, severity, relative_file(file, root), secrets)
                if finding:
                    if tool == "trivy" and category == "confirmed":
                        finding["evidence_scope"] = "dependency"
                    findings.append(finding)
                elif tool == "semgrep" and rule.endswith("javascript-innerhtml") and relative_file(file, root) in repo.files and constant_innerhtml_assignment("\n".join(repo.files[relative_file(file, root)].splitlines()[start - 1:end])):
                    continue
                else:
                    status["rejected_findings"] += 1
                    status["location_diagnostics"].append({"rule_id": mask(rule, secrets)[:200], "reason": "file_or_line_unverified"})
                    status.update(status="partial", message="実在パス・行番号の根拠を確認できない検出を除外しました")
            if status["status"] == "failed":
                status.update(status="completed", message="設定されたルールで検査を実行しました")
        except (OSError, ValueError, TypeError, KeyError, TimeoutError):
            status.update(status="failed", message="ツール実行・JSON検証・時間制限のいずれかで失敗しました。未検査として扱います")
        finally:
            output.unlink(missing_ok=True)
    # A later tool's finding must never expose a secret discovered by Gitleaks.
    findings = scrub(findings, secrets)
    return findings, statuses, secrets
