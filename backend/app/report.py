from collections import Counter
from datetime import datetime, timezone

CATEGORIES = {"confirmed": "確認された問題", "configuration": "設定確認が必要な問題", "recommendation": "セキュリティ改善の推奨事項"}
SEVERITIES = {"critical": "重大", "high": "高", "medium": "中", "low": "低", "info": "情報"}
STATUS = {"completed": "監査完了", "partial": "部分監査", "failed": "失敗", "queued": "待機中", "running": "実行中"}


def report_base(row):
    return {"audit_id": row["id"], "repository_url": row["repository_url"], "commit_sha": None,
            "audited_at": datetime.now(timezone.utc).isoformat(), "expires_at": datetime.fromtimestamp(row["expires_at"], timezone.utc).isoformat(),
            "status": "failed", "summary": "", "files": [], "excluded_files": [], "analyzed_file_count": 0, "excluded_file_count": 0,
            "tools": [], "ai": {"status": "unavailable", "message": "未実行", "analyzed_files": [], "unanalysed_files": [], "cross_file_completed": False},
            "findings": [], "severity_counts": {key: 0 for key in SEVERITIES}, "warnings": [],
            "disclaimer": "問題が検出されなくても、安全性を完全には保証しません。静的検出は悪用可能性を証明するものではありません。"}


def finish_report(report):
    counts = Counter(item["severity"] for item in report["findings"])
    report["severity_counts"] = {key: counts[key] for key in SEVERITIES}
    return report


def markdown(report):
    def plain(value):
        # Do not render repository/AI text as active Markdown links, images or HTML.
        value = str(value).replace("\r", "")
        for char in "\\`*_{}[]<>()!#|":
            value = value.replace(char, "\\" + char)
        return value
    lines = ["# CodeAudit 監査レポート", "", f"- 対象：{plain(report['repository_url'])}", f"- コミットSHA：{report['commit_sha'] or '取得失敗'}",
             f"- 監査日時：{report['audited_at']}", f"- 閲覧期限：{report['expires_at']}", f"- 状態：{STATUS.get(report['status'], report['status'])}",
             f"- 分析対象：{report['analyzed_file_count']}ファイル / 除外：{report['excluded_file_count']}ファイル", "", plain(report["disclaimer"]), "", "## 監査範囲"]
    for tool in report["tools"]:
        lines.append(f"- {tool['tool']}：{tool['status']} / {plain(tool['message'])} / {plain(tool['rule_scope'])}")
    lines += [f"- Gemini：{report['ai']['status']} / {plain(report['ai']['message'])}", f"- 横断統合：{'実行済み' if report['ai']['cross_file_completed'] else '未完了'}", "", "## 重大度別件数"]
    lines += [f"- {label}：{report['severity_counts'][key]}件" for key, label in SEVERITIES.items()]
    for category, label in CATEGORIES.items():
        lines += ["", f"## {label}"]
        items = [item for item in report["findings"] if item["category"] == category]
        if not items:
            lines.append("該当指摘なし（安全の保証ではありません）。")
        for item in items:
            lines += ["", f"### {plain(item['title'])}", f"- 重大度：{SEVERITIES[item['severity']]}", f"- 検出元：{item['source']}",
                      f"- 場所：{plain(item['file'])}:{item['start_line']}-{item['end_line']}", f"- コードリンク：{item['github_url']}",
                      f"- AI確信度：{item['confidence'] if item['confidence'] is not None else '対象外'}", "", "**危険な理由**", plain(item["reason"]), "", "**想定される影響**", plain(item["impact"]), "", "**修正方法**", plain(item["remediation"]), "", "**マスク済み根拠**", plain(item["evidence"])]
    lines += ["", "## 分析対象ファイル"] + [f"- {plain(file)}" for file in report["files"]]
    lines += ["", "## 除外ファイル"] + [f"- {plain(item['file'])}：{plain(item['reason'])}" for item in report["excluded_files"]]
    lines += ["", "## 注意・未完了項目"] + [f"- {plain(value)}" for value in report["warnings"]]
    return "\n".join(lines) + "\n"
