from app.report import consolidate_findings, finish_report, markdown, report_base


def finding(source, cve, line, category="confirmed", title=None, evidence=None, reason="既知の問題"):
    return {"source": source, "rule_id": cve or "javascript-innerhtml",
            "severity": "medium", "category": category, "title": title or cve or "innerHTML",
            "file": "package-lock.json" if cve else "public/app.js",
            "start_line": line, "end_line": line, "evidence": evidence or ("code:" + str(line)),
            "reason": reason, "impact": "", "remediation": "更新を検討", "confidence": .8 if source == "gemini" else None,
            "github_url": "", "evidence_verified": True, "evidence_scope": "line"}


def test_same_cve_merges_but_different_cves_remain():
    values = [finding("trivy", "CVE-2026-82417", 581),
              finding("gemini", "CVE-2026-82417", 581),
              finding("trivy", "CVE-2026-82562", 581),
              finding("gemini", "CVE-2026-82562", 581)]
    merged = consolidate_findings(values)
    assert len(merged) == 2
    assert all(set(x["sources"]) == {"trivy", "gemini"} for x in merged)


def test_suggestion_merges_with_same_location_without_inflating_risk():
    values = [finding("semgrep", None, 129, category="configuration"),
              finding("gemini", None, 129, category="configuration",
                      title="固定HTMLの予防策", reason="将来的に外部入力が混入するかもしれません")]
    merged = consolidate_findings(values)
    assert len(merged) == 1
    assert merged[0]["source"] == "semgrep"
    assert merged[0]["category"] == "configuration"
    assert set(merged[0]["sources"]) == {"semgrep", "gemini"}


def test_unrelated_lines_and_future_only_recommendations_remain_separate():
    a = finding("gemini", None, 129, category="configuration", reason="将来的に変更される可能性")
    b = finding("semgrep", None, 300, category="configuration")
    merged = consolidate_findings([a, b])
    assert len(merged) == 2
    assert next(x for x in merged if x["start_line"] == 129)["category"] == "recommendation"


def test_report_counts_after_merging():
    row = {"id": "a", "repository_url": "https://github.com/a/b", "expires_at": 1900000000}
    report = report_base(row)
    report["findings"] = [finding("trivy", "CVE-2026-82417", 581),
                          finding("gemini", "CVE-2026-82417", 581)]
    finish_report(report)
    assert report["severity_counts"]["medium"] == 1
    assert report["merged_findings"] == 1
    assert "gemini, trivy" in markdown(report)
