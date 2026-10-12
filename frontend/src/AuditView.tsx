import { useEffect, useState } from 'react';

export type Ticket = { id: string; view_token: string; expires_at: number };
type Status = { status: string; repository_url: string; message: string; steps: Record<string, string> };
type Finding = { source: string; sources?: string[]; severity: string; category: string; title: string; file: string; start_line: number; end_line: number; evidence: string; reason: string; impact: string; remediation: string; confidence: number | null; github_url: string; evidence_verified: boolean; evidence_scope?: string };
type Tool = { tool: string; status: string; message: string; rule_scope: string; scanned_files: string[]; unscanned_files: string[] };
type DecisionEvent = { stage: string; message: string; round?: number; verdict?: string; action?: string; target_id?: string; ranges: { file: string; start_line: number; end_line: number }[] };
type Metrics = { input_tokens?: number | null; output_tokens?: number | null; estimated_api_cost_usd?: number | null; budget_estimate_usd?: number; price_basis?: string; model?: string; research_rounds?: number; research_completed?: boolean; decision_history?: DecisionEvent[]; calls?: number; tokens?: number; analyzed_files: string[] };
type Report = { target_line_count?: number; duration_seconds?: number; repository_url: string; commit_sha: string | null; audited_at: string; expires_at: string; status: string; summary: string; analyzed_file_count: number; excluded_file_count: number; files: string[]; excluded_files: { file: string; reason: string }[]; tools: Tool[]; ai: Metrics & { status: string; message: string; cross_file_completed: boolean; analyzed_files: string[]; unanalysed_files: string[]; tokens?: number; calls?: number; rejected_findings?: number; coverage_diagnostics?: { stage: string; expected_count: number; returned_count: number; missing_ids: string[]; unexpected_id_hashes: string[]; duplicate_count: number }[] }; findings: Finding[]; severity_counts: Record<string, number>; warnings: string[]; disclaimer: string };
const states: Record<string, string> = { pending: '待機中', queued: '待機中', running: '実行中', completed: '完了', partial: '部分監査', unavailable: '未検査', failed: '失敗' };
const categories: Record<string, string> = { confirmed: '確認された問題', configuration: '設定確認が必要な問題', recommendation: 'セキュリティ改善の推奨事項' };
const severities: Record<string, string> = { critical: '重大', high: '高', medium: '中', low: '低', info: '情報' };

export function safeCodeLink(value: string): boolean {
  return /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+\/blob\/[a-f0-9]{40}\//.test(value);
}

export default function AuditView({ ticket }: { ticket: Ticket }) {
  const [status, setStatus] = useState<Status>();
  const [report, setReport] = useState<Report>();
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [downloading, setDownloading] = useState(false);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    async function poll() {
      try {
        const r = await fetch(`/api/audits/${ticket.id}`, { headers: { Authorization: `Bearer ${ticket.view_token}` }, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) });
        if (!r.ok) throw Error(r.status === 404 ? '閲覧期限切れ、または閲覧トークンが無効です。' : '進捗を取得できません。');
        const body: Status = await r.json();
        if (stopped) return;
        setStatus(body); setError('');
        if (['completed', 'partial', 'failed'].includes(body.status)) {
          const result = await fetch(`/api/audits/${ticket.id}/report`, { headers: { Authorization: `Bearer ${ticket.view_token}` }, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]) });
          if (result.ok) { const data: Report = await result.json(); if (!stopped) setReport(data); }
          else if (!stopped) setError('レポートを取得できません。監査状態の説明をご確認ください。');
        } else timer = setTimeout(poll, 2000);
      } catch (e) { if (!stopped) setError(e instanceof Error ? e.message : '接続に失敗しました。'); }
    }
    setReport(undefined); setStatus(undefined); poll();
    return () => { stopped = true; controller.abort(); clearTimeout(timer); };
  }, [ticket.id, ticket.view_token, retry]);
  async function download(format: 'json' | 'markdown') {
    setDownloading(true);
    try {
      const response = await fetch(`/api/audits/${ticket.id}/download?format=${format}`, { headers: { Authorization: `Bearer ${ticket.view_token}` }, signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw Error('ダウンロードできません。閲覧期限を確認してください。');
      const address = URL.createObjectURL(await response.blob());
      const link = document.createElement('a'); link.href = address; link.download = `codeaudit-${ticket.id}.${format === 'json' ? 'json' : 'md'}`; link.click();
      setTimeout(() => URL.revokeObjectURL(address), 1000);
    } catch (e) { setError(e instanceof Error ? e.message : 'ダウンロードに失敗しました。'); }
    finally { setDownloading(false); }
  }
  return <>
    <div className="eyebrow">REPOSITORY SECURITY AUDIT</div><h1 className="page-title">{report ? '監査レポート' : '監査の進捗'}</h1>
    <section className="panel"><p className="repository-name">{status?.repository_url ?? '監査情報を取得中…'}</p><p role="status">{status?.message}</p><ol className="steps">{[['github', 'GitHub取得'], ['static', '静的解析'], ['gemini', 'Gemini全体分析'], ['report', 'レポート生成']].map(([key, label], i) => <li key={key}><span className="step-num">{i + 1}</span><strong>{label}</strong><span className={`badge state-${status?.steps[key]}`}>{states[status?.steps[key] ?? 'pending'] ?? status?.steps[key]}</span></li>)}</ol><p className="muted">閲覧期限：{new Date(ticket.expires_at * 1000).toLocaleString('ja-JP')}。閲覧トークンは画面のメモリ内に保持します。再読み込みすると結果に戻れないため、レポートをダウンロードしてください。</p></section>
    {error && <div className="panel"><p className="error" role="alert">{error}</p><button className="secondary" onClick={() => setRetry(v => v + 1)}>再取得</button></div>}
    {report && <>
      <section className="panel report-meta"><div><h2>{states[report.status] ?? report.status}</h2><p className="muted">コミットSHA：<code>{report.commit_sha ?? '未取得'}</code><br/>監査日時：{new Date(report.audited_at).toLocaleString('ja-JP')}</p></div><div className="actions"><button className="secondary" disabled={downloading} onClick={() => download('markdown')}>Markdown ↓</button><button className="secondary" disabled={downloading} onClick={() => download('json')}>JSON ↓</button></div></section>
      <div className="severity-grid">{Object.entries(severities).map(([key, label], i) => <article className={`severity level-${i}`} key={key}><span>{label}</span><strong>{report.severity_counts[key] ?? 0}</strong><small>検出件数</small></article>)}</div>
      <section className="panel"><h2>監査の概要</h2><p className="muted">同じ根拠の重複指摘は統合して件数を表示しています。確認済みは悪用可能性の証明ではなく、設定確認と予防的な改善提案は別に掲載します。</p><p>{report.summary}</p><p className="muted">{report.disclaimer}</p>{report.warnings.length > 0 && <ul className="warnings">{report.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>}</section>
      {Object.entries(categories).map(([category, label]) => <section className="panel" key={category}><h2>{label} <span className="muted">{report.findings.filter(f => f.category === category).length}件</span></h2>{!report.findings.some(f => f.category === category) && <p className="muted">該当指摘なし。未検査項目がある場合は、その範囲の安全性は判断できません。</p>}{report.findings.filter(f => f.category === category).map((f, i) => <details className="finding" key={i}><summary><span className="badge">{severities[f.severity]}</span> {f.title}<span className="finding-location">{f.file}{f.evidence_scope === 'file' ? '（ファイル全体）' : `:${f.start_line}`} · {(f.sources ?? [f.source]).join(' + ')}</span></summary><div className="finding-body"><p className="muted">根拠の位置：{f.evidence_verified ? '検証済み' : '未検証'} · AI確信度：{f.confidence === null ? '対象外' : `${Math.round(f.confidence * 100)}%`}（安全性を保証する数値ではありません）</p>{safeCodeLink(f.github_url) && <a className="code-link" href={f.github_url} target="_blank" rel="noopener noreferrer">GitHubで該当コミットのコードを確認 ↗</a>}<h3>危険な理由</h3><p>{f.reason}</p><h3>想定される影響</h3><p>{f.impact}</p><h3>修正方法</h3><p>{f.remediation}</p><h3>マスク済みの根拠</h3><pre><code>{f.evidence}</code></pre></div></details>)}</section>)}
      <section className="panel"><h2>監査範囲</h2><p>対象：{report.analyzed_file_count}ファイル / 除外：{report.excluded_file_count}ファイル</p>{report.tools.map(tool => <details className="scope-detail" key={tool.tool}><summary>{tool.tool}：{states[tool.status]} — {tool.message}</summary><p className="muted">{tool.rule_scope}</p>{tool.unscanned_files.length > 0 && <><p>未検査・非対応ファイル：{tool.unscanned_files.length}件</p><ul>{tool.unscanned_files.map(file => <li key={file}>{file}</li>)}</ul></>}</details>)}<p>Gemini：{states[report.ai.status]} / 横断統合：{report.ai.cross_file_completed ? '完了' : '未完了'} / トークン：{report.ai.tokens ?? 0}</p><p className="muted">{report.ai.message}</p><p>根拠不一致で除外したAI指摘：{report.ai.rejected_findings ?? 0}件（分析完了状況とは別に集計）</p>{report.ai.coverage_diagnostics?.filter(d => d.missing_ids.length > 0 || d.unexpected_id_hashes.length > 0).map((d, i) => <p key={i}>分析範囲の照合：{d.stage} / 期待{d.expected_count}・回答{d.returned_count} / 不足ID：{d.missing_ids.join(', ') || 'なし'} / 不明ID：{d.unexpected_id_hashes.length}件</p>)}<details className="scope-detail"><summary>AI未分析ファイル：{report.ai.unanalysed_files.length}件</summary><ul>{report.ai.unanalysed_files.map(file => <li key={file}>{file}</li>)}</ul></details><details className="scope-detail"><summary>対象ファイル一覧</summary><ul>{report.files.map(file => <li key={file}>{file}</li>)}</ul></details><details className="scope-detail"><summary>除外ファイル一覧と理由</summary><ul>{report.excluded_files.map(f => <li key={f.file}>{f.file}：{f.reason}</li>)}</ul></details></section>
      <AuditMetrics report={report}/>
    </>}
  </>;
}

export function AuditMetrics({ report }: { report: Pick<Report, 'ai' | 'analyzed_file_count' | 'target_line_count' | 'duration_seconds'> }) {
  const ai = report.ai;
  const number = (value?: number | null) => value == null ? '未計測' : value.toLocaleString('ja-JP');
  const cost = (value?: number | null) => value == null ? '算出不可' : '$' + value.toFixed(4) + ' USD';
  const stages: Record<string, string> = { batch: '分割分析', integration: '横断統合', research_request: '追加調査の要求', research_decision: '追加調査の判断', stopped: '処理停止' };
  return <>
    <section className="panel"><h2>監査の判断履歴</h2><p className="muted">確認した範囲と、根拠に基づく判断の記録です。追加調査は取得済みコードの読み取りのみで、最大3回です。静的解析の指摘はAI判断だけでは削除しません。</p>
      {!ai.decision_history?.length ? <p className="muted">判断履歴は未記録です。</p> : <ol>{ai.decision_history.map((event, i) => <li key={i}><details className="scope-detail"><summary>{stages[event.stage] ?? event.stage}{event.round ? ' ' + event.round + '回目' : ''}{event.action ? ' — ' + event.action : ''}</summary><p>{event.message}</p>{event.target_id && <p className="muted">対象指摘：{event.target_id}</p>}<ul>{event.ranges.map((range, j) => <li key={j}>{range.file}:{range.start_line}–{range.end_line}</li>)}</ul></details></li>)}</ol>}
    </section>
    <section className="panel"><h2>処理量・費用</h2>
      <p>対象：{number(report.analyzed_file_count)}ファイル / {number(report.target_line_count)}行（設定・文書を含む）</p>
      <p>AI分析済み：{number(ai.analyzed_files?.length)}ファイル / 所要時間：{report.duration_seconds == null ? '未計測' : report.duration_seconds.toFixed(1) + '秒'}</p>
      <p>モデル：{ai.model ?? '未記録'} / AI生成呼び出し：{number(ai.calls)}回 / 追加調査：{number(ai.research_rounds)}回</p>
      <p>入力：{number(ai.input_tokens)} / 出力・思考：{number(ai.output_tokens)}トークン</p>
      <p>上限判定用トークン：{number(ai.tokens)}（応答失敗時の予約分を含む場合があります）</p>
      <p><strong>推定API費用：{cost(ai.estimated_api_cost_usd)}</strong></p>
      <p className="muted">{ai.price_basis ?? '旧レポートには料金の計測情報がありません。'} 入出力の計測が不完全な場合、推定費用は算出しません。</p>
      <p className="muted">上限判定用の保守的な金額：{cost(ai.budget_estimate_usd)}。日次予算の予約額・実際の請求額とは別です。</p>
    </section>
  </>;
}
