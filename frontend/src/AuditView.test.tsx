import { expect, test } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { AuditMetrics, safeCodeLink } from './AuditView';
test('レポートの外部リンクはGitHubの固定コミットだけ許可する', () => {
  expect(safeCodeLink(`https://github.com/a/b/blob/${'a'.repeat(40)}/file.ts#L1`)).toBe(true);
  expect(safeCodeLink('javascript:alert(1)')).toBe(false);
  expect(safeCodeLink('https://github.com.evil/a/b')).toBe(false);
  expect(safeCodeLink('https://github.com/a/b/blob/main/file.ts')).toBe(false);
});

test('処理量と推定費用・判断履歴を表示し不可信なHTMLを実行しない', () => {
  const html = renderToStaticMarkup(createElement(AuditMetrics, { report: {
    analyzed_file_count: 2, target_line_count: 3, duration_seconds: 1.2,
    ai: { status: 'completed', message: '', cross_file_completed: true, analyzed_files: ['a.py', 'b.py'], unanalysed_files: [],
      input_tokens: 20, output_tokens: 20, estimated_api_cost_usd: .48, calls: 3, research_rounds: 1,
      decision_history: [{ stage: 'research_decision', message: '<script>alert(1)</script>', action: 'AI指摘を取り下げ',
        ranges: [{ file: 'a.py', start_line: 1, end_line: 2 }] }] }
  } }));
  expect(html).toContain('推定API費用');
  expect(html).toContain('$0.4800 USD');
  expect(html).toContain('AI指摘を取り下げ');
  expect(html).toContain('&lt;script&gt;');
  expect(html).not.toContain('<script>');
});
test('旧レポートや計測欠落をゼロ円と表示しない', () => {
  const html = renderToStaticMarkup(createElement(AuditMetrics, { report: {
    analyzed_file_count: 0, ai: { status: 'failed', message: '', cross_file_completed: false, analyzed_files: [], unanalysed_files: [] }
  } }));
  expect(html).toContain('算出不可');
  expect(html).toContain('未計測');
  expect(html).not.toContain('$0.0000');
});
