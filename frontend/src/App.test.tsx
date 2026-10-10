import { expect, test } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import App from './App';

test('ホームでAPI接続状況とサンプルを明示する', () => {
  const html = renderToStaticMarkup(<App />);
  expect(html).toContain('INFO');
  expect(html).not.toContain('AI SECURITY CODE REVIEW');
  expect(html).toContain('GitHubリポジトリURL');
  expect(html).not.toContain('コードを、複数の視点から。');
  expect(html).toContain('進捗サンプル');
  expect(html).toContain('結果サンプル');
});
