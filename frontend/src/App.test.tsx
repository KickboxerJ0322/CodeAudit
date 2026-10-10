import { expect, test } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import App from './App';

test('ホームでAPI接続状況とサンプルを明示する', () => {
  const html = renderToStaticMarkup(<App />);
  expect(html).toContain('APIの設定を確認中です');
  expect(html).toContain('GitHubリポジトリURL');
  expect(html).toContain('進捗サンプル');
  expect(html).toContain('結果サンプル');
});
