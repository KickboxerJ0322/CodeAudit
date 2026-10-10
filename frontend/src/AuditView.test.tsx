import { expect, test } from 'vitest';
import { safeCodeLink } from './AuditView';
test('レポートの外部リンクはGitHubの固定コミットだけ許可する', () => {
  expect(safeCodeLink(`https://github.com/a/b/blob/${'a'.repeat(40)}/file.ts#L1`)).toBe(true);
  expect(safeCodeLink('javascript:alert(1)')).toBe(false);
  expect(safeCodeLink('https://github.com.evil/a/b')).toBe(false);
  expect(safeCodeLink('https://github.com/a/b/blob/main/file.ts')).toBe(false);
});
