import { expect, test } from 'vitest';
import { validRepository } from './repository';
test('公開リポジトリ形式のみを受け付ける', () => {
  expect(validRepository('https://github.com/KickboxerJ0322/rain-map')).toBe(true);
  for (const url of ['http://github.com/a/b', 'https://github.com.evil/a/b', 'https://github.com/a/b/tree/main', 'https://github.com/a/b?x=1', 'https://github.com/a/..', 'https://user@github.com/a/b']) expect(validRepository(url)).toBe(false);
});
