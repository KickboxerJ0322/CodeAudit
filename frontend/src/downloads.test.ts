import { expect, test } from 'vitest';
import { markdownBlob } from './downloads';

test('Markdown download has one UTF-8 BOM and preserves Japanese', async () => {
  const text = '# CodeAudit 画面サンプル\n\n実際の監査結果ではありません。';
  for (const input of [text, '\uFEFF' + text]) {
    const blob = markdownBlob(input);
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect([...bytes.slice(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(bytes[3]).toBe(0x23);
    expect(new TextDecoder('utf-8', { fatal: true }).decode(bytes)).toBe(text);
    expect(blob.type).toBe('text/markdown;charset=utf-8');
  }
});
