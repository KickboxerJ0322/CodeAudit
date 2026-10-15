// File viewers may not retain the Blob MIME charset after a download.
export function markdownBlob(content: string): Blob {
  return new Blob(['\uFEFF', content.replace(/^\uFEFF+/, '')], { type: 'text/markdown;charset=utf-8' });
}
