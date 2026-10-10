export function validRepository(value: string): boolean {
  return /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9_.-]+\/?$/.test(value) && !['.', '..'].includes(value.split('/')[4]);
}
