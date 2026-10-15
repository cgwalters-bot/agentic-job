import { isIP } from 'node:net';

export function destinations(text) {
  const found = new Set();
  for (const line of text.split('\n')) {
    const match = line.match(/\bIP6? .* > ([0-9a-fA-F:.]+): /);
    if (!match) continue;
    const endpoint = match[1];
    const dot = endpoint.lastIndexOf('.');
    const address = endpoint.slice(0, dot);
    const port = endpoint.slice(dot + 1);
    if (isIP(address) && /^\d+$/.test(port) && Number(port) <= 65535) {
      found.add(`${isIP(address) === 6 ? `[${address}]` : address}:${port}`);
    } else if (isIP(endpoint)) {
      found.add(endpoint);
    }
  }
  return [...found].sort();
}
