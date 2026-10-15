import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { refresh, setting, propose, publish } from './refresh-feed.mjs';

const text = 'const DENYLIST_COMMIT: &str = "old";\n\nconst DENYLIST_SHA256: &str = "oldhash";\n';
const commit = 'a'.repeat(40);
const bytes = Buffer.from('# feed\nmalware.example\n');

test('changes only the two pins and hashes the exact downloaded bytes', () => {
  const result = refresh(text, commit, bytes);
  assert.equal(setting(result, 'DENYLIST_COMMIT'), commit);
  assert.equal(setting(result, 'DENYLIST_SHA256'), createHash('sha256').update(bytes).digest('hex'));
  assert.equal(result.replace(commit, 'old').replace(setting(result, 'DENYLIST_SHA256'), 'oldhash'), text);
  assert.equal(refresh(result, commit, bytes), result);
});

test('refuses malformed commits, oversized/empty/error feeds and ambiguous source', () => {
  for (const bad of ['', 'main', '../evil', 'a'.repeat(41)]) {
    assert.throws(() => refresh(text, bad, bytes), /commit/);
  }
  for (const bad of ['', '# comments only\n', '<html>error</html>', 'good.example\nnot a domain', 'x'.repeat(16 * 1024 * 1024 + 1)]) {
    assert.throws(() => refresh(text, commit, Buffer.from(bad)), /feed/);
  }
  assert.throws(() => refresh('', commit, bytes), /expected one/);
  assert.throws(() => refresh(text + text, commit, bytes), /expected one/);
});

test('resolves configured upstream once, then fetches only the immutable commit', async () => {
  const configured = `${text}const DENYLIST_REPOSITORY: &str = "https://raw.githubusercontent.com/example/feed";\nconst DENYLIST_FILE: &str = "lists/domains.txt";\n`;
  const calls = [];
  const result = await propose(configured, async (url, maximum) => {
    calls.push([url, maximum]);
    return calls.length === 1 ? Buffer.from(JSON.stringify([{ sha: commit }])) : bytes;
  });
  assert.equal(setting(result, 'DENYLIST_COMMIT'), commit);
  assert.deepEqual(calls, [
    ['https://api.github.com/repos/example/feed/commits?path=lists%2Fdomains.txt&per_page=1', 256 * 1024],
    [`https://raw.githubusercontent.com/example/feed/${commit}/lists/domains.txt`, 16 * 1024 * 1024],
  ]);
  await assert.rejects(propose(configured, async () => Buffer.from('[{"sha":"main"}]')), /invalid upstream commit/);
  await assert.rejects(propose(configured.replace('raw.githubusercontent.com', 'evil.example')), /unsupported/);
  await assert.rejects(propose(configured.replace('lists/domains.txt', '../domains.txt')), /invalid feed path/);
});

test('publishing is bounded and does not touch an open proposal or unchanged source', () => {
  const pinned = refresh(text, commit, bytes);
  for (const prs of [[{ headRefName: 'maintenance/threat-feed-older', isCrossRepository: false }], Array(100).fill({ headRefName: 'other' })]) {
    const calls = [];
    publish(pinned, 'example/project', (cmd, args) => {
      calls.push([cmd, args]);
      return JSON.stringify(prs);
    });
    assert.equal(calls.length, 1);
  }
  const calls = [];
  publish(pinned, 'example/project', (cmd, args) => {
    calls.push([cmd, args]);
    return cmd === 'gh' ? '[]' : '';
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[1][1][0], 'diff');
});

test('publishing creates one draft with explicit repository and no force push', () => {
  const calls = [];
  publish(refresh(text, commit, bytes), 'example/project', (cmd, args) => {
    calls.push([cmd, args]);
    return cmd === 'gh' && args[0] === 'pr' && args[1] === 'list'
      ? JSON.stringify([{ headRefName: 'maintenance/threat-feed-attacker', isCrossRepository: true }]) : 'diff';
  });
  const create = calls.find(([cmd, args]) => cmd === 'gh' && args[1] === 'create')[1];
  assert.ok(create.includes('--draft'));
  assert.ok(create.includes('example/project'));
  assert.deepEqual(calls.find(([cmd, args]) => cmd === 'git' && args[0] === 'push')[1],
    ['push', 'origin', `HEAD:refs/heads/maintenance/threat-feed-${commit}`]);
});
