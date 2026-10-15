import assert from 'node:assert/strict';
import test from 'node:test';
import { destinations } from './parse.mjs';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('numeric IPv4/IPv6 endpoints, duplicates, and non-port IP traffic', () => {
  assert.deepEqual(destinations([
    'eth0 Out IP 10.0.0.1.1234 > 192.0.2.1.443: tcp 0',
    'eth0 Out IP 10.0.0.1.1234 > 192.0.2.1.443: tcp 0',
    'eth0 Out IP6 2001:db8::1.1234 > 2001:db8::2.443: tcp 0',
    'eth0 Out IP 10.0.0.1 > 192.0.2.2: ICMP echo request',
    'eth0 Out IP 10.0.0.1.53 > example.com.443: UDP, length 20',
    '::error::untrusted text',
  ].join('\n')), ['192.0.2.1:443', '192.0.2.2', '[2001:db8::2]:443']);
});

test('empty or partial lines do not invent destinations', () => {
  for (const text of ['', 'IP source > ', 'IP source > 999.0.0.1.443: tcp']) {
    assert.deepEqual(destinations(text), []);
  }
});

test('final post publishes only numeric metadata and refuses absent or oversized traces', () => {
  const dir = mkdtempSync(join(tmpdir(), 'runner-egress-'));
  try {
    const trace = join(dir, 'trace');
    const summary = join(dir, 'summary');
    const run = () => spawnSync(process.execPath, [new URL('./post.mjs', import.meta.url).pathname], {
      env: { ...process.env, STATE_trace: trace, GITHUB_STEP_SUMMARY: summary },
      encoding: 'utf8',
    });
    assert.notEqual(run().status, 0);
    writeFileSync(trace, '');
    assert.notEqual(run().status, 0);
    writeFileSync(trace, 'eth0 Out IP 10.0.0.1.123 > 192.0.2.1.443: tcp 0\nSECRET\n');
    assert.equal(run().status, 0);
    const report = readFileSync(summary, 'utf8');
    assert.match(report, /192\.0\.2\.1:443/);
    assert.match(report, /traffic after the last step is not observed/);
    assert.doesNotMatch(report, /SECRET/);
    writeFileSync(trace, 'x'.repeat(4 * 1024 * 1024 + 1));
    assert.notEqual(run().status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('workflow is opt-in and observer registers before all other actions', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/runner-egress.yml', import.meta.url), 'utf8');
  assert.match(workflow, /if: vars\.RUNNER_EGRESS_TRACE == 'true'/);
  assert.match(workflow, /runs-on: ubuntu-26\.04/);
  assert.match(workflow, /timeout-minutes: 10/);
  assert.equal(workflow.match(/- uses: (\S+)/)[1], './workflow/runner-egress');
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /secrets\.|id-token:|contents: write|secure-host@/);
});
