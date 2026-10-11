'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { upsert, MARKER, MAX_PAGES } = require('./status.cjs');

const env = { REPO: 'o/r', ITEM: '7', TEXT: 'running', GITHUB_RUN_ID: '100' };
const named = (login = 'github-actions[bot]', body = `old\n\n${MARKER}`) => ({ id: 42, user: { login }, body });

for (const [label, comments, method] of [
  ['new item', [], 'POST'],
  ['later run', [named()], 'PATCH'],
  ['copied marker', [named('mallory')], 'POST'],
  ['quoted marker', [named(undefined, `${MARKER}\nquoted`)], 'POST'],
]) {
  test(label, () => {
    const calls = [];
    upsert(env, (...args) => { calls.push(args); return args[0] === 'GET' ? comments : { id: 42 }; });
    assert.equal(calls[1][0], method);
    assert.equal(calls[1][2], `running\n\n<!-- agentic-job-run: 100 -->\n\n${MARKER}`);
    assert.equal(calls[1][1], method === 'PATCH' ? 'repos/o/r/issues/comments/42' : 'repos/o/r/issues/7/comments');
  });
}

test('start, finish, rerun and next run edit the same item comment', () => {
  const comments = [];
  const methods = [];
  const api = (method, path, body) => {
    methods.push(method);
    if (method === 'GET') return comments;
    if (method === 'POST') comments.push(named());
    comments[0].body = body;
    return comments[0];
  };
  for (const text of ['running', 'failed: check refused', 'result: https://github.com/o/r/pull/8', 'running again']) {
    upsert({ ...env, TEXT: text }, api);
  }
  assert.equal(comments.length, 1);
  assert.equal(methods.filter(method => method === 'POST').length, 1);
  assert.equal(methods.filter(method => method === 'PATCH').length, 3);
});

test('lookup is bounded and fails without a duplicate', () => {
  let calls = 0;
  assert.throws(() => upsert(env, method => {
    assert.equal(method, 'GET');
    calls++;
    return Array(100).fill(named('mallory'));
  }), /exceeded/);
  assert.equal(calls, MAX_PAGES);
});

test('an older run cannot overwrite the current running or finished status', () => {
  const newer = named(undefined, `running\n\n<!-- agentic-job-run: 101 -->\n\n${MARKER}`);
  assert.equal(upsert(env, method => {
    assert.equal(method, 'GET');
    return [newer];
  }), newer);
});

test('later pages and API failure', () => {
  let calls = 0;
  upsert(env, method => {
    if (method !== 'GET') return {};
    return ++calls === 1 ? Array(100).fill(named('mallory')) : [named()];
  });
  assert.equal(calls, 2);
  assert.throws(() => upsert(env, () => { throw new Error('forge unavailable'); }), /forge unavailable/);
  for (const item of ['', '*', '0', '$(exit 9)']) {
    assert.throws(() => upsert({ ...env, ITEM: item }, () => assert.fail()), /numeric item/);
  }
});

test('dispatch and event status use the same trusted helper, opt-in only', () => {
  const read = name => readFileSync(`${__dirname}/../.github/workflows/${name}.yml`, 'utf8');
  const policy = read('policy');
  assert.match(policy, /default: none/);
  assert.match(policy, /needs.policy.outputs.comment-target != '\*'/);
  assert.match(policy, /!cancelled\(\) && needs.policy.result == 'success'/);
  assert.match(policy, /inputs.proposals-artifact != '' && needs.activate.result == 'skipped'/);
  assert.match(policy, /inputs.output-repo == '' \|\| inputs.output-repo == github.repository/);
  assert.match(policy, /notify-repo:\n[^\n]*\n        value: \$\{\{ jobs.policy.outputs.item != '' && github.repository \|\| inputs.output-repo \|\| github.repository \}\}/);
  assert.doesNotMatch(policy.split('\n  notify:\n')[1].split('runs-on:')[0], /inputs.event/);
  for (const source of [policy, read('apply')]) assert.match(source, /workflow\/status.cjs/);
  assert.match(read('dispatch'), /notify: \$\{\{ inputs.kind == 'review' && 'none' \|\| 'comment' \}\}/);
  assert.doesNotMatch(read('apply'), /await once\(/);
  assert.match(read('apply'), /Edit the status comment\n[^\n]*\n        continue-on-error: true/);
});

test('non-event target selection accepts only numeric targets, with or without an event file', () => {
  const policy = readFileSync(`${__dirname}/../.github/workflows/policy.yml`, 'utf8');
  const source = policy.split('- name: What to react to, and where to comment\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].split('\n').map(line => line.slice(10)).join('\n');
  for (const payload of [null, { item: null }]) {
    for (const target of ['7', '*', '', '0', '$(exit 9)']) {
      const dir = mkdtempSync(join(tmpdir(), 'status-'));
      try {
        const output = join(dir, 'output');
        writeFileSync(output, '');
        if (payload) writeFileSync(join(dir, 'event.json'), JSON.stringify(payload));
        const result = spawnSync('bash', ['-eo', 'pipefail', '-c', source], {
          env: { ...process.env, JOB_DIR: dir, TARGET: target, GITHUB_OUTPUT: output }, encoding: 'utf8',
        });
        assert.equal(result.status, target === '7' ? 0 : 1, result.stderr);
        assert.equal(readFileSync(output, 'utf8'), target === '7' ? 'item=7\nwhat=item\n' : '');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  }
});
