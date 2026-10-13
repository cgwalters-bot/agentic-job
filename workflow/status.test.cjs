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
  assert.doesNotMatch(policy.split('\n  notify:\n')[1].split('runs-on:')[0], /inputs.output-repo == github.repository/);
  assert.match(policy, /notify-repo:\n[^\n]*\n        value: \$\{\{ jobs.policy.outputs.item != '' && github.repository \|\| inputs.output-repo \|\| github.repository \}\}/);
  assert.doesNotMatch(policy.split('\n  notify:\n')[1].split('runs-on:')[0], /inputs.event/);
  for (const source of [policy, read('apply')]) assert.match(source, /workflow\/status.cjs/);
  assert.match(read('dispatch'), /notify: \$\{\{ \(inputs.kind == 'review' \|\| inputs.scripted\) && 'none' \|\| 'comment' \}\}/);
  assert.doesNotMatch(read('apply'), /await once\(/);
  assert.match(read('apply'), /Edit the status comment\n[^\n]*\n        continue-on-error: true/);
});

test('cross-repository status uses the authenticated author and keeps one comment', () => {
  const cross = { ...env, GITHUB_REPOSITORY: 'caller/repo', STATUS_TOKEN: 'supplied' };
  const comments = [named('mallory'), named('github-actions[bot]')];
  const writes = [];
  const api = (method, path, body) => {
    if (path === 'user') return { login: 'status-bot' };
    if (method === 'GET') return comments;
    writes.push(method);
    if (method === 'POST') comments.push({ id: 99, user: { login: 'status-bot' }, body });
    else comments.at(-1).body = body;
    return comments.at(-1);
  };
  for (const text of ['running', 'finished', 'rerun']) {
    upsert({ ...cross, TEXT: text, NO_RESULT_REASON: JSON.stringify('> no data') }, api);
  }
  assert.deepEqual(writes, ['POST', 'PATCH', 'PATCH']);
  assert.match(comments.at(-1).body, /Its reason:\n\n> no data/);
  assert.equal(upsert({ ...cross, GITHUB_RUN_ID: '99' }, api).id, 99);
  assert.deepEqual(writes, ['POST', 'PATCH', 'PATCH']);
  assert.throws(() => upsert(cross, () => ({})), /authenticated user/);
  let pages = 0;
  assert.throws(() => upsert(cross, (method, path) => {
    if (path === 'user') return { login: 'status-bot' };
    assert.equal(method, 'GET');
    pages++;
    return Array(100).fill(named('mallory'));
  }), /exceeded/);
  assert.equal(pages, MAX_PAGES);
});

test('cross-repository status without a supplied token skips without any API call', () => {
  const messages = [];
  assert.equal(upsert({ ...env, GITHUB_REPOSITORY: 'caller/repo' }, () => assert.fail(),
    message => messages.push(message)), null);
  assert.deepEqual(messages, ['Status comment skipped: cross-repository target requires the caller-supplied SAFE_OUTPUTS_PAT.']);
  upsert({ ...env, GITHUB_REPOSITORY: 'O/R', STATUS_TOKEN: 'unused' }, (method, path) => {
    assert.notEqual(path, 'user');
    return method === 'GET' ? [] : { id: 1 };
  });
});

test('status CLI selects the credential only for cross-repository comments and reports skips', () => {
  const dir = mkdtempSync(join(tmpdir(), 'status-cli-'));
  try {
    const preload = join(dir, 'mock.cjs');
    const log = join(dir, 'calls');
    const summary = join(dir, 'summary');
    writeFileSync(preload, `require('node:child_process').execFileSync = (program, args, options) => {
      require('node:fs').appendFileSync(process.env.CALL_LOG, JSON.stringify({ args, token: options.env.GH_TOKEN }) + '\\n');
      return JSON.stringify(args[3] === 'user' ? { login: 'status-bot' } : args[2] === 'GET' ? [] : { id: 42 });
    };`);
    for (const [caller, token, selected] of [
      ['caller/repo', 'supplied', 'supplied'], ['o/r', 'supplied', 'job-token'], ['caller/repo', '', null],
    ]) {
      writeFileSync(log, '');
      writeFileSync(summary, '');
      const result = spawnSync(process.execPath, ['--require', preload, join(__dirname, 'status.cjs')], {
        env: { ...process.env, ...env, GITHUB_REPOSITORY: caller, GH_TOKEN: 'job-token',
          STATUS_TOKEN: token, CALL_LOG: log, GITHUB_STEP_SUMMARY: summary }, encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
      const calls = readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
      if (selected) {
        assert.ok(calls.length >= 2);
        assert.ok(calls.every(call => call.token === selected));
        assert.equal(result.stdout, 'id=42\n');
        assert.equal(readFileSync(summary, 'utf8'), '');
      } else {
        assert.deepEqual(calls, []);
        assert.equal(result.stdout, '');
        assert.match(readFileSync(summary, 'utf8'), /Status comment skipped:.*SAFE_OUTPUTS_PAT/);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conclude carries the encoded reason only for a successful no-result run', () => {
  const workflow = readFileSync(`${__dirname}/../.github/workflows/apply.yml`, 'utf8');
  assert.match(workflow, /no-result-reason: \$\{\{ steps\.result\.outputs\.no-result-reason \}\}/);
  assert.match(workflow, /NO_RESULT_REASON: \$\{\{ needs\.apply\.outputs\.no-result-reason \}\}/);
  assert.match(workflow, /NO_RESULT_REASON: \$\{\{ steps\.ended\.outputs\.no-result-reason \}\}/);
  const source = workflow.split('- name: How the run ended\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].split('\n').map(line => line.slice(10)).join('\n');
  const reason = '> ask `@maintainer`\n> text=injected\n> $(exit 9)\n> "quoted" \\ path';
  for (const [results, quiet, refusal, included] of [
    ['success/success/success', 'true', '', true],
    ['success/success/success', '', '', false],
    ['success/success/failure', 'true', '', false],
    ['success/skipped/skipped', 'true', '', false],
    ['cancelled/skipped/skipped', 'true', '', false],
    ['success/success/success', 'true', 'refused', false],
  ]) {
    const dir = mkdtempSync(join(tmpdir(), 'conclude-'));
    try {
      const output = join(dir, 'output');
      writeFileSync(output, '');
      const result = spawnSync('bash', ['-eo', 'pipefail', '-c', source], {
        env: { ...process.env, RESULTS: results, EXIT: '0', PR: '', NO_RESULT: quiet,
          NO_RESULT_REASON: JSON.stringify(reason), REFUSAL: refusal, RESULT_URL: '',
          WORKFLOW: 'test', RUN_URL: 'https://example.invalid/run', GITHUB_OUTPUT: output }, encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
      const fields = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => {
        const at = line.indexOf('=');
        return [line.slice(0, at), line.slice(at + 1)];
      }));
      assert.deepEqual(Object.keys(fields).sort(), included ? ['no-result-reason', 'reaction', 'text'] : ['reaction', 'text']);
      const calls = [];
      upsert({ ...env, TEXT: fields.text, NO_RESULT_REASON: fields['no-result-reason'] },
        (...args) => { calls.push(args); return args[0] === 'GET' ? [] : { id: 42 }; });
      assert.equal(calls[1][2], `${fields.text}${included ? ` Its reason:\n\n${reason}` : ''}\n\n<!-- agentic-job-run: 100 -->\n\n${MARKER}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
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
