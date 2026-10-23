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

// The caller's own comment for the round, by id: [label, the comment (or
// an error), what is written where, and the body written].
const tag = '<!-- tag: {"round":2} -->';
const status = `running\n\n<!-- agentic-job-run: 100 -->\n\n${MARKER}`;
const given = (overrides = {}) => ({ id: 5, user: { login: 'github-actions[bot]' },
  issue_url: 'https://api.github.com/repos/O/R/issues/7', body: `${tag}\nfix round 2`, ...overrides });
for (const [label, comment, write, body, id = '5'] of [
  ['given id used', given({ body: 'fix round 2' }), 'PATCH 5', status],
  ['markers preserved', given(), 'PATCH 5', `${tag}\n\n${status}`],
  ['markers preserved across updates', given({ body: `${tag}\n<!-- more: 1 -->\n\nfailed\n\n<!-- agentic-job-run: 99 -->\n\n${MARKER}` }),
    'PATCH 5', `${tag}\n<!-- more: 1 -->\n\n${status}`],
  ['only markers', given({ body: tag }), 'PATCH 5', `${tag}\n\n${status}`],
  ['visible text beside a marker is not kept', given({ body: `<!-- a --> shown <!-- b -->\n${tag}` }), 'PATCH 5', status],
  ['older run', given({ body: `${tag}\n\nrunning\n\n<!-- agentic-job-run: 101 -->\n\n${MARKER}` }), null],
  ['foreign author', given({ user: { login: 'mallory' } }), 'POST', status],
  ['other item', given({ issue_url: 'https://api.github.com/repos/o/r/issues/8' }), 'POST', status],
  ['other repository', given({ issue_url: 'https://api.github.com/repos/o/other/issues/7' }), 'POST', status],
  ['missing comment', new Error('HTTP 404'), 'POST', status],
  ['not an id', given(), 'POST', status, '5/../../8'],
]) {
  test(`status comment by id: ${label}`, () => {
    const writes = [];
    const messages = [];
    const result = upsert({ ...env, STATUS_COMMENT: id }, (method, path, text) => {
      if (path === 'repos/o/r/issues/comments/5' && method === 'GET') {
        if (comment instanceof Error) throw comment;
        return comment;
      }
      if (method === 'GET') return [];
      writes.push([`${method}${method === 'PATCH' ? ` ${path.split('/').at(-1)}` : ''}`, text]);
      return { id: 1 };
    }, message => messages.push(message));
    assert.deepEqual(writes, write ? [[write, body]] : []);
    if (!write) assert.equal(result, comment);
    assert.equal(messages.length, write === 'POST' ? 1 : 0);
  });
}

for (const [label, id] of [['a later run without an id', ''], ['an id that cannot be read', '6']]) {
  test(`status comment by id: ${label} keeps the caller's markers on the marked comment`, () => {
    const marked = given({ body: `${tag}\n\nfailed\n\n<!-- agentic-job-run: 99 -->\n\n${MARKER}` });
    const writes = [];
    upsert({ ...env, STATUS_COMMENT: id }, (method, path, text) => {
      if (path.endsWith('/comments/6')) throw new Error('HTTP 502');
      if (method === 'GET') return [marked];
      writes.push([path, text]);
      return { id: 5 };
    });
    assert.deepEqual(writes, [['repos/o/r/issues/comments/5', `${tag}\n\n${status}`]]);
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
  assert.match(policy, /notify-repo:\n[^\n]*\n        value: \$\{\{ jobs.policy.outputs.item != '' && github.repository \|\| inputs.item-repo \|\| inputs.output-repo \|\| github.repository \}\}/);
  assert.doesNotMatch(policy.split('\n  notify:\n')[1].split('runs-on:')[0], /inputs.event/);
  for (const source of [policy, read('apply')]) assert.match(source, /workflow\/status.cjs/);
  assert.match(read('dispatch'), /notify: \$\{\{ \(inputs.kind == 'review' \|\| inputs.scripted\) && 'none' \|\| 'comment' \}\}/);
  assert.doesNotMatch(read('apply'), /await once\(/);
  assert.match(read('apply'), /Edit the status comment\n[^\n]*\n        continue-on-error: true/);
  // The caller's comment id reaches both status steps, off unless given.
  assert.match(read('dispatch'), /status-comment: \$\{\{ inputs.status-comment \}\}/);
  assert.match(read('agentic-job'), /status-comment: \$\{\{ inputs.status-comment \}\}/);
  assert.match(policy, /status-comment:\n(?:[^\n]*\n){5} {8}default: ""/);
  assert.match(policy, /STATUS_COMMENT: \$\{\{ inputs.status-comment \}\}\n[^\n]*\n {10}node "\$SOURCE_DIR\/workflow\/status.cjs"/);
  assert.match(read('apply'), /STATUS_COMMENT: \$\{\{ fromJSON\(inputs.policy\).notify == 'comment' && fromJSON\(inputs.policy\).status-comment \|\| '' \}\}/);
});

for (const caller of ['caller/repo', 'O/R']) {
  test(`status with a supplied token from ${caller} uses the authenticated author and keeps one comment`, () => {
    const target = { ...env, GITHUB_REPOSITORY: caller, STATUS_TOKEN: 'supplied' };
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
      upsert({ ...target, TEXT: text, NO_RESULT_REASON: JSON.stringify('> no data') }, api);
    }
    assert.deepEqual(writes, ['POST', 'PATCH', 'PATCH']);
    assert.match(comments.at(-1).body, /Its reason:\n\n> no data/);
    assert.equal(upsert({ ...target, GITHUB_RUN_ID: '99' }, api).id, 99);
    assert.deepEqual(writes, ['POST', 'PATCH', 'PATCH']);
    assert.throws(() => upsert(target, () => ({})), /authenticated user/);
    let pages = 0;
    assert.throws(() => upsert(target, (method, path) => {
      if (path === 'user') return { login: 'status-bot' };
      assert.equal(method, 'GET');
      pages++;
      return Array(100).fill(named('mallory'));
    }), /exceeded/);
    assert.equal(pages, MAX_PAGES);
  });
}

test('cross-repository status without a supplied token skips without any API call', () => {
  const messages = [];
  assert.equal(upsert({ ...env, GITHUB_REPOSITORY: 'caller/repo' }, () => assert.fail(),
    message => messages.push(message)), null);
  assert.deepEqual(messages, ['Status comment skipped: cross-repository target requires the caller-supplied SAFE_OUTPUTS_PAT.']);
  upsert({ ...env, GITHUB_REPOSITORY: 'O/R' }, (method, path) => {
    assert.notEqual(path, 'user');
    return method === 'GET' ? [] : { id: 1 };
  });
});

test('status CLI prefers the supplied credential, falls back to the job token and reports skips', () => {
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
      ['caller/repo', 'supplied', 'supplied'], ['o/r', 'supplied', 'supplied'],
      ['o/r', '', 'job-token'], ['caller/repo', '', null],
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
        assert.equal(calls.some(call => call.args[3] === 'user'), Boolean(token));
        assert.equal(calls.at(-1).args[2], 'POST');
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

test('conclude carries the encoded reason for a decline, a blocked run or a missing-data failure', () => {
  const workflow = readFileSync(`${__dirname}/../.github/workflows/apply.yml`, 'utf8');
  assert.match(workflow, /no-result-reason: \$\{\{ steps\.result\.outputs\.no-result-reason \}\}/);
  assert.match(workflow, /NO_RESULT_REASON: \$\{\{ needs\.apply\.outputs\.no-result-reason \}\}/);
  assert.match(workflow, /NO_RESULT_REASON: \$\{\{ steps\.ended\.outputs\.no-result-reason \}\}/);
  const source = workflow.split('- name: How the run ended\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].split('\n').map(line => line.slice(10)).join('\n');
  const reason = '> ask `@maintainer`\n> text=injected\n> $(exit 9)\n> "quoted" \\ path';
  for (const [results, quiet, refusal, included, missing = '', blocked = ''] of [
    ['success/success/success', 'true', '', true],
    ['success/success/success', '', '', false],
    ['success/success/failure', 'true', '', false],
    ['success/skipped/skipped', 'true', '', false],
    ['cancelled/skipped/skipped', 'true', '', false],
    ['success/success/success', 'true', 'refused', false],
    ['success/success/failure', 'true', '', true, 'true'],
    ['success/success/failure', 'true', 'refused', false, 'true'],
    ['success/success/success', 'true', '', true, 'true', 'true'], ['success/success/failure', 'true', '', true, 'true', 'true'],
  ]) {
    const dir = mkdtempSync(join(tmpdir(), 'conclude-'));
    try {
      const output = join(dir, 'output');
      writeFileSync(output, '');
      const result = spawnSync('bash', ['-eo', 'pipefail', '-c', source], {
        env: { ...process.env, RESULTS: results, EXIT: '0', PR: '', NO_RESULT: quiet, MISSING_DATA: missing, BLOCKED: blocked,
          NO_RESULT_REASON: JSON.stringify(reason), REFUSAL: refusal, RESULT_URL: '',
          WORKFLOW: 'test', RUN_URL: 'https://example.invalid/run', GITHUB_OUTPUT: output }, encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
      const fields = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => line.split(/=(.*)/s).slice(0, 2)));
      assert.deepEqual(Object.keys(fields).sort(), included ? ['no-result-reason', 'reaction', 'text'] : ['reaction', 'text']);
      if (missing && !refusal) {
        assert.match(fields.text, blocked && results === 'success/success/success' ? /^<!-- agentic-job-outcome: blocked -->⏸️ .* is blocked: / : /required data was missing/);
        assert.equal(fields.reaction, /is blocked/.test(fields.text) ? '+1' : 'confused');
      }
      const calls = [];
      upsert({ ...env, TEXT: fields.text, NO_RESULT_REASON: fields['no-result-reason'] },
        (...args) => { calls.push(args); return args[0] === 'GET' ? [] : { id: 42 }; });
      assert.equal(calls[1][2], `${fields.text}${included ? ` Its reason:\n\n${reason}` : ''}\n\n<!-- agentic-job-run: 100 -->\n\n${MARKER}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('missing-data failures reach the bounded status path even with notify none', () => {
  const workflow = readFileSync(`${__dirname}/../.github/workflows/apply.yml`, 'utf8');
  const conclude = workflow.split('\n  conclude:\n')[1];
  const expressions = [conclude.match(/^    if: \$\{\{ (.*) \}\}$/m)[1],
    conclude.split('- name: Edit the status comment\n')[1].match(/if: \$\{\{ (.*) \}\}/)[1]];
  for (const notify of ['none', 'reaction', 'comment']) {
    for (const notified of ['false', 'true']) {
      for (const missing of ['true', 'false']) {
        for (const item of ['453', '', '*']) {
          const policy = { notify, notified, 'notify-item': item };
          const evaluated = expressions.map(expression => new Function('policy', 'missing',
            `return ${expression.replaceAll('always()', 'true').replaceAll('fromJSON(inputs.policy)', 'policy')
              .replaceAll('needs.apply.outputs.missing-data', 'missing').replaceAll('policy.notify-item', 'policy["notify-item"]')}`)(policy, missing));
          assert.deepEqual(evaluated, [notify !== 'none' && notified === 'true' || missing === 'true',
            notify === 'comment' && notified === 'true' || missing === 'true' && item === '453']);
        }
      }
    }
  }
  assert.match(conclude, /ITEM: \$\{\{ fromJSON\(inputs.policy\).notify-item \}\}/);
  assert.match(conclude, /REPO: \$\{\{ fromJSON\(inputs.policy\).notify-repo \}\}/);
  assert.match(conclude, /node .*workflow\/status.cjs/);
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
