'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { admit, taskFile, checkRequest, checkOutputs, resolveDispatch } = require('./review.cjs');

const decision = { admitted: true, event: 'pull_request_target', action: 'opened',
  item: { kind: 'pull_request', number: 147 }, base: 'main', head: { sha: 'a'.repeat(40) } };

test('dispatch resolves same-repository and fork heads and refuses hostile routing', async () => {
  const env = { REVIEW: 'true', EVENT: 'false', KIND: 'analysis', OUTPUTS: 'add_comment,noop',
    MAX_OUTPUTS: '1', NOTIFY: 'none', APPLY_PARTIAL: 'false', ITEM: '147', TARGET: '147',
    REPO: 'o/r', BASE: 'main' };
  const data = { number: 147, state: 'open', base: { ref: 'main', repo: { full_name: 'o/r' } },
    head: { sha: 'a'.repeat(40), repo: { full_name: 'o/r' } } };
  const api = value => ({ rest: { pulls: { get: async args => {
    assert.deepEqual(args, { owner: 'o', repo: 'r', pull_number: 147 });
    return { data: value };
  } } } });
  for (const repo of [{ full_name: 'o/r' }, { full_name: 'fork/r', fork: true }, null]) {
    const head = { ...data.head, repo, ref: '--upload-pack=evil' };
    assert.equal(await resolveDispatch(env, api({ ...data, head })), data.head.sha);
  }
  for (const change of [{ TARGET: '*' }, { ITEM: '01' }, { KIND: 'branch' },
    { OUTPUTS: 'all' }, { MAX_OUTPUTS: '3' }, { EVENT: 'true' }, { REVIEW: 'false' },
    { OUTPUT_REPO: 'other/repo' }, { NOTIFY: 'comment' }, { APPLY_PARTIAL: 'true' },
    { ITEM: '9007199254740992', TARGET: '9007199254740992' }, { REPO: 'o/r/evil' }]) {
    await assert.rejects(resolveDispatch({ ...env, ...change }, api(data)));
  }
  for (const change of [{ state: 'closed' }, { number: 148 },
    { head: { sha: '--evil', repo: { full_name: 'o/r' } } },
    { head: null }, { head: { sha: 'A'.repeat(40) } }, { head: { sha: 'a'.repeat(39) } },
    { base: null }, { base: { ...data.base, ref: 'other' } },
    { base: { ...data.base, repo: { full_name: 'other/r' } } }]) {
    await assert.rejects(resolveDispatch(env, api({ ...data, ...change })),
      /open PR on the configured base with an exact head SHA/);
  }
  await assert.rejects(resolveDispatch(env, { rest: { pulls: { get: async () => {
    throw new Error('PR unavailable');
  } } } }), /PR unavailable/);
});

test('review admission narrows, never overrides, event authorization', () => {
  for (const event of ['pull_request', 'pull_request_target']) {
    for (const action of ['opened', 'synchronize', 'ready_for_review']) {
      assert.equal(admit({ ...decision, event, action }, 'main').admitted, true);
    }
  }
  assert.equal(admit({ ...decision, event: 'issue_comment', action: 'created', command: 'review' }, 'main').admitted, true);
  for (const change of [
    { admitted: false }, { item: { kind: 'issue', number: 147 } },
    { item: { kind: 'pull_request', number: '147' } }, { head: null },
    { head: { sha: '--upload-pack=evil' } }, { base: 'other' },
    { event: 'push' }, { action: 'reopened' }, { action: 'labeled' },
    { event: 'issue_comment', action: 'created', command: 'agent' },
  ]) {
    assert.equal(admit({ ...decision, ...change }, 'main').admitted, false, JSON.stringify(change));
  }
});

test('review request has no branch, alternate target/token or notification authority', () => {
  const env = { EVENT: 'true', KIND: 'analysis', OUTPUTS: 'add_comment,noop',
    MAX_OUTPUTS: '1', NOTIFY: 'none', TARGET: '', REPO: 'o/r', GITHUB_REPOSITORY: 'o/r',
    OUTPUT_REPO: '', APPLY_ENVIRONMENT: '', APPLY_PARTIAL: 'false', AGENT: 'fake' };
  checkRequest(env);
  for (const AGENT of ['fake', 'claude', 'opencode']) {
    checkRequest({ ...env, AGENT });
  }
  for (const AGENT of ['', 'unknown']) {
    assert.throws(() => checkRequest({ ...env, AGENT }), /supported agent/);
  }
  for (const [key, value] of Object.entries({ EVENT: 'false', KIND: 'branch',
    OUTPUTS: 'all', MAX_OUTPUTS: 'max', NOTIFY: 'comment', TARGET: '*',
    REPO: 'other/repo', OUTPUT_REPO: 'other/repo', APPLY_ENVIRONMENT: 'write',
    APPLY_PARTIAL: 'true' })) {
    assert.throws(() => checkRequest({ ...env, [key]: value }), /Review requires/);
  }
});

test('only a single verdict comment on this PR or noop passes', () => {
  const check = item => checkOutputs({ items: [item] }, 147);
  for (const verdict of ['APPROVE', 'CHANGES', 'REJECT']) {
    check({ type: 'add_comment', body: `VERDICT: ${verdict}\nREASON: ${'é'.repeat(192)}\nFindings` });
  }
  check({ type: 'noop', message: 'No review possible.' });
  for (const item of [
    { type: 'create_pull_request' }, { type: 'add_comment', body: 'APPROVE' },
    { type: 'add_comment', body: 'VERDICT: approve\nREASON: no' },
    { type: 'add_comment', body: `VERDICT: APPROVE\nREASON: ${'x'.repeat(193)}` },
    { type: 'add_comment', body: 'VERDICT: APPROVE\nREASON: ' },
    { type: 'add_comment', body: 'VERDICT: APPROVE\nREASON: no\rhidden' },
    { type: 'add_comment', body: 'VERDICT: APPROVE\nREASON: no', issue_number: 148 },
    { type: 'add_comment', body: 'VERDICT: APPROVE\nREASON: no', pull_request_number: 148 },
  ]) assert.throws(() => check(item), undefined, JSON.stringify(item));
  for (const key of ['item_number', 'pr', 'pr_number', 'repo', 'comment_id',
    'reply_to_id', 'target', 'temporary_id']) {
    assert.throws(() => check({ type: 'add_comment',
      body: 'VERDICT: APPROVE\nREASON: no', [key]: '147' }), undefined, key);
  }
  for (const items of [[], [{ type: 'noop' }, { type: 'noop' }]]) {
    assert.throws(() => checkOutputs({ items }, 147), /exactly one/);
  }
});

test('task comes from a bounded regular base file, not a symlink or escape', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review-task-'));
  try {
    fs.writeFileSync(path.join(dir, 'task.md'), 'Trusted base task');
    fs.symlinkSync('task.md', path.join(dir, 'link.md'));
    assert.equal(taskFile(dir, 'task.md'), 'Trusted base task');
    for (const name of ['', '../task.md', '/task.md', 'link.md', './task.md']) {
      assert.throws(() => taskFile(dir, name));
    }
    fs.writeFileSync(path.join(dir, 'task.md'), 'x'.repeat(65537));
    assert.throws(() => taskFile(dir, 'task.md'), /64 KiB/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scripted review reports the checked-out SHA', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'review-script-'));
  try {
    const root = path.join(__dirname, '..');
    execFileSync('sh', [path.join(root, '.github/agentic-job/e2e/review.sh')],
      { env: { ...process.env, HOME: home } });
    fs.mkdirSync(path.join(home, 'out'));
    const script = JSON.parse(fs.readFileSync(path.join(home, '.config/fake-agent/demo.json'), 'utf8'));
    const command = script.find(step => step.execute?.command.includes('safe-outputs.jsonl')).execute.command;
    execFileSync('sh', ['-c', command], { cwd: root, env: { ...process.env, HOME: home } });
    const item = JSON.parse(fs.readFileSync(path.join(home, 'out/safe-outputs.jsonl'), 'utf8'));
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    assert.ok(item.body.includes(`\nReviewed SHA: ${sha}\n`));
    checkOutputs({ items: [item] }, 147);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('caller and write job retain the trusted-source boundary', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');
  const checker = fs.readFileSync(path.join(__dirname, '../.github/workflows/check.yml'), 'utf8');
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(caller, /pull_request_target:\s+types: \[opened, synchronize, ready_for_review\]/);
  assert.match(caller, /kind: analysis/);
  assert.match(caller, /notify: none/);
  assert.doesNotMatch(caller, /contents: write|secrets: inherit/);
  const policy = fs.readFileSync(path.join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  assert.match(policy, /inputs.review && !inputs.review-item && \(github.event.pull_request.base.sha \|\| inputs.base\)/);
  assert.match(workflow, /ref: \$\{\{ needs.policy.outputs.ref \}\}/);
  const check = workflow.split('\n  check:')[1].split('\n  apply:')[0];
  assert.match(check, /policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}/);
  assert.match(checker, /if: \$\{\{ fromJSON\(inputs.policy\).review == 'true' \}\}/);
  assert.match(checker, /require\(`\$\{process.env.SOURCE_DIR\}\/workflow\/review.cjs`\)/);
  assert.match(checker, /errors: \[error.message\]/);
  const applier = fs.readFileSync(path.join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
  const apply = applier.split('\n  apply:')[1].split('\n  conclude:')[0];
  assert.match(apply, /if: \$\{\{ fromJSON\(inputs.check\).outputs.has-patch == 'true' \}\}\s+with:\s+repository: \$\{\{ env.OUTPUT_REPO \}\}/);
  assert.doesNotMatch(apply, /pull_request.head|refs\/pull/);
  const ci = fs.readFileSync(path.join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  assert.match(ci, /e2e-review:\s+needs: \[changes, review-base\]/);
  assert.match(ci, /Exactly one scripted verdict was posted/);
  assert.match(ci, /HEAD_SHA: \$\{\{ github.event.pull_request.head.sha \}\}/);
  assert.match(ci, /contains\("Reviewed SHA: " \+ \$sha \+ "\\n"\)/);
  assert.match(ci, /\.key == "e2e-review" and \.value.result == "skipped" and \$installed == "false"/);
});
