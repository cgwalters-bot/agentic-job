'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { admit, taskFile, checkRequest, checkOutputs, reviewStatus, reportStatus, resolveDispatch } = require('./review.cjs');

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
    for (const action of ['opened', 'synchronize', 'reopened', 'ready_for_review']) {
      assert.equal(admit({ ...decision, event, action }, 'main').admitted, true);
    }
  }
  assert.equal(admit({ ...decision, event: 'issue_comment', action: 'created', command: 'review' }, 'main').admitted, true);
  for (const change of [
    { admitted: false }, { item: { kind: 'issue', number: 147 } },
    { item: { kind: 'pull_request', number: '147' } }, { head: null },
    { head: { sha: '--upload-pack=evil' } }, { base: 'other' },
    { event: 'push' }, { action: 'closed' }, { action: 'labeled' },
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
  for (const [body, verdict] of [
    ['VERDICT: APPROVE', 'APPROVE'],
    ['VERDICT: APPROVE\nLooks right.', 'APPROVE'],
    ['VERDICT: APPROVE. Looks right.', 'APPROVE'],
    ['VERDICT: CHANGES\n\n1. Fix the test.', 'CHANGES'],
    ['VERDICT: CHANGES — one finding', 'CHANGES'],
    // Briefs written before CHANGES ask for REJECT and a REASON line.
    ['VERDICT: REJECT\nREASON: Breaks the build.', 'CHANGES'],
    ['VERDICT: REJECT', 'CHANGES'],
  ]) {
    assert.equal(check({ type: 'add_comment', body }), verdict, body);
  }
  assert.equal(check({ type: 'noop', message: 'No review possible.' }), '');
  for (const item of [
    { type: 'create_pull_request' }, { type: 'add_comment', body: 'APPROVE' },
    { type: 'add_comment', body: 'VERDICT: approve' },
    { type: 'add_comment', body: 'VERDICT: REJECTED' },
    { type: 'add_comment', body: 'VERDICT: REJECT, or APPROVE' },
    { type: 'add_comment', body: 'VERDICT: APPROVE unless REJECT' },
    { type: 'add_comment', body: 'VERDICT: APPROVED' },
    { type: 'add_comment', body: 'VERDICT: APPROVE-ish' },
    { type: 'add_comment', body: 'VERDICT: APPROVE?' },
    { type: 'add_comment', body: 'VERDICT: APPROVE|CHANGES' },
    { type: 'add_comment', body: 'VERDICT: APPROVE / CHANGES' },
    { type: 'add_comment', body: 'VERDICT: CHANGES, or APPROVE if you like' },
    { type: 'add_comment', body: ' VERDICT: APPROVE' },
    { type: 'add_comment', body: 'Summary\nVERDICT: APPROVE' },
    { type: 'add_comment', body: 'VERDICT: APPROVE', issue_number: 148 },
    { type: 'add_comment', body: 'VERDICT: APPROVE', pull_request_number: 148 },
  ]) assert.throws(() => check(item), undefined, JSON.stringify(item));
  for (const key of ['item_number', 'pr', 'pr_number', 'repo', 'comment_id',
    'reply_to_id', 'target', 'temporary_id']) {
    assert.throws(() => check({ type: 'add_comment',
      body: 'VERDICT: APPROVE', [key]: '147' }), undefined, key);
  }
  for (const items of [[], [{ type: 'noop' }, { type: 'noop' }]]) {
    assert.throws(() => checkOutputs({ items }, 147), /exactly one/);
  }
});

test('the review status maps each run to one state, only for the one open pull request', () => {
  const head = 'a'.repeat(40);
  const approved = { pull: '147', head, check: 'success', verdict: 'APPROVE', apply: 'success',
    url: 'https://github.com/o/r/pull/147#issuecomment-1' };
  const did = { state: 'failure', description: 'The review did not approve this commit' };
  for (const [name, change, open, expected] of [
    ['approved', {}, [147], { state: 'success', description: 'The review approved this commit' }],
    ['changes', { verdict: 'CHANGES', url: '' }, [147], { state: 'failure', description: 'The review asked for changes' }],
    ['noop', { verdict: '' }, [147], did],
    ['check failed', { check: 'failure', verdict: '' }, [147], did],
    ['check failed after the verdict', { check: 'failure' }, [147], did],
    ['changes, check failed', { check: 'failure', verdict: 'CHANGES' }, [147], did],
    ['check skipped', { check: 'skipped', verdict: '' }, [147], did],
    ['apply failed', { apply: 'failure' }, [147], did],
    ['apply skipped', { apply: 'skipped', url: '' }, [147], did],
    ['no comment posted', { url: '' }, [147], did],
    ['no open pull request', {}, [], { skip: `No review status on ${head}: its open pull requests are none, not only #147` }],
    ['two open pull requests', {}, [147, 148], { skip: `No review status on ${head}: its open pull requests are 147, 148, not only #147` }],
    ['another pull request', {}, [148], { skip: `No review status on ${head}: its open pull requests are 148, not only #147` }],
  ]) assert.deepEqual(reviewStatus({ ...approved, ...change }, open), expected, name);
  for (const change of [{ head: 'A'.repeat(40) }, { head: `${head}\n` }, { head: undefined },
    { pull: '0' }, { pull: '01' }, { pull: '147;' }, { pull: '9007199254740992' }]) {
    assert.throws(() => reviewStatus({ ...approved, ...change }, [147]), /exact head SHA/, JSON.stringify(change));
  }
});

test('the review status is posted only after the open pull requests are listed', async () => {
  const head = 'a'.repeat(40);
  const env = { GITHUB_REPOSITORY: 'o/r', PULL: '147', HEAD_SHA: head, CHECK_RESULT: 'success',
    VERDICT: 'APPROVE', APPLY_RESULT: 'success', RESULT_URL: 'https://x/1', RUN_URL: 'https://x/run' };
  const fake = pulls => {
    const calls = { posted: [], notices: [] };
    const github = { rest: { pulls: { list: 'list' }, repos: {
      createCommitStatus: async args => { calls.posted.push(args); } } },
    paginate: async (route, args) => {
      assert.equal(route, 'list');
      assert.deepEqual(args, { owner: 'o', repo: 'r', state: 'open', per_page: 100 });
      return pulls;
    } };
    return { calls, github, core: { notice: message => calls.notices.push(message) } };
  };
  let { calls, github, core } = fake([{ number: 147, head: { sha: head } }, { number: 150, head: { sha: 'b'.repeat(40) } }]);
  assert.equal((await reportStatus(env, github, core)).state, 'success');
  assert.deepEqual(calls.posted, [{ owner: 'o', repo: 'r', sha: head, context: 'review',
    state: 'success', description: 'The review approved this commit', target_url: 'https://x/run' }]);
  ({ calls, github, core } = fake([{ number: 147, head: { sha: head } }, { number: 148, head: { sha: head } }]));
  assert.ok((await reportStatus(env, github, core)).skip);
  assert.deepEqual(calls.posted, []);
  assert.equal(calls.notices.length, 1);
  ({ calls, github, core } = fake([]));
  await assert.rejects(reportStatus({ ...env, HEAD_SHA: 'main' }, github, core), /exact head SHA/);
  assert.deepEqual(calls.posted, []);
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
  assert.match(caller, /pull_request_target: *(?:#[^\n]*)?\n\s+types: \[opened, synchronize, reopened, ready_for_review\]/);
  assert.match(caller, /kind: analysis/);
  assert.match(caller, /notify: none/);
  assert.doesNotMatch(caller, /contents: write|secrets: inherit|pull_request.head|refs\/pull/);
  // Which job holds which token: writes only in apply (the comment) and
  // status (the status), the identity token only in the agent job.
  const jobs = Object.fromEntries(caller.split('\njobs:\n')[1].split(/\n(?=  [a-z]+:\n)/)
    .map(job => [job.match(/^\s*([a-z]+):/)[1], job]));
  assert.deepEqual(Object.keys(jobs), ['policy', 'agent', 'check', 'apply', 'status']);
  for (const [name, writes] of Object.entries({ policy: [], agent: ['id-token'], check: [],
    apply: ['pull-requests'], status: ['statuses'] })) {
    const granted = [...jobs[name].split('\n    permissions:\n')[1].matchAll(/^      ([a-z-]+): write$/gm)].map(m => m[1]);
    assert.deepEqual(granted, writes, name);
    if (name !== 'apply') assert.doesNotMatch(jobs[name], /secrets/, name);
  }
  assert.match(jobs.agent, /ref: \$\{\{ needs.policy.outputs.ref \}\}/);
  for (const [, action] of caller.matchAll(/^ +(?:- )?uses: ([^.\s]\S*)/gm)) assert.match(action, /@[0-9a-f]{40}$/, action);
  // The status takes the verdict check.yml set and the head policy
  // admitted, nothing the agent wrote.
  // reviewStatus maps them; the only code it runs is the policy call's
  // pinned source, never the head.
  assert.doesNotMatch(jobs.status, /needs\.agent\.outputs|artifact|pull_request\.head|needs\.policy\.outputs\.ref\b/);
  assert.match(jobs.status, /repository: \$\{\{ needs.policy.outputs.source-repository \}\}\s+ref: \$\{\{ needs.policy.outputs.source-sha \}\}/);
  assert.match(jobs.status, /VERDICT: \$\{\{ needs.check.outputs.verdict \}\}/);
  assert.match(jobs.status, /HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}/);
  assert.match(jobs.status, /await reportStatus\(process.env, github, core\)/);
  assert.match(jobs.status, /runs-on: ubuntu-26.04/);
  // Automatic reviews only for the owner, members and collaborators;
  // anyone else, a past contributor included, waits for a `/review`.
  assert.match(jobs.policy, /github.event_name == 'pull_request_target' && !github.event.pull_request.draft &&\s+contains\(fromJSON\('\["OWNER","MEMBER","COLLABORATOR"\]'\), github.event.pull_request.author_association\)\) \|\|/);
  assert.match(checker, /core.setOutput\('verdict', checkOutputs\(/);
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
