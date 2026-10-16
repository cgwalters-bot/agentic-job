'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { admit, taskFile, mergePolicy, mergeStatement, checkRequest, checkOutputs, reviewStatus, reportStatus, resolveDispatch } = require('./review.cjs');

// The policy job's `if:` as a function of the event context and the
// repository variables: GitHub's expression syntax is close enough to
// JavaScript for the functions it uses, with missing properties null.
function policyStarts(job) {
  const expression = job.match(/\n    if: >-\n((?: {6}.*\n)+)/)[1]
    .replace(/\b(github|vars)((?:\.\w+)+)/g, (_, root, rest) => root + rest.replaceAll('.', '?.'));
  const fromJSON = JSON.parse;
  const contains = (search, item) => Array.isArray(search)
    ? search.some(element => element == item)
    : String(search).toLowerCase().includes(String(item).toLowerCase());
  const startsWith = (text, prefix) => String(text).toLowerCase().startsWith(String(prefix).toLowerCase());
  const evaluate = Function('github', 'vars', 'fromJSON', 'contains', 'startsWith', `return Boolean(${expression});`);
  return (github, vars) => evaluate(github, vars, fromJSON, contains, startsWith);
}

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
  for (const AGENT of ['fake', 'claude', 'opencode', 'vibe']) {
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
    ['VERDICT: APPROVE, no blockers\n\n## Follow-ups\n\n- important: a.rs:3\n- nit: b.rs:7', 'APPROVE'],
    ['VERDICT: CHANGES: one blocker', 'CHANGES'],
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
  for (const item_number of [147, '147']) {
    assert.equal(check({ type: 'add_comment', body: 'VERDICT: APPROVE', item_number }), 'APPROVE');
  }
  for (const item_number of [148, '148', null, false, {}, [147], '0147', '147\n',
    'aw_other', 0, -1, 1.47, 9007199254740992]) {
    assert.throws(() => check({ type: 'add_comment', body: 'VERDICT: APPROVE', item_number }),
      /triggering pull request/, JSON.stringify(item_number));
  }
  for (const key of ['pr', 'pr_number', 'repo', 'comment_id',
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
  const notPosted = { state: 'failure', description: 'The review did not post; see the workflow run' };
  for (const [name, change, open, expected] of [
    ['approved', {}, [147], { state: 'success', description: 'The review approved this commit' }],
    ['changes', { verdict: 'CHANGES' }, [147], { state: 'failure', description: 'The review asked for changes' }],
    ['noop', { verdict: '' }, [147], did],
    ['check failed', { check: 'failure', verdict: '' }, [147], notPosted],
    ['check failed after the verdict', { check: 'failure' }, [147], notPosted],
    ['changes, check failed', { check: 'failure', verdict: 'CHANGES' }, [147], notPosted],
    ['check skipped', { check: 'skipped', verdict: '' }, [147], notPosted],
    ['apply failed', { apply: 'failure' }, [147], notPosted],
    ['apply skipped', { apply: 'skipped', url: '' }, [147], notPosted],
    ['no comment posted', { url: '' }, [147], notPosted],
    ['submitted as the review, apply skipped', { apply: 'skipped', url: '', review: 'https://github.com/o/r/pull/147#pullrequestreview-1' }, [147],
      { state: 'success', description: 'The review approved this commit' }],
    ['changes submitted as the review', { verdict: 'CHANGES', apply: 'skipped', url: '', review: 'https://x/1' }, [147],
      { state: 'failure', description: 'The review asked for changes' }],
    ['submitted, check failed', { check: 'failure', review: 'https://x/1' }, [147], notPosted],
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
  ({ calls, github, core } = fake([{ number: 147, head: { sha: head } }]));
  await reportStatus({ ...env, CHECK_RESULT: 'failure', VERDICT: '', APPLY_RESULT: 'skipped', RESULT_URL: '' }, github, core);
  assert.deepEqual(calls.posted, [{ owner: 'o', repo: 'r', sha: head, context: 'review',
    state: 'failure', description: 'The review did not post; see the workflow run', target_url: 'https://x/run' }]);
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

test('merge policy comes from one strict base file, person by default', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review-merge-'));
  const file = path.join(dir, '.github/agentic-job/merge.toml');
  try {
    assert.deepEqual(mergePolicy(dir), { merge: 'person', set: false });
    fs.mkdirSync(path.dirname(file), { recursive: true });
    for (const [text, want] of [
      ['merge = "agent"\n', 'agent'],
      ['# The owner\'s decision.\n\nmerge = "person"  \n', 'person'],
      ['merge = "agent"', 'agent'],
      ['# Windows lines.\r\nmerge = "agent"\r\n', 'agent'],
      ['\ufeffmerge = "agent"\n', /may hold only/],
      ['', /exactly once/],
      ['# nothing\n', /exactly once/],
      ['merge = "agent"\nmerge = "agent"\n', /exactly once/],
      ['merge = "anyone"\n', /may hold only/],
      ['merge = \'agent\'\n', /may hold only/],
      ['merge = "agent" # inline\n', /may hold only/],
      ['merge="agent"\n', /may hold only/],
      ['[review]\nmerge = "agent"\n', /may hold only/],
      ['merge = "agent"\nmerge = "person"\n', /exactly once/],
      ['x'.repeat(4097), /at most 4 KiB/],
    ]) {
      fs.writeFileSync(file, text);
      if (typeof want === 'string') assert.deepEqual(mergePolicy(dir), { merge: want, set: true }, text);
      else assert.throws(() => mergePolicy(dir), want, text);
    }
    fs.rmSync(file);
    fs.writeFileSync(path.join(dir, 'other.toml'), 'merge = "agent"\n');
    fs.symlinkSync('../../other.toml', file);
    assert.throws(() => mergePolicy(dir), /without symlinks/);
    fs.rmSync(file);
    fs.mkdirSync(file);
    assert.throws(() => mergePolicy(dir), /regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // The statement says whose it is, for each value, and asks for the owned
  // paths and any change to who decides.
  const agent = { merge: 'agent', set: true };
  const person = { merge: 'person', set: true };
  const unset = { merge: 'person', set: false };
  assert.match(mergeStatement(agent), /## Merge policy\n\nThe repository owner set this in \.github\/agentic-job\/merge\.toml on the default branch/);
  assert.match(mergeStatement(agent), /merge = "agent": an approving review from this job merges/);
  assert.match(mergeStatement(person), /The repository owner set this[\s\S]*merge = "person": the repository expects a person/);
  assert.match(mergeStatement(unset), /The default branch has no \.github\/agentic-job\/merge\.toml, so the default holds[\s\S]*merge = "person"/);
  assert.doesNotMatch(mergeStatement(unset), /owner set this/);
  for (const policy of [person, unset]) assert.match(mergeStatement(policy), /Review as hard as if your approval merged\./);
  for (const policy of [agent, person, unset]) {
    assert.match(mergeStatement(policy), /it is a fact, not a question for this review/);
    assert.match(mergeStatement(policy), /"Needs the owner's review: " and those paths/);
    assert.match(mergeStatement(policy), /review those paths as hard as any\s+other/);
    assert.match(mergeStatement(policy), /changes the merge policy file or a CODEOWNERS file/);
  }
});

test('the task command appends the base merge policy to the task', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review-task-merge-'));
  const env = { ...process.env, EVENT: 'true', KIND: 'analysis', OUTPUTS: 'add_comment,noop',
    MAX_OUTPUTS: '1', NOTIFY: 'none', TARGET: '', REPO: 'o/r', GITHUB_REPOSITORY: 'o/r',
    OUTPUT_REPO: '', APPLY_ENVIRONMENT: '', APPLY_PARTIAL: 'false', AGENT: 'fake' };
  const task = () => execFileSync(process.execPath, [path.join(__dirname, 'review.cjs'), 'task', 'task.md'],
    { cwd: dir, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    fs.writeFileSync(path.join(dir, 'task.md'), 'Trusted base task\n');
    assert.equal(task(), 'Trusted base task\n' + mergeStatement({ merge: 'person', set: false }));
    fs.mkdirSync(path.join(dir, '.github/agentic-job'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github/agentic-job/merge.toml'), 'merge = "agent"\n');
    assert.equal(task(), 'Trusted base task\n' + mergeStatement({ merge: 'agent', set: true }));
    // A malformed policy fails the run instead of being guessed at.
    fs.writeFileSync(path.join(dir, '.github/agentic-job/merge.toml'), 'merge = "always"\n');
    assert.throws(task, /may hold only/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The owner's value is theirs to change; a file the review job would refuse is not.
test('this repository\'s merge policy is one the review job reads', () => {
  const { merge, set } = mergePolicy(path.join(__dirname, '..'));
  assert.ok(set && ['agent', 'person'].includes(merge));
});

// The example the docs show must be one the parser accepts (#558).
test('the merge policy example in docs/review.md parses', () => {
  const docs = fs.readFileSync(path.join(__dirname, '../docs/review.md'), 'utf8');
  const start = docs.indexOf('### Merge policy');
  assert.ok(start !== -1, 'no Merge policy section in docs/review.md');
  const example = [...docs.slice(start).matchAll(/```toml\n([\s\S]*?)```/g)]
    .map(match => match[1]).find(block => block.includes('merge = '));
  assert.ok(example, 'no toml example with merge = in the Merge policy section');
  const want = example.match(/merge = "(agent|person)"/);
  assert.ok(want, 'the Merge policy example sets neither agent nor person');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review-docs-merge-'));
  try {
    fs.mkdirSync(path.join(dir, '.github/agentic-job'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github/agentic-job/merge.toml'), example);
    assert.deepEqual(mergePolicy(dir), { merge: want[1], set: true });
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

test('automatic and dispatched review prompts allow concern-specific experiments, not routine verification', () => {
  const standing = fs.readFileSync(path.join(__dirname, 'review.md'), 'utf8');
  const dispatch = fs.readFileSync(path.join(__dirname, '../.github/workflows/dispatch.yml'), 'utf8');
  const instructions = dispatch.match(/const instructions = profile === 'review'\s+\? '([^']+)'/)[1];
  for (const prompt of [standing, dispatch]) {
    assert.match(prompt, /do not set item_number or other routing fields: the workflow fixes the target\./);
  }
  for (const prompt of [standing, instructions]) {
    assert.match(prompt, /Read the diff and the code around it, and report findings only\./);
    assert.match(prompt, /Do not run existing test suites, formatters or linters to confirm they pass\./);
    assert.match(prompt, /Build and run code when needed to test whether a specific concern holds,/);
    assert.match(prompt, /for example whether a function can fail under a condition no test covers\./);
    assert.match(prompt, /Report what you ran and what it showed, only for that concern\./);
    assert.match(prompt, /Do not look up or report CI results\./);
    assert.match(prompt, /Do not include a `?Verification:`? paragraph\./);
    assert.match(prompt, /exact admitted head SHA/);
    // The review is the merge gate for the harness's own changes (#526):
    // it must argue against the change, not take its description's word.
    assert.match(prompt, /Review adversarially/);
    assert.match(prompt, /Assume the change is wrong or malicious until the code\s+shows otherwise\./);
    assert.match(prompt, /Look for what it weakens, not only what it adds/);
    assert.match(prompt, /state the worst thing a changed file\s+could now do and why it cannot\./);
    assert.match(prompt, /Never approve because the description or\s+comments say the change is safe\./);
    assert.match(prompt, /cite files and lines for actionable findings/);
    // Only blockers block (#550): a CHANGES per new narrow finding cost a
    // fix, CI and review round each, so important findings and nits ride
    // along with an approval as follow-ups.
    assert.match(prompt, /Report every finding you can see in this one pass, not only the first\./);
    assert.match(prompt, /Tag each finding with exactly one severity: blocker, important or nit; an\s+untagged finding is not allowed\./);
    assert.match(prompt, /A blocker makes the change wrong for its\s+main purpose, loses data, or opens a security hole with a concrete path/);
    assert.match(prompt, /For supply-chain hardening, a blocker requires that the change newly runs\s+third-party code with a write credential in reach, including in apply, with a\s+PAT, in a write-permission pull_request_target job, or on the broker host\./);
    assert.match(prompt, /Otherwise supply-chain findings are important at most and go under Follow-ups\./);
    assert.match(prompt, /Supply-chain hardening is wanted over time as tracked follow-ups, not as a\s+gate on each change\./);
    assert.match(prompt, /This ceiling covers trusting an ordinary upstream, not a\s+concrete path the change itself opens for code an attacker controls to alter a\s+published artifact or read a credential or private source; that is a blocker\./);
    assert.match(prompt, /VERDICT: CHANGES only when there is at\s+least one blocker, and VERDICT: APPROVE otherwise/);
    assert.match(prompt, /list\s+important findings and nits under a "Follow-ups" heading, each with its file\s+and line, for later pull requests\./);
    assert.match(prompt, /When there is a blocker, the fix may take\s+important findings and nits along\./);
    assert.doesNotMatch(prompt, /\bP[0-3]\b/);
    assert.doesNotMatch(prompt, /VERDICT: CHANGES when there is\s+something actionable/);
    assert.doesNotMatch(prompt, /Do not build|Run relevant tests|what you verified or could not verify/);
  }
  // Whether its approval merges is the owner's merge policy (#556), stated
  // after the task, not prose the reviewer weighs.
  assert.match(standing, /Whether your approval merges is the\s+repository owner's decision, stated under "Merge policy"/);
  assert.match(standing, /Without that section, a\s+person approves every merge after you\./);
  assert.match(standing, /Ask for a person only when you find a\s+concrete risk you cannot bound, and say which\./);
  assert.doesNotMatch(standing, /merge gate for every change here/);
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(caller, /review-task: workflow\/review.md/);
  const agent = caller.split('\n  agent:')[1].split('\n  check:')[0];
  assert.doesNotMatch(agent, /rust-toolchain|rust-cache|setup-(?:node|python|go|java)|cargo (?:build|test|fmt|clippy)|npm (?:test|ci)/);
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
  // status (the status), the identity token in agent and check's detector.
  const jobs = Object.fromEntries(caller.split('\njobs:\n')[1].split(/\n(?=  [a-z]+:\n)/)
    .map(job => [job.match(/^\s*([a-z]+):/)[1], job]));
  assert.deepEqual(Object.keys(jobs), ['policy', 'refusal', 'agent', 'check', 'submit', 'apply', 'status']);
  for (const [name, writes] of Object.entries({ policy: [], agent: ['id-token'], check: ['id-token'],
    refusal: ['pull-requests'], submit: ['pull-requests'], apply: ['pull-requests'], status: ['statuses'] })) {
    const granted = [...jobs[name].split('\n    permissions:\n')[1].matchAll(/^      ([a-z-]+): write$/gm)].map(m => m[1]);
    assert.deepEqual(granted, writes, name);
    // The agent job holds the provider's key, for its check and `run`
    // alone, as agentic-job.yml's does; no other secret.
    const secrets = name === 'agent' ? jobs[name].replaceAll('${{ secrets.INFERENCE_API_KEY }}', '') : jobs[name];
    if (name !== 'apply') assert.doesNotMatch(secrets, /secrets/, name);
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
  assert.match(jobs.status, /REVIEW_URL: \$\{\{ needs.submit.outputs.review-url \}\}/);
  // The verdict is posted once: as the review, or else as apply's comment.
  // The review's body is check's accepted upload, from the pinned source's
  // code, and only a checked verdict is submitted.
  assert.match(jobs.apply, /if: \$\{\{ !cancelled\(\) && needs.policy.result == 'success' && needs.submit.outputs.review-url == '' \}\}/);
  assert.match(jobs.submit, /vars.AGENT_REAL_REVIEWS == 'true'/);
  assert.match(jobs.submit, /needs.check.result == 'success' && needs.check.outputs.artifact-id != ''/);
  assert.match(jobs.submit, /artifact-ids: \$\{\{ needs.check.outputs.artifact-id \}\}/);
  assert.match(jobs.submit, /repository: \$\{\{ needs.policy.outputs.source-repository \}\}\s+ref: \$\{\{ needs.policy.outputs.source-sha \}\}/);
  assert.match(jobs.submit, /VERDICT: \$\{\{ needs.check.outputs.verdict \}\}/);
  assert.match(jobs.submit, /HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}/);
  assert.match(jobs.submit, /AGENT_EXIT: \$\{\{ needs.agent.outputs.exit \}\}/);
  // The footer's job link is the agent job's own ID, from Actions.
  assert.match(jobs.submit, /AGENT_JOB: \$\{\{ needs.agent.outputs.job \}\}/);
  assert.match(jobs.agent, /\n {6}job: \$\{\{ job.check_run_id \}\}\n/);
  assert.doesNotMatch(jobs.submit, /secrets|safe-outputs-artifact-id|pull_request\.head|needs\.policy\.outputs\.ref\b/);
  assert.match(jobs.status, /if: \$\{\{ !cancelled\(\) && needs.policy.outputs.review-head != '' && needs.agent.result != 'cancelled' \}\}/);
  assert.match(jobs.status, /runs-on: ubuntu-26.04/);
  // Automatic reviews only for the owner, members and collaborators;
  // anyone else, a past contributor included, waits for a `/review`.
  // A bot only by its user id in REVIEW_BOT_IDS, and only a Bot.
  const starts = policyStarts(jobs.policy);
  const dependabot = { login: 'dependabot[bot]', id: 49699333, type: 'Bot' };
  const listed = { REVIEW_BOT_IDS: '[49699333]' };
  for (const [name, author, vars, started, extra = {}] of [
    ['the owner', { type: 'User', id: 1 }, {}, true, { author_association: 'OWNER' }],
    ['a collaborator', { type: 'User', id: 1 }, {}, true, { author_association: 'COLLABORATOR' }],
    ['a past contributor', { type: 'User', id: 1 }, listed, false, { author_association: 'CONTRIBUTOR' }],
    ['a collaborator\'s draft', { type: 'User', id: 1 }, {}, false, { author_association: 'COLLABORATOR', draft: true }],
    ['Dependabot, listed', dependabot, listed, true],
    ['Dependabot, listed as a string', dependabot, { REVIEW_BOT_IDS: '["49699333"]' }, true],
    ['Dependabot, nothing listed', dependabot, {}, false],
    ['Dependabot, its id not in an array', dependabot, { REVIEW_BOT_IDS: '49699333' }, false],
    ['a bot whose id is part of a listed one', { login: 'x[bot]', id: 4969, type: 'Bot' }, { REVIEW_BOT_IDS: '"49699333"' }, false],
    ['Dependabot, another bot listed', dependabot, { REVIEW_BOT_IDS: '[29139614]' }, false],
    ['Dependabot\'s draft', dependabot, listed, false, { draft: true }],
    ['another bot', { login: 'renovate[bot]', id: 29139614, type: 'Bot' }, listed, false],
    ['a bot with Dependabot\'s login', { login: 'dependabot[bot]', id: 7, type: 'Bot' }, listed, false],
    ['a user with a listed id', { login: 'mallory', id: 49699333, type: 'User' }, listed, false],
  ]) {
    const pull = { draft: false, author_association: 'NONE', user: author, ...extra };
    assert.equal(starts({ event_name: 'pull_request_target', event: { pull_request: pull } }, vars), started, name);
  }
  const comment = body => ({ event_name: 'issue_comment', event: { issue: { pull_request: {} }, comment: { body } } });
  assert.equal(starts(comment('/review'), {}), true);
  assert.equal(starts(comment('please /review'), {}), false);
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
  assert.match(apply, /if: \$\{\{ fromJSON\(inputs.check\).outputs.has-patch == 'true' && fromJSON\(inputs.policy\).apply-staged != 'true' \}\}\s+with:\s+repository: \$\{\{ env.OUTPUT_REPO \}\}/);
  assert.doesNotMatch(apply, /pull_request.head|refs\/pull/);
  const ci = fs.readFileSync(path.join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  // Whether the base has the review files is read from the base commit.
  assert.match(ci, /e2e-review:\s+needs: changes\n\s+if: \$\{\{ needs\.changes\.outputs\.e2e == 'true' && needs\.changes\.outputs\.review == 'true' \}\}/);
  assert.match(ci, /git cat-file -t "\$BASE:\$file"/);
  assert.match(ci, /Exactly one scripted verdict was posted/);
  assert.match(ci, /HEAD_SHA: \$\{\{ github.event.pull_request.head.sha \}\}/);
  assert.match(ci, /contains\("Reviewed SHA: " \+ \$sha \+ "\\n"\)/);
  assert.match(ci, /\(\.key == "e2e-review" and \$review != "true"\)/);
});

test('target events read workflow policy without changing the trusted review base', () => {
  const policy = fs.readFileSync(path.join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  const checkout = policy.split('      # The calling repository, for its bounds file.')[1]
    .split('      # Logs, transcripts')[0].match(/ref: \$\{\{ (.*) \}\}/)[1];
  const base = policy.match(/^      ref: \$\{\{ (.*) \}\}/m)[1];
  const inputs = { review: true, 'review-item': '', base: 'main' };
  const evaluate = expression => Function('github', 'inputs',
    `return ${expression.replaceAll('inputs.review-item', 'inputs["review-item"]')}`);
  const github = { event_name: 'pull_request_target', workflow_sha: 'current-policy',
    sha: 'event-sha', event: { pull_request: { base: { sha: 'stale-base' } } } };
  assert.equal(evaluate(checkout)(github, inputs), 'current-policy');
  assert.equal(evaluate(base)(github, inputs), 'stale-base');
  github.event_name = 'pull_request';
  assert.equal(evaluate(checkout)(github, inputs), 'stale-base');
  inputs.review = false;
  assert.equal(evaluate(checkout)(github, inputs), 'event-sha');
});

test('refused event reviews update one author-owned bounded status comment', () => {
  const { refusalText } = require('./review.cjs');
  const { upsert, MARKER } = require('./status.cjs');
  const reason = 'the bounds do not allow forks';
  assert.equal(refusalText(reason), `Review refused by policy: ${reason}`);
  assert.equal(refusalText('a\n\r@user [link](url)'), 'Review refused by policy: a \\@user \\[link\\]\\(url\\)');
  assert.ok(refusalText('a'.repeat(2000)).length < 1100);
  const comments = [{ id: 1, user: { login: 'attacker' }, body: `copied\n\n${MARKER}` }];
  const calls = [];
  const api = (method, route, body) => {
    calls.push([method, route, body]);
    if (method === 'GET') return comments;
    if (method === 'POST') {
      const comment = { id: 2, user: { login: 'github-actions[bot]' }, body };
      comments.push(comment);
      return comment;
    }
    comments[1].body = body;
    return comments[1];
  };
  const env = { REPO: 'owner/repo', ITEM: '472', GITHUB_RUN_ID: '100', TEXT: refusalText(reason) };
  upsert(env, api);
  upsert({ ...env, GITHUB_RUN_ID: '101' }, api);
  assert.equal(calls.filter(([method]) => method === 'POST').length, 1);
  assert.equal(calls.filter(([method]) => method === 'PATCH').length, 1);
  assert.equal(comments[1].body.split('\n')[0], `Review refused by policy: ${reason}`);
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  const refusal = caller.split('\n  refusal:\n')[1].split('\n  agent:\n')[0];
  assert.match(refusal, /needs.policy.outputs.admitted == 'false'/);
  assert.match(refusal, /ref: \$\{\{ needs.policy.outputs.source-sha \}\}/);
  assert.match(refusal, /REASON: \$\{\{ needs.policy.outputs.reason \}\}/);
  assert.match(refusal, /run: node .agentic-job-source\/workflow\/review.cjs refusal/);
  assert.match(refusal, /group: agentic-job-status-/);
});

// A caller sets AGENT_CONFIG only to override: without it, review and
// dispatch read this repository's hosted.toml at the called commit, from
// the checkout policy.yml makes of its own source, and no caller copies it.
test('review and dispatch default to this source\'s hosted.toml', () => {
  const read = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const source = '.agentic-job-source/';
  const hosted = `${source}.github/agentic-job/hosted.toml`;
  assert.ok(fs.statSync(path.join(__dirname, '..', hosted.slice(source.length))).isFile());
  // In the policy job, before the step that reads it.
  const policy = read('.github/workflows/policy.yml').split('\n  policy:\n')[1].split('- name: Write the configuration')[0];
  assert.match(policy,
    /\n          repository: \$\{\{ job\.workflow_repository \}\}\n          ref: \$\{\{ job\.workflow_sha \}\}\n          path: \.agentic-job-source\n/);
  // dispatch.yml's goes through agentic-job.yml unchanged.
  assert.match(read('.github/workflows/agentic-job.yml'), /^      config: \$\{\{ inputs\.config \}\}$/m);
  for (const file of ['review.yml', 'dispatch.yml']) {
    const expression = read(`.github/workflows/${file}`).match(/^      config: \$\{\{ (.+) \}\}$/m)?.[1];
    assert.ok(expression, file);
    const value = Function('inputs', 'vars', `return ${expression}`);
    for (const scripted of [false, true]) {
      assert.equal(value({ scripted }, {}), hosted, file);
      assert.equal(value({ scripted }, { AGENT_CONFIG: '' }), hosted, file);
      assert.equal(value({ scripted }, { AGENT_CONFIG: 'own.toml' }),
        file === 'dispatch.yml' && scripted ? hosted : 'own.toml', file);
    }
  }
});
