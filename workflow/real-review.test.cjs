'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { WITHHELD, submitReview } = require('./review.cjs');

const head = 'a'.repeat(40);
const env = { REAL_REVIEWS: 'true', PULL: '12', HEAD_SHA: head,
  CHECK_RESULT: 'success', APPLY_RESULT: 'success', VERDICT: 'APPROVE',
  RESULT_URL: 'https://github.com/owner/repo/pull/12#issuecomment-123',
  GITHUB_REPOSITORY: 'owner/repo' };

function fixture({ files = [{ filename: 'src/lib.rs' }], sha = head, count = files.length,
  body = 'VERDICT: APPROVE\nFindings', issue = '12' } = {}) {
  const reviews = [];
  const pages = [];
  const github = { rest: { pulls: {
    get: async () => ({ data: { state: 'open', head: { sha }, changed_files: count } }),
    listFiles: async ({ page }) => { pages.push(page); return { data: files.slice((page - 1) * 100, page * 100) }; },
    createReview: async review => reviews.push(review),
  }, issues: { getComment: async () => ({ data: { body,
    issue_url: `https://api.github.com/repos/owner/repo/issues/${issue}` } }) } } };
  return { github, reviews, pages, core: { notice() {} } };
}

test('real reviews preserve the first line, state and exact commit', async () => {
  for (const verdict of ['APPROVE', 'CHANGES']) {
    const f = fixture({ body: `VERDICT: ${verdict}\nFindings` });
    await submitReview({ ...env, VERDICT: verdict }, f.github, f.core);
    assert.deepEqual(f.reviews, [{ owner: 'owner', repo: 'repo', pull_number: 12,
      commit_id: head, event: verdict === 'APPROVE' ? 'APPROVE' : 'REQUEST_CHANGES',
      body: `VERDICT: ${verdict}\nFindings` }]);
  }
});

test('off by default, incomplete runs and stale heads submit nothing', async () => {
  for (const overrides of [{ REAL_REVIEWS: '' }, { REAL_REVIEWS: 'false' },
    { CHECK_RESULT: 'failure' }, { APPLY_RESULT: 'failure' }, { VERDICT: '' }]) {
    await submitReview({ ...env, ...overrides }, {}, {});
  }
  const f = fixture({ sha: 'b'.repeat(40) });
  await submitReview(env, f.github, f.core);
  assert.equal(f.reviews.length, 0);
});

test('only changes to the review gate, including renames, withhold approval', async () => {
  for (const [file, withheld] of [[{ filename: '.github/workflows/review.yml' }, true],
    [{ filename: '.github/workflows/policy.yml' }, true], [{ filename: '.github/workflows/check.yml' }, true],
    [{ filename: '.github/workflows/apply.yml' }, true],
    [{ filename: '.github/workflows/workflow-ingress.yml' }, true],
    [{ filename: 'workflow/review.cjs' }, true], [{ filename: 'workflow/ingress.py' }, true],
    ...['workflow/activation.cjs', 'workflow/policy-command.cjs', 'workflow/status.cjs',
      'workflow/review.toml', 'workflow/review-command.toml', 'workflow/actionlint.yaml',
      'workflow/review.md', '.github/agentic-job/hosted.toml'].flatMap(filename => [
      [{ filename }, true], [{ filename: 'elsewhere.cjs', previous_filename: filename }, true],
      [{ filename, previous_filename: 'elsewhere.cjs' }, true],
    ]),
    [{ filename: 'docs/review.md' }, true],
    [{ filename: 'elsewhere.cjs', previous_filename: 'workflow/review.cjs' }, true],
    [{ filename: '.github/workflows/ci.yml' }, false], [{ filename: 'workflow/push.cjs' }, false],
    [{ filename: 'docs/review.md.bak' }, false],
    [{ filename: '.github/agentic-job/hosted.toml.bak' }, false]]) {
    for (const verdict of ['APPROVE', 'CHANGES']) {
      const body = `VERDICT: ${verdict}\nFindings`;
      const f = fixture({ files: [file], body });
      await submitReview({ ...env, VERDICT: verdict }, f.github, f.core);
      const event = verdict === 'CHANGES' ? 'REQUEST_CHANGES' : withheld ? 'COMMENT' : 'APPROVE';
      assert.deepEqual(f.reviews, [{ owner: 'owner', repo: 'repo', pull_number: 12, commit_id: head,
        event, body: event === 'COMMENT' ? `${WITHHELD}\n\n${body}` : body }], file.filename);
    }
  }
});

test('the selected non-default reviewer configuration requires human approval, including renames', async () => {
  for (const config of ['.github/agentic-job/reviewer.toml', 'config/reviewer.toml']) {
    for (const file of [{ filename: config },
      { filename: 'elsewhere.toml', previous_filename: config },
      { filename: config, previous_filename: 'elsewhere.toml' }]) {
      const f = fixture({ files: [file] });
      await submitReview({ ...env, AGENT_CONFIG: `./${config}` }, f.github, f.core);
      assert.equal(f.reviews[0].event, 'COMMENT');
      assert.equal(f.reviews[0].body, `${WITHHELD}\n\nVERDICT: APPROVE\nFindings`);
    }
    const f = fixture({ files: [{ filename: `${config}.bak` }] });
    await submitReview({ ...env, AGENT_CONFIG: config }, f.github, f.core);
    assert.equal(f.reviews[0].event, 'APPROVE');
  }
});

test('file inspection is complete and bounded to three pages', async () => {
  const f = fixture({ files: Array.from({ length: 300 }, (_, i) => ({ filename: `src/${i}.rs` })) });
  await submitReview(env, f.github, f.core);
  assert.deepEqual(f.pages, [1, 2, 3]);
  for (const options of [{ count: 301 }, { count: 2 }, { count: -1 }]) {
    const invalid = fixture(options);
    await assert.rejects(submitReview(env, invalid.github, invalid.core), /300|Incomplete/);
    assert.equal(invalid.reviews.length, 0);
  }
});

test('caller-held paths are additive, match simple globs and check both rename names', async () => {
  const patterns = '\n.github/agentic-job/dispatch.toml\n.github/agentic-job/profiles/*\n.github/poll/**\nconfig/**/authority.toml\nconfig/a+b.toml\n';
  for (const [filename, held] of [
    ['.github/agentic-job/dispatch.toml', true],
    ['.github/agentic-job/dispatch.toml.bak', false],
    ['.github/agentic-job/profiles/fix.toml', true],
    ['.github/agentic-job/profiles/nested/fix.toml', false],
    ['.github/poll/nested/run.cjs', true], ['.github/poll/run.cjs', true],
    ['.github/poller/run.cjs', false], ['config/authority.toml', true],
    ['config/nested/deeper/authority.toml', true], ['config/a+b.toml', true],
    ['config/ab.toml', false], ['.github/workflows/review.yml', true],
  ]) {
    for (const file of [{ filename }, { filename: 'elsewhere', previous_filename: filename }]) {
      for (const verdict of ['APPROVE', 'CHANGES']) {
        const f = fixture({ files: [file], body: `VERDICT: ${verdict}` });
        await submitReview({ ...env, HUMAN_APPROVAL_PATHS: patterns, VERDICT: verdict }, f.github, f.core);
        assert.equal(f.reviews[0].event,
          verdict === 'CHANGES' ? 'REQUEST_CHANGES' : held ? 'COMMENT' : 'APPROVE', filename);
      }
    }
  }
  const f = fixture({ files: [{ filename: '.github/agentic-job/dispatch.toml' }] });
  await submitReview(env, f.github, f.core);
  assert.equal(f.reviews[0].event, 'APPROVE');
});

test('invalid or oversized held-path lists fail closed before API calls', async () => {
  for (const input of ['/absolute', '../escape', './relative', 'a//b', '!negation',
    'a/**b', 'a?', 'a[bc]', 'a\\b', 'a\u0000b', 'a'.repeat(257),
    Array(65).fill('a').join('\n'), ' '.repeat(16385), 42]) {
    await assert.rejects(submitReview({ ...env, HUMAN_APPROVAL_PATHS: input }, {}, {}), /Human approval paths/);
  }
  const f = fixture();
  await submitReview({ ...env, HUMAN_APPROVAL_PATHS: Array(64).fill('a'.repeat(255)).join('\n') + '\n' }, f.github, f.core);
  assert.equal(f.reviews[0].event, 'APPROVE');
});

test('held paths are an optional reusable-workflow input passed as inert environment data', () => {
  const fs = require('node:fs');
  const workflow = fs.readFileSync(require('node:path').join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(workflow, /workflow_call:\n    inputs:\n      human-approval-paths:/);
  assert.match(workflow, /type: string\n        required: false\n        default: ''/);
  assert.match(workflow, /HUMAN_APPROVAL_PATHS: \$\{\{ inputs.human-approval-paths \|\| '' \}\}/);
});

test('body must match checked verdict and triggering pull request', async () => {
  for (const options of [{ body: 'VERDICT: CHANGES' }, { issue: '13' }]) {
    const f = fixture(options);
    await assert.rejects(submitReview(env, f.github, f.core), /does not match/);
    assert.equal(f.reviews.length, 0);
  }
  const f = fixture();
  await assert.rejects(submitReview({ ...env, RESULT_URL: 'https://example.com/123' }, f.github, f.core), /applied comment/);
});
