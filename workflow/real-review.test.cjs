'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { submitReview } = require('./review.cjs');

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

test('trusted workflow changes including renames cannot receive approval', async () => {
  for (const file of [{ filename: '.github/workflows/review.yml' },
    { filename: 'workflow/review.cjs' },
    { filename: 'elsewhere.cjs', previous_filename: 'workflow/review.cjs' }]) {
    const f = fixture({ files: [file] });
    await submitReview(env, f.github, f.core);
    assert.equal(f.reviews.length, 0);
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

test('body must match checked verdict and triggering pull request', async () => {
  for (const options of [{ body: 'VERDICT: CHANGES' }, { issue: '13' }]) {
    const f = fixture(options);
    await assert.rejects(submitReview(env, f.github, f.core), /does not match/);
    assert.equal(f.reviews.length, 0);
  }
  const f = fixture();
  await assert.rejects(submitReview({ ...env, RESULT_URL: 'https://example.com/123' }, f.github, f.core), /applied comment/);
});
