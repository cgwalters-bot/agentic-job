'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { submitReview } = require('./review.cjs');

const head = 'a'.repeat(40);
const env = { REAL_REVIEWS: 'true', PULL: '12', HEAD_SHA: head,
  CHECK_RESULT: 'success', APPLY_RESULT: 'success', VERDICT: 'APPROVE',
  RESULT_URL: 'https://github.com/owner/repo/pull/12#issuecomment-123',
  GITHUB_REPOSITORY: 'owner/repo' };

function fixture({ sha = head, body = 'VERDICT: APPROVE\nFindings', issue = '12' } = {}) {
  const reviews = [];
  const github = { rest: { pulls: {
    get: async () => ({ data: { state: 'open', head: { sha } } }),
    createReview: async review => reviews.push(review),
  }, issues: { getComment: async () => ({ data: { body,
    issue_url: `https://api.github.com/repos/owner/repo/issues/${issue}` } }) } } };
  return { github, reviews, core: { notice() {} } };
}

// The fixture has no listFiles: by the operator's decision (#540) the review is
// the merge gate for every change, the harness's own included, so nothing may
// look at which files changed to withhold an APPROVE.
test('real reviews preserve the first line, state and exact commit for any files', async () => {
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

test('body must match checked verdict and triggering pull request', async () => {
  for (const options of [{ body: 'VERDICT: CHANGES' }, { issue: '13' }]) {
    const f = fixture(options);
    await assert.rejects(submitReview(env, f.github, f.core), /does not match/);
    assert.equal(f.reviews.length, 0);
  }
  const f = fixture();
  await assert.rejects(submitReview({ ...env, RESULT_URL: 'https://example.com/123' }, f.github, f.core), /applied comment/);
});
