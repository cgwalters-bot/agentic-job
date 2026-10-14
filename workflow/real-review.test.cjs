'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { submitReview } = require('./review.cjs');

const head = 'a'.repeat(40);
const env = { REAL_REVIEWS: 'true', PULL: '12', HEAD_SHA: head,
  CHECK_RESULT: 'success', AGENT_EXIT: '0', VERDICT: 'APPROVE',
  GITHUB_REPOSITORY: 'owner/repo', GITHUB_RUN_ID: '77' };
const marker = '<!-- gh-aw-agentic-workflow: review, id: 77, workflow_id: agentic-job, run: https://github.com/owner/repo/actions/runs/77 -->';
const checked = (body = 'VERDICT: APPROVE\nFindings', extra = {}) => ({ items: [{ type: 'add_comment', body, ...extra }], errors: [] });

function fixture({ sha = head, state = 'open', comments = [], reviewed = [] } = {}) {
  const reviews = [];
  const github = { rest: { pulls: {
    get: async () => ({ data: { state, head: { sha } } }),
    listReviews: 'listReviews',
    createReview: async review => { reviews.push(review); return { data: { id: 5, html_url: 'https://github.com/owner/repo/pull/12#pullrequestreview-5' } }; },
  }, issues: { listComments: 'listComments' } },
  paginate: async (route, args) => {
    assert.equal(args.per_page, 100);
    assert.equal(args.issue_number ?? args.pull_number, 12);
    return route === 'listComments' ? comments : reviewed;
  } };
  return { github, reviews, core: { notice() {} } };
}

// agent-board's cited_run (board-forge/src/poll.rs): exactly one marker,
// whose `run: ` field is this run's URL.
function citedRun(body) {
  const parts = body.split('<!-- gh-aw-agentic-workflow: ');
  if (parts.length !== 2) return null;
  const marker = parts[1].slice(0, parts[1].indexOf('-->'));
  return marker.split(', ').find(field => field.startsWith('run: '))?.slice(5).trimEnd() ?? null;
}

// The fixture has no listFiles: by the operator's decision (#540) the review is
// the merge gate for every change, the harness's own included, so nothing may
// look at which files changed to withhold an APPROVE.
test('real reviews submit the checked body, with the run marker, at the exact commit', async () => {
  for (const verdict of ['APPROVE', 'CHANGES']) {
    const f = fixture();
    const url = await submitReview({ ...env, VERDICT: verdict }, checked(`VERDICT: ${verdict}\nFindings`, { item_number: 12 }), f.github, f.core);
    assert.equal(url, 'https://github.com/owner/repo/pull/12#pullrequestreview-5');
    assert.deepEqual(f.reviews, [{ owner: 'owner', repo: 'repo', pull_number: 12,
      commit_id: head, event: verdict === 'APPROVE' ? 'APPROVE' : 'REQUEST_CHANGES',
      body: `VERDICT: ${verdict}\nFindings\n\n${marker}` }]);
    assert.equal(citedRun(f.reviews[0].body), 'https://github.com/owner/repo/actions/runs/77');
  }
});

// A re-run of failed jobs posts the verdict no second time.
test('a verdict an earlier attempt posted is not submitted again', async () => {
  const applied = '<!-- agentic-job-applied: 77/0/0123456789abcdef -->';
  for (const [name, comments, posted] of [
    ['the bot\'s comment', [{ user: { login: 'github-actions[bot]' }, author_association: 'NONE', body: `VERDICT: APPROVE\n\n${applied}` }], true],
    ['a collaborator\'s (the PAT\'s) comment', [{ user: { login: 'pat' }, author_association: 'COLLABORATOR', body: `x ${applied}` }], true],
    ['a stranger quoting the name', [{ user: { login: 'mallory' }, author_association: 'NONE', body: applied }], false],
    ['another run\'s comment', [{ user: { login: 'github-actions[bot]' }, body: applied.replace('77/', '78/') }], false],
    ['this run\'s name, not last', [{ user: { login: 'github-actions[bot]' }, body: `${applied}\n${applied.replace('77/', '78/')}` }], false],
  ]) {
    const f = fixture({ comments });
    assert.equal(await submitReview(env, checked(), f.github, f.core) === '', posted, name);
    assert.equal(f.reviews.length, posted ? 0 : 1, name);
  }
  const earlier = { user: { login: 'github-actions[bot]' }, html_url: 'https://github.com/owner/repo/pull/12#pullrequestreview-4',
    commit_id: head, state: 'APPROVED', body: `VERDICT: APPROVE\nFindings\n\n${marker}` };
  let f = fixture({ reviewed: [earlier] });
  assert.equal(await submitReview(env, checked(), f.github, f.core), earlier.html_url);
  assert.equal(f.reviews.length, 0);
  // Only the same review: a re-run of all jobs that reached another verdict,
  // other findings or another head submits its own.
  for (const other of [{ user: { login: 'mallory' } }, { commit_id: 'b'.repeat(40) },
    { state: 'CHANGES_REQUESTED' }, { body: `VERDICT: APPROVE\nOther findings\n\n${marker}` }]) {
    f = fixture({ reviewed: [{ ...earlier, ...other }] });
    assert.equal(await submitReview(env, checked(), f.github, f.core), 'https://github.com/owner/repo/pull/12#pullrequestreview-5');
    assert.equal(f.reviews.length, 1, JSON.stringify(other));
  }
});

// A submission whose response was lost is not posted again as the comment.
test('a review posted despite an error counts as submitted', async () => {
  const posted = { user: { login: 'github-actions[bot]' }, html_url: 'https://github.com/owner/repo/pull/12#pullrequestreview-6',
    commit_id: head, state: 'APPROVED', body: `VERDICT: APPROVE\nFindings\n\n${marker}` };
  const reviewed = [];
  const f = fixture({ reviewed });
  f.github.rest.pulls.createReview = async () => { reviewed.push(posted); throw new Error('502'); };
  assert.equal(await submitReview(env, checked(), f.github, f.core), posted.html_url);
  reviewed.length = 0;
  f.github.rest.pulls.createReview = async () => { throw new Error('403'); };
  await assert.rejects(submitReview(env, checked(), f.github, f.core), /403/);
});

// An empty result is what lets apply post the comment instead.
test('off by default, incomplete runs, noops and stale heads submit nothing', async () => {
  for (const overrides of [{ REAL_REVIEWS: '' }, { REAL_REVIEWS: 'false' },
    { CHECK_RESULT: 'failure' }, { AGENT_EXIT: '3' }, { AGENT_EXIT: '124' }, { AGENT_EXIT: '' }, { VERDICT: '' }]) {
    assert.equal(await submitReview({ ...env, ...overrides }, checked(), {}, {}), '', JSON.stringify(overrides));
  }
  for (const options of [{ sha: 'b'.repeat(40) }, { state: 'closed' }]) {
    const f = fixture(options);
    assert.equal(await submitReview(env, checked(), f.github, f.core), '');
    assert.equal(f.reviews.length, 0);
  }
});

test('the checked output must match the checked verdict and the triggering pull request', async () => {
  for (const [output, error] of [
    [checked('VERDICT: CHANGES'), /does not match/],
    [checked('Findings only'), /must start with VERDICT/],
    [checked('VERDICT: APPROVE', { item_number: 13 }), /triggering pull request/],
    [{ items: [{ type: 'noop' }] }, /does not match/],
    [{ items: [] }, /exactly one/],
  ]) {
    const f = fixture();
    await assert.rejects(submitReview(env, output, f.github, f.core), error);
    assert.equal(f.reviews.length, 0);
  }
  for (const overrides of [{ HEAD_SHA: 'main' }, { PULL: '0' }, { GITHUB_RUN_ID: '7 -->' }, { GITHUB_RUN_ID: undefined }]) {
    const f = fixture();
    await assert.rejects(submitReview({ ...env, ...overrides }, checked(), f.github, f.core));
    assert.equal(f.reviews.length, 0);
  }
});
