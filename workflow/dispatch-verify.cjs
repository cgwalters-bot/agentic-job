'use strict';

// Proposed CI code runs with read-only permissions; cleanup is a separate job.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

const { GH_REPO: repo, RUN: run, PR: pr, REVIEW_HEAD: head, RESULT: result,
  COMPOSE_RESULT: composed } = process.env;
assert.equal(result, 'success', 'all shipped dispatch profiles must succeed');
assert.equal(composed, 'success', 'the composed example must succeed');
const api = endpoint => JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', endpoint], { encoding: 'utf8' })).flat();
const comments = item => api(`repos/${repo}/issues/${item}/comments`)
  .filter(comment => comment.user.login === 'github-actions[bot]' && comment.body.includes(run));
// Research and the composed example each comment once.
assert.equal(comments(64).filter(comment => comment.body.includes('Scripted dispatch completed.')).length, 2);
if (pr) {
  assert.match(head, /^[0-9a-f]{40}$/);
  const verdicts = comments(pr).filter(comment => comment.body.startsWith('VERDICT: APPROVE\nREASON: Scripted dispatch'));
  assert.equal(verdicts.length, 1);
  assert.ok(verdicts[0].body.includes(`Reviewed SHA: ${head}`));
  // hosted.toml gives this repository, and no fork of it, cargo; the
  // scripted review ran `cargo metadata --locked` before writing this.
  if (repo === 'cgwalters-forge/agentic-job') {
    assert.match(verdicts[0].body, /\nToolchain: cargo \d/, 'the review sandbox must have a working cargo');
  }
}
