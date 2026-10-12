'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { resolvePush } = require('./push.cjs');

test("a push resolves an open pull request from a fork's branch and refuses hostile routing", async () => {
  const env = { EVENT: 'false', REVIEW: 'false', KIND: 'branch', ITEM: '42', REPO: 'o/r', OUTPUT_REPO: '',
    GITHUB_REPOSITORY: 'o/r' };
  const data = { number: 42, state: 'open', base: { ref: 'main', sha: 'b'.repeat(40), repo: { full_name: 'o/r' } },
    head: { ref: 'agent-run-12', sha: 'a'.repeat(40), repo: { full_name: 'bot/r', fork: true } } };
  const api = value => ({ rest: { pulls: { get: async args => {
    assert.deepEqual(args, { owner: 'o', repo: 'r', pull_number: 42 });
    return { data: value };
  } } } });
  const want = { branch: 'agent-run-12', head: 'a'.repeat(40), base: 'b'.repeat(40) };
  assert.deepEqual(await resolvePush(env, api(data)), want);
  for (const change of [{ OUTPUT_REPO: 'o/r' }, { OUTPUT_REPO: 'O/R' }, { OUTPUT_REPO: 'o/r', GITHUB_REPOSITORY: 'caller/repo' }]) {
    assert.deepEqual(await resolvePush({ ...env, ...change }, api(data)), want);
  }
  // The forge's names in another case are the same repository.
  assert.deepEqual(await resolvePush(env, api({ ...data, base: { ...data.base, repo: { full_name: 'O/R' } } })), want);
  // (the request's routing)
  for (const change of [{ EVENT: 'true' }, { REVIEW: 'true' }, { KIND: 'analysis' },
    { OUTPUT_REPO: 'other/repo' }, { GITHUB_REPOSITORY: 'caller/repo' }, { GITHUB_REPOSITORY: undefined },
    { ITEM: '01' }, { ITEM: '42 ' }, { ITEM: '' },
    { ITEM: '9999999999' }, { REPO: 'o/r/x' }]) {
    await assert.rejects(resolvePush({ ...env, ...change }, api(data)), /needs a branch run/, JSON.stringify(change));
  }
  // (the forge's answer) A branch of the repository itself is refused:
  // a push there runs the target's CI with its secrets (#430).
  for (const change of [{ state: 'closed' }, { number: 43 },
    { base: { ...data.base, sha: undefined } },
    { base: { ...data.base, sha: 'B'.repeat(40) } },
    { base: { ref: 'main', repo: { full_name: 'other/r' } } },
    { head: { ...data.head, repo: { full_name: 'o/r', fork: false } } },
    { head: { ...data.head, repo: { full_name: 'O/R', fork: true } } },
    { head: { ...data.head, repo: { full_name: 'bot/r' } } },
    { head: { ...data.head, repo: { fork: true } } },
    { head: { ...data.head, repo: null } },
    { head: { ...data.head, sha: 'A'.repeat(40) } },
    { head: { ...data.head, ref: undefined } }]) {
    await assert.rejects(resolvePush(env, api({ ...data, ...change })), /open pull request/, JSON.stringify(change));
  }
});
