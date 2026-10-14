'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { resolvePush, currentBase, pushTarget, OWNER_BRANCHES } = require('./push.cjs');

test("a push resolves an open pull request from any repository's branch and refuses hostile routing", async () => {
  const env = { EVENT: 'false', REVIEW: 'false', KIND: 'branch', ITEM: '42', REPO: 'o/r', OUTPUT_REPO: '',
    GITHUB_REPOSITORY: 'o/r' };
  const data = { number: 42, state: 'open', base: { ref: 'main', sha: 'b'.repeat(40), repo: { full_name: 'o/r' } },
    head: { ref: 'agent-run-12', sha: 'a'.repeat(40), repo: { full_name: 'bot/r', fork: true } } };
  const api = value => ({ rest: { pulls: { get: async args => {
    assert.deepEqual(args, { owner: 'o', repo: 'r', pull_number: 42 });
    return { data: value };
  } }, git: { getRef: async args => {
    assert.deepEqual(args, { owner: 'o', repo: 'r', ref: 'heads/main' });
    return { data: { object: { type: 'commit', sha: 'c'.repeat(40) } } };
  } } } });
  const want = { branch: 'agent-run-12', head: 'a'.repeat(40), base: 'c'.repeat(40) };
  assert.deepEqual(await resolvePush(env, api(data)), want);
  for (const change of [{ OUTPUT_REPO: 'o/r' }, { OUTPUT_REPO: 'O/R' }, { OUTPUT_REPO: 'o/r', GITHUB_REPOSITORY: 'caller/repo' }]) {
    assert.deepEqual(await resolvePush({ ...env, ...change }, api(data)), want);
  }
  // The forge's names in another case are the same repository.
  assert.deepEqual(await resolvePush(env, api({ ...data, base: { ...data.base, repo: { full_name: 'O/R' } } })), want);
  // Whose branch it is, and whether apply may push there, apply decides (#553).
  for (const repo of [{ full_name: 'o/r', fork: false }, { full_name: 'bot/r' }]) {
    assert.deepEqual(await resolvePush(env, api({ ...data, head: { ...data.head, repo } })), want, JSON.stringify(repo));
  }
  // (the request's routing)
  for (const change of [{ EVENT: 'true' }, { REVIEW: 'true' }, { KIND: 'analysis' },
    { OUTPUT_REPO: 'other/repo' }, { GITHUB_REPOSITORY: 'caller/repo' }, { GITHUB_REPOSITORY: undefined },
    { ITEM: '01' }, { ITEM: '42 ' }, { ITEM: '' },
    { ITEM: '9999999999' }, { REPO: 'o/r/x' }]) {
    await assert.rejects(resolvePush({ ...env, ...change }, api(data)), /needs a branch run/, JSON.stringify(change));
  }
  // (the forge's answer) A deleted head repository names no branch.
  for (const change of [{ state: 'closed' }, { number: 43 },
    { base: { ...data.base, sha: undefined } },
    { base: { ...data.base, sha: 'B'.repeat(40) } },
    { base: { ref: 'main', repo: { full_name: 'other/r' } } },
    { head: { ...data.head, repo: { fork: true } } },
    { head: { ...data.head, repo: null } },
    { head: { ...data.head, sha: 'A'.repeat(40) } },
    { head: { ...data.head, ref: undefined } }]) {
    await assert.rejects(resolvePush(env, api({ ...data, ...change })), /open pull request/, JSON.stringify(change));
  }
});

test('current replacement base is resolved from the forge branch, never the stale PR sha', async () => {
  const pull = { base: { ref: 'release/v1', sha: 'a'.repeat(40), repo: { full_name: 'O/R' } } };
  for (const object of [{ type: 'commit', sha: 'b'.repeat(40) }, { type: 'tag', sha: 'b'.repeat(40) },
    { type: 'commit', sha: 'main' }, { type: 'commit', sha: 'B'.repeat(40) }, {}]) {
    const github = { rest: { git: { getRef: async args => {
      assert.deepEqual(args, { owner: 'o', repo: 'r', ref: 'heads/release/v1' });
      return { data: { object } };
    } } } };
    if (object.type === 'commit' && object.sha === 'b'.repeat(40)) {
      assert.equal(await currentBase('o/r', pull, github), object.sha);
    } else await assert.rejects(currentBase('o/r', pull, github), /Invalid current base/);
  }
  await assert.rejects(currentBase('other/r', pull, {}), /Invalid pull request base/);
  await assert.rejects(currentBase('o/r', { base: { ...pull.base, ref: '' } }, {}), /Invalid pull request base/);
  await assert.rejects(currentBase('o/r', pull, { rest: { git: { getRef: async () => { throw new Error('unavailable'); } } } }), /unavailable/);
});

// Apply's own reading of a push's pull request, with its token, before
// anything is fetched or pushed (#553). The forge answers for a pull
// request from `carol/r` unless a case says otherwise.
test("a push goes to any pull request's branch apply may push to, but not a default, protected or unaccepted one", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'push-target-'));
  try {
    const run = async ({ config = {}, pull = {}, repo = {}, branch = { protected: false }, rules = [], accepts = null, fails = null, me = 'bot', env = {} } = {}) => {
      writeFileSync(join(dir, 'config.json'), JSON.stringify({ push_to_pull_request_branch: { target: '42', head: 'a'.repeat(40), ...config } }));
      const asked = [];
      // `fails` names the call the forge cannot answer.
      const answer = (call, args, data) => {
        asked.push([call, args]);
        if (fails === call) throw Object.assign(new Error('Not Found'), { status: 404 });
        return { data };
      };
      const github = { rest: {
        pulls: { get: async args => {
          asked.push(['pull', args]);
          return { data: { number: 42, state: 'open', base: { ref: 'main', repo: { full_name: 'o/r' } },
            head: { ref: 'fix/x', repo: { full_name: 'carol/r', fork: true, owner: { login: 'carol' } } }, ...pull } };
        } },
        repos: {
          get: async args => answer('repo', args, { default_branch: 'main', fork: true, parent: { full_name: 'o/r' }, permissions: { push: true }, ...repo }),
          getBranch: async args => answer('branch', args, branch),
          getBranchRules: async args => answer('rules', args, rules),
          getContent: async args => {
            asked.push(['content', args]);
            if (accepts instanceof Error) throw accepts;
            if (accepts === null) throw Object.assign(new Error('Not Found'), { status: 404 });
            return { data: accepts };
          },
        },
        git: { getRef: async () => ({ data: { object: { type: 'commit', sha: 'c'.repeat(40) } } }) },
      } };
      const target = await pushTarget({ GH_AW_TMP: dir, OUTPUT_REPO: 'o/r', REPO: 'o/r', GITHUB_REPOSITORY: 'caller/r', BASE: 'fix/x', REPLACEMENT: 'false', ...env }, me, github);
      return { target, asked };
    };
    const own = { head: { ref: 'fix/x', repo: { full_name: 'o/r', fork: false, owner: { login: 'o' } } } };
    const from = full_name => ({ pull: { head: { ref: 'fix/x', repo: { full_name, fork: true, owner: { login: full_name.split('/')[0] } } } } });
    // The opt-in as the forge answers it, naming the repositories given.
    const naming = (...names) => {
      const content = Buffer.from(names.map(name => `${name}\n`).join(''));
      return { type: 'file', path: OWNER_BRANCHES, encoding: 'base64', size: content.length, content: content.toString('base64') };
    };
    const file = naming('carol/r');

    // Another's fork that accepts it: its head repository, the branch read
    // to be neither default nor protected, and the opt-in read from the
    // fork's default branch. The identity's own fork, held to the same but
    // to no opt-in, is the fork step's.
    const { target, asked } = await run({ accepts: file });
    assert.deepEqual(target, { repo: 'carol/r', base: null });
    const branchOf = { owner: 'carol', repo: 'r', branch: 'fix/x' };
    assert.deepEqual(asked, [['pull', { owner: 'o', repo: 'r', pull_number: 42 }], ['repo', { owner: 'carol', repo: 'r' }],
      ['branch', branchOf], ['rules', branchOf], ['content', { owner: 'carol', repo: 'r', path: OWNER_BRANCHES }]]);
    // Among other names, in any case, with any line ending.
    assert.deepEqual((await run({ accepts: naming('o/r', ' Carol/R\r') })).target, { repo: 'carol/r', base: null });
    const mine = await run({ me: 'Carol' });
    assert.equal(mine.target, null);
    // Whatever the forge forked for it, which the fork step checks.
    assert.equal((await run({ me: 'Carol', repo: { parent: { full_name: 'upstream/r' } } })).target, null);
    assert.ok(!mine.asked.some(([call]) => call === 'content'));
    await assert.rejects(run({ me: 'Carol', repo: { default_branch: 'fix/x' } }), /default branch/);
    assert.deepEqual((await run({ accepts: file, env: { REPLACEMENT: 'true' } })).target, { repo: 'carol/r', base: 'c'.repeat(40) });
    // A branch of the repository itself, where its default branch accepts it.
    const accepted = await run({ pull: own, accepts: naming('O/R') });
    assert.deepEqual(accepted.target, { repo: 'o/r', base: null });
    // The same where the output repository calls the run itself, as for dispatch.
    assert.deepEqual((await run({ pull: own, accepts: naming('o/r'), env: { GITHUB_REPOSITORY: 'o/r' } })).target, { repo: 'o/r', base: null });
    assert.deepEqual(accepted.asked.at(-1), ['content', { owner: 'o', repo: 'r', path: '.github/agentic-job/accept-owner-branches' }]);

    for (const [name, options, error] of [
      ['a closed pull request', { pull: { state: 'closed' } }, /is closed, from carol\/r:fix\/x, not open/],
      ['another branch than the policy read', { pull: { head: { ref: 'other', repo: { full_name: 'carol/r', fork: true } } } },
        /from carol\/r:other, not open from a branch named fix\/x/],
      ['a deleted head repository', { pull: { head: { ref: 'fix/x', repo: null } } }, /from a deleted repository:fix\/x/],
      ['a base in another repository', { pull: { base: { ref: 'main', repo: { full_name: 'x/r' } } } }, /not open from a branch/],
      ['no pull request in the policy', { config: { target: null } }, /names no pull request/],
      ['a head repository the identity cannot push to', { repo: { permissions: { push: false } } }, /is from carol\/r, which bot cannot push to/],
      ['an answer without permissions', { repo: { permissions: undefined } }, /cannot push to/],
      ["the head repository's default branch", { repo: { default_branch: 'fix/x' } }, /carol\/r's default branch fix\/x, which a push never goes to/],
      ['a protected branch', { branch: { protected: true } }, /carol\/r:fix\/x, a protected branch/],
      ['an answer that does not say', { branch: {} }, /a protected branch/],
      ['a branch a ruleset applies to', { rules: [{ type: 'non_fast_forward' }] }, /one rules apply to/],
      ['an answer of rules that is not a list', { rules: {} }, /one rules apply to/],
      // Not a fork: the repository the target was forked from, say.
      ['a head repository that is not a fork', { ...from('upstream/r'), repo: { fork: false } }, /upstream\/r, which is neither a fork of o\/r nor o\/r itself/],
      // Another fork in the network, of the target's own parent, say.
      ['a fork of another repository', { ...from('mid/r'), repo: { parent: { full_name: 'upstream/r' } } }, /mid\/r, which is neither a fork of o\/r/],
      ['an answer without a parent', { repo: { parent: undefined } }, /neither a fork of o\/r/],
      ["the caller's repository, which holds the run's secrets", from('caller/r'), /caller\/r, which .* is the calling repository/],
      ['.github exempted, outside the fork with Actions off', { config: { unprotected_dot_folders: ['.github'] } }, /not from bot's fork .*\.github exempted/],
      ['.github exempted, in the repository itself', { pull: own, accepts: naming('o/r'), config: { unprotected_dot_folders: ['.github'] } }, /\.github exempted/],
      ['the repository itself, without its opt-in', { pull: own },
        /from a branch of o\/r itself, .*add \.github\/agentic-job\/accept-owner-branches naming o\/r to its default branch/],
      ['the repository itself, with a directory there', { pull: own, accepts: [{ ...naming('o/r'), path: `${OWNER_BRANCHES}/x` }] }, /add \.github/],
      ['the repository itself, with a symbolic link there', { pull: own, accepts: { ...naming('o/r'), type: 'symlink' } }, /add \.github/],
      ['the repository itself, with an empty file', { pull: own, accepts: naming() }, /add \.github\/agentic-job\/accept-owner-branches naming o\/r/],
      // Write access is not the fork owner's acceptance that its workflows
      // run an agent's commit with its secrets.
      ["another's writable fork, without its opt-in", {},
        /is from carol\/r, not bot's fork with Actions turned off, .*add \.github\/agentic-job\/accept-owner-branches naming carol\/r to its default branch/],
      ["another's fork, with a directory there", { accepts: [{ ...file, path: `${OWNER_BRANCHES}/x` }] }, /add \.github/],
      // A fork made or synced from a target that accepts holds its file.
      ["another's fork, with the file it inherited", { accepts: naming('o/r') }, /naming carol\/r/],
      ["another's fork, with a name like its own", { accepts: naming('carol/r2', 'xcarol/r') }, /naming carol\/r/],
      ["another's fork, with a file too large to be one", { accepts: { ...file, size: 4097 } }, /naming carol\/r/],
      ["another's fork, with content the forge did not give", { accepts: { ...file, content: undefined } }, /naming carol\/r/],
    ]) {
      await assert.rejects(run(options), error, name);
    }
    // A forge that could not answer is not a refusal to report as one, and
    // only a missing opt-in is read as its absence.
    await assert.rejects(run({ pull: own, accepts: Object.assign(new Error('Server Error'), { status: 500 }) }), /^Error: Server Error$/);
    await assert.rejects(run({ accepts: Object.assign(new Error('Server Error'), { status: 500 }) }), /^Error: Server Error$/);
    for (const call of ['repo', 'branch', 'rules']) await assert.rejects(run({ accepts: file, fails: call }), /^Error: Not Found$/, call);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
