'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { checkApplyToken } = require('./apply-token.cjs');

const env = { TOKEN_IS_PAT: 'true', OUTPUT_REPO: 'owner/repo' };

// A forge that answers GET /user as `user` (or fails with `status`) and
// lets the token read the output repository unless `unreadable`.
function forge({ login = 'bot', scopes = 'repo, workflow', status, unreadable } = {}) {
  const asked = [];
  return {
    asked,
    request: async route => {
      asked.push(route);
      if (status) throw Object.assign(new Error('Bad credentials'), { status });
      return { data: { login }, headers: scopes === undefined ? {} : { 'x-oauth-scopes': scopes } };
    },
    rest: { repos: { get: async args => {
      asked.push(args);
      if (unreadable) throw Object.assign(new Error('Not Found'), { status: 404 });
      return { data: {} };
    } } },
  };
}

for (const [name, change, answer, refusal] of [
  // A secret the caller did not pass reads as empty in Actions, like an unset one.
  ['missing', { TOKEN_IS_PAT: undefined }, {}, /SAFE_OUTPUTS_PAT is missing or empty: store a classic PAT of a bot account/],
  ['empty', { TOKEN_IS_PAT: 'false' }, {}, /SAFE_OUTPUTS_PAT is missing or empty/],
  ["the owner's", {}, { login: 'Owner' }, /SAFE_OUTPUTS_PAT is Owner's, who owns owner\/repo and has no fork/],
  ['not a user\'s', {}, { status: 401 }, /SAFE_OUTPUTS_PAT names no user \(GET \/user answered 401\)/],
  ['without the repo scope', {}, { scopes: 'read:org, workflow' }, /has the scopes "read:org, workflow", not repo/],
  ['without scopes', {}, { scopes: '' }, /has the scopes "", not repo/],
  ['unable to read the output repository', {}, { unreadable: true }, /SAFE_OUTPUTS_PAT of bot cannot read owner\/repo \(404\)/],
  ['for no output repository', { OUTPUT_REPO: '' }, {}, /needs the output repository/],
]) {
  test(`a SAFE_OUTPUTS_PAT ${name} is refused, naming the secret and the fix`, async () => {
    const github = forge(answer);
    await assert.rejects(checkApplyToken({ ...env, ...change }, github), refusal);
    // Nothing is asked of the forge without a PAT, so the job token is never used.
    if ('TOKEN_IS_PAT' in change) assert.deepEqual(github.asked, []);
  });
}

for (const [name, answer] of [
  ['a bot\'s classic PAT', {}],
  ['one for public repositories', { scopes: 'public_repo' }],
  ['a fine-grained one, which lists no scopes', { scopes: undefined }],
]) {
  test(`${name} is accepted`, async () => {
    const github = forge(answer);
    assert.equal(await checkApplyToken(env, github), 'bot');
    assert.deepEqual(github.asked, ['GET /user', { owner: 'owner', repo: 'repo' }]);
  });
}

// Each bad case fails the policy call before the agent: the agent job
// needs the whole call, and nothing that would report a run started runs.
test('the check runs before the agent, off by default, in the apply environment, with the PAT in its step only', () => {
  const workflows = join(__dirname, '../.github/workflows');
  const policy = readFileSync(join(workflows, 'policy.yml'), 'utf8');
  const wrapper = readFileSync(join(workflows, 'agentic-job.yml'), 'utf8');
  for (const caller of [policy, wrapper]) {
    assert.match(caller, /\n      require-safe-outputs-pat:\n        description: >-\n(?:          [^\n]+\n)+        type: boolean\n        default: false\n/);
  }
  assert.match(wrapper, /\n      require-safe-outputs-pat: \$\{\{ inputs.require-safe-outputs-pat \}\}\n/);
  const job = policy.split('\n  apply-token:\n')[1].split(/\n  (?=[-\w]+:\n)/)[0];
  assert.match(job, /^    needs: policy\n    if: \$\{\{ inputs.require-safe-outputs-pat && needs.policy.outputs.admitted == 'true' \}\}\n/);
  assert.match(job, /\n    environment: \$\{\{ inputs.apply-environment \}\}\n    permissions:\n      contents: read\n/);
  assert.doesNotMatch(job, /continue-on-error|always\(\)|cancelled\(\)/);
  const [before, check] = job.split('- name: Check SAFE_OUTPUTS_PAT\n');
  assert.doesNotMatch(before, /secrets\./);
  assert.equal(check.match(/secrets\.SAFE_OUTPUTS_PAT/g).length, 2);
  assert.match(check, /TOKEN_IS_PAT: \$\{\{ secrets.SAFE_OUTPUTS_PAT != '' \}\}/);
  assert.match(check, /github-token: \$\{\{ secrets.SAFE_OUTPUTS_PAT \|\| github.token \}\}/);
  assert.match(check, /require\('\.\/apply-token-source\/workflow\/apply-token\.cjs'\)/);
  assert.match(job, /ref: \$\{\{ job.workflow_sha \}\}\n          path: apply-token-source\n          persist-credentials: false\n/);
  // A refusal leaves no status comment that nothing would conclude.
  const notify = policy.split('\n  notify:\n')[1].split('\n    runs-on:')[0];
  assert.match(notify, /needs: \[policy, activate, apply-token\]/);
  assert.match(notify, /needs.apply-token.result != 'failure'/);
  for (const file of ['agentic-job.yml', 'example-compose.yml']) {
    const agent = readFileSync(join(workflows, file), 'utf8').split('\n  agent:\n')[1].split('\n    steps:\n')[0];
    assert.match(agent, /^    needs: policy\n/, file);
    assert.doesNotMatch(agent, /always\(\)|cancelled\(\)|failure\(\)/, file);
  }
});
