const { test } = require('node:test');
const assert = require('node:assert/strict');
const { resolveContext } = require('./context.cjs');

const sha = 'a'.repeat(40);
test('both reusable workflows expose context and the policy command receives it', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const workflow = name => fs.readFileSync(path.join(__dirname, '../.github/workflows', name), 'utf8');
  for (const name of ['agentic-job.yml', 'policy.yml']) {
    assert.match(workflow(name), /\n      context:\n[\s\S]*?type: string\n        default: '\[\]'/);
  }
  assert.match(workflow('agentic-job.yml'), /context: \$\{\{ inputs.context \}\}/);
  assert.match(workflow('policy.yml'), /CONTEXT_REPOS: \$\{\{ inputs.context \}\}/);
  const admission = workflow('policy.yml').split('CONTEXT_REPOS:')[1].split('\n        run:')[0];
  assert.match(admission, /GH_TOKEN: \$\{\{ github.token \}\}/);
  const command = fs.readFileSync(path.join(__dirname, 'policy-command.cjs'), 'utf8');
  assert.match(command, /resolveContext\(process.env.CONTEXT_REPOS\)/);
});
test('empty context is off; refs resolve once to immutable commits', () => {
  assert.deepEqual(resolveContext('', () => assert.fail('unexpected API call')), []);
  for (const ref of [undefined, 'topic/branch', sha]) {
    const calls = [];
    const result = resolveContext(JSON.stringify([{ repo: 'owner/repo', ...(ref && { ref }) }]), path => {
      calls.push(path);
      return calls.length === 1
        ? { private: false, visibility: 'public', default_branch: 'main', clone_url: 'https://example.test/owner/repo' }
        : { sha };
    });
    assert.deepEqual(calls, ['repos/owner/repo', `repos/owner/repo/commits/${encodeURIComponent(ref ?? 'main')}`]);
    assert.deepEqual(result, [{ repo: 'owner/repo', clone_url: 'https://example.test/owner/repo', commit: sha, public: true }]);
  }
});

test('malformed, excessive or duplicate input is refused', () => {
  for (const text of ['{}', 'null', '[null]', '["owner/repo"]',
    JSON.stringify(Array(9).fill({ repo: 'owner/repo' })), ' '.repeat(16385),
    ...['../repo', 'owner/..', '-owner/repo', 'owner/repo/extra', 'owner/repo\n'].map(repo => JSON.stringify([{ repo }])),
    ...['--evil', '../main', '', 'a b'].map(ref => JSON.stringify([{ repo: 'owner/repo', ref }])),
    JSON.stringify([{ repo: 'owner/repo', public: true }]),
  ]) assert.throws(() => resolveContext(text, () => assert.fail('invalid input reached API')));
  assert.throws(() => resolveContext('[{"repo":"owner/repo"},{"repo":"OWNER/REPO"}]', path =>
    path.includes('/commits/') ? { sha } : { private: false, visibility: 'public', default_branch: 'main' }), /Duplicate/);
});

test('visibility and commit lookup fail closed', () => {
  for (const metadata of [{}, { private: true, visibility: 'private' }, { private: false, visibility: 'internal' },
    { private: true, visibility: 'public' }, { visibility: 'public' }, { private: false }]) {
    assert.throws(() => resolveContext('[{"repo":"owner/repo"}]', () => metadata),
      /private runs are refused.*docs\/private-repositories\.md/);
  }
  assert.throws(() => resolveContext('[{"repo":"owner/repo"}]', path => path.includes('/commits/')
    ? { sha: 'main' } : { private: false, visibility: 'public', default_branch: 'main' }), /commit/);
});
