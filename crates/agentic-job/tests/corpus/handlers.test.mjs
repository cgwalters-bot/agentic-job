// Real pinned collector -> Rust check -> real pinned handler, with no forge.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../..');
const js = resolve(process.env.GH_AW_JS);
const binary = resolve(process.env.AGENTIC_JOB);
const require = createRequire(import.meta.url);
const workflow = readFileSync(join(root, '.github/workflows/apply.yml'), 'utf8');
const configStep = workflow.split('- name: Write the handlers\' configuration\n')[1]
  .split('        run: |\n')[1].split(/\n        [^ ]/)[0]
  .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');

test('project boundary refusal fails the apply job', () => {
  assert.match(workflow, /core\.setOutput\("project-refused", "true"\)/);
  const final = workflow.split('- name: Every output was applied\n')[1];
  assert.match(final, /PROJECT_REFUSED: \$\{\{ steps\.apply\.outputs\.project-refused \}\}/);
  const guard = final.split('        run: |\n')[1].split('\n')[0].trim();
  for (const [value, code] of [['true', 1], ['', 0]]) {
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', guard], { env: { ...process.env, PROJECT_REFUSED: value } });
    assert.equal(result.status, code);
  }
});

test('agent-board proposals pass the pinned collector and bounded project check', async () => {
  // reconcile plan --snapshot fixtures/board.json --emit, as documented by
  // agent-board. Keep its target_repo/content_number grammar, not issue aliases.
  const proposal = { content_number: 1, content_type: 'issue', fields: { Status: 'Triage' },
    project: 'https://github.com/orgs/example/projects/1', target_repo: 'example/intake', type: 'update_project' };
  const work = mkdtempSync(join(homedir(), 'project-test-'));
  const file = name => join(work, name);
  try {
    mkdirSync(file('outputs'));
    writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["example/intake"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.update_project]\nmax = 1\nprojects = ["${proposal.project}"]\nfields = ["Status"]\n`);
    const policy = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', proposal.target_repo,
      '--clone-url', 'https://github.com/example/intake', '--base', 'main', '--kind', 'analysis',
      '--outputs', 'update_project', '--max-outputs', '3'], { encoding: 'utf8' });
    assert.equal(policy.status, 0, policy.stderr);
    writeFileSync(file('policy.json'), policy.stdout);
    writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policy.stdout).safe_outputs));
    for (const [name, items, ok] of [
      ['real board output', [proposal], true],
      ['another project', [{ ...proposal, project: 'https://github.com/orgs/example/projects/2' }], false],
      ['unlisted field', [{ ...proposal, fields: { Priority: 'P1' } }], false],
      ['another repository', [{ ...proposal, target_repo: 'example/other' }], false],
      ['over count', [proposal, proposal], false],
      ['schema mutation', [{ ...proposal, operation: 'create_fields' }], false],
      ['draft content', [{ ...proposal, content_type: 'draft_issue' }], false],
      ['null is not clearing', [{ ...proposal, fields: { Status: null } }], false],
      ['routing alias', [{ ...proposal, target_repo: undefined, targetRepo: 'example/other' }], false],
    ]) {
      writeFileSync(file('outputs/outputs.jsonl'), items.map(item => JSON.stringify(item)).join('\n') + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), proposal.target_repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, collected.stderr);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      assert.equal(checked.status, ok ? 0 : 1, `${name}: ${checked.stderr}`);
    }
    const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
      ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), REPO: proposal.target_repo, OUTPUT_REPO: 'example/other', ITEM_REPO: 'example/other',
      BASE: 'main', BRANCH_PREFIX: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
    } });
    assert.equal(configured.status, 0, configured.stderr);
    const config = JSON.parse(readFileSync(file('handler-config.json')));
    assert.equal(config.update_project['target-repo'], proposal.target_repo);
    const guardSource = workflow.split('const guarded = client => {')[1].split('client.hook.before')[0];
    const preflight = workflow.split('const pending = new Map();')[1].split('const guarded = client => {')[0];
    for (const [name, fieldName, present, requested, ok] of [
      ['existing exact field', 'Status', true, { Status: 'Triage' }, true],
      ['missing field cannot create schema', 'Status', false, { Status: 'Triage' }, false],
      ['case normalization cannot escape bounds', 'STATUS', true, { Status: 'Triage' }, false],
      ['unknown option', 'Status', true, { Status: 'Nonexistent option' }, false],
      ['unknown iteration', 'Status', true, { Sprint: 'Unknown' }, false],
      ['invalid number', 'Status', true, { Estimate: 'not a number' }, false],
      ['partially numeric string', 'Status', true, { Estimate: '12bad' }, false],
      ['nonfinite number', 'Status', true, { Estimate: 'Infinity' }, false],
      ['mixed successful and skipped fields', 'Status', true, { Status: 'Triage', Sprint: 'Unknown' }, false],
      ['all fields valid', 'Status', true, { Status: 'Triage', Sprint: 'Sprint 1', Estimate: '12' }, true],
      ['option disappears after preflight', 'Status', true, { Status: 'Triage' }, false],
      ['mixed completed and skipped after preflight', 'Status', true, { Estimate: '12', Status: 'Triage' }, false],
      ['mutation has no completion payload', 'Status', true, { Status: 'Triage' }, false],
      ['underscore field before membership write', 'Status', true, { Status: 'Triage', Estimate_points: 12 }, false],
      ['hyphen field before membership write', 'Status', true, { Status: 'Triage', 'Estimate-points': 12 }, false],
    ]) {
      const request = { ...proposal, fields: requested };
      const projectConfig = { ...config, update_project: { ...config.update_project, fields: ['Status', 'Sprint', 'Estimate', 'Estimate_points', 'Estimate-points'] } };
      const writes = [];
      let applying = false;
      const client = { graphql: async (query, vars) => {
        if (query.includes('viewer {')) return { viewer: { login: 'project-writer' } };
        if (query.includes('projectV2(number:')) return { organization: { projectV2: { id: 'project', url: proposal.project } } };
        if (query.includes('repository(owner:')) return { repository: { owner: { __typename: 'Organization', login: 'example' }, issue: { id: 'issue' } } };
        if (query.includes('projectItems(')) return { node: { projectItems: { nodes: name.includes('membership') ? [] : [{ id: 'item', project: { id: 'project' } }], pageInfo: { hasNextPage: false } } } };
        if (query.includes('fields(')) return { node: { fields: { nodes: present ? [
          { id: 'field', name: fieldName, dataType: 'SINGLE_SELECT', options: applying && name.includes('after preflight') ? [] : [{ id: 'triage', name: 'Triage' }] },
          { id: 'sprint', name: 'Sprint', dataType: 'ITERATION', configuration: { iterations: [{ id: 'iteration', title: 'Sprint 1' }] } },
          { id: 'estimate', name: 'Estimate', dataType: 'NUMBER' },
          { id: 'underscore', name: 'Estimate_points', dataType: 'NUMBER' },
          { id: 'hyphen', name: 'Estimate-points', dataType: 'NUMBER' },
        ] : [], pageInfo: { hasNextPage: false } } } };
        writes.push({ query, vars });
        if (name === 'mutation has no completion payload') return { updateProjectV2ItemFieldValue: null };
        return { updateProjectV2ItemFieldValue: { projectV2Item: { id: 'item' } } };
      } };
      const sandbox = { client, github: client, projectRefusal: false, URL, core: { setOutput() {} },
        require: () => ({ readFileSync: () => JSON.stringify({ items: [request] }) }),
        process: { env: { GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG: JSON.stringify(projectConfig) } } };
      let prepared = true;
      try {
        await runInNewContext(`(async () => { const pending = new Map(); ${preflight}
          (client => { ${guardSource} })(client);
          globalThis.complete = () => !projectRefusal && [...pending.values()].every(count => count === 0);
        })()`, sandbox);
      } catch (error) {
        prepared = false;
        assert.equal(ok, false, `${name}: ${error}`);
      }
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, setOutput() {}, startGroup() {}, endGroup() {} },
        context: { repo: { owner: 'example', repo: 'intake' }, payload: {} }, github: client,
      });
      // Reproduce the pinned handler's false success, then prove the actual
      // workflow preflight prevented that handler from making any writes.
      if (!prepared && ['unknown option', 'unknown iteration', 'invalid number', 'mixed successful and skipped fields'].includes(name)) {
        const rawHandler = await require(join(js, 'update_project.cjs')).main(projectConfig.update_project);
        const rawResult = await rawHandler(request, {});
        assert.equal(rawResult.success, true, name);
        assert.equal(writes.length, name === 'mixed successful and skipped fields' ? 1 : 0, name);
        writes.length = 0;
      }
      if (prepared) {
        applying = true;
        const handler = await require(join(js, 'update_project.cjs')).main(projectConfig.update_project);
        const result = await handler(request, {});
        assert.equal(result.success && sandbox.complete(), ok, `${name}: ${JSON.stringify(result)}`);
      }
      const incompleteWrite = name === 'mixed completed and skipped after preflight' || name === 'mutation has no completion payload';
      assert.equal(writes.length, ok ? Object.keys(requested).length : incompleteWrite ? 1 : 0, name);
      if (ok) assert.deepEqual(writes[0].vars, { projectId: 'project', itemId: 'item', fieldId: 'field', value: { singleSelectOptionId: 'triage' } });
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test('checked issue actions preserve the actual handler payload', async () => {
  for (const labelType of ['add_labels', 'remove_labels']) {
  const repo = 'owner/source';
  const prefix = 'r'.repeat(64);
  for (const [name, labels, max, blocked, ok] of [
    ['ordinary labels', ['triage', 'docs'], 2, [], true],
    ['case preserved', ['TRIAGE'], 1, [], true],
    ['safe punctuation and spaces', ['area/docs: needs_triage-v1.0'], 1, [], true],
    ['64 characters', [prefix], 1, [], true],
    ['punctuation bypass', ['release&'], 1, ['release'], false],
    ['Unicode hardening', ['release\u200b'], 1, ['release'], false],
    ['Unicode normalization', ['ｒｅｌｅａｓｅ'], 1, ['release'], false],
    ['truncation bypass', [prefix + 'x'], 1, [prefix], false],
    ['per-request cap', ['triage', 'docs'], 1, [], false],
    ['bodyless close', null, 1, [], true],
    ['close with body', null, 1, [], false],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
       const type = labels ? labelType : 'close_issue';
      const item = labels
        ? { type, repo, item_number: 7, labels }
        : { type, repo, issue_number: 7, ...(name === 'close with body' ? { body: 'Do not silently discard this comment.' } : {}) };
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.${type}]\nmax = ${max}\n` +
        (labels ? `allowed = ${JSON.stringify(labels)}\nblocked = ${JSON.stringify(blocked)}\n` : ''));
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', type,
        '--max-outputs', String(max)], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      const policy = JSON.parse(policyResult.stdout);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(policy.safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(item) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      assert.deepEqual(JSON.parse(readFileSync(file('collected.json'))).errors, [], name);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      assert.equal(checked.status, ok ? 0 : 1, name);
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), REPO: repo, OUTPUT_REPO: 'owner/other', ITEM_REPO: 'owner/other',
        BASE: 'main', BRANCH_PREFIX: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const calls = [];
      const entity = { number: 7, title: 'test', state: 'open', labels: [], html_url: 'https://example.invalid/7' };
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        context: { repo: { owner: 'owner', repo: 'source' }, payload: {}, eventName: 'workflow_dispatch' },
        github: { rest: { issues: {
          get: async () => ({ data: entity }),
          addLabels: async payload => { calls.push(payload); return { data: payload.labels.map(name => ({ name })) }; },
          removeLabel: async payload => { calls.push(payload); return { data: [] }; },
          update: async payload => { calls.push(payload); return { data: { ...entity, state: 'closed' } }; },
          createComment: async () => { assert.fail('closure must not post a comment'); },
        } } },
      });
      if (verdict.ok) {
        const config = JSON.parse(readFileSync(file('handler-config.json')));
        const handler = await require(join(js, `${type}.cjs`)).main(config[type]);
        const result = await handler(verdict.items[0], {});
        assert.equal(result.success, true, `${name}: ${JSON.stringify(result)}`);
        const target = { owner: 'owner', repo: 'source', issue_number: 7 };
        assert.deepEqual(calls, labels && type === 'remove_labels'
          ? labels.map(name => ({ ...target, name }))
          : [{ ...target, ...(labels ? { labels } : { state: 'closed', state_reason: 'completed' }) }], name);
        if (!labels) {
          // Defense in depth: even if a body reaches apply, the workflow's
          // explicit configuration must suppress the handler's comment path.
          const direct = await require(join(js, `${type}.cjs`)).main(config[type]);
          const closed = await direct({ ...item, body: 'Ignored by allow_body: false.' }, {});
          assert.equal(closed.success, true, JSON.stringify(closed));
          assert.deepEqual(calls[1], calls[0]);
          assert.equal(calls.length, 2);
        }
      } else {
        assert.deepEqual(calls, [], `${name}: refused outputs never reach apply`);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
  }
});

// gh-aw's `safe-outputs.urls`, as the step NAME of a workflow sets it.
function urlPolicy(file, name) {
  const text = readFileSync(join(root, '.github/workflows', file), 'utf8');
  const section = text.split(`- name: ${name}\n`)[1]?.split('\n      - ')[0];
  assert.ok(section, `${file}: ${name}`);
  return section.match(/^ {10}GH_AW_SAFE_OUTPUTS_URLS: (\S+)$/m)?.[1];
}

test('build output in code survives gh-aw\'s URL filtering, a secret in it does not', () => {
  const policies = [
    urlPolicy('check.yml', 'Ingest the outputs with gh-aw\'s collector'),
    urlPolicy('apply.yml', 'Apply the outputs with gh-aw\'s handlers'),
  ];
  assert.deepEqual(policies, ['allowed-or-code-region', 'allowed-or-code-region']);
  const repo = 'owner/source';
  // The head of a `cargo metadata` that gh-aw's default policy cut (#401).
  const cargo = '{"packages":[{"name":"agentic-job","version":"0.0.3","id":"path+file:///home/u/agentic-job#0.0.3","license":"MIT OR Apache-2.0"}]}';
  // Put together here, so that no file holds a secret-shaped string.
  const token = ['gh', 's_', 'a1B2'.repeat(10)].join('');
  // [name, body, accepted, what the comment shows, what it must not]
  for (const [name, body, ok, shown, hidden] of [
    ['cargo metadata in a code block', `\`\`\`text\n${cargo}\n\`\`\``, true, cargo, '(redacted)'],
    ['a package id in inline code', 'id `path+file:///home/u/x#0.1.0` ok', true, 'path+file:///home/u/x#0.1.0', '(redacted)'],
    ['cargo metadata in prose', cargo, true, '"id":"(redacted) OR Apache-2.0"', 'path+file'],
    ['a link in prose', 'see ftp://evil.example/x', true, '(evil.example/redacted)', 'ftp://'],
    ['a job token in a code block', `\`\`\`text\n${cargo} ${token}\n\`\`\``, false],
    ['a job token in a URL in code', `\`git://x/${token}\``, false],
  ]) {
    const work = mkdtempSync(join(homedir(), 'url-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.add_comment]\nmax = 1\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', 'add_comment',
        '--max-outputs', '1'], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify({ type: 'add_comment', item_number: 7, body }) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      assert.equal(checked.status, ok ? 0 : 1, name);
      if (!ok) {
        assert.match(verdict.errors.join('\n'), /secret-shaped/, name);
        continue;
      }
      // The handler sanitizes the body again before posting it, with apply's policy.
      globalThis.core = { info() {}, warning() {}, debug() {}, error() {} };
      const { sanitizeContent } = require(join(js, 'sanitize_content.cjs'));
      const previous = process.env.GH_AW_SAFE_OUTPUTS_URLS;
      process.env.GH_AW_SAFE_OUTPUTS_URLS = policies[1];
      let posted;
      try {
        posted = sanitizeContent(verdict.items[0].body, {});
      } finally {
        if (previous === undefined) delete process.env.GH_AW_SAFE_OUTPUTS_URLS;
        else process.env.GH_AW_SAFE_OUTPUTS_URLS = previous;
      }
      for (const text of [verdict.items[0].body, posted]) {
        assert.ok(text.includes(shown), `${name}: ${text}`);
        assert.ok(!text.includes(hidden), `${name}: ${text}`);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});
