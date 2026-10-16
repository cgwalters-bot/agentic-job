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
      BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
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
    // The body is the closing comment; without one the handler would fail.
    ['bodyless close', null, 1, [], false],
    ['close with body', null, 1, [], true],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
       const type = labels ? labelType : 'close_issue';
      const item = labels
        ? { type, repo, item_number: 7, labels }
        : { type, repo, issue_number: 7, ...(name === 'close with body' ? { body: 'Done in #8.', state_reason: 'not_planned' } : {}) };
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
        BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
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
          createComment: async payload => { calls.push({ comment: payload.issue_number, body: payload.body }); return { data: { id: 1, html_url: 'u' } }; },
        } } },
      });
      if (verdict.ok) {
        const config = JSON.parse(readFileSync(file('handler-config.json')));
        const handler = await require(join(js, `${type}.cjs`)).main(config[type]);
        const result = await handler(verdict.items[0], {});
        assert.equal(result.success, true, `${name}: ${JSON.stringify(result)}`);
        const target = { owner: 'owner', repo: 'source', issue_number: 7 };
        if (labels) {
          assert.deepEqual(calls, type === 'remove_labels'
            ? labels.map(name => ({ ...target, name }))
            : [{ ...target, labels }], name);
        } else {
          // The checked body is posted on the issue it closes, then the
          // issue closed with the requested reason.
          assert.equal(calls.length, 2, JSON.stringify(calls));
          assert.equal(calls[0].comment, 7);
          assert.ok(calls[0].body.startsWith('Done in #8.'), calls[0].body);
          assert.deepEqual(calls[1], { ...target, state: 'closed', state_reason: 'not_planned' });
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

test('checked updates reach the pinned handlers with only the listed fields', async () => {
  const repo = 'owner/source';
  for (const [type, fields, item, api] of [
    ['update_issue', ['body'], { issue_number: 7, operation: 'replace', body: 'New body.' }, 'issues'],
    ['update_pull_request', ['title'], { pull_request_number: 7, title: 'New title' }, 'pulls'],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 1\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.${type}]\nmax = 1\nfields = ${JSON.stringify(fields)}\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', type,
        '--max-outputs', '1'], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify({ type, repo, ...item }) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${type}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, true, `${type}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), REPO: repo, OUTPUT_REPO: 'owner/other', ITEM_REPO: 'owner/other',
        BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const calls = [];
      const entity = { number: 7, title: 'old', body: 'Old body.', state: 'open', draft: true, labels: [], html_url: 'https://example.invalid/7' };
      const forge = { get: async () => ({ data: entity }), update: async payload => { calls.push(payload); return { data: { ...entity, ...payload } }; } };
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        context: { repo: { owner: 'owner', repo: 'source' }, payload: {}, eventName: 'workflow_dispatch', runId: 1, serverUrl: 'https://github.com' },
        github: { rest: { issues: forge, pulls: forge } },
      });
      // What apply's runner and step give the handlers' execution provenance.
      Object.assign(process.env, { GITHUB_REPOSITORY: repo, GITHUB_REPOSITORY_ID: '1', GITHUB_RUN_ID: '1',
        GITHUB_RUN_ATTEMPT: '1', GITHUB_JOB: 'apply', GH_AW_WORKFLOW_ID: 'agentic-job', GH_AW_JOB_CHECK_RUN_ID: '1' });
      const config = JSON.parse(readFileSync(file('handler-config.json')));
      const handler = await require(join(js, `${type}.cjs`)).main(config[type]);
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, true, `${type}: ${JSON.stringify(result)}`);
      // The checked item's one field, against the checked number in the run's repository.
      assert.equal(calls.length, 1, `${type}: ${JSON.stringify(calls)}`);
      const { owner, repo: name, ...changed } = calls[0];
      assert.deepEqual({ owner, repo: name }, { owner: 'owner', repo: 'source' }, api);
      assert.deepEqual(Object.keys(changed).sort(), [api === 'issues' ? 'issue_number' : 'pull_number', fields[0]].sort(), type);
      assert.ok(changed[fields[0]].startsWith(item[fields[0]]), `${type}: ${changed[fields[0]]}`);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});

test('checked reviewer and assignee requests name exactly the allowed logins', async () => {
  const repo = 'owner/source';
  for (const [type, key, people] of [['add_reviewer', 'pull_request_number', 'reviewers'], ['assign_to_user', 'issue_number', 'assignees']]) {
    for (const [name, logins, ok] of [
      ['listed logins', ['octocat', 'hubot'], true],
      ['an unlisted login the handler would drop', ['octocat', 'mallory'], false],
      ['another case the handler would drop', ['OctoCat'], false],
      ['over the per-request cap the handler would cut', ['octocat', 'hubot', 'octocat'], false],
    ]) {
      const work = mkdtempSync(join(homedir(), 'handler-test-'));
      try {
        const file = name => join(work, name);
        mkdirSync(file('outputs'));
        writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.${type}]\nmax = 2\nallowed = ["octocat", "hubot"]\n`);
        const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
          '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', type,
          '--max-outputs', '2'], { encoding: 'utf8' });
        assert.equal(policyResult.status, 0, policyResult.stderr);
        writeFileSync(file('policy.json'), policyResult.stdout);
        writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
        writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify({ type, repo, [key]: 7, [people]: logins }) + '\n');
        const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
          file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
        assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
        assert.deepEqual(JSON.parse(readFileSync(file('collected.json'))).errors, [], name);
        const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
          '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
        const verdict = JSON.parse(readFileSync(file('report.json')));
        assert.equal(verdict.ok, ok, `${type} ${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
        assert.equal(checked.status, ok ? 0 : 1, name);
        if (!ok) continue;
        const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
          ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), REPO: repo, OUTPUT_REPO: 'owner/other', ITEM_REPO: 'owner/other',
          BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
        } });
        assert.equal(configured.status, 0, configured.stderr);
        const calls = [];
        const pull = { number: 7, state: 'open', requested_reviewers: [], requested_teams: [] };
        Object.assign(globalThis, {
          core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
          context: { repo: { owner: 'owner', repo: 'source' }, payload: {}, eventName: 'workflow_dispatch' },
          github: { rest: {
            issues: { addAssignees: async payload => { calls.push(payload); return { data: {} }; } },
            pulls: {
              get: async () => ({ data: pull }),
              listReviews: async () => ({ data: [] }),
              requestReviewers: async payload => { calls.push(payload); return { data: pull }; },
            },
          } },
        });
        const config = JSON.parse(readFileSync(file('handler-config.json')))[type];
        const result = await (await require(join(js, `${type}.cjs`)).main(config))(verdict.items[0], {});
        assert.equal(result.success, true, `${name}: ${JSON.stringify(result)}`);
        assert.deepEqual(calls, [type === 'add_reviewer'
          ? { owner: 'owner', repo: 'source', pull_number: 7, reviewers: logins }
          : { owner: 'owner', repo: 'source', issue_number: 7, assignees: logins }], name);
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    }
  }
});

test('a checked check run is posted with the pinned name on the pull request head', async () => {
  const repo = 'owner/source';
  const item = { type: 'create_check_run', conclusion: 'neutral', title: 'Verdict', summary: 'Looked.', pull_request_number: 7 };
  for (const [name, line, ok] of [
    ['neutral', item, true],
    ['the pinned name', { ...item, name: 'agent verdict' }, true],
    ['another name', { ...item, name: 'required-ci' }, false],
    ['success', { ...item, conclusion: 'success' }, false],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 1\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.create_check_run]\nmax = 1\nname = "agent verdict"\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', 'create_check_run',
        '--max-outputs', '1'], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(line) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      if (!ok) continue;
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), GITHUB_REPOSITORY: repo, REPO: repo, OUTPUT_REPO: repo,
        ITEM_REPO: repo, BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const calls = [];
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        // The apply job's own commit, which the check run must not take.
        context: { repo: { owner: 'owner', repo: 'source' }, payload: {}, eventName: 'workflow_dispatch', sha: 'a'.repeat(40) },
        github: { rest: {
          pulls: { get: async ({ pull_number }) => ({ data: { number: pull_number, head: { sha: 'b'.repeat(40) } } }) },
          checks: { create: async payload => { calls.push(payload); return { data: { id: 1, html_url: 'https://example.invalid/1' } }; } },
        } },
      });
      const config = JSON.parse(readFileSync(file('handler-config.json')));
      const handler = await require(join(js, 'create_check_run.cjs')).main(config.create_check_run);
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, true, `${name}: ${JSON.stringify(result)}`);
      assert.equal(calls.length, 1, name);
      assert.deepEqual({ ...calls[0], completed_at: undefined, output: undefined }, {
        owner: 'owner', repo: 'source', name: 'agent verdict', head_sha: 'b'.repeat(40), status: 'completed',
        conclusion: 'neutral', completed_at: undefined, output: undefined,
      }, name);
    } finally {
      rmSync(work, { recursive: true, force: true });
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

test('links and build output survive gh-aw\'s URL filtering, a private key does not', () => {
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
  const key = ['-----BEGIN ', 'PRIVATE KEY-----'].join('');
  const link = '[the report](https://arbitrary-host.example.net/a/b?c=d#e)';
  // [name, body, accepted, what the comment shows, what it must not]
  for (const [name, body, ok, shown, hidden] of [
    ['cargo metadata in a code block', `\`\`\`text\n${cargo}\n\`\`\``, true, cargo, '(redacted)'],
    ['a package id in inline code', 'id `path+file:///home/u/x#0.1.0` ok', true, 'path+file:///home/u/x#0.1.0', '(redacted)'],
    ['cargo metadata in prose', cargo, true, '"id":"(redacted) OR Apache-2.0"', 'path+file'],
    ['a link in prose', 'see ftp://evil.example/x', true, '(evil.example/redacted)', 'ftp://'],
    ['an https link to any public host in prose', `See ${link}.`, true, link, 'redacted'],
    // Shaped like a token, as a fixture is: a warning, not a refusal.
    ['a token-shaped string in a code block', `\`\`\`text\n${cargo} ${token}\n\`\`\``, true, token, '(redacted)'],
    ['a private key in a code block', `\`\`\`text\n${key}\n\`\`\``, false],
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
      // As policy.yml passes it to check.yml and apply.yml.
      const domains = JSON.parse(policyResult.stdout).allowed_domains.join(',');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')],
      { encoding: 'utf8', env: { ...process.env, GH_AW_ALLOWED_DOMAINS: domains } });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      assert.equal(checked.status, ok ? 0 : 1, name);
      if (!ok) {
        assert.match(verdict.errors.join('\n'), /private key/, name);
        continue;
      }
      // The handler sanitizes the body again before posting it, with apply's policy.
      globalThis.core = { info() {}, warning() {}, debug() {}, error() {} };
      const { sanitizeContent } = require(join(js, 'sanitize_content.cjs'));
      const previous = [process.env.GH_AW_SAFE_OUTPUTS_URLS, process.env.GH_AW_ALLOWED_DOMAINS];
      process.env.GH_AW_SAFE_OUTPUTS_URLS = policies[1];
      process.env.GH_AW_ALLOWED_DOMAINS = domains;
      let posted;
      try {
        posted = sanitizeContent(verdict.items[0].body, {});
      } finally {
        for (const [env, value] of [['GH_AW_SAFE_OUTPUTS_URLS', previous[0]], ['GH_AW_ALLOWED_DOMAINS', previous[1]]]) {
          if (value === undefined) delete process.env[env];
          else process.env[env] = value;
        }
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

test('checked pull request closures and sub-issue links reach only the named items', async () => {
  const repo = 'owner/source';
  const close = { type: 'close_pull_request', repo, pull_request_number: 7, body: 'Superseded by #8.' };
  const link = { type: 'link_sub_issue', repo, parent_issue_number: 5, sub_issue_number: 6 };
  for (const [name, item, ok] of [
    ['close', close, true],
    ['close in another repository', { ...close, repo: 'owner/other' }, false],
    ['close the triggering pull request', { ...close, pull_request_number: undefined }, false],
    ['close by alias', { ...close, pull_request_number: undefined, pr_number: 7 }, false],
    ['link', link, true],
    ['link in another repository', { ...link, repo: 'owner/other' }, false],
    ['link a temporary ID', { ...link, sub_issue_number: 'aw_sub1' }, false],
    // The collector drops a field link_sub_issue's rule lacks, before check.
    ['link with a parent alias', { ...link, item_number: 9 }, true],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.${item.type}]\nmax = 1\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', item.type,
        '--max-outputs', '1'], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(item) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      assert.equal(checked.status, ok ? 0 : 1, name);
      if (!ok) continue;
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), REPO: repo, OUTPUT_REPO: 'owner/other', ITEM_REPO: 'owner/other',
        BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '', PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const calls = [];
      const issue = number => ({ number, title: 'test', state: 'open', labels: [], node_id: `I_${number}`, html_url: `https://example.invalid/${number}` });
      // Started from pull request 9, which neither request names.
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        context: { repo: { owner: 'owner', repo: 'source' }, eventName: 'pull_request',
          payload: { pull_request: { number: 9 }, issue: { number: 9 } } },
        github: {
          rest: {
            issues: {
              get: async ({ issue_number }) => ({ data: issue(issue_number) }),
              createComment: async payload => { calls.push(['comment', payload.owner, payload.repo, payload.issue_number, payload.body]); return { data: { id: 1, html_url: 'u' } }; },
            },
            pulls: {
              get: async ({ pull_number }) => ({ data: issue(pull_number) }),
              update: async payload => { calls.push(['close', payload.owner, payload.repo, payload.pull_number, payload.state]); return { data: { ...issue(payload.pull_number), state: 'closed' } }; },
            },
          },
          graphql: async (query, variables) => {
            if (/addSubIssue/.test(query)) calls.push(['link', variables]);
            return { repository: { issue: { parent: null } }, addSubIssue: { issue: { id: 'I_5' }, subIssue: { id: 'I_6' } } };
          },
        },
      });
      const config = JSON.parse(readFileSync(file('handler-config.json')));
      const handler = await require(join(js, `${item.type}.cjs`)).main(config[item.type]);
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, true, `${name}: ${JSON.stringify(result)}`);
      if (item.type === 'close_pull_request') {
        assert.deepEqual(calls.map(call => call.slice(0, 4)), [['comment', 'owner', 'source', 7], ['close', 'owner', 'source', 7]], name);
        assert.match(calls[0][4], /^Superseded by #8\./);
      } else {
        assert.deepEqual(calls, [['link', { parentId: 'I_5', subIssueId: 'I_6' }]], name);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});

test('a checked discussion is posted only in the category the bounds pin', async () => {
  const repo = 'owner/source';
  const pinned = { id: 'DIC_reports', name: 'Agent reports', slug: 'agent-reports' };
  const announcements = { id: 'DIC_ann', name: 'Announcements', slug: 'announcements' };
  const item = { type: 'create_discussion', title: 'Weekly report', body: 'Nothing unusual this week: every scheduled job passed, and the details are in the linked run.' };
  for (const [name, line, categories, ok, posted] of [
    ['the pinned category', item, [announcements, pinned], true, pinned.id],
    ['the pin named', { ...item, category: 'Agent reports' }, [announcements, pinned], true, pinned.id],
    ['another category', { ...item, category: 'Announcements' }, [announcements, pinned], false],
    ['another repository', { ...item, repo: 'owner/other' }, [announcements, pinned], false],
    // The collector drops labels, which the handler would apply unbounded.
    ['labels', { ...item, labels: ['release'] }, [announcements, pinned], true, pinned.id],
    // The handler would fall back to Announcements; apply's guard refuses.
    ['the pin missing from the repository', item, [announcements], true, null],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}"]\nbases = ["main"]\nmax_outputs = 1\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.create_discussion]\nmax = 1\ncategory = "Agent reports"\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', 'create_discussion',
        '--max-outputs', '1'], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(line) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json')], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      if (!ok) continue;
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), GITHUB_REPOSITORY: repo, REPO: repo, OUTPUT_REPO: 'owner/other',
        ITEM_REPO: 'owner/other', BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: '',
        PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const config = JSON.parse(readFileSync(file('handler-config.json')));
      assert.deepEqual(config.create_discussion, { max: 1, category: 'Agent reports', 'target-repo': repo,
        fallback_to_issue: false, close_older_discussions: false });
      const calls = [];
      const client = { graphql: async (query, variables) => {
        if (/\bcreateDiscussion\b/.test(query)) {
          calls.push(['create', variables.repositoryId, variables.categoryId]);
          return { createDiscussion: { discussion: { id: 'D_1', number: 1, title: variables.title, url: 'https://example.invalid/1' } } };
        }
        if (/addLabelsToLabelable/.test(query)) calls.push(['labels', variables]);
        return { repository: { id: `R_${variables.owner}/${variables.repo}`, discussionCategories: { nodes: categories } } };
      } };
      // apply's guarded client, as the handlers get it.
      const guardSource = workflow.split('const guarded = client => {')[1].split('client.hook.before')[0];
      runInNewContext(`(client => { ${guardSource} })(client)`, { client,
        process: { env: { GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG: JSON.stringify(config) } } });
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        context: { repo: { owner: 'owner', repo: 'source' }, runId: 1, serverUrl: 'https://github.com', eventName: 'workflow_dispatch', payload: {} },
        github: client,
      });
      // What apply's runner and step give the handlers' execution provenance.
      Object.assign(process.env, { GITHUB_REPOSITORY: repo, GITHUB_REPOSITORY_ID: '1', GITHUB_RUN_ID: '1',
        GITHUB_RUN_ATTEMPT: '1', GITHUB_JOB: 'apply', GH_AW_WORKFLOW_ID: 'agentic-job', GH_AW_JOB_CHECK_RUN_ID: '1' });
      const handler = await require(join(js, 'create_discussion.cjs')).main(config.create_discussion);
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, posted !== null, `${name}: ${JSON.stringify(result)}`);
      assert.deepEqual(calls, posted === null ? [] : [['create', `R_owner/source`, posted]], name);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});

test('a checked comment is hidden only on the triggering item, for a pinned reason', async () => {
  const repo = 'owner/source';
  const itemRepo = 'owner/item';
  // Comments by node ID: on the triggering issue #64, on #65, and on #64 of
  // another repository; and by REST ID, which the handler looks up in the
  // item repository: 1001 is on #64, 1002 on #65.
  const comments = {
    IC_64: { issue: { number: 64, repository: { nameWithOwner: itemRepo } } },
    IC_65: { issue: { number: 65, repository: { nameWithOwner: itemRepo } } },
    IC_other: { issue: { number: 64, repository: { nameWithOwner: 'owner/other' } } },
  };
  const item = { type: 'hide_comment', comment_id: 'IC_64' };
  for (const [name, line, target, ok, hidden] of [
    ['the triggering item', item, '64', true, ['IC_64', 'SPAM']],
    ['a pinned reason', { ...item, reason: 'outdated' }, '64', true, ['IC_64', 'OUTDATED']],
    ['by REST ID', { ...item, comment_id: '1001' }, '64', true, ['IC_rest', 'SPAM']],
    ['another reason', { ...item, reason: 'ABUSE' }, '64', false],
    ['another repository named', { ...item, repo: 'owner/other' }, '64', false],
    ['no triggering item', item, '*', false],
    // Only the handler can look a comment up: it refuses these.
    ['another item', { ...item, comment_id: 'IC_65' }, '64', true, null],
    ['another repository', { ...item, comment_id: 'IC_other' }, '64', true, null],
    ['another item by REST ID', { ...item, comment_id: '1002' }, '64', true, null],
    ['no such comment', { ...item, comment_id: 'IC_missing' }, '64', true, null],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}", "${itemRepo}"]\nbases = ["main"]\nmax_outputs = 1\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs.hide_comment]\nmax = 1\nallowed_reasons = ["SPAM", "OUTDATED"]\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', 'hide_comment',
        '--max-outputs', '1', '--item-repo', itemRepo], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(line) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      // As check.yml passes the triggering item, and nothing for `*`.
      const destination = target === '*' ? [] : ['--comment-repo', itemRepo, '--comment-target', target];
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json'), ...destination], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      if (!ok) continue;
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), GITHUB_REPOSITORY: repo, REPO: repo, OUTPUT_REPO: repo,
        ITEM_REPO: itemRepo, BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: target,
        PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const config = JSON.parse(readFileSync(file('handler-config.json')));
      assert.deepEqual(config.hide_comment, { max: 1, allowed_reasons: ['SPAM', 'OUTDATED'], 'target-repo': itemRepo, target: '64' });
      const calls = [];
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        // Started by an event on another item, which the handler must not take.
        context: { repo: { owner: 'owner', repo: 'source' }, eventName: 'issue_comment', payload: { issue: { number: 9 } } },
        github: {
          rest: { issues: { getComment: async ({ owner, repo: name, comment_id }) => {
            calls.push(['get', `${owner}/${name}`, comment_id]);
            return { data: { node_id: 'IC_rest', issue_url: `https://api.github.com/repos/${owner}/${name}/issues/${comment_id === 1001 ? 64 : 65}` } };
          } } },
          graphql: async (query, variables) => {
            if (/\bminimizeComment\b/.test(query)) {
              calls.push(['hide', variables.nodeId, variables.classifier]);
              return { minimizeComment: { minimizedComment: { isMinimized: true } } };
            }
            return { node: comments[variables.nodeId] ?? null };
          },
        },
      });
      const handler = await require(join(js, 'hide_comment.cjs')).main(config.hide_comment);
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, hidden !== null, `${name}: ${JSON.stringify(result)}`);
      assert.deepEqual(calls.filter(call => call[0] === 'hide'), hidden === null ? [] : [['hide', ...hidden]], name);
      if (line.comment_id === '1001') assert.deepEqual(calls[0], ['get', itemRepo, 1001], name);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});

test('checked review comments, replies and resolved threads stay on the triggering pull request', async () => {
  const repo = 'owner/source';
  const itemRepo = 'owner/item';
  const { createPrReviewBufferRegistry } = require(join(js, 'pr_review_buffer.cjs'));
  // Review threads by node ID: on the triggering pull request #64, on #65,
  // and on #64 of another repository.
  const threads = {
    PRRT_64: { __typename: 'PullRequestReviewThread', id: 'PRRT_64', isResolved: false, pullRequest: { number: 64, repository: { nameWithOwner: itemRepo } } },
    PRRT_65: { __typename: 'PullRequestReviewThread', id: 'PRRT_65', isResolved: false, pullRequest: { number: 65, repository: { nameWithOwner: itemRepo } } },
    PRRT_other: { __typename: 'PullRequestReviewThread', id: 'PRRT_other', isResolved: false, pullRequest: { number: 64, repository: { nameWithOwner: 'owner/other' } } },
  };
  const create = { type: 'create_pull_request_review_comment', path: 'src/lib.rs', line: 3, body: 'This could overflow.' };
  const reply = { type: 'reply_to_pull_request_review_comment', comment_id: 1001, body: 'Fixed.' };
  const resolve = { type: 'resolve_pull_request_review_thread', thread_id: 'PRRT_64' };
  for (const [name, line, target, ok, call] of [
    ['a comment', create, '64', true, ['comment', itemRepo, 64, 'src/lib.rs', 3]],
    ['a comment naming the pull request', { ...create, pull_request_number: 64 }, '64', true, ['comment', itemRepo, 64, 'src/lib.rs', 3]],
    ['a reply', reply, '64', true, ['reply', itemRepo, 64, 1001]],
    ['a resolved thread', resolve, '64', true, ['resolve', 'PRRT_64']],
    ['a comment on another pull request', { ...create, pull_request_number: 65 }, '64', false],
    ['a reply on another pull request', { ...reply, pull_request_number: 65 }, '64', false],
    ['a comment in another repository', { ...create, repo: 'owner/other' }, '64', false],
    ['a comment without a triggering item', create, '*', false],
    ['a reply without a triggering item', reply, '*', false],
    ['a resolve without a triggering item', resolve, '*', false],
    // Only the handler can look a thread up: it refuses these.
    ['a thread on another pull request', { ...resolve, thread_id: 'PRRT_65' }, '64', true, null],
    ['a thread in another repository', { ...resolve, thread_id: 'PRRT_other' }, '64', true, null],
  ]) {
    const work = mkdtempSync(join(homedir(), 'handler-test-'));
    try {
      const file = name => join(work, name);
      mkdirSync(file('outputs'));
      writeFileSync(file('allow.toml'), `hosts = ["github.com"]\nrepos = ["${repo}", "${itemRepo}"]\nbases = ["main"]\nmax_outputs = 3\nmax_patch_bytes = 100000\nmax_patch_files = 10\n[outputs]\n${line.type} = { max = 1 }\n`);
      const policyResult = spawnSync(binary, ['policy', '--allow', file('allow.toml'), '--repo', repo,
        '--clone-url', `https://github.com/${repo}`, '--base', 'main', '--kind', 'analysis', '--outputs', line.type,
        '--max-outputs', '1', '--item-repo', itemRepo], { encoding: 'utf8' });
      assert.equal(policyResult.status, 0, policyResult.stderr);
      writeFileSync(file('policy.json'), policyResult.stdout);
      writeFileSync(file('config.json'), JSON.stringify(JSON.parse(policyResult.stdout).safe_outputs));
      writeFileSync(file('outputs/outputs.jsonl'), JSON.stringify(line) + '\n');
      const collected = spawnSync(process.execPath, [join(here, 'collect.cjs'), js, file('outputs/outputs.jsonl'),
        file('config.json'), join(root, 'safe-outputs/validation.json'), repo, file('collected.json')], { encoding: 'utf8' });
      assert.equal(collected.status, 0, `${name}: ${collected.stderr}`);
      // As check.yml passes the triggering item, and nothing for `*`.
      const destination = target === '*' ? [] : ['--comment-repo', itemRepo, '--comment-target', target];
      const checked = spawnSync(binary, ['check', '--policy', file('policy.json'), '--outputs', file('outputs'),
        '--collected', file('collected.json'), '--report', file('report.json'), ...destination], { encoding: 'utf8' });
      const verdict = JSON.parse(readFileSync(file('report.json')));
      assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)} ${checked.stderr}`);
      if (!ok) continue;
      const configured = spawnSync('bash', ['-euo', 'pipefail', '-c', configStep], { encoding: 'utf8', env: {
        ...process.env, GH_AW_TMP: work, GITHUB_ENV: file('env'), GITHUB_REPOSITORY: repo, REPO: repo, OUTPUT_REPO: repo,
        ITEM_REPO: itemRepo, BASE: 'main', BRANCH_PREFIX: '', READY: '', TITLE_PREFIX: '', PARTIAL: '', COMMENT_TARGET: target,
        PULL_REQUEST: '{}', PUSH: '{}', FORK: '',
      } });
      assert.equal(configured.status, 0, configured.stderr);
      const config = JSON.parse(readFileSync(file('handler-config.json')))[line.type];
      assert.deepEqual(config, { max: 1, 'target-repo': itemRepo, target: '64' });
      const calls = [];
      Object.assign(globalThis, {
        core: { info() {}, warning() {}, debug() {}, error() {}, startGroup() {}, endGroup() {} },
        // Started by an event on another item, which the handlers must not take.
        context: { repo: { owner: 'owner', repo: 'source' }, eventName: 'issue_comment', payload: { issue: { number: 9, pull_request: {} } } },
        github: {
          rest: { pulls: {
            get: async ({ owner, repo: name, pull_number }) => ({ data: { number: pull_number, head: { sha: `head-of-${owner}/${name}#${pull_number}` } } }),
            createReplyForReviewComment: async ({ owner, repo: name, pull_number, comment_id }) => {
              calls.push(['reply', `${owner}/${name}`, pull_number, comment_id]);
              return { data: { id: 2002, html_url: 'https://forge/reply' } };
            },
          } },
          graphql: async (query, variables) => {
            if (/\bresolveReviewThread\b/.test(query)) {
              calls.push(['resolve', variables.threadId]);
              return { resolveReviewThread: { thread: { id: variables.threadId, isResolved: true } } };
            }
            return { node: threads[variables.threadId] ?? null };
          },
        },
      });
      const registry = createPrReviewBufferRegistry();
      const module = { create_pull_request_review_comment: 'create_pr_review_comment.cjs',
        reply_to_pull_request_review_comment: 'reply_to_pr_review_comment.cjs',
        resolve_pull_request_review_thread: 'resolve_pr_review_thread.cjs' }[line.type];
      const handler = await require(join(js, module)).main({ ...config, _prReviewBufferRegistry: registry });
      const result = await handler(verdict.items[0], {});
      assert.equal(result.success, call !== null, `${name}: ${JSON.stringify(result)}`);
      // A comment waits in its pull request's review until the handlers are done.
      for (const { repo: bufferRepo, prNumber, buffer } of registry.getAllEntries()) {
        assert.equal(buffer.getBufferedCount(), 1, name);
        calls.push(['comment', bufferRepo, prNumber, result.metadata.path, result.metadata.line]);
      }
      assert.deepEqual(calls, call === null ? [] : [call], name);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});
