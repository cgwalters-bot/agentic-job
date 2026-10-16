'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const ci = fs.readFileSync(path.join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
// The run script of a step of changes, by its id.
const stepScript = id => ci.split(`      - id: ${id}\n`)[1].split('        run: |\n')[1].split(/\n(?! {10})/)[0]
  .split('\n').map(line => line.slice(10)).join('\n');
const script = stepScript('paths');
// The github-script source of a step of changes, by its id.
const githubScript = id => ci.split(`      - id: ${id}\n`)[1].split(/\n {6}(?! )/)[0]
  .split('          script: |\n')[1].trim().split('\n').map(line => line.trim()).join('\n');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const block = job => '\n' + ci.split(`\n  ${job}:\n`)[1].split(/\n  [a-z][a-z0-9-]*:\n/)[0];
const gates = {
  full: ['lint', 'rust', 'vibe', 'claude-acp', 'corpus', 'static'],
  host: ['session-sandbox', 'sandbox', 'secure-host', 'secure-host-options', 'world-write', 'world-write-runtime', 'confined'],
  e2e: ['proposals', 'e2e-proposals', 'e2e-scratch', 'e2e-full', 'e2e-limit', 'e2e-event', 'e2e-analysis', 'e2e-analysis-refused',
    'e2e-people', 'e2e-items-scratch', 'e2e-items', 'e2e-check-run', 'e2e-review', 'e2e-dispatch', 'e2e-compose', 'e2e-dispatch-verify', 'e2e-verify'],
};

test('the full-run CI harness skips its comment on the second apply attempt', async () => {
  const section = block('e2e-dispatch-verify').split('      - name: "Run the full run\'s apply guard again"\n')[1].split(/\n {6}(?! )/)[0];
  const source = section.split('          script: |\n')[1].split('\n')
    .filter(line => line.startsWith(' '.repeat(12))).map(line => line.slice(12)).join('\n');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-rerun-'));
  try {
    // Use the harness's environment, not a separately maintained guard fixture.
    const env = Object.fromEntries([...section.split('        with:\n')[0]
      .matchAll(/^          ([A-Z_]+): (.+)$/gm)].map(([, key, value]) => [key,
        value.replaceAll('${{ runner.temp }}', dir).replaceAll('${{ github.repository }}', 'owner/target').replace(/^["'](.*)["']$/, '$1')]));
    env.GITHUB_RUN_ID = '123';
    fs.mkdirSync(env.GH_AW_TMP, { recursive: true });
    const file = path.join(env.GH_AW_TMP, 'agent_output.json');
    const output = { items: [{ type: 'add_comment', body: 'result' }] };
    let comments = [];
    const github = { rest: { issues: { listComments: Symbol('listComments') } },
      paginate: async (method, params) => {
        assert.equal(method, github.rest.issues.listComments);
        assert.deepEqual(params, { owner: 'owner', repo: 'target', issue_number: 64, per_page: 100 });
        return comments;
      } };
    const summary = { addHeading() { return this; }, addList() { return this; }, async write() {} };
    const core = { setOutput() {}, summary };
    const run = new AsyncFunction('require', 'process', 'core', 'github', source);
    fs.writeFileSync(file, JSON.stringify(output));
    await run(require, { env }, core, github);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(env.GH_AW_TMP, 'skipped.json'))), []);
    const posted = JSON.parse(fs.readFileSync(file)).items[0];
    const name = posted.body.split('\n\n').at(-1);
    comments = [{ user: { login: 'github-actions[bot]' }, body: `result\n\n<!-- ${name} -->`, html_url: 'https://example.test/comment' }];
    fs.writeFileSync(file, JSON.stringify(output));
    await run(require, { env }, core, github);
    assert.deepEqual(JSON.parse(fs.readFileSync(file)).items, []);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(env.GH_AW_TMP, 'skipped.json'))),
      [{ type: 'add_comment', name, url: 'https://example.test/comment' }]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('PR CI tests the ingress checker with the same verified analyzers', () => {
  const ingress = fs.readFileSync(path.join(__dirname, '../.github/workflows/workflow-ingress.yml'), 'utf8');
  const install = source => source.split('      - name: Install verified static analyzers\n')[1].split(/\n {6}(?! )/)[0];
  assert.match(install(ingress), /sha256sum -c -/);
  assert.equal(install(ci), install(ingress));
  assert.ok(fs.existsSync(path.join(__dirname, 'test_ingress.py')));
  assert.match(ci, /python3 -m unittest discover -s workflow -p 'test_\*\.py' -v\n {8}env:\n {10}ZIZMOR: /);
});

test('the shared workflow check is off unless a repository variable names its commit', () => {
  const lint = block('lint');
  const step = lint.split('      - name: Shared workflow check\n')[1].split(/\n {6}(?! )/)[0];
  assert.match(step, /^ {8}if: \$\{\{ vars\.WORKFLOW_LINT != '' \}\}\n {8}env:\n {10}WORKFLOW_LINT: \$\{\{ vars\.WORKFLOW_LINT \}\}\n/);
  assert.match(step, /\n {8}run: just workflow-lint "\$WORKFLOW_LINT"$/);
  // The shared Justfile calls cache_directory(), new in just 1.23.
  const [, minor] = lint.match(/\n {8}if: \$\{\{ vars\.WORKFLOW_LINT != '' \}\}\n {8}uses: taiki-e\/install-action@[0-9a-f]{40} # v[\d.]+\n {8}with:\n {10}tool: just@1\.(\d+)\.\d+\n/);
  assert.ok(Number(minor) >= 23, minor);
  // zizmor scans the workspace: gh-aw's workflows are not there yet.
  assert.ok(lint.indexOf('Shared workflow check') < lint.indexOf('repository: github/gh-aw'));
  assert.doesNotMatch(lint, /: write|secrets\./);
  // The recipe's first check, run as just runs it, with SOURCE as $1.
  const justfile = fs.readFileSync(path.join(__dirname, '../Justfile'), 'utf8');
  const guard = justfile.split('\nworkflow-lint source:\n')[1].split('\n').find(line => line.trim().startsWith('[['));
  const commit = 'a'.repeat(40);
  for (const [source, ok] of [
    [`owner/repo@${commit}`, true],
    [`my-org/my.repo_2@${commit}`, true],
    ['owner/repo@main', false],
    [`owner/repo@${commit.slice(1)}`, false],
    [`owner/repo@${commit.toUpperCase()}`, false],
    [`owner@${commit}`, false],
    [`owner/sub/repo@${commit}`, false],
    [`owner/..@${commit}`, false],
    [`--upload-pack=x/y@${commit}`, false],
    [`owner/repo@${commit}\n`, false],
    ['', false],
  ]) {
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', guard, 'workflow-lint', source], { encoding: 'utf8' });
    assert.equal(result.status, ok ? 0 : 2, JSON.stringify(source));
  }
});

test('required ingress check reports on every PR and vets merge groups with base code', () => {
  const ingress = fs.readFileSync(path.join(__dirname, '../.github/workflows/workflow-ingress.yml'), 'utf8');
  const on = ingress.split('\non:\n')[1].split('\npermissions:')[0];
  // A paths filter would leave the required check pending on other PRs.
  assert.doesNotMatch(on, /paths/);
  assert.match(on, /\n {2}merge_group:\n {4}types: \[checks_requested\]\n/);
  assert.match(ingress, /\npermissions:\n {2}contents: read\n\njobs:\n {2}vet:\n/);
  assert.doesNotMatch(ingress, /: write|secrets\.|id-token/);
  // For merge_group, github.sha is the queued commit: never check it out.
  assert.match(ingress, /\n {10}ref: \$\{\{ github\.event\.merge_group\.base_sha \|\| github\.sha \}\}\n/);
  assert.match(ingress, /BASE: \$\{\{ github\.event\.pull_request\.base\.sha \|\| github\.event\.merge_group\.base_sha \}\}/);
  assert.match(ingress, /HEAD: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.event\.merge_group\.head_sha \}\}/);
  assert.match(ingress, /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request_target' \}\}/);
  assert.match(ingress, /python3 workflow\/ingress\.py \. "\$BASE" "\$HEAD"\n/);
});

test('privileged jobs and required check remain gated for forks', () => {
  assert.match(ci, /\non:\n  pull_request:\n  merge_group:\n  push:\n    branches: \[main\]\n\n/);
  assert.doesNotMatch(ci, /pull_request_target|\bworkflow_run\b|secrets\./);
  const jobs = ci.split('\njobs:\n')[1].split(/\n(?=  [a-z][a-z0-9-]*:\n)/);
  let privileged = 0;
  for (const job of jobs) {
    if (!/: write|permissions: \*/.test(job)) continue;
    privileged++;
    assert.match(job, /\n    if: \$\{\{ (always\(\) && )?needs\.changes\.outputs\.e2e == 'true'( && [^|\n]*)? \}\}\n|\n    if: \$\{\{ github\.event_name == 'push' \}\}\n/, job.split('\n')[0]);
  }
  assert.ok(privileged >= 10);
  assert.match(ci, /^      e2e:.*steps\.queue\.outputs\.enabled == 'true' \|\| github\.event\.pull_request\.head\.repo\.full_name != github\.repository.*$/m);
  assert.match(ci, /^      fork-e2e:.*steps\.queue\.outputs\.enabled != 'true'.*$/m);
  assert.match(ci, /^            const rules = await github\.paginate\('GET \/repos\/\{owner\}\/\{repo\}\/rules\/branches\/\{branch\}', \{$/m);
  assert.match(ci, /branch: context.payload.pull_request.base.ref/);
  assert.match(ci, /\n  ci:\n    if: \$\{\{ always\(\) \}\}\n    needs: required-checks\n/);
});

test('the aggregate accepts a skip only under a gate that said false', () => {
  const required = block('required-checks');
  const command = required.slice(required.indexOf('        run: >-\n'))
    .replace('        run: >-\n', '').trim().split('\n').map(line => line.trim()).join(' ');
  // The jq filter is folded into the step's environment, as GitHub does.
  const filter = required.slice(required.indexOf('          FILTER: >-\n'), required.indexOf('        run: >-\n'))
    .replace('          FILTER: >-\n', '').trim().split('\n').map(line => line.trim()).join(' ');
  // Every job but the sentinels and the push-only one is aggregated, under exactly one gate.
  const all = ci.split('\njobs:\n')[1].match(/^  [a-z][a-z0-9-]*(?=:\n)/gm).map(name => name.trim())
    .filter(name => !['required-checks', 'ci', 'secure-host-published'].includes(name));
  assert.deepEqual(required.match(/needs: \[(.*)\]/)[1].split(', ').sort(), [...all].sort());
  assert.deepEqual(['changes', ...Object.values(gates).flat()].sort(), [...all].sort());
  for (const [gate, jobs] of Object.entries(gates)) {
    for (const job of jobs) assert.match(block(job), new RegExp(`\\n    if: \\$\\{\\{ (always\\(\\) && )?needs\\.changes\\.outputs\\.${gate} == 'true'( && [^\\n]*)? \\}\\}\\n`), job);
  }
  assert.equal(block('changes').match(/\n    if:/), null);
  const success = Object.fromEntries(all.map(key => [key, { result: 'success' }]));
  const skip = (...keys) => ({ ...success, ...Object.fromEntries(keys.map(key => [key, { result: 'skipped' }])) });
  const outputs = { FULL: 'true', HOST: 'true', E2E: 'true', REVIEW: 'true', FORK_E2E: 'false' };
  const run = (needs, change = {}) => spawnSync('bash', ['-c', command], {
    env: { ...process.env, ...outputs, ...change, FILTER: filter, NEEDS: JSON.stringify(needs) }, encoding: 'utf8',
  }).status;
  const queuedPush = { FULL: 'false', HOST: 'false', E2E: 'false', REVIEW: '' };
  const queuedPr = { HOST: 'false', E2E: 'false', REVIEW: 'false' };
  for (const [name, needs, change, expected] of [
    ['everything ran', success, {}, 0],
    ['push the queue passed', skip(...gates.full, ...gates.host, ...gates.e2e), queuedPush, 0],
    ['PR with a queue', skip(...gates.host, ...gates.e2e), queuedPr, 0],
    ['docs-only merge group', skip(...gates.e2e), { E2E: 'false', REVIEW: '' }, 0],
    ['merge group skips review', skip('e2e-review'), { REVIEW: '' }, 0],
    ['review not installed on base', skip('e2e-review'), { REVIEW: 'false' }, 0],
    ['review installed but skipped', skip('e2e-review'), {}, 1],
    ['changes skipped', skip('changes'), queuedPush, 1],
    ['host skipped on a merge group', skip('sandbox'), { E2E: 'false' }, 1],
    ['light job skipped on a PR with a queue', skip('rust'), queuedPr, 1],
    ['e2e skipped with host off', skip('e2e-full'), { HOST: 'false' }, 1],
    ['fork without a queue', skip(...gates.e2e), { E2E: 'false', FORK_E2E: 'true' }, 1],
  ]) assert.equal(run(needs, change), expected, name);
  // Each job may be skipped under its own gate, and under no other.
  const off = { full: queuedPush, host: { HOST: 'false' }, e2e: { E2E: 'false' } };
  for (const [gate, jobs] of Object.entries(gates)) {
    for (const job of jobs) {
      assert.equal(run(skip(job), off[gate]), 0, `${job} under ${gate}`);
      for (const other of Object.keys(gates).filter(name => name !== gate && name !== 'full')) {
        assert.notEqual(run(skip(job), off[other]), 0, `${job} under ${other}`);
      }
    }
  }
  for (const value of ['true', '', 'unknown']) {
    for (const gate of ['FULL', 'HOST', 'E2E']) assert.notEqual(run(skip(...gates[gate.toLowerCase()]), { [gate]: value }), 0, gate);
    assert.notEqual(run(success, { FORK_E2E: value }), 0);
  }
  for (const key of all) {
    for (const result of ['failure', 'cancelled']) assert.notEqual(run({ ...success, [key]: { result } }, queuedPush), 0, key);
  }
});

test('gates skip what a queue tested and run everything otherwise', () => {
  // Approximation for these canonical inputs only: GitHub expressions differ
  // from JavaScript in truthiness and case-insensitive string comparisons.
  // The substring assertions above check wiring; this table checks scheduling.
  const vm = require('node:vm');
  const expressions = Object.fromEntries(['full', 'host', 'e2e', 'fork-e2e'].map(key => [key,
    ci.match(new RegExp(`      ${key}: \\$\\{\\{ (.*) \\}\\}`))[1]]));
  for (const event of ['pull_request', 'merge_group', 'push']) {
    for (const queue of ['true', 'false']) {
      for (const fork of [true, false]) {
        for (const paths of ['true', 'false']) {
          for (const passed of event === 'push' ? ['true', 'false'] : [undefined]) {
            const context = {
              github: { event_name: event, repository: 'owner/repo', event: {
                pull_request: { head: { repo: { full_name: fork ? 'fork/repo' : 'owner/repo' } } },
              } },
              steps: { queue: { outputs: { enabled: event === 'pull_request' ? queue : undefined } },
                queued: { outputs: { passed } }, paths: { outputs: { e2e: paths } } },
            };
            const tested = passed === 'true';
            const deferred = event === 'pull_request' && queue === 'true';
            const unavailable = event === 'pull_request' && fork;
            const evaluate = key => String(vm.runInNewContext(expressions[key], context));
            assert.equal(evaluate('full'), String(!tested));
            assert.equal(evaluate('host'), String(!tested && !deferred));
            assert.equal(evaluate('e2e'), tested || deferred || unavailable ? 'false' : paths);
            assert.equal(evaluate('fork-e2e'), String(unavailable && !deferred && paths !== 'false'));
          }
        }
      }
    }
  }
});

test('a push skips only a commit whose merge group run passed', async () => {
  const source = githubScript('queued');
  assert.match(block('changes'), /\n    permissions:\n      contents: read\n      actions: read #[^\n]*\n/);
  assert.match(ci, /- id: queued\n        if: \$\{\{ github\.event_name == 'push' \}\}\n/);
  const sha = 'a'.repeat(40);
  const before = 'c'.repeat(40);
  const passed = async (runs, context = { repo: { owner: 'owner', repo: 'repo' }, sha, payload: { before } }) => {
    let output;
    await new AsyncFunction('github', 'context', 'core', source)({ rest: { actions: { listWorkflowRuns: async params => {
      assert.deepEqual(params, { owner: 'owner', repo: 'repo', workflow_id: 'ci.yml', head_sha: sha,
        event: 'merge_group', status: 'success', per_page: 10 });
      if (runs instanceof Error) throw runs;
      return { data: { workflow_runs: runs } };
    } } } }, context, { setOutput: (key, value) => { assert.equal(key, 'passed'); output = value; } });
    return output;
  };
  const group = { head_sha: sha, event: 'merge_group', conclusion: 'success',
    head_branch: `gh-readonly-queue/main/pr-7-${before}` };
  assert.equal(await passed([group]), true);
  assert.equal(await passed([{ ...group, head_sha: 'b'.repeat(40) }, group]), true);
  // The filters are the API's; what comes back is checked all the same.
  for (const run of [{ head_sha: 'b'.repeat(40) }, { event: 'push' }, { conclusion: 'failure' }, { conclusion: null },
    // A group built on another commit, as when one push lands two groups.
    { head_branch: `gh-readonly-queue/main/pr-7-${'d'.repeat(40)}` }, { head_branch: `main-${before}` }]) {
    assert.equal(await passed([{ ...group, ...run }]), false, JSON.stringify(run));
  }
  assert.equal(await passed([]), false);
  await assert.rejects(passed([{ ...group, head_branch: null }]));
  const pushed = value => ({ repo: { owner: 'owner', repo: 'repo' }, sha, payload: { before: value } });
  // A new branch's before is all zeros, which no queue branch is built on.
  assert.equal(await passed([group], pushed('0'.repeat(40))), false);
  for (const value of ['C'.repeat(40), '', undefined]) {
    assert.equal(await passed([{ ...group, head_branch: `gh-readonly-queue/main/pr-7-${value}` }], pushed(value)), false, value);
  }
  await assert.rejects(passed(new Error('API unavailable')), /API unavailable/);
});

test('review bootstrap reads trusted base files, on pull requests only', () => {
  assert.match(ci, /pull_request and merge_group both run the proposed workflow/);
  assert.match(ci, /- id: review\n        if: \$\{\{ github\.event_name == 'pull_request' \}\}\n        env:\n          BASE: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\n/);
  assert.match(block('e2e-dispatch'), /profile: \$\{\{ fromJSON\(github\.event_name == 'pull_request' && '\["research","review"\]' \|\| '\["research"\]'\) \}\}/);
  const root = fs.mkdtempSync(path.join(os.homedir(), 'ci-test-'));
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  const files = ['workflow/review.md', 'workflow/review.toml', '.github/agentic-job/e2e/review.sh'];
  try {
    git('init', '-q');
    git('config', 'user.name', 'Test');
    git('config', 'user.email', 'test@example.invalid');
    const commit = names => {
      git('rm', '-rqf', '--ignore-unmatch', '.');
      for (const name of names) {
        fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
        fs.writeFileSync(path.join(root, name), 'x');
      }
      fs.writeFileSync(path.join(root, 'code.rs'), String(Math.random()));
      git('add', '-A');
      git('commit', '-qm', 'commit');
      return git('rev-parse', 'HEAD');
    };
    const output = path.join(root, 'output');
    // As GitHub runs a step: bash -e.
    const review = base => {
      fs.writeFileSync(output, '');
      return spawnSync('bash', ['-e', '-c', stepScript('review')], {
        cwd: root, encoding: 'utf8', env: { ...process.env, BASE: base, GITHUB_OUTPUT: output },
      });
    };
    const installed = base => {
      const result = review(base);
      assert.equal(result.status, 0, result.stderr);
      return fs.readFileSync(output, 'utf8').trim();
    };
    const base = commit(files);
    for (const missing of files) assert.equal(installed(commit(files.filter(name => name !== missing))), 'installed=false', missing);
    assert.equal(installed(commit(['workflow/review.md/nested', ...files.slice(1)])), 'installed=false');
    // The base's files, whatever the checked-out head has.
    commit([]);
    assert.equal(installed(base), 'installed=true');
    // A base that is not there fails the gate rather than skip the review.
    for (const missing of ['b'.repeat(40), '']) {
      assert.notEqual(review(missing).status, 0, missing);
      assert.equal(fs.readFileSync(output, 'utf8'), '');
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('merge-group analysis uses a branch name, not a fully qualified ref', () => {
  const source = githubScript('merge-base');
  const run = ref => {
    let branch;
    new Function('context', 'core', source)(
      { payload: { merge_group: { head_ref: ref } } },
      { setOutput: (key, value) => { assert.equal(key, 'branch'); branch = value; } },
    );
    return branch;
  };
  assert.equal(run('refs/heads/gh-readonly-queue/main/pr-123-abcd'), 'gh-readonly-queue/main/pr-123-abcd');
  assert.throws(() => run('refs/tags/main'), /not a branch/);
  assert.equal((ci.match(/base: \$\{\{ github.head_ref \|\| needs.changes.outputs.analysis-base \|\| 'main' \}\}/g) || []).length, 2);
});

test('queue detection fails closed and sentinel rejects non-success', async () => {
  const source = githubScript('queue');
  const detect = new AsyncFunction('github', 'context', 'core', source);
  const context = { repo: { owner: 'owner', repo: 'repo' }, payload: { pull_request: { base: { ref: 'main' } } } };
  for (const rules of [[], [{ type: 'merge_queue' }], [{ type: 'required_status_checks' }]]) {
    let enabled;
    await detect({ paginate: async (route, params) => {
      assert.equal(params.branch, 'main');
      return rules;
    } }, context, { setOutput: (key, value) => { assert.equal(key, 'enabled'); enabled = value; } });
    assert.equal(enabled, rules.some(rule => rule.type === 'merge_queue'));
  }
  await assert.rejects(detect({ paginate: async () => { throw new Error('API unavailable'); } }, context,
    { setOutput: () => assert.fail('must not publish an output after API failure') }), /API unavailable/);
  const sentinel = ci.split('\n  ci:\n')[1].split('        run: ')[1].trim();
  for (const result of ['success', 'failure', 'cancelled', 'skipped', '']) {
    assert.equal(spawnSync('bash', ['-c', sentinel], { env: { ...process.env, RESULT: result } }).status,
      result === 'success' ? 0 : 1);
  }
});

test('E2E callers, concurrency and apt safeguards remain wired', () => {
  for (const job of ['e2e-full', 'e2e-limit', 'e2e-event', 'e2e-analysis', 'e2e-analysis-refused', 'e2e-check-run', 'e2e-review', 'e2e-scratch', 'e2e-items', 'e2e-dispatch', 'e2e-compose', 'e2e-dispatch-verify', 'e2e-verify']) {
    const block = ci.split(`\n  ${job}:\n`)[1].split(/\n  [a-z][a-z-]*:\n/)[0];
    assert.match(block, /needs:.*changes/);
    assert.match(block, /if:.*needs\.changes\.outputs\.e2e == 'true'/);
  }
  assert.doesNotMatch(ci, /paths-ignore:|paths:/);
  assert.match(ci, /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}/);
  const review = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(review, /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request_target' \}\}/);
  assert.match(review, /group: review-pull-\$\{\{ github\.event\.pull_request\.number \|\| github\.event\.issue\.number \}\}/);
  let operations = 0;
  for (const file of ['ci.yml', 'build.yml']) {
    const workflow = fs.readFileSync(path.join(__dirname, '../.github/workflows', file), 'utf8');
    assert.match(workflow, /run: sudo node secure-host\/apt\.mjs/);
    for (const match of workflow.matchAll(/^      - run: (sudo apt-get[^\n]*)\n([^]*?)(?=^      - |\s*$)/gm)) {
      operations++;
      assert.ok(workflow.indexOf('run: sudo node secure-host/apt.mjs') < match.index);
      assert.match(match[1], /-o Acquire::Retries=3/);
      assert.match(match[2], /^        timeout-minutes: 5$/m);
    }
  }
  assert.equal(operations, 3);
  const action = fs.readFileSync(path.join(__dirname, '../secure-host/action.yml'), 'utf8');
  assert.ok(action.includes('run: sudo node "$ACTION/apt.mjs"'));
  assert.ok(action.indexOf('run: sudo node "$ACTION/apt.mjs"') < action.indexOf('- name: Get the binary'));
  const binary = fs.readFileSync(path.join(__dirname, '../secure-host/binary.mjs'), 'utf8');
  assert.match(binary, /run\("sudo", \["node", join\(HERE, "apt.mjs"\)\]\);\s+run\("sudo", \["apt-get"/);
});

test('confined proves the checkout from run steps and a local action main and post step', () => {
  const job = ci.split('\n  confined:\n')[1].split('\n  required-checks:\n')[0];
  // The one local action is the probe, exempted only from self-repository.
  assert.doesNotMatch(job, /uses: cgwalters-forge\/agentic-job/);
  const local = '        uses: ./.github/actions/confine-probe # zizmor: ignore[self-repository] ';
  assert.equal(job.split('uses: ./').length, 2);
  assert.equal(job.split('zizmor: ignore').length, 2);
  assert.ok(job.includes(`      - name: The JavaScript action main and post steps are confined\n${local}`));
  assert.match(job, /binary\.mjs get --build --out "\$RUNNER_TEMP\/secure-host\/bin"/);
  assert.match(job, /world-write\.mjs "\$RUNNER_TEMP\/secure-host\/bin\/world_write\.bpf\.o"/);
  assert.match(job, /--boolean sandbox\.deny-runner-metadata=true/);
  assert.match(job, /agentic-job sandbox check --record/);
  assert.match(job, /probe\.mjs confined run-step/);
  // After setup, so its main and post steps run under the lock.
  assert.ok(job.indexOf('sudo agentic-job sandbox setup') < job.indexOf(local));
  assert.ok(job.indexOf(local) < job.indexOf('uses: actions/upload-artifact@'));
  assert.doesNotMatch(job, /actions\/github-script@/);
  assert.match(job, /- if: \$\{\{ !cancelled\(\) \}\}\n        uses: actions\/upload-artifact@/);
});

test('world-write-runtime proves the policy after the action, with no passing fallback', () => {
  const job = block('world-write-runtime');
  assert.match(job, /\n    runs-on: ubuntu-26\.04\n/);
  assert.match(job, /\n    permissions:\n      contents: read\n    steps:\n/);
  // This checkout's action, binary and object, never a release's.
  assert.match(job, /uses: \.\/secure-host # zizmor: ignore\[self-repository\] .*\n        with:\n          build: true\n/);
  const refused = job.indexOf('      - name: The sandbox user is refused a write to a world-writable file of root\n');
  const control = job.indexOf('      - name: The sandbox user writes its own world-writable file (control)\n');
  assert.ok(job.indexOf('uses: ./secure-host') < refused && refused < control);
  assert.match(job, /"0 666 \$\(stat -c %d \/\)"/);
  assert.match(job, /grep -qF "cannot create \$probe: Permission denied" "\$RUNNER_TEMP\/refused\.txt"/);
  assert.match(job, /shell: agentic-job sandbox exec --stdin \{0\} -- bash -eo pipefail -s/);
  assert.match(job, /"666 \$\(stat -c %d \/\)"/);
  assert.doesNotMatch(job, /continue-on-error|\|\| true|lock: false|filesystem-view/);
});

test('the workflow classifies real Git paths without executing PR scripts', () => {
  const root = fs.mkdtempSync(path.join(os.homedir(), 'ci-test-'));
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  try {
    git('init', '-q');
    git('config', 'user.name', 'Test');
    git('config', 'user.email', 'test@example.invalid');
    fs.writeFileSync(path.join(root, 'code.rs'), 'code');
    git('add', '.');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    const output = path.join(root, 'output');
    const run = (head, event = 'pull_request', before = base) => {
      fs.writeFileSync(output, '');
      const result = spawnSync('bash', ['-euo', 'pipefail', '-c', script], {
        cwd: root, encoding: 'utf8',
        env: { ...process.env, BASE: before, HEAD: head, GITHUB_EVENT_NAME: event,
          RUNNER_TEMP: root, GITHUB_OUTPUT: output },
      });
      assert.equal(result.status, 0, result.stderr);
      return fs.readFileSync(output, 'utf8').trim();
    };
    for (const [name, expected] of [
      ['README.md', false], ['docs/page.md', false], ['docs/nested/page.md', false],
      ['workflow/ci-paths.cjs', true], ['docs/line\nbreak.md', true], ['docs/file.sh', true],
    ]) {
      git('reset', '--hard', base);
      fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      fs.writeFileSync(path.join(root, name), 'e2e=false');
      git('add', name);
      git('commit', '-qm', 'change');
      const head = git('rev-parse', 'HEAD');
      for (const event of ['pull_request', 'push', 'merge_group']) assert.equal(run(head, event), `e2e=${expected}`, name);
    }
    assert.equal(run(base), 'e2e=true');
    assert.equal(run(base, 'push', '0'.repeat(40)), 'e2e=true');
    assert.equal(run(base, 'push', '--output=bad'), 'e2e=true');
    git('reset', '--hard', base);
    fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
    git('mv', 'code.rs', 'docs/code.md');
    git('commit', '-qm', 'rename');
    assert.equal(run(git('rev-parse', 'HEAD')), 'e2e=true');
    assert.doesNotMatch(ci, /run: node workflow\/ci-paths/);
    assert.match(ci, /fork-e2e:.*steps.paths.outputs.e2e != 'false'/);
    assert.match(ci, /\$fork_e2e == "false"/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// `run` refuses to upload a fake agent's run whose redaction replaced
// nothing, and the write-capable E2E jobs run only in a merge group when a
// queue is enabled: a scenario without the canary would fail first there.
// The whole command, since a shortened token is not secret-shaped (#641).
test('every scripted E2E session prints the secret-shaped string run must redact', () => {
  const canary = "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef";
  const dir = path.join(__dirname, '../.github/agentic-job/e2e');
  const setups = fs.readdirSync(dir).filter(name => name.endsWith('.sh'));
  for (const [, file] of ci.matchAll(/^      setup: \.github\/agentic-job\/e2e\/([\w-]+\.sh)$/gm)) {
    assert.ok(setups.includes(file), file);
  }
  assert.ok(setups.length >= 9, setups.join(' '));
  for (const file of setups) {
    const setup = fs.readFileSync(path.join(dir, file), 'utf8');
    const fixture = JSON.parse(setup.split("<<'JSON'\n")[1].split('\nJSON')[0]);
    assert.ok(fixture.some(step => step.execute?.command === canary), file);
  }
});
