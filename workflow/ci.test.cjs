'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const ci = fs.readFileSync(path.join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
const script = ci.split('        run: |\n')[1].split('\n  docs:')[0]
  .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');

test('PR CI tests the ingress checker with the same verified analyzers', () => {
  const ingress = fs.readFileSync(path.join(__dirname, '../.github/workflows/workflow-ingress.yml'), 'utf8');
  const install = source => source.split('      - name: Install verified static analyzers\n')[1].split(/\n {6}(?! )/)[0];
  assert.match(install(ingress), /sha256sum -c -/);
  assert.equal(install(ci), install(ingress));
  assert.ok(fs.existsSync(path.join(__dirname, 'test_ingress.py')));
  assert.match(ci, /python3 -m unittest discover -s workflow -p 'test_\*\.py' -v\n {8}env:\n {10}ZIZMOR: /);
});

test('privileged jobs and required check remain gated for forks', () => {
  assert.match(ci, /\non:\n  pull_request:\n  merge_group:\n  push:\n    branches: \[main\]\n\n/);
  assert.doesNotMatch(ci, /pull_request_target|workflow_run|secrets\./);
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
  const command = ci.slice(ci.indexOf('        run: >-\n', ci.indexOf('\n  required-checks:')), ci.indexOf('\n  ci:\n'))
    .replace('        run: >-\n', '').trim().split('\n').map(line => line.trim()).join(' ');
  const skipped = ['proposals', 'e2e-proposals', 'e2e-full', 'e2e-limit', 'e2e-event', 'e2e-analysis', 'e2e-analysis-refused', 'review-base', 'e2e-review', 'e2e-dispatch', 'e2e-compose', 'e2e-dispatch-verify', 'e2e-verify'];
  const normal = ['changes', 'docs', 'rust', 'sandbox'];
  const needs = Object.fromEntries([...normal, ...skipped].map(key => [key, { result: 'success' }]));
  const run = (state, e2e, installed = 'true', forkE2e = 'false') => spawnSync('bash', ['-c', command], {
    env: { ...process.env, NEEDS: JSON.stringify(state), E2E: e2e, REVIEW_INSTALLED: installed, FORK_E2E: forkE2e },
    encoding: 'utf8',
  }).status;
  assert.equal(run(needs, 'true'), 0);
  const docs = { ...needs, ...Object.fromEntries(skipped.map(key => [key, { result: 'skipped' }])) };
  assert.equal(run(docs, 'false'), 0);
  for (const value of ['true', '', 'unknown']) {
    assert.notEqual(run(docs, value), 0);
    assert.notEqual(run(docs, 'false', 'true', value), 0);
    assert.notEqual(run(needs, 'true', 'true', value), 0);
  }
  for (const key of [...normal, ...skipped]) {
    for (const result of ['failure', 'cancelled']) assert.notEqual(run({ ...docs, [key]: { result } }, 'false'), 0);
  }
  for (const key of normal) assert.notEqual(run({ ...docs, [key]: { result: 'skipped' } }, 'false'), 0);
  assert.equal(run({ ...needs, 'e2e-review': { result: 'skipped' } }, 'true', 'false'), 0);
  for (const key of skipped) assert.notEqual(run({ ...needs, [key]: { result: 'skipped' } }, 'true'), 0);
});

test('queue scheduling runs E2E on groups and on PRs only without a queue', () => {
  // Approximation for these canonical inputs only: GitHub expressions differ
  // from JavaScript in truthiness and case-insensitive string comparisons.
  // The substring assertions above check wiring; this table checks scheduling.
  const vm = require('node:vm');
  const expressions = Object.fromEntries(['e2e', 'fork-e2e'].map(key => [key,
    ci.match(new RegExp(`      ${key}: \\$\\{\\{ (.*) \\}\\}`))[1]]));
  for (const event of ['pull_request', 'merge_group', 'push']) {
    for (const queue of ['true', 'false']) {
      for (const fork of [true, false]) {
        for (const paths of ['true', 'false']) {
          const context = {
            github: { event_name: event, repository: 'owner/repo', event: {
              pull_request: { head: { repo: { full_name: fork ? 'fork/repo' : 'owner/repo' } } },
            } },
            steps: { queue: { outputs: { enabled: queue } }, paths: { outputs: { e2e: paths } } },
          };
          const deferred = event === 'pull_request' && queue === 'true';
          const unavailable = event === 'pull_request' && fork;
          assert.equal(vm.runInNewContext(expressions.e2e, context), deferred || unavailable ? 'false' : paths);
          assert.equal(vm.runInNewContext(expressions['fork-e2e'], context), unavailable && !deferred && paths !== 'false');
        }
      }
    }
  }
});

test('review bootstrap checks trusted base files, including on merge groups', () => {
  const block = ci.split('\n  review-base:\n')[1].split('\n  e2e-dispatch:\n')[0];
  const expression = block.match(/ref: \$\{\{ (.*) \}\}/)[1];
  const vm = require('node:vm');
  for (const [pr, group, expected] of [
    ['pr-base', 'group-base', 'pr-base'],
    ['', 'group-base', 'group-base'],
    ['', '', 'push-head'],
  ]) {
    assert.equal(vm.runInNewContext(expression, { github: {
      event: { pull_request: { base: { sha: pr } }, merge_group: { base_sha: group } },
      sha: 'push-head',
    } }), expected);
  }
  assert.match(ci, /pull_request and merge_group both run the proposed workflow/);
});

test('merge-group analysis uses a branch name, not a fully qualified ref', () => {
  const source = ci.split('      - id: merge-base\n')[1].split('      # Effective branch rules')[0]
    .split('          script: |\n')[1].trim().split('\n').map(line => line.trim()).join('\n');
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
  const source = ci.split('      - id: queue\n')[1].split('      - uses: actions/checkout@')[0]
    .split('          script: |\n')[1].trim().split('\n').map(line => line.trim()).join('\n');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
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
  for (const job of ['e2e-full', 'e2e-limit', 'e2e-event', 'e2e-analysis', 'e2e-analysis-refused', 'review-base', 'e2e-review', 'e2e-dispatch', 'e2e-compose', 'e2e-dispatch-verify', 'e2e-verify']) {
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
