// Exercise the extracted actions' actual shell without changing this host.
const assert = require('node:assert/strict');
const { mkdirSync, readFileSync, readdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { homedir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const prepare = readFileSync(join(__dirname, '../prepare/action.yml'), 'utf8');
const run = readFileSync(join(__dirname, '../run/action.yml'), 'utf8');
const wrapper = readFileSync(join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');
const compose = readFileSync(join(__dirname, '../.github/workflows/example-compose.yml'), 'utf8');
const policy = readFileSync(join(__dirname, '../.github/workflows/policy.yml'), 'utf8');

function step(source, name) {
  const section = source.split(`- name: ${name}\n`)[1];
  assert.ok(section, name);
  return section.split('      run: |\n')[1].split(/\n    [^ ]/)[0].split('\n')
    .filter(line => line.startsWith('        ')).map(line => line.slice(8)).join('\n');
}

function shell(script, env) {
  return spawnSync('bash', ['-eo', 'pipefail', '-c', script], {
    encoding: 'utf8', env: { ...process.env, ...env },
  });
}

test('prepare rejects missing and nonnumeric trusted artifact IDs before download', () => {
  for (const [binary, policy, expected] of [
    ['1', '2', 0], ['', '2', 1], ['1', '', 1], ['0', '2', 1],
    ['1,2', '3', 1], ['1', 'policy-name', 1], ['$(exit 99)', '2', 1],
  ]) {
    const result = shell(step(prepare, 'Require trusted upload IDs'), { BINARY: binary, POLICY: policy });
    assert.equal(result.status, expected, result.stdout + result.stderr);
  }
  assert.match(prepare, /artifact-ids: \$\{\{ inputs.binary-artifact-id \}\},\$\{\{ inputs.policy-artifact-id \}\}/);
  assert.doesNotMatch(prepare, /name: \$\{\{ inputs\./);
});

test('prepare and run refuse a policy call of another commit before using its upload', (t) => {
  const directory = mkdtempSync(join(homedir(), 'agent-actions-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const git = (...args) => spawnSync('git', ['-C', directory, ...args], { encoding: 'utf8' });
  git('init', '-q');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'source');
  const head = git('rev-parse', 'HEAD').stdout.trim();
  const other = 'b'.repeat(40);
  const plain = join(directory, 'plain');
  require('node:fs').mkdirSync(plain);
  // [source_sha in run.json, the action's ref, the action's directory, status]
  for (const [sha, ref, path, expected] of [
    [head, '', directory, 0], [other, '', directory, 1], [head, head, plain, 0],
    [other, head, plain, 1], [head, other, directory, 1], [head, '', plain, 1],
    [head, 'main', plain, 1], [undefined, '', directory, 1], ['', '', plain, 1],
    [head.toUpperCase(), '', directory, 1], [`${head}\n`, '', directory, 1],
  ]) {
    require('node:fs').writeFileSync(join(directory, 'run.json'), JSON.stringify(sha === undefined ? {} : { source_sha: sha }));
    for (const source of [prepare, run]) {
      const result = shell(step(source, "The policy call is this action's commit"),
        { JOB_DIR: directory, ACTION_REF: ref, GITHUB_ACTION_PATH: path, GIT_CEILING_DIRECTORIES: directory });
      assert.equal(result.status, expected, `${sha} ${ref} ${path}: ${result.stdout}${result.stderr}`);
    }
  }
  assert.ok(prepare.indexOf("this action's commit") < prepare.indexOf('name: Install the binary'));
  assert.ok(run.indexOf("this action's commit") < run.indexOf("name: Read the run's settings"));
  assert.match(policy, /--arg source_sha "\$SOURCE_SHA" '\$ARGS.named'/);
  assert.match(policy, /SOURCE_SHA: \$\{\{ job.workflow_sha \}\}\n {8}run: \|\n {10}if \[ -n "\$PROFILE" \]/);
});

test('run rejects unlocked configuration before probing and probes before agent execution', () => {
  const guard = step(run, 'Prove the host is secured');
  const python = guard.match(/python3 -c '([^']+)'/)[1];
  // Replace only the root-owned file read with an in-memory configuration.
  for (const [sandbox, expected] of [[{}, 0], [{ 'lock-runner': true }, 0],
    [{ 'lock-runner': false }, 1], [{ 'lock-runner': 'true' }, 1]]) {
    const code = python.replace('tomllib.load(open("/etc/agentic-job/config.toml", "rb"))',
      `__import__("json").loads(${JSON.stringify(JSON.stringify({ sandbox }))})`);
    const result = spawnSync('python3', ['-c', code], { encoding: 'utf8' });
    assert.equal(result.status, expected, result.stderr);
  }
  const result = shell('python3() { return 1; }; agentic-job() { echo unexpected; };\n' + guard);
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stdout, /unexpected/);
  assert.ok(run.indexOf('name: Prove the host') < run.indexOf('name: Run the agent'));
});

test('agent exit is captured before uploads and partial result gate is unchanged', (t) => {
  const directory = mkdtempSync(join(homedir(), 'agent-actions-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const exit of [0, 1, 3, 4, 124]) {
    const output = join(directory, `output-${exit}`);
    const result = shell('agentic-job() { printf "%s\\n" "$@"; return "$STATE"; };\n' +
      step(run, 'Run the agent'), { JOB_DIR: directory, REVIEW_HEAD: 'review-head', STATE: String(exit),
        GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: join(directory, 'summary') });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, 'utf8'), `exit=${exit}\n`);
    assert.match(result.stdout, /--review-head\nreview-head/);
    for (const partial of ['false', 'true']) {
      const gate = shell(step(run, "The run's result"), { EXIT: String(exit), PARTIAL: partial });
      const expected = exit === 0 || partial === 'true' && [3, 124].includes(exit) ? 0 : 1;
      assert.equal(gate.status, expected, gate.stdout + gate.stderr);
    }
  }
  assert.ok(run.indexOf('id: safe-outputs') < run.indexOf("name: The run's result"));
  // A run that ended well over its budget says so, as a warning and an
  // output of numbers; one stopped at the budget is the exit state's.
  mkdirSync(join(directory, 'out/run'), { recursive: true });
  for (const [summary, over] of [
    [{ result: 'success', aic: 565.9, aic_budget: 500 }, '565.9 of 500 AIC'],
    [{ result: 'success', aic: 499.9, aic_budget: 500 }, ''],
    [{ result: 'success', aic: 565.9, aic_budget: null }, ''],
    [{ result: 'success', aic: '565.9 $(exit 9)', aic_budget: 500 }, ''],
    [{ result: 'budget', aic: 565.9, aic_budget: 500 }, ''],
  ]) {
    writeFileSync(join(directory, 'out/run/summary.json'), JSON.stringify(summary));
    const output = join(directory, 'output-over');
    const result = shell('agentic-job() { return 0; };\n' + step(run, 'Run the agent'), {
      JOB_DIR: directory, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: join(directory, 'summary') });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, 'utf8'), `exit=0\n${over && `over-budget=${over}\n`}`);
    assert.equal(result.stdout.includes(`::warning::the agent ended its turn over budget: spent ${over}\n`), over !== '');
    rmSync(output);
  }
  assert.match(run, /steps.settings.outputs.apply_partial == 'true' && steps.safe-outputs.outputs.artifact-id != ''/);
});

test('public visibility refusal blocks publication and repository names are data', () => {
  const script = step(run, 'Check again that the repositories are public');
  for (const [repo, repos, publicRepo, expected] of [
    ['owner/repo', 'owner/repo', 'true', 0], ['owner/repo', 'owner/repo owner/config', 'true', 0],
    ['owner/repo', 'owner/repo', 'false', 1], ['$(exit 99)', '$(exit 99)', 'true', 1],
    ['', '', 'true', 1], [' ', ' ', 'true', 1], ['owner/repo', 'owner/repo invalid', 'true', 1],
  ]) {
    const result = shell('gh() { printf "%s\\n" "$PUBLIC"; };\n' + script,
      { REPO: repo, REPOS: repos, PUBLIC: publicRepo });
    assert.equal(result.status, expected, result.stdout + result.stderr);
  }
  assert.ok(run.indexOf('Check again that') < run.indexOf('uses: actions/upload-artifact'));
});

test('admission and upload gates refuse unknown visibility with private-run guidance', () => {
  const admission = policy.split('- name: Check that the repositories are public\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].replace(/^ {10}/gm, '');
  for (const script of [admission, step(run, 'Check again that the repositories are public')]) {
    assert.match(script, /\.private == false and \.visibility == "public"/);
    for (const [answer, apiExit, expected] of [
      ['true', 0, 0], ['false', 0, 1], ['null', 0, 1], ['', 0, 1], ['true', 1, 1],
    ]) {
      const result = shell('gh() { printf "%s\\n" "$ANSWER"; return "$API_EXIT"; };\n' + script,
        { REPO: 'owner/repo', REPOS: 'owner/repo owner/config owner/item',
          ANSWER: answer, API_EXIT: String(apiExit) });
      assert.equal(result.status, expected, result.stdout + result.stderr);
      if (expected !== 0) assert.match(result.stdout, /private runs are refused.*docs\/private-repositories\.md/);
    }
  }
  assert.ok(policy.indexOf('Check that the repositories are public') < policy.indexOf('name: This workflow'));
});

// The wrapper's agent job and the example's caller-owned one are the same
// steps: the caller's repository, the actions of policy's own commit,
// then prepare, secure-host and run, in that order.
for (const [file, source] of [['agentic-job.yml', wrapper], ['example-compose.yml', compose]]) {
  test(`${file} composes the pinned-source agent job and keeps trusted edges off agent outputs`, () => {
    const agent = source.split('\n  agent:\n')[1].split('\n  check:\n')[0];
    assert.match(agent, /^    needs: policy$/m);
    assert.match(agent, /safe-outputs-artifact-id: \$\{\{ steps.run.outputs.safe-outputs-artifact-id \}\}/);
    for (const input of ['binary-artifact-id', 'policy-artifact-id']) {
      assert.ok(agent.includes(`${input}: \${{ needs.policy.outputs.${input} }}`));
    }
    assert.match(agent, /repository: \$\{\{ needs.policy.outputs.source-repository \}\}\n {10}ref: \$\{\{ needs.policy.outputs.source-sha \}\}\n {10}path: .agentic-job-source\n/);
    assert.match(agent, /^ {10}ref: \$\{\{ needs.policy.outputs.ref \}\}$/m);
    const uses = [...agent.matchAll(/^ {6}(?:- |  )uses: ([^\n]+)/gm)].map(([, use]) => use.split(' ')[0]);
    assert.deepEqual(uses.filter(use => !use.startsWith('actions/checkout@')), [
      './.agentic-job-source/prepare', './.agentic-job-source/secure-host', './.agentic-job-source/run']);
    for (const use of uses) assert.match(use, /^(\.\/\.agentic-job-source\/[-\w]+|actions\/checkout@[0-9a-f]{40})$/);
    assert.ok(agent.indexOf('source/prepare') < agent.indexOf('source/secure-host'));
    assert.ok(agent.indexOf('source/secure-host') < agent.indexOf('source/run'));
    assert.doesNotMatch(agent, /SAFE_OUTPUTS_PAT|tailscale/i);
    // An empty source would make the checkout take the caller's own.
    const sourced = agent.split("- name: The policy call's source repository and commit\n")[1];
    assert.ok(sourced.indexOf('[[ "$SOURCE_REPOSITORY"') < sourced.indexOf('path: .agentic-job-source'));
    const script = sourced.split('        run: |\n')[1].split('\n      - ')[0].replace(/^ {10}/gm, '');
    for (const [repo, sha, status] of [['o/r', 'a'.repeat(40), 0], ['', 'a'.repeat(40), 1], ['o/r', '', 1], ['o/r', 'main', 1]]) {
      const result = spawnSync('bash', ['-e', '-c', script], { encoding: 'utf8', env: { ...process.env, SOURCE_REPOSITORY: repo, SOURCE_SHA: sha } });
      assert.equal(result.status, status, `${repo} ${sha}`);
    }
    // Check and apply take the policy call's outputs as they are, and of
    // this job only what run hands on.
    const call = name => source.split(`\n  ${name}:\n`)[1].split(/\n  (?=[-\w]+:\n)/)[0].split('    with:\n')[1]
      .replace(/^ *#.*$/gm, '').trimEnd();
    assert.equal(call('check'), [
      '      policy: ${{ toJSON(needs.policy.outputs) }}',
      '      safe-outputs-artifact-id: ${{ needs.agent.outputs.safe-outputs-artifact-id }}'].join('\n'));
    assert.equal(call('apply'), [
      '      policy: ${{ toJSON(needs.policy.outputs) }}',
      '      agent: ${{ toJSON(needs.agent) }}',
      '      check: ${{ toJSON(needs.check) }}'].join('\n'));
  });
}

test('apply applies only what check accepted, whatever the caller\'s gate', () => {
  const applier = readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
  const gate = applier.split('\n  apply:\n')[1].split('    runs-on:')[0];
  assert.match(gate, /\$\{\{ !cancelled\(\) && fromJSON\(inputs.check\).result == 'success' && /);
  assert.doesNotMatch(gate, /always\(\)/);
});

test('the source an agent job takes its actions from is the policy call\'s own', () => {
  const job = policy.split('\n  policy:\n')[1].split('\n    steps:\n')[0];
  assert.match(job, /^ {6}source-repository: \$\{\{ job.workflow_repository \}\}$/m);
  assert.match(job, /^ {6}source-sha: \$\{\{ job.workflow_sha \}\}$/m);
  for (const action of [prepare, run]) {
    assert.doesNotMatch(action, /secrets\.|SAFE_OUTPUTS_PAT/);
    for (const use of action.matchAll(/uses: ([^\n]+)/g)) {
      assert.match(use[1], /^actions\/[\w-]+@[0-9a-f]{40} /);
    }
  }
});

// example-compose.yml is what a caller copies, with steps of its own in
// two marked places. Its example steps, which CI's e2e-compose runs, show
// where those run: the one before secure-host has root, the one after run
// has none.
test('the composed example marks where a caller\'s own steps go, and its examples prove their privileges', () => {
  const agent = compose.split('\n  agent:\n')[1].split('\n  check:\n')[0];
  const at = text => { const index = agent.indexOf(text); assert.ok(index >= 0, text); return index; };
  const order = [
    'uses: ./.agentic-job-source/prepare', 'Your privileged steps go here', "name: A caller's privileged step",
    'End of your privileged steps', 'uses: ./.agentic-job-source/secure-host', 'uses: ./.agentic-job-source/run',
    'Your later steps go here', "name: A caller's later step",
  ].map(at);
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
  const before = agent.split("- name: A caller's privileged step (example)\n")[1].split('\n      #')[0];
  assert.match(before, /sudo install -m 0600 -o root -g root \/dev\/null (\/var\/lib\/[-\w]+)/);
  const file = before.match(/\/dev\/null (\S+)/)[1];
  const after = agent.split("- name: A caller's later step (example)\n")[1];
  assert.ok(after.includes(`stat -c '%U %a' ${file})" = 'root 600'`));
  assert.match(after, /if sudo -n true .*exit 1; fi/);
});

// The agent holds its GitHub token and can leak it: every permission of
// the job that makes it is a read, but the run's own OIDC token.
test('the agent job token reads and write credentials stay in deterministic jobs', () => {
  const jobs = wrapper.split('\njobs:\n')[1];
  const agent = jobs.split('\n  agent:\n')[1].split('\n  check:\n')[0];
  const permissions = agent.split('    permissions:\n')[1].split('    outputs:\n')[0];
  // Every line is a permission, a comment, or a permission with one.
  const lines = permissions.split('\n').map(line => line.replace(/#.*/, '').trim()).filter(Boolean);
  assert.deepEqual(Object.fromEntries(lines.map(line => line.match(/^([-\w]+): (\w+)$/).slice(1))), {
    contents: 'read', issues: 'read', 'pull-requests': 'read', actions: 'read', 'id-token': 'write',
  });
  const line = "github-token: ${{ inputs.github-reads && github.token || '' }}";
  assert.ok(agent.includes(line));
  // Actions expressions allow a hyphen in a property name; JavaScript does not.
  const expression = line.match(/\$\{\{ (.+) \}\}/)[1].replace('inputs.github-reads', "inputs['github-reads']");
  for (const [reads, expected] of [
    [true, 'job-token'], [false, ''],
  ]) {
    assert.equal(Function('inputs', 'github', `return ${expression}`)(
      { 'github-reads': reads }, { token: 'job-token' }), expected);
  }
  assert.match(wrapper, /^      github-reads:\n[\s\S]*?type: boolean\n        default: true$/m);
  // So in the example whose agent job a caller owns, and in the pieces.
  for (const [file, source] of [['agentic-job.yml', wrapper], ['example-compose.yml', compose], ['policy.yml', policy],
    ['check.yml', readFileSync(join(__dirname, '../.github/workflows/check.yml'), 'utf8')],
    ['apply.yml', readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8')]]) {
    const named = [...source.split('\njobs:\n')[1].matchAll(/^  ([-\w]+):\n([\s\S]*?)(?=^  [-\w]+:\n|$(?![\s\S]))/gm)];
    assert.ok(named.length > 0, file);
    for (const [, name, job] of named) {
      const holdsWrite = name === 'apply' || (file === 'agentic-job.yml' && name === 'policy') ||
        (file === 'policy.yml' && name === 'notify') || (file === 'apply.yml' && name === 'conclude');
      assert.equal(job.includes('secrets.SAFE_OUTPUTS_PAT'), holdsWrite, `${file} ${name}`);
    }
  }
  const owned = compose.split('\n  agent:\n')[1].split('\n  check:\n')[0];
  assert.match(owned, /^          github-token: \$\{\{ github.token \}\}$/m);
  const ownedPermissions = owned.split('    permissions:\n')[1].split('    outputs:\n')[0];
  assert.deepEqual(ownedPermissions.split('\n').map(line => line.replace(/#.*/, '').trim()).filter(Boolean).sort(),
    ['actions: read', 'contents: read', 'id-token: write', 'issues: read', 'pull-requests: read']);
  // GitHub refuses a whole called workflow whose job asks for more than
  // the call was granted, the skipped agent job's included.
  const workflows = join(__dirname, '../.github/workflows');
  for (const file of readdirSync(workflows)) {
    const source = readFileSync(join(workflows, file), 'utf8');
    assert.ok(!source.includes('GH_READ_TOKEN'), `${file} must not declare or use a long-lived read secret`);
    for (const [, name, job] of source.matchAll(/^  ([-\w]+):\n([\s\S]*?)(?=^  [-\w]+:\n|$(?![\s\S]))/gm)) {
      if (!/^    uses: \.\/\.github\/workflows\/(agentic-job|dispatch|example-compose)\.yml/m.test(job)) continue;
      const granted = job.split('    permissions:')[1]?.split(/\n    [^ ]/)[0] ?? '';
      const anchor = granted.match(/^ \*([-\w]+)/);
      const block = anchor ? source.split(`&${anchor[1]}\n`)[1].split(/\n    [^ ]/)[0] : granted;
      for (const scope of ['contents', 'issues', 'pull-requests', 'actions']) {
        assert.match(block, new RegExp(`^      ${scope}: (read|write)\\b`, 'm'), `${file} ${name} ${scope}`);
      }
      assert.match(block, /^      id-token: write\b/m, `${file} ${name}`);
    }
  }
});

test('the agent gets its GitHub token, and a classic token that can write is refused first', () => {
  const runStep = run.split('- name: Run the agent\n')[1].split('      run: |\n')[0];
  assert.match(runStep, /^        GH_TOKEN: \$\{\{ inputs.github-token \}\}$/m);
  assert.match(run, /^  github-token:\n[\s\S]*?default: ""$/m);
  assert.ok(run.indexOf('name: Refuse a GitHub token that can write') < run.indexOf('name: Run the agent'));
  const probe = step(run, 'Refuse a GitHub token that can write');
  for (const [token, headers, status, expected] of [
    ['', '', 0, 0],
    // A job, App or fine-grained token names no scopes.
    ['ghs_job', 'HTTP/2 200\r\nx-ratelimit-limit: 5000\r\n', 0, 0],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: \r\n', 0, 0],
    ['gho_classic', 'HTTP/2 200\r\nX-OAuth-Scopes: read:org, read:user, user:email\r\n', 0, 0],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: public_repo\r\n', 0, 1],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: read:org, repo\r\n', 0, 1],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: read:packages,write:packages\r\n', 0, 1],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: gist\r\n', 0, 1],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: *\r\n', 0, 1],
    ['gho_classic', 'HTTP/2 200\r\nx-oauth-scopes: $(exit 0)\r\n', 0, 1],
    // GitHub did not take it: refused, not waved through.
    ['gho_classic', '', 22, 1],
  ]) {
    // The token is sent on stdin, never as an argument others can see.
    const result = shell('curl() { case "$*" in *"$GH_TOKEN"*) return 9 ;; esac\n' +
      '[ "$(cat)" = "Authorization: Bearer $GH_TOKEN" ] || return 8; printf "%s" "$HEADERS"; return "$STATUS"; };\n' + probe,
      { GH_TOKEN: token, HEADERS: headers, STATUS: String(status) });
    assert.equal(result.status, expected, `${headers}: ${result.stdout}${result.stderr}`);
    assert.doesNotMatch(result.stdout + result.stderr, /ghs_job|gho_classic/);
  }
});

// agentic-job.yml is the pieces composed: every setting it takes but the
// agent job's own goes to the policy call as it is, so the two cannot
// drift apart.
test('the wrapper forwards every setting to the policy call as it is', () => {
  const names = source => [...source.split('    inputs:\n')[1].split(/^    (?:outputs|secrets):\n/m)[0]
    .matchAll(/^      ([-\w]+):$/gm)].map(([, name]) => name);
  const own = ['agent-runner', 'github-reads'];
  assert.deepEqual(names(wrapper).filter(name => !own.includes(name)), names(policy));
  const call = wrapper.split('\n  policy:\n')[1].split('\n  agent:\n')[0].split('    with:\n')[1].trimEnd();
  assert.equal(call, names(policy).map(name => `      ${name}: \${{ inputs.${name} }}`).join('\n'));
});

// A network to join is the caller's own step (docs/workflow.md): no
// workflow or action of agentic-job joins one or takes its credentials.
// This repository's own deployment joins its tailnet in the network step
// it keeps as a caller (.github/agentic-job/network), outside them.
test('no workflow or action of this repository joins a network itself', () => {
  const root = join(__dirname, '..');
  const files = [...readdirSync(join(root, '.github/workflows')).map(file => `.github/workflows/${file}`),
    'prepare/action.yml', 'run/action.yml', 'secure-host/action.yml', 'workflow/inference-preflight.py'];
  for (const file of files) {
    const text = readFileSync(join(root, file), 'utf8');
    assert.doesNotMatch(text, /tailscale|join(?:s|ing)? (?:a|the) tailnet/i, file);
    assert.doesNotMatch(text, /cgwalters-forge\/actions/, file);
  }
});

// review.yml's network step is the caller's: a local action from the
// agent job's base checkout, skipped when the caller has none, once and in
// the agent job only, after prepare and before secure-host, so it runs
// before anything of the agent's is on the machine.
test('review.yml runs the caller\'s network step once, if any, before secure-host', () => {
  const root = join(__dirname, '..');
  const review = readFileSync(join(root, '.github/workflows/review.yml'), 'utf8');
  const step = './.github/agentic-job/network';
  const body = review.split(/^jobs:\n/m)[1];
  const jobs = Object.fromEntries(body.split(/^(?=  [-\w]+:\n)/m)
    .map(text => [text.match(/^  ([-\w]+):\n/)[1], text]));
  assert.deepEqual(Object.keys(jobs), ['policy', 'refusal', 'agent', 'check', 'submit', 'apply', 'status']);
  for (const [name, text] of Object.entries(jobs)) {
    if (name !== 'agent') assert.ok(!text.includes(step), name);
  }
  // The base checkout it is read from is the first, at the policy's ref.
  assert.match(jobs.agent, /steps:\n {6}# [^\n]*\n {6}- uses: actions\/checkout@[0-9a-f]{40} # [^\n]*\n {8}with:\n {10}ref: \$\{\{ needs\.policy\.outputs\.ref \}\}\n {10}persist-credentials: false\n/);
  const uses = [...jobs.agent.matchAll(/^ {6}(?:- )? *uses: (\S+)/gm)].map(([, action]) => action);
  assert.equal(uses.filter(action => action === step).length, 1, uses.join('\n'));
  assert.equal(uses.filter(action => !/^(?:actions\/checkout@[0-9a-f]{40}|\.\/\.agentic-job-source\/)/.test(action)).length, 1,
    uses.join('\n'));
  const at = uses.indexOf(step);
  assert.equal(uses[at - 1], './.agentic-job-source/prepare');
  assert.equal(uses[at + 1], './.agentic-job-source/secure-host');
  // Off unless the caller has one.
  assert.match(jobs.agent, /if: \$\{\{ hashFiles\('\.github\/agentic-job\/network\/action\.yml'\) != '' \}\}\n {8}uses: \.\/\.github\/agentic-job\/network /);
  // This repository's own, a composite action whose actions are pinned.
  const own = readFileSync(join(root, '.github/agentic-job/network/action.yml'), 'utf8');
  assert.match(own, /^  using: composite$/m);
  const pinned = [...own.matchAll(/^ +(?:- )?uses: (\S+)/gm)].map(([, action]) => action);
  assert.ok(pinned.length > 0);
  for (const action of pinned) assert.match(action, /^[-\w]+\/[-\w./]+@[0-9a-f]{40}$/, action);
});
