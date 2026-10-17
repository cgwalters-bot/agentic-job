// Exercise the extracted actions' actual shell without changing this host.
const assert = require('node:assert/strict');
const { existsSync, mkdirSync, readFileSync, readdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { homedir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const prepare = readFileSync(join(__dirname, '../prepare/action.yml'), 'utf8');
const run = readFileSync(join(__dirname, '../run/action.yml'), 'utf8');
const wrapper = readFileSync(join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');
// The wrapper's agent job, which it calls so that the run token is a secret.
const agentCall = readFileSync(join(__dirname, '../.github/workflows/agent.yml'), 'utf8');
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
  rmSync(join(directory, 'out/run'), { recursive: true });
  // A run that uploaded nothing for a secret says where, and only a place.
  for (const [at, expected] of [
    ['safe-outputs/aw-agent-run-1.patch, line 3\n', 'safe-outputs/aw-agent-run-1.patch, line 3'],
    ['transcript/acp.jsonl, line 12\nmore\n', 'transcript/acp.jsonl, line 12'],
    ['safe-outputs/a`@b`.patch, line 3\n', ''],
    ['../x, line 3\n', ''],
    ['safe-outputs/x.patch, line 3 $(exit 9)\n', ''],
  ]) {
    writeFileSync(join(directory, 'out/secret-at'), at);
    const output = join(directory, 'output-secret');
    const summary = join(directory, 'summary-secret');
    const result = shell('agentic-job() { return 1; };\n' + step(run, 'Run the agent'), {
      JOB_DIR: directory, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, 'utf8'), `exit=1\n${expected && `secret-at=${expected}\n`}`);
    assert.equal(existsSync(summary) ? readFileSync(summary, 'utf8') : '',
      expected && `Nothing of this run was uploaded: a secret or a private key is in ${expected}.\n`);
    rmSync(output);
    rmSync(summary, { force: true });
  }
  assert.match(run, /steps.settings.outputs.apply_partial == 'true' && steps.safe-outputs.outputs.artifact-id != ''/);
});

// A mock of `gh api`: the target's answer for REPO, OTHER for the rest,
// each as the step's own jq would print it.
const gh = 'gh() { if [ "$2" = "repos/$REPO" ]; then printf "%s\\n" "$TARGET"; else printf "%s\\n" "$OTHER"; fi; return "${API_EXIT:-0}"; };\n';
// A mock of the REST API by curl, for run's step: the same answers as
// the API's JSON, refused unless the token comes on stdin and nowhere
// in the arguments.
const curl = `curl() {
  local header answer
  read -r header
  [ "$header" = "Authorization: Bearer $GH_TOKEN" ] || return 9
  case " $* " in *"$GH_TOKEN"*) return 9 ;; esac
  if [ "\${*: -1}" = "https://api.github.com/repos/$REPO" ]; then answer=$TARGET; else answer=$OTHER; fi
  case "$answer" in
    public) echo '{"private": false, "visibility": "public"}' ;;
    private) echo '{"private": true, "visibility": "private"}' ;;
    unknown) echo '{"private": false, "visibility": "internal"}' ;;
  esac
  return "\${API_EXIT:-0}"
};
`;
const api = { GH_TOKEN: 'test-token-not-secret' };

test('public visibility refusal blocks publication and repository names are data', (t) => {
  const script = step(run, 'Check again that the repositories are public');
  const dir = mkdtempSync(join(homedir(), 'visibility-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const policyFile = (repo, isPrivate) => writeFileSync(join(dir, 'policy.json'),
    JSON.stringify({ repo, ...(isPrivate ? { private: true } : {}) }));
  // Target, agent configuration, the target's and the others' answers,
  // whether the policy is private and for which repository, the caller,
  // and the exit status.
  for (const [repo, repos, target, other, isPrivate, policyRepo, caller, expected] of [
    ['owner/repo', '', 'public', 'public', false, 'owner/repo', 'owner/caller', 0],
    ['owner/repo', 'owner/config', 'public', 'public', false, 'owner/repo', 'owner/caller', 0],
    ['owner/repo', '', 'private', 'public', false, 'owner/repo', 'owner/repo', 1],
    ['owner/repo', '', 'private', 'public', true, 'owner/repo', 'owner/repo', 0],
    ['owner/repo', '', 'private', 'public', true, 'owner/other', 'owner/repo', 1],
    ['owner/repo', '', 'private', 'public', true, 'owner/repo', 'owner/caller', 1],
    ['owner/repo', '', 'unknown', 'public', true, 'owner/repo', 'owner/repo', 1],
    ['owner/repo', 'owner/config', 'private', 'private', true, 'owner/repo', 'owner/repo', 1],
    ['$(exit 99)', '', 'public', 'public', false, '$(exit 99)', 'owner/caller', 1],
    ['', '', 'public', 'public', false, '', 'owner/caller', 1],
    [' ', '', 'public', 'public', false, ' ', 'owner/caller', 1],
    ['owner/repo', 'invalid', 'public', 'public', false, 'owner/repo', 'owner/caller', 1],
  ]) {
    policyFile(policyRepo, isPrivate);
    const result = shell(curl + script, {
      ...api, REPO: repo, REPOS: repos, TARGET: target, OTHER: other, JOB_DIR: dir, GITHUB_REPOSITORY: caller,
    });
    assert.equal(result.status, expected, `${repo} ${target} ${isPrivate}: ${result.stdout}${result.stderr}`);
  }
  assert.ok(run.indexOf('Check again that') < run.indexOf('uses: actions/upload-artifact'));
  // A runner need not have gh: run's own steps do without it.
  assert.doesNotMatch(run, /^\s*(?:[^#\n]*[|;&(]\s*)?gh\s/m);
});

test('admission and upload gates refuse unknown visibility with private-run guidance', (t) => {
  const admission = policy.split('- name: Check that the repositories are public\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].replace(/^ {10}/gm, '');
  const dir = mkdtempSync(join(homedir(), 'visibility-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'policy.json'), JSON.stringify({ repo: 'owner/repo' }));
  for (const [mock, script] of [[gh, admission], [curl, step(run, 'Check again that the repositories are public')]]) {
    assert.match(script, /\.private == false and \.visibility == "public"/);
    for (const [answer, apiExit, expected] of [
      ['public', 0, 0], ['private', 0, 1], ['unknown', 0, 1], ['', 0, 1], ['public', 1, 1],
    ]) {
      const result = shell(mock + script, {
        ...api, REPO: 'owner/repo', REPOS: 'owner/config owner/item', TARGET: answer, OTHER: answer,
        API_EXIT: String(apiExit), JOB_DIR: dir, GITHUB_REPOSITORY: 'owner/caller', GITHUB_OUTPUT: join(dir, 'output'),
      });
      assert.equal(result.status, expected, result.stdout + result.stderr);
      if (expected !== 0) assert.match(result.stdout, /private runs are refused.*docs\/private-repositories\.md/);
    }
  }
  assert.ok(policy.indexOf('Check that the repositories are public') < policy.indexOf('name: This workflow'));
});

test('admission marks only the calling repository, private, as a private target', (t) => {
  const admission = policy.split('- name: Check that the repositories are public\n')[1]
    .split('        run: |\n')[1].split('\n      #')[0].replace(/^ {10}/gm, '');
  const dir = mkdtempSync(join(homedir(), 'visibility-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  // Target, agent configuration and item, the target's and the others'
  // answers, the caller, the exit status and what the step outputs.
  for (const [repo, repos, target, other, caller, expected, output] of [
    ['owner/repo', 'owner/config', 'public', 'public', 'owner/caller', 0, ''],
    ['owner/repo', 'owner/config', 'private', 'public', 'owner/repo', 0, 'private=true\n'],
    ['owner/repo', '', 'private', 'public', 'owner/caller', 1, ''],
    ['owner/repo', 'owner/config', 'private', 'private', 'owner/repo', 1, 'private=true\n'],
    ['owner/repo', 'owner/repo', 'private', 'private', 'owner/repo', 1, 'private=true\n'],
    ['owner/repo', '', 'unknown', 'public', 'owner/repo', 1, ''],
  ]) {
    const file = join(dir, 'output');
    writeFileSync(file, '');
    const result = shell(gh + admission, {
      REPO: repo, REPOS: repos, TARGET: target, OTHER: other, GITHUB_REPOSITORY: caller, GITHUB_OUTPUT: file,
    });
    assert.equal(result.status, expected, `${target} ${caller}: ${result.stdout}${result.stderr}`);
    assert.equal(readFileSync(file, 'utf8'), output);
  }
  const request = policy.split('- name: Check the request against the caller\'s bounds\n')[1].split('\n      - ')[0];
  assert.match(request, /PRIVATE: \$\{\{ steps.visibility.outputs.private \}\}/);
  assert.match(request, /set -- "\$@" --private\n.*--output-repo "\$\{OUTPUT_REPO:-\$GITHUB_REPOSITORY\}"/);
});

// The wrapper's agent job and the example's caller-owned one are the same
// steps: the caller's repository, the actions of policy's own commit,
// then prepare, secure-host and run, in that order.
// agentic-job.yml's is agent.yml's, which takes the policy call's outputs
// as one input, as check.yml does, and secures its host with the public
// forwarder; the example keeps the second user of the internal action.
for (const [file, source, job, policyOutput, secureHost] of [
  ['agentic-job.yml', wrapper, agentCall, name => `fromJSON(inputs.policy).${name}`, './.agentic-job-source/secure-host'],
  ['example-compose.yml', compose, compose, name => `needs.policy.outputs.${name}`, './.agentic-job-source/secure-host/internal']]) {
  test(`${file} composes the pinned-source agent job and keeps trusted edges off agent outputs`, () => {
    const agent = job.split('\n  agent:\n')[1].split('\n  check:\n')[0];
    const out = name => `\${{ ${policyOutput(name)} }}`.replace(/[$()[\]{}.]/g, '\\$&');
    assert.match(source.split('\n  agent:\n')[1], /^    needs: (?:policy|\[policy, register\])$/m);
    assert.match(agent, /safe-outputs-artifact-id: \$\{\{ steps.run.outputs.safe-outputs-artifact-id \}\}/);
    assert.match(agent, /safe-outputs-artifact-digest: \$\{\{ steps.run.outputs.safe-outputs-artifact-digest \}\}/);
    for (const input of ['binary-artifact-id', 'policy-artifact-id']) {
      assert.ok(agent.includes(`${input}: \${{ ${policyOutput(input)} }}`));
    }
    assert.match(agent, new RegExp(`repository: ${out('source-repository')}\\n {10}ref: ${out('source-sha')}\\n {10}path: .agentic-job-source\\n`));
    assert.match(agent, new RegExp(`^ {10}ref: ${out('ref')}$`, 'm'));
    const uses = [...agent.matchAll(/^ {6}(?:- |  )uses: ([^\n]+)/gm)].map(([, use]) => use.split(' ')[0]);
    assert.deepEqual(uses.filter(use => !/^actions\/(?:checkout|download-artifact)@/.test(use)), [
      './.agentic-job-source/prepare', secureHost, './.agentic-job-source/run']);
    for (const use of uses) {
      assert.match(use, /^(\.\/\.agentic-job-source\/[-\w]+(?:\/internal)?|actions\/(?:checkout|download-artifact)@[0-9a-f]{40})$/);
    }
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
      '      safe-outputs-artifact-id: ${{ needs.agent.outputs.safe-outputs-artifact-id }}',
      '      safe-outputs-artifact-digest: ${{ needs.agent.outputs.safe-outputs-artifact-digest }}'].join('\n'));
    assert.equal(call('apply'), [
      '      policy: ${{ toJSON(needs.policy.outputs) }}',
      '      agent: ${{ toJSON(needs.agent) }}',
      '      check: ${{ toJSON(needs.check) }}'].join('\n'));
  });
}

// agent.yml runs the configuration's setup script itself, after
// secure-host, where the image would have run it as its second user:
// as the runner's user, in the agent's home, with none of the job's
// variables. `run` then starts the policy job's binary, not the one the
// image installed, with that home.
test('agent.yml runs the setup script, and run the agent, as the runner\'s user in the agent\'s home', (t) => {
  const directory = mkdtempSync(join(homedir(), 'agent-home-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const agent = agentCall.split('\n  agent:\n')[1];
  const setup = agent.split('- name: The setup script\n')[1].split('        run: |\n')[1].split(/\n {6}[^ ]/)[0]
    .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
  mkdirSync(join(directory, '.agentic-job'));
  mkdirSync(join(directory, 'tmp'));
  const home = join(directory, 'tmp/agent-home');
  const env = { RUNNER_TEMP: join(directory, 'tmp'), AGENT_HOME: home, AGENTIC_JOB_TEST_JOB: 'the job\'s' };
  const inDir = script => spawnSync('bash', ['-eo', 'pipefail', '-c', `cd "$1" && ${script.replace('.agentic-job-source/workflow/runner-setup.py', join(__dirname, 'runner-setup.py'))}`, 'bash', directory],
    { encoding: 'utf8', env: { ...process.env, ...env } });
  writeFileSync(join(directory, '.agentic-job/config.toml'), '[setup]\npackages = []\n');
  const admit = agent.split('- name: Admit the runner-user configuration\n')[1]
    .split('        run: ')[1].split('\n')[0];
  assert.ok(agent.indexOf('- name: Admit the runner-user configuration') < agent.indexOf('- uses: ./.agentic-job-source/secure-host'));
  assert.ok(agent.indexOf('- name: Admit the runner-user configuration') < agent.indexOf('- name: The setup script'));
  for (const [caller, policy, status] of [
    ['false', {}, 0], ['false', { private: false }, 0],
    ['true', {}, 1], ['null', {}, 1], ['false', { private: true }, 1],
  ]) {
    env.CALLER_PRIVATE = caller;
    writeFileSync(join(directory, '.agentic-job/policy.json'), JSON.stringify(policy));
    const admission = inDir(admit);
    assert.equal(admission.status, status, admission.stderr);
    assert.ok(!existsSync(home));
  }
  env.CALLER_PRIVATE = 'false';
  writeFileSync(join(directory, '.agentic-job/policy.json'), '{}');
  for (const config of [
    '[inference]\nregister = "api-key"', '[mcp.server]\nurl = "https://example.com"',
    '[session]\nlisten = true', '[sandbox.check]\nbefore-agent = true',
    '[setup.tools]\nrust = "stable"',
  ]) {
    writeFileSync(join(directory, '.agentic-job/config.toml'), config);
    assert.equal(inDir(admit).status, 1, config);
    assert.ok(!existsSync(home));
  }
  writeFileSync(join(directory, '.agentic-job/config.toml'), '[setup]\npackages = []\n');
  let result = inDir(setup);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!existsSync(home));
  writeFileSync(join(directory, '.agentic-job/config.toml'), '[setup]\nscript = "setup.sh"\n[sandbox.env]\nTOOLCHAIN_OPTION = "configured"\n');
  writeFileSync(join(directory, 'setup.sh'), '#!/bin/sh\nset -e\npwd > "$HOME/pwd.txt"\nenv > "$HOME/env.txt"\n');
  result = inDir(setup);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(join(home, 'pwd.txt'), 'utf8').trim(), home);
  const seen = readFileSync(join(home, 'env.txt'), 'utf8');
  assert.match(seen, new RegExp(`^HOME=${home}$`, 'm'));
  assert.match(seen, /^TOOLCHAIN_OPTION=configured$/m);
  assert.doesNotMatch(seen, /AGENTIC_JOB_TEST_JOB|RUNNER_TEMP/);
  writeFileSync(join(directory, 'setup.sh'), '#!/bin/sh\nexit 3\n');
  assert.equal(inDir(setup).status, 3);

  // The run step: the job directory's binary with --runner-home, or the
  // installed one, for a caller with a sandbox user.
  const jobDir = join(directory, 'job');
  const bin = join(directory, 'bin');
  mkdirSync(jobDir);
  mkdirSync(bin);
  const recorder = '#!/bin/sh\nprintf "%s\\n" "$0" "$@" > "$RECORD"\n';
  writeFileSync(join(jobDir, 'agentic-job'), recorder, { mode: 0o644 });
  writeFileSync(join(bin, 'agentic-job'), recorder, { mode: 0o755 });
  for (const [runnerHome, binary] of [[home, join(jobDir, 'agentic-job')], ['', join(bin, 'agentic-job')]]) {
    const record = join(directory, 'record');
    result = shell(step(run, 'Run the agent'), {
      JOB_DIR: jobDir, RUNNER_HOME: runnerHome, RECORD: record, REVIEW_HEAD: '', WATCH_ITEM: '',
      GITHUB_OUTPUT: join(directory, 'output'), GITHUB_STEP_SUMMARY: join(directory, 'summary'),
      PATH: `${bin}:${process.env.PATH}`,
    });
    assert.equal(result.status, 0, result.stderr);
    const args = readFileSync(record, 'utf8').trim().split('\n');
    assert.equal(args[0], binary);
    assert.equal(args[1], 'run');
    assert.deepEqual(args.slice(-2), runnerHome ? ['--runner-home', home] : ['--out', join(jobDir, 'out')]);
  }
});

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

// Followed through the composite actions in place: the agent job installs
// the policy job's binary, writes no configuration of its own, checks the
// inference proxy with that binary before setup, and runs the agent only
// after the host is secured. secure-host knows nothing of inference or
// sessions: the agent job checks the proxy, and run reads the endpoint.
test('the agent job installs the trusted binary and checks the proxy before setup', () => {
  const secure = readFileSync(join(__dirname, '../secure-host/internal/action.yml'), 'utf8');
  assert.doesNotMatch(secure, /inference|session/i);
  assert.match(policy, /"\$JOB_DIR\/bin\/agentic-job" config/);
  assert.ok(policy.split('agentic-job-policy\n')[1].split('\n  activate:')[0].includes('.agentic-job/config.toml'));
  assert.doesNotMatch(policy, /CONFIG_BINARY/);
  assert.ok(prepare.includes('sudo install -m 0755 "$JOB_DIR/agentic-job" /usr/local/bin/agentic-job'));
  assert.ok(prepare.indexOf('artifact-ids:') < prepare.indexOf('- name: Install the binary'));
  const forwarder = readFileSync(join(__dirname, '../secure-host/action.yml'), 'utf8');
  const review = readFileSync(join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  for (const [file, source] of [['agent.yml', agentCall], ['example-compose.yml', compose], ['review.yml', review]]) {
    const agent = source.split('\n  agent:\n')[1].split('\n  check:\n')[0];
    assert.equal([...agent.matchAll(/agentic-job secure-host inference/g)].length, 1, file);
    assert.ok(agent.includes('- name: Check inference proxy reachability\n' +
      '        run: agentic-job secure-host inference .agentic-job/config.toml\n'), file);
    // agent.yml's host is the new action's, which takes the policy job's
    // configuration but for the setup script, and that is all it writes.
    const own = file === 'agent.yml'
      ? '        run: agentic-job config --host --no-script --from .agentic-job/config.toml > "$RUNNER_TEMP/agentic-job-host.toml"\n'
      : '';
    assert.doesNotMatch(agent.replace(own, ''), / config /, file);
    assert.ok(agent.includes(file === 'agent.yml' ? 'config: ${{ runner.temp }}/agentic-job-host.toml' : 'config: .agentic-job/config.toml'), file);
    const expanded = agent.replace('uses: ./.agentic-job-source/prepare', prepare)
      .replace('uses: ./.agentic-job-source/secure-host/internal', secure)
      .replace('uses: ./.agentic-job-source/secure-host', forwarder)
      .replace('uses: ./.agentic-job-source/run', run);
    const names = file === 'agent.yml'
      ? ['Install the binary', 'Write what the run is called', 'Check inference proxy reachability', "The host's configuration",
        "Refuse the old action's inputs", 'The setup script', "The session's endpoint", 'Prove the host is secured', 'Run the agent']
      : ['Install the binary', 'Write what the run is called', 'Check inference proxy reachability',
        'Write the configuration', 'Secure the host', "The session's endpoint", 'Prove the host is secured', 'Run the agent'];
    let position = 0;
    for (const name of names) {
      position = expanded.indexOf(`- name: ${name}\n`, position);
      assert.ok(position >= 0, `${file}: ${name}`);
    }
  }
  assert.ok(agentCall.includes('      session-endpoint: ${{ steps.run.outputs.session-endpoint }}\n'));
  assert.ok(wrapper.includes('        value: ${{ jobs.agent.outputs.session-endpoint }}\n'));
  assert.ok(run.includes('    value: ${{ steps.session.outputs.endpoint }}\n'));
  assert.ok(policy.includes('@agentclientprotocol/claude-agent-acp@0.88.0'));
});

// echo stands in for the binary to record its arguments.
test('the policy job writes the configuration with its own binary, and not for proposals', () => {
  const directory = mkdtempSync(join(homedir(), 'policy-config-'));
  try {
    mkdirSync(join(directory, 'bin'));
    writeFileSync(join(directory, 'bin/agentic-job'), '#!/bin/sh\necho "$@"\n', { mode: 0o755 });
    const env = Object.fromEntries(['CONFIG', 'MODEL', 'CONFIG_REPO', 'CONFIG_REF', 'CONFIG_PATH', 'SKILLS', 'URL',
      'REGISTER', 'AUDIENCE', 'TOKEN_FILE', 'PROVIDER', 'TIMEOUT', 'MAX_REQUESTS', 'MAX_TASKS', 'BUDGET', 'PACKAGES',
      'NPM', 'AGENTS', 'SETUP', 'SESSION', 'IDLE_MINUTES'].map(name => [name, '']));
    // A workflow's step, two levels deeper than an action's.
    const body = policy.split('- name: Write the configuration\n')[1].split('        run: |\n')[1];
    const script = body.match(/^(?: {10}[^\n]*\n)+/)[0].replace(/^ {10}/gm, '');
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', script], {
      encoding: 'utf8', env: { ...env, JOB_DIR: directory, PATH: '/usr/bin:/bin', AGENT: 'fake', REPO: 'example/repo' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(readFileSync(join(directory, 'config.toml'), 'utf8').startsWith('config --repo example/repo --string agent.name=fake '));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const section = policy.split('- name: Write the configuration\n')[1].split('- name:')[0];
  assert.ok(section.includes("if: ${{ inputs.proposals-artifact == '' && steps.event.outputs.admitted != 'false' }}"));
});

test('the end-to-end callers run the scripted agent, which needs no proxy', () => {
  const ci = readFileSync(join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  for (const name of ['e2e-full', 'e2e-limit', 'e2e-event', 'e2e-analysis', 'e2e-analysis-refused', 'e2e-review']) {
    // Job bodies are indented at least four spaces.
    const job = ci.split(`\n  ${name}:\n`)[1].split(/\n  [^ ]/)[0];
    assert.ok(job.includes('agent: fake'), name);
    assert.ok(!job.includes('inference-url:'), name);
  }
  // Every agent job of theirs secures its host with this revision's
  // image, the static job's archive, by the ID build.yml hands on.
  for (const [, name, job] of ci.matchAll(/^  ([-\w]+):\n([\s\S]*?)(?=^  [-\w]+:\n|$(?![\s\S]))/gm)) {
    if (!/^    uses: \.\/\.github\/workflows\/agentic-job\.yml/m.test(job) || job.includes('proposals-artifact:')) continue;
    assert.match(job, /^    needs: \[changes, static(?:, [-\w]+)?\]$/m, name);
    assert.ok(job.includes('      secure-host-image-artifact-id: ${{ needs.static.outputs.secure-host-image-artifact-id }}\n'), name);
  }
  const build = readFileSync(join(__dirname, '../.github/workflows/build.yml'), 'utf8');
  assert.ok(build.includes('        value: ${{ jobs.build.outputs.secure-host-image-artifact-id }}\n'));
  assert.ok(build.includes('      secure-host-image-artifact-id: ${{ steps.image.outputs.artifact-id }}\n'));
  assert.match(build, /- id: image\n {8}uses: actions\/upload-artifact@[0-9a-f]{40} # [^\n]*\n {8}with:\n {10}name: secure-host-image\n/);
  // agent.yml downloads it by that ID alone, and hands the archive to
  // secure-host only then.
  assert.ok(agentCall.includes("      - if: ${{ inputs.secure-host-image-artifact-id != '' }}\n" +
    '        uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n' +
    '        with:\n          artifact-ids: ${{ inputs.secure-host-image-artifact-id }}\n'));
  assert.ok(agentCall.includes("image-archive: ${{ inputs.secure-host-image-artifact-id != '' && format('{0}/secure-host-image/secure-host.tar', runner.temp) || '' }}\n"));
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
// the job that makes it is a read. The identity token is the register
// job's alone, which runs nothing but the policy job's binary and hands
// on the run token, which reaches agent.yml as a secret and `run` alone.
test('the agent job token reads and write credentials stay in deterministic jobs', () => {
  const jobs = wrapper.split('\njobs:\n')[1];
  // Up to the blank line before the next job's comment.
  const job = name => jobs.split(`\n  ${name}:\n`)[1].split('\n\n')[0];
  const granted = (text, end) => Object.fromEntries(text.split('    permissions:\n')[1].split(end)[0].split('\n')
    // Every line is a permission, a comment, or a permission with one.
    .map(line => line.replace(/#.*/, '').trim()).filter(Boolean).map(line => line.match(/^([-\w]+): (\w+)$/).slice(1)));
  const reads = { contents: 'read', issues: 'read', 'pull-requests': 'read', actions: 'read' };
  const agent = agentCall.split('\n  agent:\n')[1];
  assert.deepEqual(granted(agent, '    outputs:\n'), reads);
  assert.deepEqual(granted(job('agent'), '    uses:'), reads);
  assert.doesNotMatch(agentCall + job('agent'), /^ *id-token:/m);
  // The agent is the runner's user, as every step after secure-host is:
  // the job holds no secret but the run token, no git credential, and
  // neither the second user's action nor its way in.
  assert.deepEqual([...agentCall.matchAll(/secrets\.([\w]+)/g)].map(([, name]) => name), ['INFERENCE_RUN_TOKEN']);
  assert.deepEqual([...agentCall.split('    secrets:\n')[1].split('    outputs:\n')[0].matchAll(/^ {6}([\w]+):$/gm)]
    .map(([, name]) => name), ['INFERENCE_RUN_TOKEN']);
  assert.deepEqual([...job('agent').split('    secrets:\n')[1].split('    with:\n')[0].matchAll(/^ {6}([\w]+):/gm)]
    .map(([, name]) => name), ['INFERENCE_RUN_TOKEN']);
  const checkouts = agent.split('\n      - ').filter(step => step.startsWith('uses: actions/checkout@'));
  assert.equal(checkouts.length, 2);
  for (const step of checkouts) assert.match(step, /^ {10}persist-credentials: false$/m);
  assert.doesNotMatch(agentCall, /secure-host\/internal|sandbox exec/);
  assert.match(agent, /^ {10}runner-home: \$\{\{ runner\.temp \}\}\/agent-home$/m);
  const register = job('register');
  assert.deepEqual(granted(register, '    outputs:\n'), { 'id-token': 'write' });
  assert.match(register, /^    runs-on: \$\{\{ fromJSON\(inputs.agent-runner\) \}\}$/m);
  assert.deepEqual([...register.matchAll(/^ {6}- uses: (\S+)/gm)].map(([, use]) => use),
    ['actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333']);
  assert.doesNotMatch(register, /secrets\.|checkout|github\.token/);
  assert.ok(register.endsWith('\n          "$JOB_DIR/agentic-job" register --config "$JOB_DIR/config.toml" --output "$GITHUB_OUTPUT"'));
  assert.match(register, /^ {6}run-token: \$\{\{ steps.register.outputs.run-token \}\}$/m);
  // Out of the register job only as the agent call's secret, and in
  // agent.yml only to run's input.
  assert.deepEqual([...wrapper.matchAll(/.*needs\.register\.outputs.*/g)].map(([text]) => text),
    ['      INFERENCE_RUN_TOKEN: ${{ needs.register.outputs.run-token }}']);
  assert.match(job('agent'), /^    secrets:\n(?: {6}.*\n)*? {6}INFERENCE_RUN_TOKEN: /m);
  assert.deepEqual([...agentCall.matchAll(/.*secrets\.INFERENCE_RUN_TOKEN.*/g)].map(([text]) => text),
    ['          inference-run-token: ${{ secrets.INFERENCE_RUN_TOKEN }}']);
  const runStep = run.split('- name: Run the agent\n')[1].split('      run: |\n')[0];
  assert.match(runStep, /^        AGENTIC_JOB_INFERENCE_RUN_TOKEN: \$\{\{ inputs.inference-run-token \}\}$/m);
  assert.equal([...run.matchAll(/inputs\.inference-run-token/g)].length, 1);
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
  for (const [file, source] of [['agentic-job.yml', wrapper], ['agent.yml', agentCall], ['example-compose.yml', compose], ['policy.yml', policy],
    ['check.yml', readFileSync(join(__dirname, '../.github/workflows/check.yml'), 'utf8')],
    ['apply.yml', readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8')]]) {
    const named = [...source.split('\njobs:\n')[1].matchAll(/^  ([-\w]+):\n([\s\S]*?)(?=^  [-\w]+:\n|$(?![\s\S]))/gm)];
    assert.ok(named.length > 0, file);
    for (const [, name, job] of named) {
      const holdsWrite = name === 'apply' || (file === 'agentic-job.yml' && name === 'policy') ||
        (file === 'policy.yml' && ['notify', 'apply-token'].includes(name)) || (file === 'apply.yml' && name === 'conclude');
      assert.equal(job.includes('secrets.SAFE_OUTPUTS_PAT'), holdsWrite, `${file} ${name}`);
    }
  }
  const owned = compose.split('\n  agent:\n')[1].split('\n  check:\n')[0];
  assert.match(owned, /^          github-token: \$\{\{ github.token \}\}$/m);
  const ownedPermissions = owned.split('    permissions:\n')[1].split('    outputs:\n')[0];
  assert.deepEqual(ownedPermissions.split('\n').map(line => line.replace(/#.*/, '').trim()).filter(Boolean).sort(),
    ['actions: read', 'contents: read', 'id-token: write', 'issues: read', 'pull-requests: read']);
  // GitHub refuses a whole called workflow whose job asks for more than
  // the call was granted, a skipped job's included: the identity token
  // for agentic-job.yml's register job.
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
  const own = ['agent-runner', 'github-reads', 'secure-host-image-artifact-id'];
  assert.deepEqual(names(wrapper).filter(name => !own.includes(name)), names(policy));
  const call = wrapper.split('\n  policy:\n')[1].split('    with:\n')[1].split('\n\n')[0];
  assert.equal(call, names(policy).map(name => `      ${name}: \${{ inputs.${name} }}`).join('\n'));
});

// A network to join is the caller's own step (docs/workflow.md): no
// workflow or action of agentic-job joins one or takes its credentials.
// This repository's own deployment joins its tailnet in the network step
// it keeps as a caller (.github/agentic-job/network), outside them.
test('no workflow or action of this repository joins a network itself', () => {
  const root = join(__dirname, '..');
  const files = [...readdirSync(join(root, '.github/workflows')).map(file => `.github/workflows/${file}`),
    'prepare/action.yml', 'run/action.yml', 'secure-host/action.yml', 'secure-host/internal/action.yml'];
  for (const file of files) {
    const text = readFileSync(join(root, file), 'utf8');
    assert.doesNotMatch(text, /tailscale|join(?:s|ing)? (?:a|the) tailnet/i, file);
    // Of that repository's actions only secure-host, which the public
    // path forwards to and which joins no network.
    assert.doesNotMatch(text, /cgwalters-forge\/actions(?!\/secure-host(?![-\w/]))/, file);
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
  assert.equal(uses[at + 1], './.agentic-job-source/secure-host/internal');
  // Off unless the caller has one.
  assert.match(jobs.agent, /if: \$\{\{ hashFiles\('\.github\/agentic-job\/network\/action\.yml'\) != '' \}\}\n {8}uses: \.\/\.github\/agentic-job\/network /);
  // This repository's own, a composite action whose actions are pinned.
  const own = readFileSync(join(root, '.github/agentic-job/network/action.yml'), 'utf8');
  assert.match(own, /^  using: composite$/m);
  const pinned = [...own.matchAll(/^ +(?:- )?uses: (\S+)/gm)].map(([, action]) => action);
  assert.ok(pinned.length > 0);
  for (const action of pinned) assert.match(action, /^[-\w]+\/[-\w./]+@[0-9a-f]{40}$/, action);
});

// An MCP server's credential and the provider's key would be readable by
// an agent that is the runner's user, as agent.yml's is: agentic-job.yml
// still takes both, so that callers that pass them parse, and passes on
// neither (`run --runner-home` refuses the configurations that need them).
// The run action, as a caller-owned agent job with a second user uses
// it, gives the MCP credential to the step that runs `agentic-job run`
// alone.
test('agentic-job.yml passes no MCP credential or inference key to its agent job', () => {
  for (const name of ['MCP_TOKEN', 'INFERENCE_API_KEY']) {
    assert.doesNotMatch(wrapper + agentCall, new RegExp(`secrets\\.${name}`), name);
    assert.match(wrapper, new RegExp(`^      ${name}:\\n(?: +#[^\\n]*\\n)*? +(?:description: [^\\n]*\\n +)?required: false$`, 'm'), name);
  }
  assert.doesNotMatch(agentCall, /check-key|mcp-token|inference-api-key/);
  const action = readFileSync(join(__dirname, '../run/action.yml'), 'utf8');
  const uses = [...action.matchAll(/inputs\.mcp-token/g)];
  assert.equal(uses.length, 1);
  const steps = action.split('\n    - ');
  const holder = steps.filter(step => step.includes('inputs.mcp-token'));
  assert.equal(holder.length, 1);
  assert.match(holder[0], /AGENTIC_JOB_MCP_TOKEN: \$\{\{ inputs\.mcp-token \}\}/);
  assert.match(holder[0], /"\$binary" run --policy/);
});

// The provider's key, with `api-key`, reaches two steps of review.yml's
// agent job, which has a second user, and nothing else: its check before
// secure-host, which fails a bad key before the minutes of setup, and
// `run`, outside the sandbox. The check follows the caller's network
// step, which never gets it, and the policy call takes the mode from
// repository variables.
for (const file of ['review.yml']) {
  test(`${file} checks the inference API key before secure-host and gives it to run alone`, () => {
    const source = readFileSync(join(__dirname, '../.github/workflows', file), 'utf8');
    const agent = source.split('\n  agent:\n')[1].split('\n  check:\n')[0];
    const uses = [...source.matchAll(/secrets\.INFERENCE_API_KEY/g)].length;
    assert.equal(uses, 2, file);
    const check = "      - name: Check the inference API key\n        env:\n          AGENTIC_JOB_INFERENCE_KEY: ${{ secrets.INFERENCE_API_KEY }}\n" +
      '        run: agentic-job check-key --config .agentic-job/config.toml\n';
    assert.ok(agent.includes(check), file);
    assert.match(agent, /\n {10}inference-api-key: \$\{\{ secrets\.INFERENCE_API_KEY \}\}\n/);
    const at = text => { const index = agent.indexOf(text); assert.ok(index >= 0, `${file}: ${text}`); return index; };
    const order = ['uses: ./.agentic-job-source/prepare',
      ...(file === 'review.yml' ? ['uses: ./.github/agentic-job/network'] : []),
      '- name: Check the inference API key', 'uses: ./.agentic-job-source/secure-host', 'uses: ./.agentic-job-source/run'].map(at);
    assert.deepEqual(order, [...order].sort((a, b) => a - b), file);
    assert.match(source, /^      INFERENCE_API_KEY:\n(?: +#[^\n]*\n)*? +(?:description: [^\n]*\n +)?required: false$/m);
    if (file === 'review.yml') {
      assert.ok(source.includes("      inference-register: ${{ vars.INFERENCE_REGISTER || 'github-oidc' }}\n"));
      assert.ok(source.includes('      inference-provider: ${{ vars.INFERENCE_PROVIDER }}\n'));
    }
  });
}
