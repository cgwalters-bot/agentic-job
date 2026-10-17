// Test the actual mode gate and routing without forge credentials.
const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const { homedir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const workflow = readFileSync(join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');
const policy = readFileSync(join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
const applier = readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
const checker = readFileSync(join(__dirname, '../.github/workflows/check.yml'), 'utf8');
const gate = policy.split('- name: Check the proposals mode\n')[1]
  .split('        run: |\n')[1].split('      #')[0]
  .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');

function checkMode(change) {
  return spawnSync('bash', ['-e', '-o', 'pipefail', '-c', gate], {
    encoding: 'utf8', env: { ...process.env, PROPOSALS: '', EVENT: 'false',
      REVIEW: 'false', PARTIAL: 'false', TASK: '', ...change },
  });
}

test('mode gate accepts derived tasks and refuses incompatible proposals', () => {
  for (const [name, change, expected] of [
    ['proposals', { PROPOSALS: 'proposals' }, 0],
    ['proposals with event', { PROPOSALS: 'proposals', EVENT: 'true' }, 1],
    ['proposals with review', { PROPOSALS: 'proposals', REVIEW: 'true' }, 1],
    ['proposals with partial apply', { PROPOSALS: 'proposals', PARTIAL: 'true' }, 1],
    ['direct task', { TASK: 'run' }, 0],
    ['missing direct task', {}, 1],
    ['partial direct task', { TASK: 'run', PARTIAL: 'true' }, 0],
    ['partial without task', { PARTIAL: 'true' }, 1],
    ['event-derived task', { EVENT: 'true' }, 0],
    ['review-derived task', { REVIEW: 'true' }, 0],
    ['event review', { EVENT: 'true', REVIEW: 'true' }, 0],
    ['artifact name is data', { PROPOSALS: '$(exit 99)' }, 0],
  ]) {
    const result = checkMode(change);
    assert.equal(result.status, expected, `${name}: ${result.stdout}${result.stderr}`);
  }
});

test('every checked-in caller passes the mode gate', () => {
  const directory = join(__dirname, '../.github/workflows');
  const inputs = { 'proposals-artifact': 'PROPOSALS', event: 'EVENT', review: 'REVIEW',
    'apply-partial': 'PARTIAL', task: 'TASK' };
  let callers = 0;
  for (const file of readdirSync(directory).filter(file => file.endsWith('.yml'))) {
    const source = readFileSync(join(directory, file), 'utf8');
    // Local reusable-workflow calls are job-level, with inputs indented six spaces.
    for (const block of source.split(/^  [\w-]+:\s*$/m).slice(1)) {
      if (!/^    uses: \.\/\.github\/workflows\/agentic-job\.yml( +#.*)?$/m.test(block)) continue;
      const change = {};
      for (const [input, variable] of Object.entries(inputs)) {
        const match = block.match(new RegExp(`^      ${input}: *(.*)$`, 'm'));
        if (!match) continue;
        const value = match[1].trim();
        // Folded task prose and dispatch expressions represent supplied tasks;
        // the mode check does not interpret their contents.
        change[variable] = value === "''" || value === '""' ? '' : value;
      }
      const result = checkMode(change);
      assert.equal(result.status, 0, `${file}: ${result.stdout}${result.stderr}`);
      callers++;
    }
  }
  assert.ok(callers >= 8, `expected the example, review and CI callers, found ${callers}`);
});

test('proposals route retains check and token separation', () => {
  const check = workflow.split('\n  check:\n')[1].split('\n  apply:\n')[0];
  assert.match(check, /needs.policy.result == 'success'/);
  assert.match(check, /permissions:\n      contents: read/);
  assert.match(check, /uses: \.\/\.github\/workflows\/check.yml/);
  assert.match(check, /safe-outputs-artifact-id: \$\{\{ needs.agent.outputs.safe-outputs-artifact-id \}\}/);
  assert.match(check, /safe-outputs-artifact-digest: \$\{\{ needs.agent.outputs.safe-outputs-artifact-digest \}\}/);
  assert.match(checker, /name: \$\{\{ fromJSON\(inputs.policy\).proposals-artifact \}\}/);
  assert.match(checker, /artifact-ids: \$\{\{ inputs.safe-outputs-artifact-id \}\}/);
  assert.match(checker, /agentic-job" check --policy/);
  assert.doesNotMatch(check, /secrets\./);
  assert.doesNotMatch(checker, /secrets\./);
  const apply = applier.split('\n  apply:\n')[1];
  assert.match(apply, /fromJSON\(inputs.check\).result == 'success' && \(fromJSON\(inputs.policy\).proposals-artifact != ''/);
  assert.match(apply, /fromJSON\(inputs.policy\).proposals-artifact == '' && format\('\{0\}', fromJSON\(inputs.agent\).outputs.exit\) != '0'/);
  assert.match(apply.split('- name: Write applied.json')[1],
    /EXIT: \$\{\{ fromJSON\(inputs.policy\).proposals-artifact != '' && '0' \|\| fromJSON\(inputs.agent\).outputs.exit \}\}/);
  for (const [source, job] of [[policy, 'activate'], [workflow, 'agent']]) {
    assert.match(source.split(`\n  ${job}:\n`)[1].split('    steps:')[0],
      /inputs.proposals-artifact == ''/);
  }
});

test('checker requires explicit trusted IDs and one proposal selector', () => {
  const section = checker.split('- name: Require explicit artifact contracts\n')[1].split('\n      #')[0];
  const script = section.split('        run: |\n')[1].split('\n')
    .filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
  for (const [name, change, expected] of [
    ['agent upload', {}, 0],
    ['legacy proposals', { PROPOSALS: '', DIGEST: '', NAME: 'board-proposals' }, 0],
    ['missing binary', { BINARY: '' }, 1],
    ['missing policy', { POLICY: '' }, 1],
    ['missing proposals', { PROPOSALS: '' }, 1],
    ['missing digest', { DIGEST: '' }, 1],
    ['prefixed digest', { DIGEST: `sha256:${'c'.repeat(64)}` }, 1],
    ['short digest', { DIGEST: 'c'.repeat(63) }, 1],
    ['digest is not shell', { DIGEST: '$(exit 0)' }, 1],
    ['both selectors', { DIGEST: '', NAME: 'board-proposals' }, 1],
    ['legacy name with a digest', { PROPOSALS: '', NAME: 'board-proposals' }, 1],
    ['multiple trusted IDs', { POLICY: '2,4' }, 1],
    ['proposal ID is not shell', { PROPOSALS: '$(exit 99)' }, 1],
    ['legacy name is data', { PROPOSALS: '', DIGEST: '', NAME: '$(exit 99)' }, 0],
  ]) {
    const result = spawnSync('bash', ['-eo', 'pipefail', '-c', script], {
      encoding: 'utf8', env: { ...process.env, BINARY: '1', POLICY: '2', PROPOSALS: '3', DIGEST: 'c'.repeat(64), NAME: '', ...change },
    });
    assert.equal(result.status, expected, `${name}: ${result.stdout}${result.stderr}`);
  }
});

// The agent job hands back by upload ID and digest; check holds the
// upload to that digest before it downloads or validates any of it.
test('checker refuses proposals whose upload digest is missing or another', () => {
  const job = checker.split('\n  check:\n')[1];
  const verify = "- name: The proposals are the agent job's upload\n";
  const download = 'artifact-ids: ${{ inputs.safe-outputs-artifact-id }}';
  assert.ok(job.indexOf('- name: Require explicit artifact contracts\n') < job.indexOf(verify));
  assert.ok(job.indexOf(verify) < job.indexOf(download));
  assert.ok(job.indexOf(download) < job.indexOf('- name: Ingest the outputs'));
  assert.ok(job.includes(`${download}\n          path: .agentic-job/safe-outputs\n          digest-mismatch: error\n`));
  assert.match(job.split('    steps:')[0], /permissions:\n      contents: read\n      actions: read\n/);
  const section = job.split(verify)[1].split('\n      - ')[0];
  assert.match(section, /if: \$\{\{ fromJSON\(inputs.policy\).proposals-artifact == '' \}\}/);
  assert.match(section, /DIGEST: \$\{\{ inputs.safe-outputs-artifact-digest \}\}/);
  const script = section.split('        run: |\n')[1].split('\n')
    .filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
  const digest = 'c'.repeat(64);
  const artifact = (hash, run = 7) => JSON.stringify({ id: 3, name: 'safe-outputs', digest: hash, workflow_run: { id: run } });
  // [what the read API says of artifact 3, the digest the agent job gave, status]
  for (const [name, answer, given, expected] of [
    ['matching', artifact(`sha256:${digest}`), digest, 0],
    ['mismatched digest', artifact(`sha256:${'d'.repeat(64)}`), digest, 1],
    ['missing digest', artifact(`sha256:${digest}`), '', 1],
    ['no digest on the server', artifact(null), digest, 1],
    ['unprefixed server digest', artifact(digest), digest, 1],
    ['another run', artifact(`sha256:${digest}`, 8), digest, 1],
    ['not found or not readable', '', digest, 1],
  ]) {
    const result = spawnSync('bash', ['-eo', 'pipefail', '-c',
      'gh() { [ "$*" = "api repos/o/r/actions/artifacts/3" ] || return 9; [ -n "$ANSWER" ] && printf "%s" "$ANSWER"; }\n' + script], {
      encoding: 'utf8', env: { ...process.env, PROPOSALS: '3', DIGEST: given, GITHUB_REPOSITORY: 'o/r', GITHUB_RUN_ID: '7', ANSWER: answer },
    });
    assert.equal(result.status, expected, `${name}: ${result.stdout}${result.stderr}`);
  }
});

test('wrapper passes trusted checker inputs directly and exports all checker outputs', () => {
  const check = workflow.split('\n  check:\n')[1].split('\n  apply:\n')[0];
  // The policy call's outputs, as they are: none of the agent's.
  assert.ok(check.includes('policy: ${{ toJSON(needs.policy.outputs) }}'));
  for (const input of ['binary-artifact-id', 'policy-artifact-id', 'comment-target']) {
    assert.ok(checker.includes(`\${{ fromJSON(inputs.policy).${input} }}`), input);
  }
  assert.ok(checker.includes('value: ${{ jobs.detect.outputs.artifact-id }}'));
  for (const output of ['refusal', 'has-patch']) {
    assert.ok(checker.includes(`value: \${{ jobs.check.outputs.${output} }}`));
  }
  assert.match(checker, /permissions:\n  contents: read/);
  assert.match(checker, /repository: \$\{\{ job.workflow_repository \}\}/);
  assert.match(checker, /ref: \$\{\{ job.workflow_sha \}\}/);
  assert.doesNotMatch(check, /secrets:|needs.agent.outputs.(binary|policy|comment)/);
  // Only the proposals' upload ID and digest are not the policy call's.
  const inputs = checker.split('    inputs:\n')[1].split('    outputs:\n')[0];
  assert.deepEqual([...inputs.matchAll(/^ {6}([-\w]+):$/gm)].map(([, name]) => name),
    ['policy', 'safe-outputs-artifact-id', 'safe-outputs-artifact-digest']);
});

test('documented proposals caller matches the CI trial and shipped bounds', () => {
  const docs = readFileSync(join(__dirname, '../docs/workflow.md'), 'utf8');
  const snippet = docs.split('## Proposals from a non-agent job\n')[1]
    .split('```yaml\n')[1].split('```')[0];
  const ci = readFileSync(join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  const producer = ci.split('\n  proposals:\n')[1].split('\n  e2e-proposals:\n')[0];
  const caller = ci.split('\n  e2e-proposals:\n')[1].split('\n  e2e-full:\n')[0];
  // Compare the executable producer verbatim but for action versions: a
  // Dependabot bump changes ci.yml, not the documentation it is shown in.
  // The documented steps must still pin a full commit, as callers copy them.
  const anyRef = steps => steps.replace(/^( *(?:- )?uses: [^@\s]+)@\S+(?: +#.*)?$/gm, '$1@REF');
  const documented = snippet.split('    steps:\n')[1].split('  apply:\n')[0];
  for (const [, ref] of documented.matchAll(/uses: \S+?@(.*)$/gm)) assert.match(ref, /^[0-9a-f]{40} # v\S+$/);
  assert.equal(anyRef(documented), anyRef(producer.split('    steps:\n')[1].trimEnd() + '\n'));
  assert.notEqual(anyRef('- uses: actions/upload-artifact@x # v1'), anyRef('- uses: actions/download-artifact@x # v1'));
  for (const block of [snippet.split('  apply:\n')[1], caller]) {
    assert.match(block, /contents: read\n      issues: write[^\n]*\n      pull-requests: read[^\n]*\n      actions: read[^\n]*\n      id-token: write/);
    assert.match(block, /allow: \.github\/agentic-job\/allow.toml/);
    assert.match(block, /outputs: add_comment,noop/);
    assert.match(block, /max-outputs: '2'/);
    assert.match(block, /proposals-artifact: board-proposals/);
  }
  const bounds = readFileSync(join(__dirname, '../.github/agentic-job/allow.toml'), 'utf8');
  for (const type of ['add_comment', 'noop']) assert.match(bounds, new RegExp(`^${type} =`, 'm'));
  assert.ok(Number(bounds.match(/^max_outputs = (\d+)$/m)[1]) >= 2);
  assert.match(ci.split('\n  required-checks:\n')[1], /needs: \[.*proposals, e2e-proposals,/);
});

// Mirror ActionCommand.TryParseV2/TryParse command recognition: modern syntax
// follows leading whitespace, but legacy syntax can appear anywhere in a line.
function runnerCommand(line) {
  const registered = new Set(['error', 'warning', 'set-output', 'add-mask', 'stop-commands']);
  const modern = line.trimStart().match(/^::([^ :]+)(?: [^]*?)?::/);
  if (modern && registered.has(modern[1].toLowerCase())) return modern[1].toLowerCase();
  const start = line.indexOf('##[');
  if (start < 0) return null;
  const end = line.indexOf(']', start);
  if (end < 0) return null;
  const name = line.slice(start + 3, end).split(' ')[0].toLowerCase();
  return registered.has(name) ? name : null;
}

test('policy errors preserve the exit status and escape annotation data', () => {
  const wrapper = join(__dirname, 'policy-command.cjs');
  const hostile = 'bad%\r\n  ::warning::data\n' +
    ['warning', 'set-output name=hostile', 'add-mask', 'stop-commands', 'WaRnInG']
      .map(command => `embedded ##[${command}]hostile`).join('\r\n');
  // Ensure the test parser recognizes the attacks even behind the old prefix.
  for (const line of hostile.split(/[\r\n]/).filter(Boolean).slice(1)) {
    assert.ok(runnerCommand(line));
    if (line.includes('##[')) assert.ok(runnerCommand(`policy: ${line}`));
  }
  for (const status of [0, 1, 2]) {
    const result = spawnSync(process.execPath, [wrapper, process.execPath, '-e',
      `process.stdout.write('policy'); process.stderr.write(${JSON.stringify(hostile)}); process.exitCode=${status}`],
    { encoding: 'utf8' });
    assert.equal(result.status, status);
    assert.equal(result.stdout, 'policy');
    assert.equal(result.stderr.split('\n').some(line => line.startsWith('::error::') &&
      line.includes('bad%25%0D%0A  ::warning::data')), status !== 0);
    assert.deepEqual(result.stderr.split(/[\r\n]/).map(runnerCommand).filter(Boolean),
      status === 0 ? [] : ['error']);
    assert.doesNotMatch(result.stderr, /##\[/);
    assert.match(result.stderr, /policy: embedded # #\[set-output name=hostile\]hostile/);
  }
  const step = policy.split('- name: Check the request against')[1].split('- id: binary')[0];
  assert.match(step, /node "\$SOURCE_DIR\/workflow\/policy-command.cjs"/);
});

const head = 'a'.repeat(40);
const push = { PUSH_ITEM: '42', PUSH_BRANCH: 'agent-run-1', PUSH_HEAD: head, REPLACEMENT_BASE: 'b'.repeat(40), OUTPUT_REPO: '', GITHUB_REPOSITORY: 'o/r' };
const pushArgs = ['--pull-request', '42', '--head', head, '--output-repo'];
for (const [environment, issue, expected, extra = {}] of [['', '', ['--job-token']], ['', '64', ['--job-token']], ['apply', '64', []],
  ['apply', '0', null], ['apply', '64 ', null], ['apply', 'owner/repo#64', null], ['apply', '$(exit 0)', null],
  // A push names where apply applies it, for the binary to refuse any
  // repository but the run's: the calling one when `output-repo` is empty.
  ['apply', '', [...pushArgs, 'o/r'], push], ['', '', [...pushArgs, 'o/r', '--job-token'], push],
  ['apply', '', [...pushArgs, 'x/y'], { ...push, OUTPUT_REPO: 'x/y' }],
  // The binary holds an item's repository to the bounds; an event's item is the caller's.
  ['apply', '64', ['--item-repo', 'o/tracker'], { ITEM_REPO: 'o/tracker' }],
  ['apply', '', null, { ITEM_REPO: 'o/tracker', EVENT: 'true' }],
  // A review's or a push's pull request is the target's.
  ['apply', '', null, { ITEM_REPO: 'o/tracker', REVIEW_ITEM: '42' }],
  ['apply', '', null, { ITEM_REPO: 'o/tracker', REVIEW: 'true' }],
  ['apply', '', null, { ...push, ITEM_REPO: 'o/tracker' }]]) {
  test(`the policy command is told when apply holds only the job token: environment ${JSON.stringify(environment)}, issue ${JSON.stringify(issue)}, ${JSON.stringify(extra)}`, () => {
    const dir = mkdtempSync(join(homedir(), 'request-'));
    try {
      mkdirSync(join(dir, 'workflow'));
      // Stands in for the CLI: the arguments it was given are the policy.
      writeFileSync(join(dir, 'workflow/policy-command.cjs'),
        'process.stdout.write(JSON.stringify({args: process.argv.slice(2), safe_outputs: {push_to_pull_request_branch: {}}}))');
      const script = policy.split("- name: Check the request against the caller's bounds\n")[1]
        .split('        run: |\n')[1].split(/\n      [^ ]/)[0]
        .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
      const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', script], {
        encoding: 'utf8', env: { ...process.env, SOURCE_DIR: dir, JOB_DIR: dir, GITHUB_OUTPUT: join(dir, 'output'),
          ALLOW: 'allow', REPO: 'o/r', BASE: 'main', KIND: 'implement', OUTPUTS: 'all', MAX_OUTPUTS: '3',
          TARGET: '', APPLY_ENVIRONMENT: environment, ISSUE: issue, ...extra },
      });
      // An issue is a number, or the run stops before the policy is written.
      assert.equal(result.status, expected ? 0 : 1, result.stderr);
      if (!expected) {
        return assert.match(result.stdout, extra.EVENT ? /::error::item-repo is not for an event-triggered run/
          : extra.ITEM_REPO ? /::error::item-repo is not for a review or a push/ : /::error::issue is not a number/);
      }
      const compiled = JSON.parse(readFileSync(join(dir, 'policy.json'), 'utf8'));
      const args = compiled.args;
      assert.deepEqual(args.slice(args.indexOf('--max-outputs') + 2), expected);
      if (extra.PUSH_ITEM) assert.equal(compiled.safe_outputs.push_to_pull_request_branch.replacement_base, extra.REPLACEMENT_BASE);
      // Policy hands on the issue it checked, not the input.
      assert.match(policy, /^      issue: \$\{\{ steps\.request\.outputs\.issue \}\}$/m);
      assert.ok(readFileSync(join(dir, 'output'), 'utf8').split('\n').includes(`issue=${issue}`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// An event's item is in the calling repository; with outputs going to
// another one, check and apply would hold a hidden comment, or a review
// thread, to the event's number there, on an item the event was not about.
for (const type of ['hide_comment', 'create_pull_request_review_comment', 'reply_to_pull_request_review_comment', 'resolve_pull_request_review_thread'])
for (const [extra, ok] of [[{}, true], [{ EVENT: 'true' }, true], [{ EVENT: 'true', OUTPUT_REPO: 'O/R' }, true],
  [{ OUTPUT_REPO: 'x/y' }, true], [{ EVENT: 'true', OUTPUT_REPO: 'x/y' }, false]]) {
  test(`${type} is refused before the agent for an event's item elsewhere: ${JSON.stringify(extra)}`, () => {
    const dir = mkdtempSync(join(homedir(), 'request-'));
    try {
      mkdirSync(join(dir, 'workflow'));
      writeFileSync(join(dir, 'workflow/policy-command.cjs'),
        `process.stdout.write(JSON.stringify({safe_outputs: {noop: {max: 1}, ${type}: {max: 1}}}))`);
      const script = policy.split("- name: Check the request against the caller's bounds\n")[1]
        .split('        run: |\n')[1].split(/\n      [^ ]/)[0]
        .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
      const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', script], {
        encoding: 'utf8', env: { ...process.env, SOURCE_DIR: dir, JOB_DIR: dir, GITHUB_OUTPUT: join(dir, 'output'),
          GITHUB_REPOSITORY: 'o/r', ALLOW: 'allow', REPO: 'o/r', BASE: 'main', KIND: 'analysis', OUTPUTS: 'all',
          MAX_OUTPUTS: '1', TARGET: '', APPLY_ENVIRONMENT: 'apply', ISSUE: '', ...extra },
      });
      assert.equal(result.status, ok ? 0 : 1, result.stderr);
      if (!ok) assert.match(result.stdout, new RegExp(`::error::${type} is for an event-triggered run only when output-repo is the calling repository`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
