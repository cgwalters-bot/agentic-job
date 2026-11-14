// Exercise the actual workflow shell, without tokens or a forge.
const assert = require('node:assert/strict');
const { execFile, spawnSync } = require('node:child_process');
const { copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } = require('node:fs');
const { createServer } = require('node:http');
const { join } = require('node:path');
const { homedir } = require('node:os');
const { test } = require('node:test');
const { promisify } = require('node:util');

const workflow = readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
const wrapper = readFileSync(join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');

function step(name) {
  const section = workflow.split(`- name: ${name}\n`)[1];
  assert.ok(section, name);
  return section.split('        run: |\n')[1].split(/\n        [^ ]/)[0]
    .split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
}

function command(cwd, program, args, env = {}) {
  return spawnSync(program, args, { cwd, encoding: 'utf8', env: { ...process.env, ...env } });
}

function git(cwd, ...args) {
  const result = command(cwd, 'git', args);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

// The settings a push is applied with, as the workflow states them.
function stepEnv(name, key) {
  const section = workflow.split(`- name: ${name}\n`)[1].split('        run: |\n')[0];
  return section.match(new RegExp(`^          ${key}: '(.*)'$`, 'm'))[1];
}

for (const filename of ['full', 'limit', 'event']) {
  test(`scripted ${filename} comments inherit the caller's fixed destination`, () => {
    const setup = readFileSync(join(__dirname, `../.github/agentic-job/e2e/${filename}.sh`), 'utf8');
    const fixture = JSON.parse(setup.split("<<'JSON'\n")[1].split('\nJSON')[0]);
    // full's comment is appended by its GitHub probe, once the probe passed.
    const appended = [...setup.matchAll(/^printf '%s\\n' '(\{.*\})' >> "\$HOME\/out\/safe-outputs\.jsonl"$/gm)]
      .map(([, line]) => JSON.parse(line));
    const comments = fixture.filter(step => step.write?.path.endsWith('safe-outputs.jsonl'))
      .flatMap(step => step.write.content.trim().split('\n').map(line => JSON.parse(line)))
      .concat(appended)
      .filter(output => output.type === 'add_comment');
    assert.equal(comments.length, 1);
    assert.deepEqual(Object.keys(comments[0]).sort(), ['body', 'type']);
  });
}

test('scripted negative analysis reaches check with a misdirected comment', () => {
  const setup = readFileSync(join(__dirname, '../.github/agentic-job/e2e/misdirected.sh'), 'utf8');
  const fixture = JSON.parse(setup.split("<<'JSON'\n")[1].split('\nJSON')[0]);
  // Fake runs must exercise redaction before any hand-back may be uploaded.
  assert.ok(fixture.some(step => step.execute?.command.includes('gh%s_%s')));
  const outputs = fixture.filter(step => step.write?.path.endsWith('safe-outputs.jsonl'));
  assert.equal(outputs.length, 1);
  assert.deepEqual(JSON.parse(outputs[0].write.content), {
    type: 'add_comment', item_number: 65, body: 'This misdirected analysis must be refused.',
  });
  const outcome = fixture.find(step => step.write?.path.endsWith('outcome.json'));
  assert.equal(JSON.parse(outcome.write.content).stopped_early, null);
});

test('negative analysis verification refuses any posted misdirected comment', () => {
  const ci = readFileSync(join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  const filter = ci.split('- name: The refused comment was not posted on either item\n')[1]
    .split("--arg run \"$RUN\" '")[1].split("'\n")[0].trim();
  const hostile = { body: 'This misdirected analysis must be refused. actions/runs/123' };
  for (const [comments, expected] of [
    [[], 0],
    [[{ body: 'unrelated comment' }], 0],
    [[hostile], 1],
    [[{ body: 'unrelated comment' }, hostile], 1],
  ]) {
    const result = spawnSync('jq', ['-se', '--arg', 'run', 'actions/runs/123', filter], {
      encoding: 'utf8', input: JSON.stringify(comments),
    });
    assert.equal(result.status, expected, result.stderr);
  }
});

for (const [name, filename, files, unrelated, expected] of [
  ['ordinary edit', 'file.txt', ['file.txt'], false, 0],
  ['CRLF edit', 'file.txt', ['file.txt'], false, 0],
  ['Unicode path', 'café.txt', ['café.txt'], false, 0],
  ['unchecked path', 'file.txt', ['other.txt'], false, 1],
  ['empty file list', 'file.txt', [], false, 1],
  ['unrelated base', 'file.txt', ['file.txt'], true, 1],
]) {
  test(`apply guard: ${name}`, () => {
    const root = mkdtempSync(join(homedir(), 'apply-test-'));
    try {
      const repo = join(root, 'repo');
      const outputs = join(root, 'outputs');
      mkdirSync(repo);
      mkdirSync(outputs);
      git(repo, 'init', '-q');
      git(repo, 'config', 'user.name', 'Test');
      git(repo, 'config', 'user.email', 'test@example.invalid');
      const cr = name === 'CRLF edit' ? '\r' : '';
      writeFileSync(join(repo, filename), `before${cr}\n`);
      git(repo, 'add', '.');
      git(repo, 'commit', '-qm', 'base');
      const base = git(repo, 'rev-parse', 'HEAD');
      git(repo, 'update-ref', 'refs/agentic-job/target-base', base);
      writeFileSync(join(repo, filename), `after${cr}\n`);
      git(repo, 'commit', '-qam', 'edit');
      writeFileSync(join(outputs, 'aw-test.patch'), command(repo, 'git', ['format-patch', '-1', '--stdout']).stdout);
      git(repo, 'reset', '--hard', base);
      if (unrelated) {
        git(repo, 'checkout', '--orphan', 'unrelated');
        git(repo, 'commit', '-qm', 'unrelated root');
        git(repo, 'update-ref', 'refs/agentic-job/target-base', 'HEAD');
      }
      const report = join(root, 'report.json');
      writeFileSync(report, JSON.stringify({ patch: { file: 'aw-test.patch', base_commit: base, files } }));
      const configured = command(repo, 'bash', ['-euo', 'pipefail', '-c', step('Configure git')]);
      assert.equal(configured.status, 0, configured.stderr);
      assert.equal(git(repo, 'config', 'merge.renames'), 'false');
      assert.equal(git(repo, 'config', 'am.keepcr'), 'true');
      const result = command(repo, 'bash', ['-euo', 'pipefail', '-c', step('Apply the patch on its own base, and compare what changed with what was checked')], {
        REPORT: report, RUNNER_TEMP: root, GH_AW_TMP: outputs, REPO: 'test/repo', BASE: 'main', GITHUB_OUTPUT: join(root, 'output'),
      });
      if (expected === 0) {
        assert.equal(result.status, 0, result.stderr + result.stdout);
        // The tree the patch makes, for the push step to know it by.
        assert.match(readFileSync(join(root, 'output'), 'utf8'), /^tree=[0-9a-f]{40}\n$/);
      } else {
        assert.notEqual(result.status, 0, result.stderr + result.stdout);
      }
      if (name === 'CRLF edit') {
        git(repo, 'am', '--3way', join(outputs, 'aw-test.patch'));
        assert.equal(readFileSync(join(repo, filename), 'utf8'), 'after\r\n');
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test('handler cannot follow a renamed file into a protected path', () => {
  const root = mkdtempSync(join(homedir(), 'apply-test-'));
  try {
    git(root, 'init', '-q');
    git(root, 'config', 'user.name', 'Test');
    git(root, 'config', 'user.email', 'test@example.invalid');
    writeFileSync(join(root, 'file.txt'), 'before\n');
    git(root, 'add', '.');
    git(root, 'commit', '-qm', 'base');
    const base = git(root, 'rev-parse', 'HEAD');
    writeFileSync(join(root, 'file.txt'), 'after\n');
    git(root, 'commit', '-qam', 'edit');
    const patch = join(root, 'mail.patch');
    writeFileSync(patch, command(root, 'git', ['format-patch', '-1', '--stdout']).stdout);
    git(root, 'reset', '--hard', base);
    git(root, 'mv', 'file.txt', '.envrc');
    git(root, 'commit', '-qm', 'rename');
    const configured = command(root, 'bash', ['-eo', 'pipefail', '-c', step('Configure git')]);
    assert.equal(configured.status, 0, configured.stderr);
    const result = command(root, 'git', ['am', '--3way', patch]);
    assert.notEqual(result.status, 0, result.stderr);
    assert.equal(readFileSync(join(root, '.envrc'), 'utf8'), 'before\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function script(name) {
  const section = workflow.split(`- name: ${name}\n`)[1].split(/\n      - /)[0];
  return section.split('script: |\n')[1].split('\n')
    .filter(line => line.startsWith('            ')).map(line => line.slice(12)).join('\n');
}

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

// Runs policy binary's guard (`agentic-job applied`, which
// src/apply/applied.rs tests) with the job token, against a loopback forge
// holding the comments `posted` on every item and no pull request or issue.
async function guard(items, posted = [], { target = '64', artifacts = '' } = {}) {
  const dir = mkdtempSync(join(homedir(), 'apply-test-'));
  const forge = createServer((request, response) => {
    const { pathname, searchParams } = new URL(request.url, 'http://forge');
    const answer = pathname === '/search/issues' ? { items: [] }
      : pathname.endsWith('/comments') && !searchParams.has('page') ? posted : [];
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(answer));
  });
  await new Promise(resolve => forge.listen(0, '127.0.0.1', resolve));
  try {
    writeFileSync(join(dir, 'agent_output.json'), JSON.stringify({ items, errors: [] }));
    writeFileSync(join(dir, 'report.json'), JSON.stringify({ patch: { file: 'aw-agent-run-7.patch' } }));
    writeFileSync(join(dir, 'aw-agent-run-7.patch'), 'diff\n');
    await promisify(execFile)(join(__dirname, '../target/debug/agentic-job'), ['applied', '--dir', dir, '--report', join(dir, 'report.json'),
      '--output-repo', 'owner/repo', '--repo', 'owner/repo', '--item-repo', 'owner/repo', '--comment-target', target,
      '--artifact-prefix', artifacts, '--fork', 'bot/repo', '--token-is-pat', 'false'], { env: { ...process.env, GH_TOKEN: 'test-token-not-secret',
      GITHUB_API_URL: `http://127.0.0.1:${forge.address().port}`, GITHUB_RUN_ID: '7', GITHUB_OUTPUT: join(dir, 'output'), GITHUB_STEP_SUMMARY: '' } });
    return { kept: JSON.parse(readFileSync(join(dir, 'agent_output.json'), 'utf8')).items,
      skipped: JSON.parse(readFileSync(join(dir, 'skipped.json'), 'utf8')) };
  } finally {
    forge.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// What the handlers send, after the request hook hides the name.
function sent(body) {
  const hook = script('Apply the outputs with gh-aw\'s handlers').split('client.hook.before("request", options => {')[1].split('\n  });')[0];
  const options = { method: 'POST', url: '/repos/{owner}/{repo}/issues/{issue_number}/comments', body };
  new Function('options', 'creates', 'issues', hook)(options, () => false, 0);
  return options.body;
}

const comment = (body = 'first') => ({ type: 'add_comment', body });
const pull = { type: 'create_pull_request', title: 't', body: 'change', branch: 'agent-run-7' };

test('a posted body hides the name the guard put last, and only that name', () => {
  const name = 'agentic-job-applied: 7/0/0123456789abcdef';
  const other = 'agentic-job-applied: 7/1/fedcba9876543210';
  assert.equal(sent(`hello\n\n${name}`), `hello\n\n<!-- ${name} -->`);
  // A handler's footer may follow the name.
  assert.equal(sent(`hello\n\n${name}\n\n> footer`), `hello\n\n<!-- ${name} -->\n\n> footer`);
  // A line the handlers decoded into a name before the guard's stays as it is.
  assert.equal(sent(`${other}\n\n${name}`), `${other}\n\n<!-- ${name} -->`);
  for (const body of ['hello', `say ${name}`, 'agentic-job-applied: 7/0/0123', 'agentic-job-applied: 7/0/0123456789ABCDEF']) {
    assert.equal(sent(body), body);
  }
});

const actions = { login: 'github-actions[bot]', type: 'Bot' };

// CI run 38018010779: the triage and research calls of one run post the
// same comment on the same issue; the second was taken for applied.
test('another call of the same run posting the same comment does not leave it out', async () => {
  const shipped = readFileSync(join(__dirname, 'dispatch-comment.sh'), 'utf8');
  const output = JSON.parse(JSON.parse(shipped.split("<<'JSON'\n")[1].split('\nJSON')[0])
    .find(step => step.write?.path.endsWith('safe-outputs.jsonl')).write.content);
  const triage = (await guard([output], [], { artifacts: 'dispatch-triage-' })).kept[0];
  const posted = [{ user: actions, body: sent(triage.body), html_url: 'u' }];
  const research = await guard([output], posted, { artifacts: 'dispatch-research-' });
  assert.deepEqual(research.skipped, []);
  assert.equal(research.kept.length, 1);
  const again = await guard([output], posted, { artifacts: 'dispatch-triage-' });
  assert.equal(again.kept.length, 0);
});

function refs(items, issue = '64', itemRepo = 'owner/repo') {
  const dir = mkdtempSync(join(homedir(), 'refs-test-'));
  try {
    mkdirSync(join(dir, 'apply-binary'));
    copyFileSync(join(__dirname, '../target/debug/agentic-job'), join(dir, 'apply-binary/agentic-job'));
    writeFileSync(join(dir, 'agent_output.json'), JSON.stringify({ items, errors: [] }));
    const result = command(dir, 'bash', ['-e', '-o', 'pipefail', '-c', step('Say which issue a pull request is for')],
      { GH_AW_TMP: dir, RUNNER_TEMP: dir, GITHUB_WORKSPACE: dir,
        OUTPUT_REPO: 'owner/repo', ITEM_REPO: itemRepo, ISSUE: issue });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(readFileSync(join(dir, 'agent_output.json'), 'utf8')).items;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('the generated reference links an implementation to the caller issue', () => {
  const [opened, commented] = refs([pull, comment()]);
  assert.equal(opened.body, 'change\n\nCloses #64');
  assert.deepEqual(commented, comment());
  assert.equal(refs([{ ...pull, body: undefined }])[0].body, '\n\nCloses #64');
  // An item in another repository is named there.
  assert.equal(refs([pull], '64', 'owner/tracker')[0].body, 'change\n\nRefs owner/tracker#64');
  const steps = workflow.split('\n      - name: ').map(text => text.split('\n')[0]);
  assert.ok(steps.indexOf('Say which issue a pull request is for') < steps.indexOf('Leave out what an earlier attempt applied'));
  assert.match(workflow.split('- name: Say which issue a pull request is for\n')[1].split('\n')[0],
    /if: \$\{\{ fromJSON\(inputs\.check\)\.outputs.has-patch == 'true' && fromJSON\(inputs\.policy\)\.apply-staged != 'true' \}\}/);
});

test('a batched pull request preserves closing references for all its issues', () => {
  for (const itemRepo of ['owner/repo', 'owner/tracker']) {
    const body = 'Batch sibling work\n\nCloses #64\nCloses #65\nCloses owner/tracker#66';
    const [opened] = refs([{ ...pull, body }], '64', itemRepo);
    assert.equal(opened.body, itemRepo === 'owner/repo' ? body : `${body}\n\nRefs ${itemRepo}#64`);
  }
});

test('an existing reference is unchanged and fix outputs are untouched', () => {
  for (const [itemRepo, line] of [['owner/repo', 'Closes #64'], ['OWNER/REPO', 'Closes #64'],
    ['owner/tracker', 'Refs owner/tracker#64']]) {
    for (const ending of ['', '\r\n']) {
      const body = `Done.\n\n${line}${ending}`;
      assert.equal(refs([{ ...pull, body }], '64', itemRepo)[0].body, body);
    }
  }
  const fix = { type: 'push_to_pull_request_branch', message: 'Keep existing PR references.' };
  assert.deepEqual(refs([fix]), [fix]);
  assert.equal(refs([{ ...pull, body: 'Mentions Closes #64 in prose.' }])[0].body,
    'Mentions Closes #64 in prose.\n\nCloses #64');
});

test('examples and comments cannot suppress the generated closing reference', () => {
  for (const [body, closing] of [
    ['```text\nCloses #64\n```', ''],
    ['~~~\nCloses #64\n~~~', ''],
    ['<!--\nCloses #64\n-->', ''],
    ['<!-- Closes #64 -->', ''],
    ['```text\nCloses #64', '\n```'],
    ['<!--\nCloses #64', '\n-->'],
  ]) {
    assert.equal(refs([{ ...pull, body }])[0].body, `${body}${closing}\n\nCloses #64`);
  }
  // Partial work remains a draft; merging it still closes the primary issue.
  const body = '**Partial work.** Not all work is done.';
  assert.equal(refs([{ ...pull, body }])[0].body, `${body}\n\nCloses #64`);
});

test('a pull request that says it is only part of its issue does not close it', () => {
  for (const line of ['Part of #64', 'Part of #64 (item 5)', 'Refs #64', 'Refs #64\tthe parser']) {
    for (const body of [`${line}\n\nDid item 5; items 1 to 4 are left.`, `Did item 5.\r\n\r\n${line}\r\n`]) {
      assert.equal(refs([{ ...pull, body }])[0].body, body, line);
    }
  }
  // Only the run's own issue, on a line of its own, outside examples.
  for (const body of ['Part of #640', 'Refs #6', 'Part of #65', 'See Part of #64', 'Refs owner/repo#64',
    '```text\nPart of #64\n```', '<!-- Refs #64 -->']) {
    assert.equal(refs([{ ...pull, body }])[0].body, `${body}\n\nCloses #64`, body);
  }
  // An item elsewhere is only referenced: its line is added as before.
  assert.equal(refs([{ ...pull, body: 'Part of #64' }], '64', 'owner/tracker')[0].body,
    'Part of #64\n\nRefs owner/tracker#64');
});

// A step's `if`, as Actions evaluates the few forms apply's steps use.
function runs(name, contexts) {
  const condition = workflow.split(`- name: ${name}\n`)[1].split('\n')[0].match(/^ +if: \$\{\{ (.*) \}\}$/)?.[1];
  if (!condition) return true;
  const js = condition.replace(/fromJSON\(inputs\.(policy|check|agent)\)/g, '$1')
    .replace(/\.([a-z]+(?:-[a-z]+)+)/g, "['$1']").replace(/format\('\{0\}', ([^)]*)\)/g, 'String($1)');
  return Function('policy', 'check', 'agent', `return ${js}`)(contexts.policy, contexts.check, contexts.agent);
}

// The value the shipped dispatch caller gives a policy.yml input, and that
// it reaches apply as the call's policy output.
function dispatchedInput(key, value) {
  const dispatch = readFileSync(join(__dirname, '../.github/workflows/dispatch.yml'), 'utf8');
  const policy = readFileSync(join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  assert.match(dispatch, new RegExp(`^      ${key}: \\$\\{\\{ inputs\\.item \\}\\}$`, 'm'));
  assert.match(wrapper, new RegExp(`^      ${key}: \\$\\{\\{ inputs\\.${key} \\}\\}$`, 'm'));
  assert.match(policy, new RegExp(`^      ${key}: \\$\\{\\{ steps\\.request\\.outputs\\.${key} \\}\\}$`, 'm'));
  assert.match(workflow, new RegExp(`^      ${key.toUpperCase()}: \\$\\{\\{ fromJSON\\(inputs\\.policy\\)\\.${key} \\}\\}$`, 'm'));
  return value;
}

// An implement run's hand-back, through each step of apply that touches a
// pull request's body, to what the handlers send: issue #877, where a caller
// without `issue` had every pull request link nothing.
async function applyImplement(body, { issue = dispatchedInput('issue', '64'), exit = '0' } = {}) {
  const root = mkdtempSync(join(homedir(), 'apply-test-'));
  try {
    mkdirSync(join(root, 'apply-binary'));
    copyFileSync(join(__dirname, '../target/debug/agentic-job'), join(root, 'apply-binary/agentic-job'));
    writeFileSync(join(root, 'config.json'), JSON.stringify({ create_pull_request: { max: 1, ready_when_complete: true } }));
    writeFileSync(join(root, 'report.json'), JSON.stringify({ ok: true, patch: { file: 'aw-agent-run-7.patch' } }));
    writeFileSync(join(root, 'agent_output.json'), JSON.stringify({ items: [{ ...pull, body }], errors: [] }));
    const contexts = { policy: { issue, 'apply-staged': '', 'proposals-artifact': '', 'external-run-id': '' },
      check: { outputs: { 'has-patch': 'true' } }, agent: { outputs: { exit } } };
    const env = { GH_AW_TMP: root, REPORT: join(root, 'report.json'), GITHUB_OUTPUT: join(root, 'output'), GITHUB_ENV: join(root, 'env'),
      GITHUB_WORKSPACE: root, RUNNER_TEMP: root, REPO: 'owner/repo', OUTPUT_REPO: 'owner/repo', ITEM_REPO: 'owner/repo', ISSUE: issue };
    const logs = [];
    for (const [name, extra] of [
      ['Decide whether the work is complete', { EXIT: exit }],
      ["Write the handlers' configuration", { BASE: 'main', BRANCH_PREFIX: '', PARTIAL: '', TITLE_PREFIX: '', COMMENT_TARGET: '64',
        PULL_REQUEST: stepEnv("Write the handlers' configuration", 'PULL_REQUEST'), PUSH: '{}', FORK: 'bot/repo' }],
      ['Mark what a partial run opens or posts', { STOPPED: 'a limit' }],
      ['Say which issue a pull request is for', {}],
    ]) {
      if (!runs(name, contexts)) continue;
      const result = command(root, 'bash', ['-e', '-o', 'pipefail', '-c', step(name)], { ...env, ...extra });
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
      logs.push(result.stdout);
    }
    const { items } = JSON.parse(readFileSync(join(root, 'agent_output.json'), 'utf8'));
    assert.ok(runs('Leave out what an earlier attempt applied', contexts));
    assert.ok(runs("Apply the outputs with gh-aw's handlers", contexts));
    const { kept } = await guard(items);
    assert.equal(kept.length, 1);
    return { sent: sent(kept[0].body), logs: logs.join('') };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// What a reader sees of a sent body: the hidden name after it is not text.
const visible = body => body.replace(/\n\n<!-- agentic-job-applied: [^>]* -->$/, '');

test("an implement run's pull request ends with its item's closing line, through apply's steps to the handlers", async () => {
  assert.match(visible((await applyImplement('Done.')).sent), /^Done\.\n\nCloses #64$/);
  // A batched run's sibling lines (#657) stay, and the item's still comes last.
  const batch = 'Batch sibling work\n\nCloses #65\nCloses owner/tracker#66';
  assert.equal(visible((await applyImplement(batch)).sent), `${batch}\n\nCloses #64`);
  // Partial work says so first, and still closes its item.
  const partial = visible((await applyImplement('Half.', { exit: '3' })).sent);
  assert.match(partial, /^\*\*Partial work\.\*\* [^\n]*\n\nHalf\.\n\nCloses #64$/);
  // Work the agent says is part of the issue references it, done or not (#974).
  assert.equal(visible((await applyImplement('Part of #64 (item 5)\n\nItems 1 to 4 are left.')).sent),
    'Part of #64 (item 5)\n\nItems 1 to 4 are left.');
});

test('a pull request of a caller that passes no issue links nothing, and the run says so', async () => {
  const { sent: body, logs } = await applyImplement('Done.', { issue: '' });
  assert.equal(visible(body), 'Done.');
  assert.match(logs, /^::warning::the pull request names no issue: the caller passed policy\.yml no `issue`$/m);
  // Only a pull request is meant: a comment-only hand-back has nothing to link.
  const root = mkdtempSync(join(homedir(), 'refs-test-'));
  try {
    writeFileSync(join(root, 'agent_output.json'), JSON.stringify({ items: [comment()], errors: [] }));
    const result = command(root, 'bash', ['-e', '-o', 'pipefail', '-c', step('Say which issue a pull request is for')],
      { GH_AW_TMP: root, ISSUE: '' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// A plain value of a github-script step's environment.
function scriptEnv(name, key) {
  const section = workflow.split(`- name: ${name}\n`)[1].split('        with:\n')[0];
  return section.match(new RegExp(`^          ${key}: (.*)$`, 'm'))?.[1];
}

// gh-aw replaces its own list with GH_AW_ALLOWED_DOMAINS: the handlers
// keep the links the policy call wrote down, as `collect` does. The
// result step's reason is tests/workflows.rs's.
test('every sanitizer keeps the links the policy keeps', () => {
  const domains = '${{ fromJSON(inputs.policy).allowed-domains }}';
  assert.equal(scriptEnv("Apply the outputs with gh-aw's handlers", 'GH_AW_ALLOWED_DOMAINS'), domains);
  const policy = readFileSync(join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  assert.match(policy, /\n        value: \$\{\{ jobs\.policy\.outputs\.allowed-domains \}\}\n/);
  assert.match(policy, /\n      allowed-domains: \$\{\{ steps\.request\.outputs\.allowed-domains \}\}\n/);
  assert.match(policy, /"allowed-domains=\$\(jq -r '\.allowed_domains \/\/ \[\] \| join\(","\)' "\$JOB_DIR\/policy\.json"\)"/);
});

// The result step's outputs, which src/apply/result.rs tests, for a run
// whose checked outputs, after the guard, are `items`, with `pr` opened.
function resultOutputs(items, pr = null) {
  const dir = mkdtempSync(join(homedir(), 'result-test-'));
  try {
    mkdirSync(join(dir, 'apply-binary'));
    copyFileSync(join(__dirname, '../target/debug/agentic-job'), join(dir, 'apply-binary/agentic-job'));
    writeFileSync(join(dir, 'applied.json'), JSON.stringify({ made: [], already_applied: [], pull_request: pr }));
    writeFileSync(join(dir, 'agent_output.json'), JSON.stringify({ items, errors: [] }));
    for (const file of ['output', 'summary']) writeFileSync(join(dir, file), '');
    const ran = command(dir, 'bash', ['-eo', 'pipefail', '-c', step('Say where what the run made is')],
      { GH_AW_TMP: dir, RUNNER_TEMP: dir, GITHUB_OUTPUT: join(dir, 'output'), GITHUB_STEP_SUMMARY: join(dir, 'summary'),
        GH_AW_SAFE_OUTPUTS_URLS: 'allowed-or-code-region', CHECKED_ARTIFACT_ID: '99', RUN_URL: 'https://github.com/caller/repo/actions/runs/7' });
    assert.equal(ran.status, 0, ran.stdout + ran.stderr);
    return Object.fromEntries(readFileSync(join(dir, 'output'), 'utf8').trimEnd().split('\n')
      .map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('missing-data alone passes the guard and fails the job', async () => {
  const item = { type: 'missing_data', data_type: 'workflow', reason: 'needs workflow edits' };
  const guarded = await guard([item]);
  assert.deepEqual(guarded.kept, [item]);
  assert.deepEqual(guarded.skipped, []);
  const outputs = resultOutputs(guarded.kept);
  assert.equal(outputs['missing-data'], 'true');
  const ended = command(__dirname, 'bash', ['-euo', 'pipefail', '-c', step('Every output was applied')],
    { PROJECT_REFUSED: '', MISSING_DATA: outputs['missing-data'] });
  assert.equal(ended.status, 1, ended.stdout + ended.stderr);
  assert.match(ended.stdout, /required data was missing/);
  // A diagnostic alongside an actual result must not turn success into failure.
  const opened = { number: 39, url: 'https://github.com/owner/repo/pull/39' };
  assert.equal(resultOutputs([item], opened)['missing-data'], undefined);
});

test('the pinned comment handler posts a guarded review verdict', { skip: !process.env.GH_AW_JS }, async () => {
  const body = 'VERDICT: APPROVE\nREASON: Scripted dispatch tests wiring.\nReviewed SHA: 0123';
  const guarded = await guard([comment(body)], [], { target: '454', artifacts: 'dispatch-review-' });
  // Isolate gh-aw's globals and environment from the other workflow tests.
  const program = `
    const { join } = require('node:path');
    const dir = process.env.GH_AW_JS;
    const created = [];
    const core = { info() {}, debug() {}, warning() {}, error() {}, setOutput() {} };
    const github = { hook: { before() {} }, rest: { issues: {
      get: async () => ({ data: { user: { login: 'author', type: 'User' } } }),
      createComment: async params => {
        new Function('options', 'creates', 'issues', process.env.COMMENT_HOOK)(
          Object.assign(params, { method: 'POST', url: '/repos/{owner}/{repo}/issues/{issue_number}/comments' }), () => false, 0);
        created.push(params);
        return { data: { id: 1, html_url: 'https://github.com/owner/repo/issues/454#issuecomment-1' } };
      },
    } } };
    const context = { repo: { owner: 'owner', repo: 'repo' }, runId: 7, serverUrl: 'https://github.com',
      eventName: 'pull_request', payload: { pull_request: { number: 454 } } };
    require(join(dir, 'setup_globals.cjs')).setupGlobals(core, github, context, {}, {});
    (async () => {
      const handle = await require(join(dir, 'add_comment.cjs')).main({ max: 1, target: '454', 'target-repo': 'owner/repo' });
      const applied = await handle(JSON.parse(process.env.ITEM));
      console.log(JSON.stringify({ applied, created }));
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  const ran = command(homedir(), 'node', ['-e', program], { ITEM: JSON.stringify(guarded.kept[0]),
    COMMENT_HOOK: script('Apply the outputs with gh-aw\'s handlers').split('client.hook.before("request", options => {')[1].split('\n  });')[0],
    GH_AW_WORKFLOW_ID: 'agentic-job', GH_AW_WORKFLOW_NAME: 'ci', GH_AW_SAFE_OUTPUTS_URLS: 'allowed-or-code-region',
    // What Actions sets, and the step its job's check run: the handler posts nothing without them.
    GITHUB_REPOSITORY: 'owner/repo', GITHUB_REPOSITORY_ID: '1', GITHUB_RUN_ID: '7', GITHUB_RUN_ATTEMPT: '1', GITHUB_JOB: 'apply',
    GH_AW_JOB_CHECK_RUN_ID: scriptEnv("Apply the outputs with gh-aw's handlers", 'GH_AW_JOB_CHECK_RUN_ID') === '${{ job.check_run_id }}' ? '9' : '' });
  assert.equal(ran.status, 0, ran.stdout + ran.stderr);
  const { applied, created } = JSON.parse(ran.stdout);
  assert.equal(applied.success, true, JSON.stringify(applied));
  assert.equal(created.length, 1);
  assert.equal(created[0].issue_number, 454);
  assert.ok(created[0].body.startsWith(`${body}\n\n<!-- agentic-job-applied:`), created[0].body);
  // That the comment is the run's result, not a no-result notice, is src/apply/result.rs's.
  assert.equal(applied.url, 'https://github.com/owner/repo/issues/454#issuecomment-1');
});

// The handlers log the patch and stream git's output, both the agent's
// text, where the runner reads workflow commands (#1460). The apply step
// is run with gh-aw's modules replaced by ones logging as a handler does.
test('the apply step hands the handlers a core and an exec whose output cannot form a workflow command', async () => {
  const root = mkdtempSync(join(homedir(), 'apply-log-test-'));
  const stdout = process.stdout.write;
  try {
    const actions = join(root, 'gh-aw', 'actions');
    mkdirSync(actions, { recursive: true });
    mkdirSync(join(root, 'apply-source', 'workflow'), { recursive: true });
    // At the path the step requires it from.
    writeFileSync(join(root, 'apply-source', 'workflow', 'workflow-commands.cjs'), readFileSync(join(__dirname, 'workflow-commands.cjs')));
    writeFileSync(join(actions, 'setup_globals.cjs'), `module.exports.setupGlobals = (core, github, context, exec) => Object.assign(global, { core, github, context, exec });\n`);
    const forged = '::set-output name=created_pr_url::https://attacker.example/';
    writeFileSync(join(actions, 'safe_output_handler_manager.cjs'), `module.exports.main = async () => {
      core.info(${JSON.stringify(forged)});
      core.info('see ##[warning]legacy-marker');
      await exec.exec('git', ['am', '--3way', 'x.patch'], { cwd: '.' });
    };\n`);
    for (const [name, text] of [['agent_output.json', JSON.stringify({ items: [], errors: [] })], ['project-writes.json', '[]']]) writeFileSync(join(root, name), text);
    const logged = [], outputs = {}, written = [];
    const core = { info: text => logged.push(text), warning: text => logged.push(text), setOutput: (key, value) => { outputs[key] = value; } };
    const github = { hook: { before() {}, after() {} } };
    // Writes git's line to the step's log the way @actions/exec does.
    const exec = { exec: async (program, args, options) => {
      assert.equal(options.cwd, '.');
      await new Promise(resolve => (options.outStream ?? process.stdout).write('Applying: fix ##[set-output name=created_pr_url;]https://attacker.example/\n', resolve));
      return 0;
    } };
    process.stdout.write = (chunk, ...rest) => { written.push(String(chunk)); return stdout.call(process.stdout, chunk, ...rest); };
    const env = { RUNNER_TEMP: root, GITHUB_WORKSPACE: root, GH_AW_WORKFLOW_NAME: 'agentic-job', GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG: '{}',
      GH_AW_AGENT_OUTPUT: join(root, 'agent_output.json'), GH_AW_TMP: root, PROJECT_CHECKED: 'success' };
    await new AsyncFunction('require', 'process', 'core', 'github', 'context', 'exec', 'io', 'getOctokit', script("Apply the outputs with gh-aw's handlers"))(
      require, { env }, core, github, {}, exec, {}, () => github);
    assert.deepEqual(logged, [': :set-output name=created_pr_url: :https://attacker.example/', 'see ## [warning]legacy-marker']);
    assert.deepEqual(written.filter(text => text.includes('attacker.example')), ['Applying: fix ## [set-output name=created_pr_url;]https://attacker.example/\n']);
    // The module is the apply-source checkout's, which a run without a
    // patch, whose handlers only post, needs as the apply step does.
    const condition = name => workflow.split(`- name: ${name}\n`)[1].match(/^        if: (.*)$/m)[1];
    const checkout = workflow.split('\n      - ').find(step => step.includes('path: apply-source'));
    assert.equal(checkout.match(/^        if: (.*)$/m)[1], condition("Apply the outputs with gh-aw's handlers"));
  } finally {
    process.stdout.write = stdout;
    for (const name of ['core', 'github', 'context', 'exec']) delete global[name];
    rmSync(root, { recursive: true, force: true });
  }
});
