'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

// The policy job's `if:` as a function of the event context and the
// repository variables: GitHub's expression syntax is close enough to
// JavaScript for the functions it uses, with missing properties null.
function policyStarts(job) {
  const expression = job.match(/\n    if: >-\n((?: {6}.*\n)+)/)[1]
    .replace(/\b(github|vars)((?:\.\w+)+)/g, (_, root, rest) => root + rest.replaceAll('.', '?.'));
  const fromJSON = JSON.parse;
  const contains = (search, item) => Array.isArray(search)
    ? search.some(element => element == item)
    : String(search).toLowerCase().includes(String(item).toLowerCase());
  const startsWith = (text, prefix) => String(text).toLowerCase().startsWith(String(prefix).toLowerCase());
  const evaluate = Function('github', 'vars', 'fromJSON', 'contains', 'startsWith', `return Boolean(${expression});`);
  return (github, vars) => evaluate(github, vars, fromJSON, contains, startsWith);
}

// apply posts the fold check made (`agentic-job review fold`), before
// anything that names or marks what it posts.
test('apply posts inline findings in the verdict comment, not beside it', () => {
  const apply = fs.readFileSync(path.join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
  const fold = apply.indexOf('mv "$GH_AW_TMP/folded.json" "$GH_AW_TMP/agent_output.json"');
  assert.ok(fold !== -1 && fold < apply.indexOf('- name: Mark what a partial run opens or posts') &&
    fold < apply.indexOf('- name: Leave out what an earlier attempt applied'));
  const check = fs.readFileSync(path.join(__dirname, '../.github/workflows/check.yml'), 'utf8');
  const made = check.indexOf('review fold "$GH_AW_TMP/agent_output.json"');
  assert.ok(made > check.indexOf('- name: Put the patch beside the ingested outputs') && made < check.indexOf('- id: upload'));
  assert.match(check, /\n {12}\$\{\{ env.GH_AW_TMP \}\}\/folded.json\n/);
});

test('scripted review reports the checked-out SHA', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'review-script-'));
  try {
    const root = path.join(__dirname, '..');
    execFileSync('sh', [path.join(root, '.github/agentic-job/e2e/review.sh')],
      { env: { ...process.env, HOME: home } });
    fs.mkdirSync(path.join(home, 'out'));
    const script = JSON.parse(fs.readFileSync(path.join(home, '.config/fake-agent/demo.json'), 'utf8'));
    const command = script.find(step => step.execute?.command.includes('safe-outputs.jsonl')).execute.command;
    execFileSync('sh', ['-c', command], { cwd: root, env: { ...process.env, HOME: home } });
    const item = JSON.parse(fs.readFileSync(path.join(home, 'out/safe-outputs.jsonl'), 'utf8'));
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    assert.ok(item.body.includes(`\nReviewed SHA: ${sha}\n`));
    // The verdict line `agentic-job review verdict` reads in check.
    assert.match(item.body, /^VERDICT: (APPROVE|CHANGES)\n/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('automatic and dispatched review prompts allow concern-specific experiments, not routine verification', () => {
  const standing = fs.readFileSync(path.join(__dirname, 'review.md'), 'utf8');
  const dispatch = fs.readFileSync(path.join(__dirname, '../.github/workflows/dispatch.yml'), 'utf8');
  const instructions = dispatch.match(/const instructions = profile === 'review'\s+\? '([^']+)'/)[1];
  for (const prompt of [standing, dispatch]) {
    assert.match(prompt, /do not set item_number or other routing fields: the workflow fixes the target\./);
  }
  for (const prompt of [standing, instructions]) {
    assert.match(prompt, /Read the diff and the code around it, and report findings only\./);
    assert.match(prompt, /Do not run existing test suites, formatters or linters to confirm they pass\./);
    assert.match(prompt, /Build and run code when needed to test whether a specific concern holds,/);
    assert.match(prompt, /for example whether a function can fail under a condition no test covers\./);
    assert.match(prompt, /Report what you ran and what it showed, only for that concern\./);
    assert.match(prompt, /Do not look up or report CI results\./);
    assert.match(prompt, /Do not include a `?Verification:`? paragraph\./);
    assert.match(prompt, /exact admitted head SHA/);
    // The review is the merge gate for the harness's own changes (#526):
    // it must argue against the change, not take its description's word.
    assert.match(prompt, /Review adversarially/);
    assert.match(prompt, /Assume the change is wrong or malicious until the code\s+shows otherwise\./);
    assert.match(prompt, /Look for what it weakens, not only what it adds/);
    assert.match(prompt, /state the worst thing a changed file\s+could now do and why it cannot\./);
    assert.match(prompt, /Never approve because the description or\s+comments say the change is safe\./);
    assert.match(prompt, /cite files and lines for actionable findings/);
    // Only blockers block (#550): a CHANGES per new narrow finding cost a
    // fix, CI and review round each, so important findings and nits ride
    // along with an approval as follow-ups.
    assert.match(prompt, /Report every finding you can see in this one pass, not only the first\./);
    assert.match(prompt, /Tag each finding with exactly one severity: blocker, important or nit; an\s+untagged finding is not allowed\./);
    assert.match(prompt, /A blocker makes the change wrong for its\s+main purpose, loses data, or opens a security hole with a concrete path/);
    assert.match(prompt, /For supply-chain hardening, a blocker requires that the change newly runs\s+third-party code with a write credential in reach, including in apply, with a\s+PAT, in a write-permission pull_request_target job, or on the broker host\./);
    assert.match(prompt, /Otherwise supply-chain findings are important at most and go under Follow-ups\./);
    assert.match(prompt, /Supply-chain hardening is wanted over time as tracked follow-ups, not as a\s+gate on each change\./);
    assert.match(prompt, /This ceiling covers trusting an ordinary upstream, not a\s+concrete path the change itself opens for code an attacker controls to alter a\s+published artifact or read a credential or private source; that is a blocker\./);
    assert.match(prompt, /VERDICT: CHANGES only when there is at\s+least one blocker, and VERDICT: APPROVE otherwise/);
    assert.match(prompt, /list\s+important findings and nits under a "Follow-ups" heading, each with its file\s+and line, for later pull requests\./);
    assert.match(prompt, /When there is a blocker, the fix may take\s+important findings and nits along\./);
    assert.doesNotMatch(prompt, /\bP[0-3]\b/);
    assert.doesNotMatch(prompt, /VERDICT: CHANGES when there is\s+something actionable/);
    assert.doesNotMatch(prompt, /Do not build|Run relevant tests|what you verified or could not verify/);
  }
  // Whether its approval merges is the owner's merge policy (#556), stated
  // after the task, not prose the reviewer weighs.
  assert.match(standing, /Whether your approval merges is the\s+repository owner's decision, stated under "Merge policy"/);
  assert.match(standing, /Without that section, a\s+person approves every merge after you\./);
  assert.match(standing, /Ask for a person only when you find a\s+concrete risk you cannot bound, and say which\./);
  assert.doesNotMatch(standing, /merge gate for every change here/);
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(caller, /review-task: workflow\/review.md/);
  const agent = caller.split('\n  agent:')[1].split('\n  check:')[0];
  assert.doesNotMatch(agent, /rust-toolchain|rust-cache|setup-(?:node|python|go|java)|cargo (?:build|test|fmt|clippy)|npm (?:test|ci)/);
});

test('caller and write job retain the trusted-source boundary', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../.github/workflows/agentic-job.yml'), 'utf8');
  const checker = fs.readFileSync(path.join(__dirname, '../.github/workflows/check.yml'), 'utf8');
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  assert.match(caller, /pull_request_target: *(?:#[^\n]*)?\n\s+types: \[opened, synchronize, reopened, ready_for_review\]/);
  assert.match(caller, /kind: analysis/);
  assert.match(caller, /notify: none/);
  assert.doesNotMatch(caller, /contents: write|secrets: inherit|pull_request.head|refs\/pull/);
  // Which job holds which token: writes only in apply (the comment) and
  // status (the status), the identity token in register and check's
  // detector, never in the agent's job.
  const jobs = Object.fromEntries(caller.split('\njobs:\n')[1].split(/\n(?=  [a-z]+:\n)/)
    .map(job => [job.match(/^\s*([a-z]+):/)[1], job]));
  assert.deepEqual(Object.keys(jobs), ['policy', 'refusal', 'register', 'agent', 'check', 'submit', 'apply', 'status']);
  for (const [name, writes] of Object.entries({ policy: [], register: ['id-token'], agent: [], check: ['id-token'],
    refusal: ['pull-requests'], submit: ['pull-requests'], apply: ['pull-requests'], status: ['statuses'] })) {
    const granted = [...jobs[name].split('\n    permissions:\n')[1].matchAll(/^      ([a-z-]+): write$/gm)].map(m => m[1]);
    assert.deepEqual(granted, writes, name);
    // The agent job gets the register job's run token, as agentic-job.yml's
    // does, and its network step's key; no other secret.
    const secrets = name === 'agent'
      ? jobs[name].replace('\n    secrets:\n      INFERENCE_RUN_TOKEN: ${{ needs.register.outputs.run-token }}\n' +
        '      NETWORK_SECRET: ${{ needs.register.outputs.network-secret }}\n', '\n') : jobs[name];
    if (name !== 'apply') assert.doesNotMatch(secrets, /secrets/, name);
  }
  assert.match(jobs.register, /ref: \$\{\{ needs.policy.outputs.ref \}\}/);
  assert.match(jobs.agent, /policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}/);
  for (const [, action] of caller.matchAll(/^ +(?:- )?uses: ([^.\s]\S*)/gm)) assert.match(action, /@[0-9a-f]{40}$/, action);
  // The status takes the verdict check.yml set and the head policy
  // admitted, nothing the agent wrote. The only code it runs is the policy
  // job's binary of the pinned source, never the head, and the only upload
  // it reads is that binary.
  assert.doesNotMatch(jobs.status, /needs\.agent\.outputs|needs\.check\.outputs\.artifact|pull_request\.head|needs\.policy\.outputs\.ref\b/);
  assert.deepEqual([...jobs.status.matchAll(/artifact-ids: (.*)/g)].map(m => m[1]), ['${{ needs.policy.outputs.binary-artifact-id }}']);
  assert.match(jobs.status, /VERDICT: \$\{\{ needs.check.outputs.verdict \}\}/);
  assert.match(jobs.status, /HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}/);
  assert.match(jobs.status, /"\$RUNNER_TEMP\/bin\/agentic-job" review status/);
  assert.match(jobs.status, /REVIEW_URL: \$\{\{ needs.submit.outputs.review-url \}\}/);
  // The verdict is posted once: as the review, or else as apply's comment.
  // The review's body is check's accepted upload, from the pinned source's
  // code, and only a checked verdict is submitted.
  assert.match(jobs.apply, /if: \$\{\{ !cancelled\(\) && needs.policy.result == 'success' && needs.submit.outputs.review-url == '' \}\}/);
  assert.match(jobs.submit, /vars.AGENT_REAL_REVIEWS == 'true'/);
  assert.match(jobs.submit, /needs.check.result == 'success' && needs.check.outputs.artifact-id != '' &&\s+needs.policy.outputs.binary-artifact-id != ''/);
  assert.deepEqual([...jobs.submit.matchAll(/artifact-ids: (.*)/g)].map(m => m[1]),
    ['${{ needs.policy.outputs.binary-artifact-id }}', '${{ needs.check.outputs.artifact-id }}']);
  assert.match(jobs.submit, /"\$RUNNER_TEMP\/bin\/agentic-job" review submit --accepted "\$RUNNER_TEMP\/checked\/agent_output.json"/);
  assert.match(jobs.submit, /VERDICT: \$\{\{ needs.check.outputs.verdict \}\}/);
  assert.match(jobs.submit, /HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}/);
  assert.match(jobs.submit, /AGENT_EXIT: \$\{\{ needs.agent.outputs.exit \}\}/);
  // The footer's job link is the agent job's own ID, from Actions.
  assert.match(jobs.submit, /AGENT_JOB: \$\{\{ needs.agent.outputs.job \}\}/);
  const agentCall = fs.readFileSync(path.join(__dirname, '../.github/workflows/agent.yml'), 'utf8');
  assert.match(agentCall, /\n {6}job: \$\{\{ job.check_run_id \}\}\n/);
  assert.match(agentCall, /\n {6}job:\n {8}value: \$\{\{ jobs.agent.outputs.job \}\}\n/);
  assert.doesNotMatch(jobs.submit, /secrets|safe-outputs-artifact-id|pull_request\.head|needs\.policy\.outputs\.ref\b/);
  assert.match(jobs.status, /if: \$\{\{ !cancelled\(\) && needs.policy.outputs.review-head != '' && needs.policy.outputs.binary-artifact-id != '' && needs.agent.result != 'cancelled' \}\}/);
  assert.match(jobs.status, /runs-on: ubuntu-26.04/);
  // Automatic reviews only for the owner, members and collaborators;
  // anyone else, a past contributor included, waits for a `/review`.
  // A bot only by its user id in REVIEW_BOT_IDS, and only a Bot.
  const starts = policyStarts(jobs.policy);
  const dependabot = { login: 'dependabot[bot]', id: 49699333, type: 'Bot' };
  const listed = { REVIEW_BOT_IDS: '[49699333]' };
  for (const [name, author, vars, started, extra = {}] of [
    ['the owner', { type: 'User', id: 1 }, {}, true, { author_association: 'OWNER' }],
    ['a collaborator', { type: 'User', id: 1 }, {}, true, { author_association: 'COLLABORATOR' }],
    ['a past contributor', { type: 'User', id: 1 }, listed, false, { author_association: 'CONTRIBUTOR' }],
    ['a collaborator\'s draft', { type: 'User', id: 1 }, {}, false, { author_association: 'COLLABORATOR', draft: true }],
    ['Dependabot, listed', dependabot, listed, true],
    ['Dependabot, listed as a string', dependabot, { REVIEW_BOT_IDS: '["49699333"]' }, true],
    ['Dependabot, nothing listed', dependabot, {}, false],
    ['Dependabot, its id not in an array', dependabot, { REVIEW_BOT_IDS: '49699333' }, false],
    ['a bot whose id is part of a listed one', { login: 'x[bot]', id: 4969, type: 'Bot' }, { REVIEW_BOT_IDS: '"49699333"' }, false],
    ['Dependabot, another bot listed', dependabot, { REVIEW_BOT_IDS: '[29139614]' }, false],
    ['Dependabot\'s draft', dependabot, listed, false, { draft: true }],
    ['another bot', { login: 'renovate[bot]', id: 29139614, type: 'Bot' }, listed, false],
    ['a bot with Dependabot\'s login', { login: 'dependabot[bot]', id: 7, type: 'Bot' }, listed, false],
    ['a user with a listed id', { login: 'mallory', id: 49699333, type: 'User' }, listed, false],
  ]) {
    const pull = { draft: false, author_association: 'NONE', user: author, ...extra };
    assert.equal(starts({ event_name: 'pull_request_target', event: { pull_request: pull } }, vars), started, name);
  }
  const comment = body => ({ event_name: 'issue_comment', event: { issue: { pull_request: {} }, comment: { body } } });
  assert.equal(starts(comment('/review'), {}), true);
  assert.equal(starts(comment('please /review'), {}), false);
  assert.match(checker, /verdict=\$\("\$JOB_DIR\/agentic-job" review verdict --collected "\$GH_AW_TMP\/agent_output.json" --target "\$TARGET" --report "\$GH_AW_TMP\/report.json"\)/);
  const policy = fs.readFileSync(path.join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  assert.match(policy, /inputs.review && !inputs.review-item && \(github.event.pull_request.base.sha \|\| inputs.base\)/);
  // agentic-job.yml's agent job is agent.yml's, which takes the policy
  // call's outputs as check.yml does.
  const agent = fs.readFileSync(path.join(__dirname, '../.github/workflows/agent.yml'), 'utf8');
  assert.match(agent, /ref: \$\{\{ fromJSON\(inputs.policy\).ref \}\}/);
  assert.match(workflow, /\n {4}uses: \.\/\.github\/workflows\/agent\.yml .*\n(?: {4}.*\n)*? {6}policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}\n/);
  const check = workflow.split('\n  check:')[1].split('\n  apply:')[0];
  assert.match(check, /policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}/);
  assert.match(checker, /if: \$\{\{ fromJSON\(inputs.policy\).review == 'true' \}\}/);
  const applier = fs.readFileSync(path.join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
  const apply = applier.split('\n  apply:')[1].split('\n  conclude:')[0];
  assert.match(apply, /if: \$\{\{ fromJSON\(inputs.check\).outputs.has-patch == 'true' && fromJSON\(inputs.policy\).apply-staged != 'true' \}\}\s+with:\s+repository: \$\{\{ env.OUTPUT_REPO \}\}/);
  assert.doesNotMatch(apply, /pull_request.head|refs\/pull/);
  const ci = fs.readFileSync(path.join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  // Whether the base has the review files is read from the base commit.
  assert.match(ci, /e2e-review:\s+needs: \[changes, static\]\n\s+if: \$\{\{ needs\.changes\.outputs\.e2e == 'true' && needs\.changes\.outputs\.review == 'true' \}\}/);
  assert.match(ci, /git cat-file -t "\$BASE:\$file"/);
  assert.match(ci, /Exactly one scripted verdict was posted/);
  assert.match(ci, /HEAD_SHA: \$\{\{ github.event.pull_request.head.sha \}\}/);
  assert.match(ci, /contains\("Reviewed SHA: " \+ \$sha \+ "\\n"\)/);
  assert.match(ci, /\(\.key == "e2e-review" and \$review != "true"\)/);
});

test('target events read workflow policy without changing the trusted review base', () => {
  const policy = fs.readFileSync(path.join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  const checkout = policy.split('      # The calling repository, for its bounds file.')[1]
    .split('      # Logs, transcripts')[0].match(/ref: \$\{\{ (.*) \}\}/)[1];
  const base = policy.match(/^      ref: \$\{\{ (.*) \}\}/m)[1];
  const inputs = { review: true, 'review-item': '', base: 'main' };
  const evaluate = expression => Function('github', 'inputs',
    `return ${expression.replaceAll('inputs.review-item', 'inputs["review-item"]')}`);
  const github = { event_name: 'pull_request_target', workflow_sha: 'current-policy',
    sha: 'event-sha', event: { pull_request: { base: { sha: 'stale-base' } } } };
  assert.equal(evaluate(checkout)(github, inputs), 'current-policy');
  assert.equal(evaluate(base)(github, inputs), 'stale-base');
  github.event_name = 'pull_request';
  assert.equal(evaluate(checkout)(github, inputs), 'stale-base');
  inputs.review = false;
  assert.equal(evaluate(checkout)(github, inputs), 'event-sha');
});

test('refused event reviews update one author-owned bounded status comment', () => {
  const { upsert, MARKER } = require('./status.cjs');
  // As `agentic-job review refusal` writes it in the policy job.
  const reason = 'the bounds do not allow forks';
  const comments = [{ id: 1, user: { login: 'attacker' }, body: `copied\n\n${MARKER}` }];
  const calls = [];
  const api = (method, route, body) => {
    calls.push([method, route, body]);
    if (method === 'GET') return comments;
    if (method === 'POST') {
      const comment = { id: 2, user: { login: 'github-actions[bot]' }, body };
      comments.push(comment);
      return comment;
    }
    comments[1].body = body;
    return comments[1];
  };
  const env = { REPO: 'owner/repo', ITEM: '472', GITHUB_RUN_ID: '100', TEXT: `Review refused by policy: ${reason}` };
  upsert(env, api);
  upsert({ ...env, GITHUB_RUN_ID: '101' }, api);
  assert.equal(calls.filter(([method]) => method === 'POST').length, 1);
  assert.equal(calls.filter(([method]) => method === 'PATCH').length, 1);
  assert.equal(comments[1].body.split('\n')[0], `Review refused by policy: ${reason}`);
  const caller = fs.readFileSync(path.join(__dirname, '../.github/workflows/review.yml'), 'utf8');
  const refusal = caller.split('\n  refusal:\n')[1].split('\n  agent:\n')[0];
  assert.match(refusal, /needs.policy.outputs.admitted == 'false'/);
  assert.match(refusal, /ref: \$\{\{ needs.policy.outputs.source-sha \}\}/);
  assert.match(refusal, /TEXT: \$\{\{ needs.policy.outputs.refusal \}\}/);
  assert.match(refusal, /run: node .agentic-job-source\/workflow\/status.cjs/);
  const policy = fs.readFileSync(path.join(__dirname, '../.github/workflows/policy.yml'), 'utf8');
  assert.match(policy, /core.setOutput\('refusal', execFileSync\(process.env.JOB_DIR \+ '\/bin\/agentic-job', \['review', 'refusal'\]/);
  assert.match(refusal, /group: agentic-job-status-/);
});

// A caller sets AGENT_CONFIG only to override: without it, review and
// dispatch read this repository's hosted.toml at the called commit, from
// the checkout policy.yml makes of its own source, and no caller copies it.
test('review and dispatch default to this source\'s hosted.toml', () => {
  const read = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const source = '.agentic-job-source/';
  const hosted = `${source}.github/agentic-job/hosted.toml`;
  assert.ok(fs.statSync(path.join(__dirname, '..', hosted.slice(source.length))).isFile());
  // In the policy job, before the step that reads it.
  const policy = read('.github/workflows/policy.yml').split('\n  policy:\n')[1].split('- name: Write the configuration')[0];
  assert.match(policy,
    /\n          repository: \$\{\{ job\.workflow_repository \}\}\n          ref: \$\{\{ job\.workflow_sha \}\}\n          path: \.agentic-job-source\n/);
  // dispatch.yml's goes through agentic-job.yml unchanged.
  assert.match(read('.github/workflows/agentic-job.yml'), /^      config: \$\{\{ inputs\.config \}\}$/m);
  for (const file of ['review.yml', 'dispatch.yml']) {
    const expression = read(`.github/workflows/${file}`).match(/^      config: \$\{\{ (.+) \}\}$/m)?.[1];
    assert.ok(expression, file);
    const value = Function('inputs', 'vars', `return ${expression}`);
    for (const scripted of [false, true]) {
      assert.equal(value({ scripted }, {}), hosted, file);
      assert.equal(value({ scripted }, { AGENT_CONFIG: '' }), hosted, file);
      assert.equal(value({ scripted }, { AGENT_CONFIG: 'own.toml' }),
        file === 'dispatch.yml' && scripted ? hosted : 'own.toml', file);
    }
  }
});
