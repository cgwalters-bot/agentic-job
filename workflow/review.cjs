'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function refusalText(reason) {
  // Policy reasons can name event fields. Keep them inert and on one line;
  // a refusal must not turn a PR-controlled name into Markdown or a mention.
  const text = String(reason ?? '').replace(/[\x00-\x20\x7f]+/g, ' ').trim().slice(0, 1000)
    .replace(/[\\`*_{}\[\]()<>!#|~@]/g, '\\$&');
  return `Review refused by policy: ${text || 'no reason supplied'}`;
}

// Run only from the reusable workflow's pinned source, never from the review head.
function admit(decision, base) {
  if (!decision.admitted) return decision;
  const valid = decision.item?.kind === 'pull_request' &&
    Number.isSafeInteger(decision.item.number) && decision.item.number > 0 &&
    decision.base === base && /^[0-9a-f]{40}$/.test(decision.head?.sha ?? '') &&
    ((['pull_request', 'pull_request_target'].includes(decision.event) &&
      ['opened', 'synchronize', 'reopened', 'ready_for_review'].includes(decision.action)) ||
      (decision.event === 'issue_comment' && decision.action === 'created' &&
        decision.command === 'review'));
  return valid ? decision : { ...decision, admitted: false,
    reason: 'review requires an admitted pull request on the configured base, at an exact commit' };
}

function taskFile(root, name) {
  if (!name || path.isAbsolute(name) || name.split('/').some(p => !p || p === '..' || p === '.')) {
    throw new Error('Review task must be a relative repository file');
  }
  const file = path.join(root, name);
  if (fs.realpathSync(file) !== file || !fs.statSync(file).isFile() || fs.statSync(file).size > 65536) {
    throw new Error('Review task must be a regular file without symlinks, at most 64 KiB');
  }
  const task = fs.readFileSync(file, 'utf8');
  if (!task.trim()) throw new Error('Review task is empty');
  return task;
}

function checkRequest(env) {
  if (env.EVENT !== 'true' || env.KIND !== 'analysis' || env.OUTPUTS !== 'add_comment,noop' ||
      env.MAX_OUTPUTS !== '1' || env.NOTIFY !== 'none' || env.TARGET ||
      env.REPO !== env.GITHUB_REPOSITORY || env.OUTPUT_REPO || env.APPLY_ENVIRONMENT ||
      env.APPLY_PARTIAL !== 'false' || !['fake', 'claude', 'opencode', 'vibe'].includes(env.AGENT)) {
    throw new Error('Review requires an analysis event run, one comment or noop on the triggering repository, no notifications, alternate token or partial application, and a supported agent');
  }
}

// The verdict, for the `review` status: APPROVE or CHANGES, or '' for a
// noop, which approves nothing. REJECT, which briefs written before
// CHANGES still ask for, is read as CHANGES.
function checkOutputs(output, number) {
  if (!/^[1-9][0-9]*$/.test(String(number))) throw new Error('Review target must be a pull request number');
  if (!Array.isArray(output.items) || output.items.length !== 1) {
    throw new Error('Review must return exactly one comment or noop');
  }
  const item = output.items[0];
  if (item.type === 'noop') return '';
  // gh-aw recognizes aliases and editing/reply routes. The handler's trusted
  // configuration fixes the target: the agent supplies only text.
  if (item.type !== 'add_comment' || typeof item.body !== 'string' ||
      Object.keys(item).some(key => !['type', 'body'].includes(key))) {
    throw new Error('Review output must be a comment on the triggering pull request');
  }
  // One word, then the end of the line, a space or a stop; a first line
  // naming both is no verdict.
  const line = item.body.split('\n', 1)[0];
  const verdict = /^VERDICT: (APPROVE|CHANGES|REJECT)(?=$|[\s.,;:])/.exec(line)?.[1];
  if (!verdict || /APPROVE[\s\S]*(CHANGES|REJECT)|(CHANGES|REJECT)[\s\S]*APPROVE/.test(line)) throw new Error('Review comment must start with VERDICT: APPROVE or VERDICT: CHANGES');
  return verdict === 'APPROVE' ? verdict : 'CHANGES';
}

// The commit status `review` for one finished run, from its jobs' results
// and the open pull requests at the reviewed head, or `skip` with why it
// sets none. It reads no agent text: the verdict is one of two words
// check set, and success needs a checked APPROVE whose comment was posted.
// A status belongs to the commit, so it is set only when the triggering
// pull request is the one open there (docs/review.md).
function reviewStatus(run, open) {
  if (!/^[0-9a-f]{40}$/.test(run.head ?? '') || !/^[1-9][0-9]*$/.test(run.pull ?? '') ||
      !Number.isSafeInteger(Number(run.pull))) {
    throw new Error('Review status requires a pull request number and an exact head SHA');
  }
  if (open.length !== 1 || open[0] !== Number(run.pull)) {
    return { skip: `No review status on ${run.head}: its open pull requests are ${open.join(', ') || 'none'}, not only #${run.pull}` };
  }
  const checked = run.check === 'success';
  if (checked && run.verdict === 'APPROVE' && run.apply === 'success' && run.url) {
    return { state: 'success', description: 'The review approved this commit' };
  }
  if (checked && run.verdict === 'CHANGES') {
    return { state: 'failure', description: 'The review asked for changes' };
  }
  return { state: 'failure', description: 'The review did not approve this commit' };
}

async function reportStatus(env, github, core) {
  const run = { pull: env.PULL, head: env.HEAD_SHA, check: env.CHECK_RESULT,
    verdict: env.VERDICT, apply: env.APPLY_RESULT, url: env.RESULT_URL };
  // Validate before the head goes into any request.
  reviewStatus(run, [Number(run.pull)]);
  const [owner, repo] = env.GITHUB_REPOSITORY.split('/');
  const pulls = await github.paginate(github.rest.pulls.list, { owner, repo, state: 'open', per_page: 100 });
  const status = reviewStatus(run, pulls.filter(pull => pull.head?.sha === run.head).map(pull => pull.number));
  if (status.skip) {
    core.notice(status.skip);
    return status;
  }
  await github.rest.repos.createCommitStatus({ owner, repo, sha: run.head, context: 'review',
    state: status.state, description: status.description, target_url: env.RUN_URL });
  return status;
}

// The review's own gate: the workflow, script and task that decide and
// submit approvals, the reusable workflows it calls to admit the event,
// validate its output and apply it, their review-path helpers and admission
// configuration, the selected agent configuration it composes (which can
// select the reviewer's instructions), the workflow-ingress check and its
// analyzer configuration, and the ruleset settings in docs/review.md. Other
// workflow changes are approved on the review's judgement like any change,
// with the base branch's required ingress check
// as their deterministic guard. A change to these would otherwise merge on
// an approval from the very gate it weakens, with nobody reading it.
const GATE_FILES = new Set(['.github/workflows/review.yml', '.github/workflows/policy.yml',
  '.github/workflows/check.yml', '.github/workflows/apply.yml', '.github/workflows/workflow-ingress.yml',
  '.github/agentic-job/hosted.toml',
  'workflow/review.cjs', 'workflow/review.md', 'workflow/activation.cjs',
  'workflow/policy-command.cjs', 'workflow/status.cjs', 'workflow/review.toml',
  'workflow/review-command.toml', 'workflow/ingress.py', 'workflow/actionlint.yaml', 'docs/review.md']);

// First line of the COMMENT review left in place of a withheld approval.
// Agent text never starts a review body (its first line is VERDICT:), so
// a poll can match this line exactly and label the pull request.
const WITHHELD = "Approval withheld: this pull request changes the review's own gate and needs a human approval.";

// This job runs only base-revision code.
async function submitReview(env, github, core) {
  if (env.REAL_REVIEWS !== 'true') return;
  const run = { pull: env.PULL, head: env.HEAD_SHA, check: env.CHECK_RESULT,
    verdict: env.VERDICT, apply: env.APPLY_RESULT, url: env.RESULT_URL };
  reviewStatus(run, [Number(run.pull)]); // Validate the target before API calls.
  if (run.check !== 'success' || run.apply !== 'success' || !run.url ||
      !['APPROVE', 'CHANGES'].includes(run.verdict)) return;
  const [owner, repo] = env.GITHUB_REPOSITORY.split('/');
  const target = { owner, repo, pull_number: Number(run.pull) };
  const { data: pull } = await github.rest.pulls.get(target);
  if (pull.state !== 'open' || pull.head.sha !== run.head) {
    core.notice('No review submitted: the reviewed head is no longer current');
    return;
  }
  // Fail closed rather than paginate an unbounded diff. Renames must check
  // both names so moving gate code out does not evade the human gate.
  if (!Number.isSafeInteger(pull.changed_files) || pull.changed_files < 0 || pull.changed_files > 300) {
    throw new Error('Real review requires at most 300 changed files');
  }
  const { data: files } = await github.rest.pulls.listFiles({ ...target, per_page: 100, page: 1 });
  for (let page = 2; files.length < pull.changed_files && page <= 3; page++) {
    const { data } = await github.rest.pulls.listFiles({ ...target, per_page: 100, page });
    files.push(...data);
  }
  if (files.length !== pull.changed_files) throw new Error('Incomplete review file list');
  const config = path.posix.normalize(env.AGENT_CONFIG || '.github/agentic-job/hosted.toml');
  const gate = files.some(file => [file.filename, file.previous_filename]
    .some(name => GATE_FILES.has(name) || name === config));
  const prefix = `https://github.com/${env.GITHUB_REPOSITORY}/pull/${run.pull}#issuecomment-`;
  const id = run.url.startsWith(prefix) ? run.url.slice(prefix.length) : '';
  if (!/^[1-9][0-9]*$/.test(id) || !Number.isSafeInteger(Number(id))) {
    throw new Error('Review body must come from the applied comment on this pull request');
  }
  const { data: comment } = await github.rest.issues.getComment({ owner, repo, comment_id: Number(id) });
  if (comment.issue_url !== `https://api.github.com/repos/${env.GITHUB_REPOSITORY}/issues/${run.pull}` ||
      checkOutputs({ items: [{ type: 'add_comment', body: comment.body }] }, run.pull) !== run.verdict) {
    throw new Error('Applied comment does not match the checked review');
  }
  // commit_id prevents a racing push from making this an approval of new code;
  // stale-review dismissal in the branch ruleset is also required.
  if (run.verdict === 'APPROVE' && gate) {
    core.notice(WITHHELD);
    await github.rest.pulls.createReview({ ...target, commit_id: run.head,
      event: 'COMMENT', body: `${WITHHELD}\n\n${comment.body}` });
    return;
  }
  await github.rest.pulls.createReview({ ...target, commit_id: run.head,
    event: run.verdict === 'APPROVE' ? 'APPROVE' : 'REQUEST_CHANGES', body: comment.body });
}

async function resolveDispatch(env, github) {
  if (env.REVIEW !== 'true' || env.EVENT !== 'false' || env.KIND !== 'analysis' ||
      env.OUTPUTS !== 'add_comment,noop' || env.MAX_OUTPUTS !== '1' ||
      env.NOTIFY !== 'none' || env.APPLY_PARTIAL !== 'false' ||
      (env.OUTPUT_REPO && env.OUTPUT_REPO !== env.REPO) ||
      env.TARGET !== env.ITEM || !/^[1-9][0-9]*$/.test(env.ITEM) ||
      !Number.isSafeInteger(Number(env.ITEM)) ||
      !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.REPO)) {
    throw new Error('Dispatch review requires one verdict or noop on the selected PR, analysis only, no event, notifications or partial apply');
  }
  const [owner, repo] = env.REPO.split('/');
  const { data } = await github.rest.pulls.get({ owner, repo, pull_number: Number(env.ITEM) });
  // Bind the review to the target PR and exact commit, not its source repository
  // or author-controlled branch. The sandbox fetches this SHA from the target
  // without forge credentials; accepting a fork adds no write authority.
  if (data.number !== Number(env.ITEM) || data.state !== 'open' ||
      data.base?.ref !== env.BASE || data.base?.repo?.full_name !== env.REPO ||
      !/^[0-9a-f]{40}$/.test(data.head?.sha ?? '')) {
    throw new Error('Dispatch review requires an open PR on the configured base with an exact head SHA');
  }
  return data.head.sha;
}

if (require.main === module) {
  const [command, file, number] = process.argv.slice(2);
  if (command === 'task') {
    checkRequest(process.env);
    process.stdout.write(taskFile(process.cwd(), file));
  } else if (command === 'check') {
    checkOutputs(JSON.parse(fs.readFileSync(file, 'utf8')), number);
  } else if (command === 'refusal') {
    execFileSync(process.execPath, [path.join(__dirname, 'status.cjs')], {
      env: { ...process.env, TEXT: refusalText(process.env.REASON) }, stdio: 'inherit',
    });
  } else {
    throw new Error('Expected task, check or refusal');
  }
}

module.exports = { WITHHELD, admit, taskFile, checkRequest, checkOutputs, reviewStatus, reportStatus, submitReview, resolveDispatch, refusalText };
