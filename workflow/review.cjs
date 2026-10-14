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

// The repository owner's merge policy, read from the same trusted checkout
// of the default branch as the task (policy.yml), never the head. It used to live only in prose (the task and
// operator notes), so reviewers at older pins kept arguing whether a
// person should be required (#556). One line, `merge = "agent"` or
// `merge = "person"`, among blank lines and comments; anything else fails
// the run rather than guess. No file is `person`, which `set` tells apart
// from the owner's choice. Check refuses a patch to this file, as to
// CODEOWNERS (src/check/patch.rs), so no agent can propose its own merge
// authority.
const MERGE_POLICY_FILE = '.github/agentic-job/merge.toml';
const MERGE_POLICY_MAX_BYTES = 4096;

function mergePolicy(root) {
  const file = path.join(root, MERGE_POLICY_FILE);
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') return { merge: 'person', set: false };
    throw error;
  }
  if (fs.realpathSync(file) !== file || !stat.isFile() || stat.size > MERGE_POLICY_MAX_BYTES) {
    throw new Error(`${MERGE_POLICY_FILE} must be a regular file without symlinks, at most 4 KiB`);
  }
  const values = [];
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (/^\s*(#.*)?$/.test(line)) continue;
    const value = /^merge = "(agent|person)"\s*$/.exec(line)?.[1];
    if (!value) throw new Error(`${MERGE_POLICY_FILE} may hold only merge = "agent" or merge = "person"`);
    values.push(value);
  }
  if (values.length !== 1) throw new Error(`${MERGE_POLICY_FILE} must set merge exactly once`);
  return { merge: values[0], set: true };
}

// What the reviewer is told, as a fact rather than a question for it to
// weigh. Either way it reviews as hard: an APPROVE is submitted whatever
// the policy, and only the ruleset decides what that approval merges. Code
// owners' paths wait for their owner where the ruleset requires it; the
// verdict names them so the pull request says why it waits, and names any
// change to who decides, which a person's pull request can still propose.
function mergeStatement({ merge, set }) {
  const source = set
    ? `The repository owner set this in ${MERGE_POLICY_FILE} on the default branch`
    : `The default branch has no ${MERGE_POLICY_FILE}, so the default holds`;
  const who = merge === 'agent'
    ? 'merge = "agent": an approving review from this job merges the pull request by default, ' +
      'so no person approves after you. Do not ask for changes because no person stands behind ' +
      'a change; review it harder instead, naming the worst merged outcome and what stops it.'
    : 'merge = "person": the repository expects a person to approve every merge after you. ' +
      'Review as hard as if your approval merged.';
  return `\n\n## Merge policy\n\n${source}; it is a fact, not a question for this review: ${who}\n` +
    'Where the ruleset requires code-owner review, paths that the base\'s CODEOWNERS file ' +
    '(in .github/, the root or docs/, the first GitHub finds) assigns an owner also wait for that ' +
    'owner, whatever your verdict; you cannot see the ruleset, so review those paths as hard as any ' +
    'other. If the pull request changes any, or changes the merge policy file or a CODEOWNERS file, ' +
    'which changes who decides, add a line after the verdict line: "Needs the owner\'s review: " ' +
    'and those paths.\n';
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
  // configuration fixes the target. A redundant item_number cannot redirect
  // the comment; aliases and editing/reply routes remain forbidden.
  if (item.type !== 'add_comment' || typeof item.body !== 'string' ||
      Object.keys(item).some(key => !['type', 'body', 'item_number'].includes(key)) ||
      (Object.hasOwn(item, 'item_number') &&
        (!/^[1-9][0-9]*$/.test(String(item.item_number)) ||
          !['number', 'string'].includes(typeof item.item_number) ||
          !Number.isSafeInteger(Number(item.item_number)) ||
          String(item.item_number) !== String(number)))) {
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
// check set, and success needs a checked APPROVE that was posted, as the
// submitted review or else apply's comment.
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
  const posted = run.review || (run.apply === 'success' && run.url);
  if (run.check !== 'success' || !posted) {
    return { state: 'failure', description: 'The review did not post; see the workflow run' };
  }
  if (run.verdict === 'APPROVE') {
    return { state: 'success', description: 'The review approved this commit' };
  }
  if (run.verdict === 'CHANGES') {
    return { state: 'failure', description: 'The review asked for changes' };
  }
  return { state: 'failure', description: 'The review did not approve this commit' };
}

async function reportStatus(env, github, core) {
  const run = { pull: env.PULL, head: env.HEAD_SHA, check: env.CHECK_RESULT,
    verdict: env.VERDICT, apply: env.APPLY_RESULT, url: env.RESULT_URL, review: env.REVIEW_URL };
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

// With real reviews on, the verdict is posted once, as the pull request's
// review, and apply posts no comment (#583). The body is check's accepted
// output, read from check's upload in this run, so what is submitted is
// exactly what check and the collector's sanitizing passed, never text read
// back from the forge. Nothing submitted (off, a noop, a run stopped at a
// limit, a moved head, a failed submission) leaves the comment to apply as
// before. This job runs only base-revision code.
async function submitReview(env, output, github, core) {
  if (env.REAL_REVIEWS !== 'true') return '';
  const run = { pull: env.PULL, head: env.HEAD_SHA, verdict: env.VERDICT };
  reviewStatus(run, [Number(run.pull)]); // Validate the target before API calls.
  // apply-partial is false for a review (checkRequest): a run stopped at a
  // limit is not applied, so it is not submitted either.
  if (env.CHECK_RESULT !== 'success' || env.AGENT_EXIT !== '0' ||
      !['APPROVE', 'CHANGES'].includes(run.verdict)) return '';
  if (checkOutputs(output, run.pull) !== run.verdict) {
    throw new Error('Checked output does not match the checked verdict');
  }
  const [owner, repo] = env.GITHUB_REPOSITORY.split('/');
  const target = { owner, repo, pull_number: Number(run.pull) };
  const { data: pull } = await github.rest.pulls.get(target);
  if (pull.state !== 'open' || pull.head.sha !== run.head) {
    core.notice('No review submitted: the reviewed head is no longer current');
    return '';
  }
  if (!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? '')) throw new Error('Review submission requires this run\'s ID');
  // The run marker gh-aw's handler ends a comment with (generate_footer.cjs).
  // agent-board's poll (board-forge/src/poll.rs, cited_run) needs exactly
  // one, with its run URL, to tie the review to this run.
  const runUrl = `https://github.com/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`;
  const marker = `<!-- gh-aw-agentic-workflow: review, id: ${env.GITHUB_RUN_ID}, workflow_id: agentic-job, run: ${runUrl} -->`;
  const body = `${output.items[0].body}\n\n${marker}`;
  const event = run.verdict === 'APPROVE' ? 'APPROVE' : 'REQUEST_CHANGES';
  // A re-run of failed jobs after a failed submission, whose verdict apply
  // then posted as the comment, must not post it again as the review. Apply
  // names each comment it posts by run, last in the body (its
  // `agentic-job-applied` name, which check refuses in agent output). Only a
  // comment by the job token's bot or someone with write access counts, as
  // with the PAT: a commenter quoting the name must not turn the review back
  // into a comment.
  const comments = await github.paginate(github.rest.issues.listComments,
    { owner, repo, issue_number: Number(run.pull), per_page: 100 });
  if (comments.some(c => (c.user?.login === 'github-actions[bot]' ||
      ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(c.author_association)) &&
      [...String(c.body).matchAll(/<!-- agentic-job-applied: (\d+)\/\d+\/[0-9a-f]{16} -->/g)].at(-1)?.[1] === env.GITHUB_RUN_ID)) {
    core.notice('No review submitted: an earlier attempt of this run posted the verdict as a comment');
    return '';
  }
  // Nor is a review submitted twice: after a re-run, or a submission whose
  // response was lost. Only the same review counts, at this head with this
  // verdict and body; a re-run of all jobs that reached another verdict
  // submits its own, which pollers take as the latest.
  const earlier = async () => (await github.paginate(github.rest.pulls.listReviews, { ...target, per_page: 100 }))
    .find(r => r.user?.login === 'github-actions[bot]' && r.commit_id === run.head &&
      r.state === (event === 'APPROVE' ? 'APPROVED' : 'CHANGES_REQUESTED') && r.body === body)?.html_url;
  const found = await earlier();
  if (found) return found;
  // commit_id prevents a racing push from making this an approval of new code;
  // stale-review dismissal in the branch ruleset is also required. An APPROVE
  // is submitted whatever files the pull request changes, the workflows and
  // this review's own files included (#540): whether it suffices to merge is
  // the merge policy and GitHub's code-owner rule (docs/review.md), and the
  // required ci and workflow-ingress checks stay its deterministic guard.
  let data;
  try {
    ({ data } = await github.rest.pulls.createReview({ ...target, commit_id: run.head, event, body }));
  } catch (error) {
    // Posted all the same, the review is not to be posted again as the comment.
    const posted = await earlier().catch(() => undefined);
    if (posted) return posted;
    throw error;
  }
  return data.html_url || `https://github.com/${env.GITHUB_REPOSITORY}/pull/${run.pull}#pullrequestreview-${data.id}`;
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
    process.stdout.write(taskFile(process.cwd(), file) + mergeStatement(mergePolicy(process.cwd())));
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

module.exports = { admit, taskFile, mergePolicy, mergeStatement, checkRequest, checkOutputs, reviewStatus, reportStatus, submitReview, resolveDispatch, refusalText };
