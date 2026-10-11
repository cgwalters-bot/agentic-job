'use strict';

const fs = require('node:fs');
const path = require('node:path');

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
      env.APPLY_PARTIAL !== 'false' || !['fake', 'claude', 'opencode'].includes(env.AGENT)) {
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
  } else {
    throw new Error('Expected task or check');
  }
}

module.exports = { admit, taskFile, checkRequest, checkOutputs, reviewStatus, reportStatus, resolveDispatch };
