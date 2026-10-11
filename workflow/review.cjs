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
      ['opened', 'synchronize', 'ready_for_review'].includes(decision.action)) ||
      (decision.event === 'issue_comment' && decision.action === 'created' &&
        decision.command === 'review'));
  return valid ? decision : { ...decision, admitted: false,
    reason: 'review requires an admitted same-repository pull request on the configured base' };
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

function checkOutputs(output, number) {
  if (!/^[1-9][0-9]*$/.test(String(number))) throw new Error('Review target must be a pull request number');
  if (!Array.isArray(output.items) || output.items.length !== 1) {
    throw new Error('Review must return exactly one comment or noop');
  }
  const item = output.items[0];
  if (item.type === 'noop') return;
  // gh-aw recognizes aliases and editing/reply routes. The handler's trusted
  // configuration fixes the target: the agent supplies only text.
  if (item.type !== 'add_comment' || typeof item.body !== 'string' ||
      Object.keys(item).some(key => !['type', 'body'].includes(key))) {
    throw new Error('Review output must be a comment on the triggering pull request');
  }
  const lines = item.body.split('\n');
  if (!/^VERDICT: (APPROVE|CHANGES|REJECT)$/.test(lines[0]) ||
      !/^REASON: [^\r\n\x00-\x1f\x7f]+$/u.test(lines[1] ?? '') ||
      Array.from(lines[1]).length > 200) {
    throw new Error('Review comment requires VERDICT and a REASON line of at most 200 characters');
  }
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

module.exports = { admit, taskFile, checkRequest, checkOutputs, resolveDispatch };
