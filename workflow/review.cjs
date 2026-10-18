'use strict';

const crypto = require('node:crypto');
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

// Why GitHub refused a submission, from the error octokit raises: the
// response body's message and errors, never its headers or URL, which
// hold the credential and the request. One line, bounded: an annotation
// is one line. The caller escapes the message again for the comment that
// explains a refusal, where it must stay inert.
function reviewRefusal(error) {
  const data = error?.response?.data;
  if (!Number.isInteger(error?.status) || data === null || typeof data !== 'object') return null;
  const line = (text, max) => String(text ?? '').replace(/[\x00-\x20\x7f]+/g, ' ').trim().slice(0, max);
  return { message: line(data.message, 400),
    errors: Array.isArray(data.errors) ? line(JSON.stringify(data.errors), 250) : '' };
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

// Inline findings next to the verdict (#516): at most this many, held to
// the triggering pull request by check like any review comment. Folded
// into one body, as apply posts them when nothing was submitted, the
// verdict and its findings stay under GitHub's 65536-character limit for a
// comment or review body, with room for the footer and markers added after.
const REVIEW_COMMENT = 'create_pull_request_review_comment';
const REVIEW_COMMENTS_MAX = 10;
const REVIEW_BODY_MAX = 60000;
const REVIEW_PATH_MAX = 1024;

// review.yml's request, or the verdict alone, which CI's e2e-review still
// makes: it reads the bounds and scripted agent from the pull request's
// base, so it moves to inline comments only once they are on main.
function checkRequest(env) {
  const request = `${env.OUTPUTS}/${env.MAX_OUTPUTS}`;
  if (env.EVENT !== 'true' || env.KIND !== 'analysis' ||
      ![`add_comment,noop,${REVIEW_COMMENT}/${1 + REVIEW_COMMENTS_MAX}`, 'add_comment,noop/1'].includes(request) ||
      env.NOTIFY !== 'none' || env.TARGET ||
      env.REPO !== env.GITHUB_REPOSITORY || env.OUTPUT_REPO || env.APPLY_ENVIRONMENT ||
      env.APPLY_PARTIAL !== 'false' || !['fake', 'claude', 'opencode', 'vibe'].includes(env.AGENT)) {
    throw new Error('Review requires an analysis event run, one comment or noop and its inline comments on the triggering repository, no notifications, alternate token or partial application, and a supported agent');
  }
}

const positive = value => ['number', 'string'].includes(typeof value) &&
  /^[1-9][0-9]*$/.test(String(value)) && Number.isSafeInteger(Number(value));

// One inline finding: a line, or lines, of the triggering pull request's
// diff. Check (src/check) already holds it to that pull request; here it
// also names no repository, and has only fields the review can carry.
function checkInline(item, number) {
  if (Object.keys(item).some(key => !['type', 'path', 'line', 'start_line', 'side', 'body', 'pull_request_number'].includes(key)) ||
      typeof item.body !== 'string' || !item.body.trim() ||
      typeof item.path !== 'string' || !item.path || item.path.length > REVIEW_PATH_MAX ||
      /[\x00-\x1f\x7f]/.test(item.path) || !positive(item.line) ||
      (item.start_line !== undefined && (!positive(item.start_line) || Number(item.start_line) > Number(item.line))) ||
      (item.side !== undefined && !['LEFT', 'RIGHT'].includes(item.side)) ||
      (item.pull_request_number !== undefined &&
        (!positive(item.pull_request_number) || String(item.pull_request_number) !== String(number)))) {
    throw new Error('Review inline comment must be a body on a path and line of the triggering pull request');
  }
}

// Where an inline finding was, as plain text: a path is agent text that
// gh-aw does not sanitize, so it is kept to one inert line, as refusalText
// keeps a reason, and can neither mention anyone nor become markup.
function inlineAnchor(item) {
  const file = item.path.replace(/[\\`*_{}\[\]()<>!#|~@]/g, '\\$&');
  const lines = item.start_line !== undefined && Number(item.start_line) < Number(item.line)
    ? `lines ${item.start_line}-${item.line}` : `line ${item.line}`;
  return `${file}, ${lines}${item.side === 'LEFT' ? ' of the base' : ''}`;
}

// Inline findings that are not inline comments, appended to the verdict's
// body after its first line, which stays VERDICT:.
function inlineSection(items) {
  if (!items.length) return '';
  return `\n\n### Inline findings\n${items.map(item => `\n**${inlineAnchor(item)}**\n\n${item.body}\n`).join('')}`;
}

// What apply posts when nothing was submitted: the verdict comment with
// every inline finding in its body, and no review comments beside it, so
// they are neither lost nor posted as a second review without a verdict.
function foldInline(output) {
  const inline = output.items.filter(item => item.type === REVIEW_COMMENT);
  if (!inline.length) return output;
  return { ...output, items: output.items.filter(item => item.type !== REVIEW_COMMENT)
    .map(item => item.type === 'add_comment' ? { ...item, body: item.body + inlineSection(inline) } : item) };
}

// The verdict, for the `review` status: APPROVE or CHANGES, or '' for a
// noop, which approves nothing. REJECT, which briefs written before
// CHANGES still ask for, is read as CHANGES. Inline comments may come
// with a verdict comment, never with a noop, which apply would not post.
function checkOutputs(output, number) {
  if (!/^[1-9][0-9]*$/.test(String(number))) throw new Error('Review target must be a pull request number');
  const items = Array.isArray(output.items) ? output.items.filter(item => item?.type !== REVIEW_COMMENT) : [];
  if (items.length !== 1) {
    throw new Error('Review must return exactly one comment or noop');
  }
  const inline = output.items.filter(item => item?.type === REVIEW_COMMENT);
  if (inline.length > REVIEW_COMMENTS_MAX) {
    throw new Error(`Review may return at most ${REVIEW_COMMENTS_MAX} inline comments`);
  }
  const item = items[0];
  if (item.type === 'noop') {
    if (inline.length) throw new Error('Review inline comments need a verdict comment, not a noop');
    return '';
  }
  for (const comment of inline) checkInline(comment, number);
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
  if ((item.body + inlineSection(inline)).length > REVIEW_BODY_MAX) {
    throw new Error(`Review comment and inline comments together must be at most ${REVIEW_BODY_MAX} characters`);
  }
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

// The visible footer gh-aw's handler puts on a comment (messages_footer.cjs,
// "> Generated by [workflow](run) for #N"), which a submitted review would
// otherwise lack: without it a reader of an approval cannot get to the job
// that made it (#592). Everything in it is this job's own context, never
// agent output, so the review text cannot choose where it points; a footer
// the text imitates comes before this one, which is last. As with gh-aw's
// own footer, text that leaves a <details> or code fence open can still
// fold this footer away or show it as code, under an imitation above it;
// the raw body still ends with this one. It links the agent job where its ID
// is known, else the run, and names the head the verdict is for, as the
// review's commit_id binds it.
function reviewFooter(env, runUrl, run) {
  const job = /^[1-9][0-9]*$/.test(env.AGENT_JOB ?? '') ? `${runUrl}/job/${env.AGENT_JOB}` : runUrl;
  // A workflow's name is the repository's; it is kept to plain characters
  // so that it neither ends the link text nor mentions anyone.
  const name = String(env.GITHUB_WORKFLOW || '').replace(/[^\w .:()-]/g, ' ').trim() || 'review';
  return `> Generated by [${name}](${job}) for #${run.pull} at ${run.head}`;
}

// The lines a review comment can sit on, from the pull request's files as
// the API lists them: for each path and side, each line of the diff with
// the hunk it is in. A file without a `patch` (binary, or too large for
// the API to show) has none.
function diffLines(files) {
  const lines = new Map();
  for (const file of files) {
    if (typeof file.filename !== 'string' || typeof file.patch !== 'string') continue;
    const sides = { LEFT: new Map(), RIGHT: new Map() };
    let left = 0, right = 0, hunk = -1;
    for (const line of file.patch.split('\n')) {
      const start = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      if (start) {
        [left, right] = [Number(start[1]), Number(start[2])];
        hunk += 1;
      } else if (hunk < 0 || line === '' || line.startsWith('\\')) {
        // A context line is never empty (it starts with a space): this is
        // the end of a patch that ends in a newline.
        continue;
      } else if (line.startsWith('+')) {
        sides.RIGHT.set(right++, hunk);
      } else if (line.startsWith('-')) {
        sides.LEFT.set(left++, hunk);
      } else {
        sides.LEFT.set(left++, hunk);
        sides.RIGHT.set(right++, hunk);
      }
    }
    lines.set(file.filename, sides);
  }
  return lines;
}

// The review comment for an inline finding, or null where GitHub would
// refuse its anchor and with it the whole review: a path or line outside
// the diff, or lines across hunks.
function reviewComment(lines, item) {
  const side = item.side ?? 'RIGHT';
  const line = Number(item.line);
  const start = item.start_line === undefined ? line : Number(item.start_line);
  const hunk = lines.get(item.path)?.[side].get(line);
  if (hunk === undefined || lines.get(item.path)[side].get(start) !== hunk) return null;
  return { path: item.path, line, side, ...(start < line ? { start_line: start, start_side: side } : {}), body: item.body };
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
  // Inline findings go in the same review, as its comments, where their
  // lines are in the diff of the head just read, and the rest in its body,
  // so a bad anchor loses nothing and fails nothing. The files are read
  // only to place comments, never to decide whether to approve (#540). At
  // the same head the split, and so the body, is the same on a re-run.
  const inline = output.items.filter(item => item.type === REVIEW_COMMENT);
  const lines = inline.length ? diffLines(await github.paginate(github.rest.pulls.listFiles, { ...target, per_page: 100 })) : new Map();
  const placed = inline.map(item => reviewComment(lines, item));
  const verdict = output.items.find(item => item.type === 'add_comment').body;
  const anchored = placed.filter(Boolean);
  // The anchored comments are not in the body text, so their digest is, to
  // make them part of the review's identity below: a re-run at this head
  // whose verdict is the same but whose inline findings differ is another
  // review, not the earlier one found again with these findings lost.
  const digest = anchored.length
    ? `<!-- agentic-job-review-comments: ${crypto.createHash('sha256').update(JSON.stringify(anchored)).digest('hex')} -->\n\n`
    : '';
  const body = `${verdict}${inlineSection(inline.filter((_, i) => !placed[i]))}\n\n${reviewFooter(env, runUrl, run)}\n\n${digest}${marker}`;
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
  // verdict and body; a re-run of all jobs submits its own, whose footer
  // links its own agent job, and pollers take it as the latest.
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
    ({ data } = await github.rest.pulls.createReview({ ...target, commit_id: run.head, event, body,
      ...(anchored.length ? { comments: anchored } : {}) }));
  } catch (error) {
    // Posted all the same, the review is not to be posted again as the comment.
    const posted = await earlier().catch(() => undefined);
    if (posted) return posted;
    const refusal = reviewRefusal(error);
    if (Number.isInteger(error?.status)) {
      const why = refusal ? [refusal.message, refusal.errors && `errors: ${refusal.errors}`].filter(Boolean).join('; ') : '';
      core.error(`Submitting the review failed: status ${error.status}${why ? ` (${why})` : ''}`);
    }
    if (Number.isInteger(error?.status) && error.status === 422) {
      // GitHub refused the submission (a locked conversation, for example):
      // the verdict is posted as the plain comment apply would otherwise
      // post, saying the review could not be submitted and why, so the pull
      // request does not sit blocked with no explanation. Its URL counts as
      // posted for the status, and apply posts nothing beside it.
      const folded = foldInline(output);
      const why = refusal?.message.replace(/[\\`*_{}\[\]()<>!#|~@]/g, '\\$&');
      const comment = `${folded.items.find(item => item.type === 'add_comment').body}\n\n` +
        `The review could not be submitted: GitHub refused it with status 422${why ? ` (${why})` : ''}.\n\n` +
        `${reviewFooter(env, runUrl, run)}\n\n${marker}`;
      const { data } = await github.rest.issues.createComment({ owner, repo, issue_number: Number(run.pull), body: comment });
      return data.html_url || `https://github.com/${env.GITHUB_REPOSITORY}/pull/${run.pull}#issuecomment-${data.id}`;
    }
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
  } else if (command === 'fold') {
    // apply.yml, on check's accepted output, in place.
    const output = JSON.parse(fs.readFileSync(file, 'utf8'));
    const folded = foldInline(output);
    if (folded !== output) fs.writeFileSync(file, JSON.stringify(folded));
  } else if (command === 'refusal') {
    execFileSync(process.execPath, [path.join(__dirname, 'status.cjs')], {
      env: { ...process.env, TEXT: refusalText(process.env.REASON) }, stdio: 'inherit',
    });
  } else {
    throw new Error('Expected task, check, fold or refusal');
  }
}

module.exports = { admit, taskFile, mergePolicy, mergeStatement, checkRequest, checkOutputs, foldInline, diffLines, reviewStatus, reportStatus, submitReview, resolveDispatch, refusalText };
