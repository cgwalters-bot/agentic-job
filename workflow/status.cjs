'use strict';

const { execFileSync } = require('node:child_process');
const { appendFileSync } = require('node:fs');
const MARKER = '<!-- agentic-job-status -->';
const MAX_PAGES = 20;
const RUN_MARKER = /\n\n<!-- agentic-job-run: ([1-9][0-9]*) -->\n\n<!-- agentic-job-status -->$/;
// One whole hidden comment per line, nothing visible around it: a caller's
// `<!-- tag: {...} -->` state. Not ours, so a status never keeps its own markers.
const CALLER_MARKER = /^<!--(?!\s*agentic-job-)(?:(?!-->).)*-->$/;

// A slower older run must not replace the current run's status.
const newer = (body, run) => {
  const previous = String(body).match(RUN_MARKER);
  return previous && BigInt(previous[1]) > BigInt(run);
};

// The caller's comment for the item (STATUS_COMMENT), when it is one the
// status may edit: the same credential's author, on this repository's
// item. Otherwise null, and the status goes in the marked comment, so a
// dispatcher's id can neither edit someone else's words nor move the
// status to another item.
function named(env, api, repo, item, author, summary) {
  const id = env.STATUS_COMMENT;
  if (!id) return null;
  if (!/^[1-9][0-9]*$/.test(id)) {
    summary('Status comment: STATUS_COMMENT is not a comment id; using the marked status comment.');
    return null;
  }
  let comment;
  try {
    comment = api('GET', `repos/${repo}/issues/comments/${id}`);
  } catch {
    summary(`Status comment: comment ${id} could not be read; using the marked status comment.`);
    return null;
  }
  const where = String(comment?.issue_url ?? '').toLowerCase();
  if (comment?.user?.login !== author || !where.endsWith(`/repos/${repo.toLowerCase()}/issues/${item}`)) {
    summary(`Status comment: comment ${id} is not ${author}'s on ${repo}#${item}; using the marked status comment.`);
    return null;
  }
  return comment;
}

function upsert(env, api, summary = () => {}) {
  const { REPO: repo, ITEM: item, TEXT: text, GITHUB_RUN_ID: run } = env;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo ?? '') || !/^[1-9][0-9]*$/.test(item ?? '')) {
    throw new Error('status requires a caller repository and numeric item');
  }
  if (!/^[1-9][0-9]*$/.test(run ?? '')) throw new Error('status requires a numeric Actions run ID');
  // Apply already bounded, sanitized and quoted this text. Decode only here,
  // after it has crossed shell/job outputs as a single JSON string.
  const reason = env.NO_RESULT_REASON ? ` Its reason:\n\n${JSON.parse(env.NO_RESULT_REASON)}` : '';
  const body = `${text}${reason}\n\n<!-- agentic-job-run: ${run} -->\n\n${MARKER}`;
  const crossRepo = repo.toLowerCase() !== (env.GITHUB_REPOSITORY ?? repo).toLowerCase();
  if (crossRepo && !env.STATUS_TOKEN) {
    summary('Status comment skipped: cross-repository target requires the caller-supplied SAFE_OUTPUTS_PAT.');
    return null;
  }
  // The credential's identity plus the marker prevents copied markers redirecting edits.
  const author = env.STATUS_TOKEN ? api('GET', 'user').login : 'github-actions[bot]';
  if (!author) throw new Error('status token has no authenticated user identity');
  // Every edit keeps the caller's opening lines: a named comment, once
  // written, is also a marked one a later run without the id may find.
  const edit = comment => {
    if (newer(comment.body, run)) return comment;
    const lines = String(comment.body ?? '').split(/\r?\n/);
    const end = lines.findIndex(line => !CALLER_MARKER.test(line));
    const kept = end === -1 ? lines : lines.slice(0, end);
    return api('PATCH', `repos/${repo}/issues/comments/${comment.id}`,
      kept.length ? `${kept.join('\n')}\n\n${body}` : body);
  };
  const given = named(env, api, repo, item, author, summary);
  if (given) return edit(given);
  for (let page = 1; page <= MAX_PAGES; page++) {
    const comments = api('GET', `repos/${repo}/issues/${item}/comments?per_page=100&page=${page}`);
    const found = comments.find(comment => comment.user?.login === author &&
      String(comment.body).endsWith(`\n\n${MARKER}`));
    if (found) return edit(found);
    if (comments.length < 100) return api('POST', `repos/${repo}/issues/${item}/comments`, body);
  }
  throw new Error(`status comment lookup exceeded ${MAX_PAGES} pages; refusing to create a duplicate`);
}

if (require.main === module) {
  const result = upsert(process.env, (method, path, body) => JSON.parse(execFileSync('gh',
    ['api', '-X', method, path, ...(body === undefined ? [] : ['-f', `body=${body}`])], {
      encoding: 'utf8', env: { ...process.env, GH_TOKEN: process.env.STATUS_TOKEN || process.env.GH_TOKEN },
    })), message => appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${message}\n`));
  if (result) console.log(`id=${result.id}`);
}

module.exports = { upsert, MARKER, MAX_PAGES };
