'use strict';

const { execFileSync } = require('node:child_process');
const MARKER = '<!-- agentic-job-status -->';
const MAX_PAGES = 20;

function upsert(env, api) {
  const { REPO: repo, ITEM: item, TEXT: text, GITHUB_RUN_ID: run } = env;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo ?? '') || !/^[1-9][0-9]*$/.test(item ?? '')) {
    throw new Error('status requires a caller repository and numeric item');
  }
  if (!/^[1-9][0-9]*$/.test(run ?? '')) throw new Error('status requires a numeric Actions run ID');
  // Apply already bounded, sanitized and quoted this text. Decode only here,
  // after it has crossed shell/job outputs as a single JSON string.
  const reason = env.NO_RESULT_REASON ? ` Its reason:\n\n${JSON.parse(env.NO_RESULT_REASON)}` : '';
  const body = `${text}${reason}\n\n<!-- agentic-job-run: ${run} -->\n\n${MARKER}`;
  // The job token's bot identity, not a marker copied into a user's comment.
  for (let page = 1; page <= MAX_PAGES; page++) {
    const comments = api('GET', `repos/${repo}/issues/${item}/comments?per_page=100&page=${page}`);
    const found = comments.find(comment => comment.user?.login === 'github-actions[bot]' &&
      String(comment.body).endsWith(`\n\n${MARKER}`));
    if (found) {
      // A slower older run must not replace the current run's status.
      const previous = String(found.body).match(/\n\n<!-- agentic-job-run: ([1-9][0-9]*) -->\n\n<!-- agentic-job-status -->$/);
      if (previous && BigInt(previous[1]) > BigInt(run)) return found;
      return api('PATCH', `repos/${repo}/issues/comments/${found.id}`, body);
    }
    if (comments.length < 100) return api('POST', `repos/${repo}/issues/${item}/comments`, body);
  }
  throw new Error(`status comment lookup exceeded ${MAX_PAGES} pages; refusing to create a duplicate`);
}

if (require.main === module) {
  const result = upsert(process.env, (method, path, body) => JSON.parse(execFileSync('gh',
    ['api', '-X', method, path, ...(body === undefined ? [] : ['-f', `body=${body}`])], { encoding: 'utf8' })));
  console.log(`id=${result.id}`);
}

module.exports = { upsert, MARKER, MAX_PAGES };
