// This is the fixed workflow's read-only duplicate guard, not a publisher.
const { execFileSync } = require('node:child_process');
const { appendFileSync } = require('node:fs');

const BODY = 'Standalone safe-outputs deterministic CLI proof.';
const COMMENT_URL = 'https://github.com/cgwalters-forge/agentic-job/issues/64#issuecomment-';
const LIMIT = 100;

function inspect(read, attempt, verify = false) {
  // One page, byte cap and timeout; a full page is not evidence of absence.
  const comments = JSON.parse(read());
  if (!Array.isArray(comments) || comments.length >= LIMIT) {
    throw new Error('Incomplete proof lookup; inspect issue 64 before continuing.');
  }
  const matches = [];
  for (const comment of comments) {
    if (!comment || typeof comment.body !== 'string') {
      throw new Error('Malformed proof lookup; refusing publication.');
    }
    if (!comment.body.includes(BODY)) continue;
    if (comment.body !== BODY || comment.user?.id !== 41898282 ||
        comment.user?.type !== 'Bot' || comment.performed_via_github_app?.id !== 15368 ||
        !Number.isSafeInteger(comment.id) || comment.id <= 0 ||
        comment.html_url !== `${COMMENT_URL}${comment.id}`) {
      throw new Error('Ambiguous proof comment; inspect issue 64 before continuing.');
    }
    matches.push(comment.html_url);
  }
  if (matches.length > 1) throw new Error('Multiple proof comments; inspect issue 64.');
  if (matches.length === 1) return { publish: false, url: matches[0] };
  if (verify || attempt !== '1') {
    throw new Error('No proof found; inspect previous apply logs and issue 64, do not blindly retry.');
  }
  return { publish: true };
}

function readComments() {
  return execFileSync('gh', [
    'api', '--hostname', 'github.com',
    'repos/cgwalters-forge/agentic-job/issues/64/comments?per_page=100&page=1',
  ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

if (require.main === module) {
  try {
    const result = inspect(readComments, process.env.GITHUB_RUN_ATTEMPT, process.argv[2] === 'verify');
    appendFileSync(process.env.GITHUB_OUTPUT, `publish=${result.publish}\n`);
    if (result.url) {
      // A comment alone is not proof of successful jobs; verify the original
      // check/apply logs before linking evidence back to tracker #2397.
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, `Existing standalone proof comment (verify its original check/apply run): ${result.url}\n`);
    }
  } catch {
    // Do not echo API bodies, which are untrusted, or subprocess environment.
    console.error('Proof lookup refused. Inspect issue 64 and the previous apply logs; no automatic publication retry.');
    process.exitCode = 1;
  }
}

module.exports = { inspect, BODY };
