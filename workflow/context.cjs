// Admission runs on the read-only policy machine, before any agent starts.
const { spawnSync } = require('node:child_process');

function api(path) {
  const result = spawnSync('gh', ['api', path], {
    encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 120000,
  });
  if (result.status !== 0) throw new Error(`Cannot read context metadata: ${path}`);
  return JSON.parse(result.stdout);
}

function resolveContext(text, read = api) {
  if (Buffer.byteLength(text) > 16384) throw new Error('Context input exceeds 16 KiB');
  const items = JSON.parse(text || '[]');
  if (!Array.isArray(items) || items.length > 8) throw new Error('At most 8 context repositories');
  const seen = new Set();
  return items.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        Object.keys(item).some(key => !['repo', 'ref'].includes(key)) ||
        typeof item.repo !== 'string' ||
        !/^[A-Za-z0-9_][A-Za-z0-9_.-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(item.repo) ||
        (item.ref !== undefined && (typeof item.ref !== 'string' ||
          !/^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$/.test(item.ref) || item.ref.includes('..')))) {
      throw new Error('Context entries must contain OWNER/REPO and an optional branch, tag or SHA ref');
    }
    const name = item.repo.toLowerCase();
    if (seen.has(name)) throw new Error('Duplicate context repository');
    seen.add(name);
    const repo = read(`repos/${item.repo}`);
    // Everything about this run is published. Bounds admission alone must not
    // accidentally publish private source through the prompt or transcript.
    if (repo.private !== false || repo.visibility !== 'public') {
      throw new Error('Context repository cannot be confirmed public; private runs are refused because run evidence can disclose source. See docs/private-repositories.md in the agentic-job source');
    }
    const ref = item.ref ?? repo.default_branch;
    if (typeof ref !== 'string' || !ref || ref.length > 200) throw new Error('Missing default branch');
    const commit = read(`repos/${item.repo}/commits/${encodeURIComponent(ref)}`).sha;
    if (typeof commit !== 'string' || !/^[0-9a-f]{40}$/.test(commit)) throw new Error('Invalid context commit');
    return { repo: item.repo, clone_url: repo.clone_url, commit, public: true };
  });
}

module.exports = { resolveContext };
