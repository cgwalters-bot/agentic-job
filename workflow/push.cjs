'use strict';

const fs = require('node:fs');

// A repository whose default branch holds this file, naming that
// repository (`owner/repo`) on a line of its own, accepts branches of its
// own that an agent's commit is pushed to, whether it is the target or
// another's fork of it (#528 proposes the same file for a new pull
// request's branch). The name is what a fork does not inherit: one made
// or synced from a target that accepts holds the target's file, which
// names the target.
const OWNER_BRANCHES = '.github/agentic-job/accept-owner-branches';
// More than a name or two is not an opt-in file.
const OWNER_BRANCHES_MAX = 4096;

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// A run that pushes to a pull request starts from that pull request's
// branch at the head read here, with the policy job's read-only token:
// the number is the caller's input, the branch and the head are the
// forge's answer, and nothing of either comes from the agent or the
// pull request's text. `agentic-job policy` checks the branch against
// the caller's bounds and pins the head the run starts from.
//
// The branch may be in the repository itself or in any fork: whose it
// is and whether apply's account may push there, only apply knows, and
// `pushTarget` below refuses what it may not (#553).
async function resolvePush(env, github) {
  if (env.EVENT !== 'false' || env.REVIEW !== 'false' || env.KIND !== 'branch' ||
      // Apply applies outputs to the calling repository when none is named.
      !same(env.OUTPUT_REPO || env.GITHUB_REPOSITORY, env.REPO) ||
      !/^[1-9][0-9]{0,8}$/.test(env.ITEM ?? '') ||
      !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.REPO ?? '')) {
    throw new Error('A push to a pull request needs a branch run of no event or review, on a pull request number, with its outputs in the repository it works on');
  }
  const [owner, repo] = env.REPO.split('/');
  const { data } = await github.rest.pulls.get({ owner, repo, pull_number: Number(env.ITEM) });
  if (data.number !== Number(env.ITEM) || data.state !== 'open' || !same(data.base?.repo?.full_name, env.REPO) ||
      typeof data.head?.repo?.full_name !== 'string' ||
      !/^[0-9a-f]{40}$/.test(data.base?.sha ?? '') ||
      !/^[0-9a-f]{40}$/.test(data.head?.sha ?? '') || typeof data.head?.ref !== 'string') {
    throw new Error('A push needs an open pull request of the repository it works on, from a branch of a repository that still exists');
  }
  return { branch: data.head.ref, head: data.head.sha,
    base: await currentBase(env.REPO, data, github) };
}

// A PR's base.sha can lag behind its base branch. Only the forge names
// that branch; no producer-provided ref or commit is used to resolve it.
async function currentBase(repository, pull, github) {
  if (pull.base?.repo?.full_name?.toLowerCase() !== repository.toLowerCase() ||
      typeof pull.base?.ref !== 'string' || !pull.base.ref) throw new Error('Invalid pull request base branch');
  const [owner, repo] = repository.split('/');
  const { data } = await github.rest.git.getRef({ owner, repo, ref: `heads/${pull.base.ref}` });
  if (data.object?.type !== 'commit' || !/^[0-9a-f]{40}$/.test(data.object?.sha ?? '')) {
    throw new Error('Invalid current base head');
  }
  return data.object.sha;
}

// Where apply pushes a run's commit, read again with apply's own token
// before anything is fetched or pushed: null for a pull request from the
// fork of the identity apply holds (`me`), which the fork step checks
// and turns Actions off in as for a new pull request, and otherwise the
// pull request's head repository, whoever opened it. gh-aw's handler is
// then given that repository as the only one it may push to, and pushes
// on the pinned head without force; a replacement (RC-023) is pushed
// with a lease on that head, past the handler, so these checks are the
// only ones it gets.
//
// A push with `me`'s token starts the head repository's `push` and
// `pull_request` workflows on the agent's commit, with their secrets:
// - only the pull request's own branch, and never the head repository's
//   default branch or a protected one, which take reviewed changes
//   (gh-aw's handler refuses those too, but goes on where it cannot read);
// - a repository `me` cannot push to is refused here, with that reason,
//   rather than by the forge mid-apply;
// - never with `.github` exempted, as a workflow file the agent wrote
//   would run there with them: only `me`'s fork has Actions turned off;
// - a branch of the output repository itself, or of another's fork of
//   it, only where that repository accepts it (OWNER_BRANCHES naming it
//   on its default branch, which only a commit there adds), and of no other
//   repository: write access is given for people's commits, not as an
//   acceptance that the fork's own workflows run an agent's with the
//   fork's secrets. The output repository's CI runs a fork's commit as a
//   fork's.
async function pushTarget(env, me, github) {
  const config = JSON.parse(fs.readFileSync(`${env.GH_AW_TMP}/config.json`, 'utf8')).push_to_pull_request_branch ?? {};
  if (!/^[1-9][0-9]*$/.test(String(config.target))) throw new Error('a push is to be applied, and the policy names no pull request for it');
  const [owner, repo] = env.OUTPUT_REPO.split('/');
  const { data: pull } = await github.rest.pulls.get({ owner, repo, pull_number: Number(config.target) });
  const name = pull.head?.repo?.full_name;
  const what = `pull request ${config.target} of ${env.OUTPUT_REPO}`;
  if (pull.state !== 'open' || typeof name !== 'string' || pull.head.ref !== env.BASE || !same(pull.base?.repo?.full_name, env.OUTPUT_REPO)) {
    throw new Error(`${what} is ${pull.state}, from ${name ?? 'a deleted repository'}:${pull.head?.ref}, not open from a branch named ${env.BASE}: ` +
      'a push goes only to the branch the policy read');
  }
  const own = pull.head.repo.fork === true && same(pull.head.repo.owner?.login, me);
  const itself = same(name, env.OUTPUT_REPO);
  if (!own && config.unprotected_dot_folders?.includes('.github')) {
    throw new Error(`${what} is from ${name}, not from ${me}'s fork with Actions turned off: a workflow file the agent wrote would run there, so it is not pushed to with .github exempted from protection`);
  }
  const [headOwner, headRepo] = name.split('/');
  const { data: head } = await github.rest.repos.get({ owner: headOwner, repo: headRepo });
  // Write access, not a pull request's "maintainers may edit": that lets
  // the target's maintainers push, which `me` is not to be.
  if (head.permissions?.push !== true) {
    throw new Error(`${what} is from ${name}, which ${me} cannot push to: give that account write access there, or push the fix by hand`);
  }
  // Only a fork of the output repository, or that repository itself: not
  // one it was forked from or another in its network, which nothing here
  // asked, nor the caller's, which holds the run's secrets (unless it is
  // the output repository, which then has to accept the push below).
  // `me`'s own fork is whatever the forge forks for it, which the fork
  // step checks.
  if (!own && !itself && (head.fork !== true || !same(head.parent?.full_name, env.OUTPUT_REPO) || same(name, env.GITHUB_REPOSITORY))) {
    throw new Error(`${what} is from ${name}, which is neither a fork of ${env.OUTPUT_REPO} nor ${env.OUTPUT_REPO} itself, or is the calling repository: ` +
      'a push goes to neither');
  }
  if (pull.head.ref === head.default_branch) throw new Error(`${what} is from ${name}'s default branch ${pull.head.ref}, which a push never goes to`);
  // Classic protection is the branch's `protected`; a ruleset only the rules
  // that apply to it say. Any of either is a branch for reviewed changes.
  const { data: branch } = await github.rest.repos.getBranch({ owner: headOwner, repo: headRepo, branch: pull.head.ref });
  const { data: rules } = await github.rest.repos.getBranchRules({ owner: headOwner, repo: headRepo, branch: pull.head.ref });
  if (branch.protected !== false || !Array.isArray(rules) || rules.length) {
    throw new Error(`${what} is from ${name}:${pull.head.ref}, a protected branch or one rules apply to, which a push never goes to`);
  }
  if (own) return null;
  // Without a ref this reads the default branch.
  const accepts = await github.rest.repos.getContent({ owner: headOwner, repo: headRepo, path: OWNER_BRANCHES })
    .then(({ data }) => data?.type === 'file' && data.encoding === 'base64' && typeof data.content === 'string' &&
      data.size <= OWNER_BRANCHES_MAX &&
      Buffer.from(data.content, 'base64').toString('utf8').split('\n').some(line => same(line.trim(), name)),
    error => { if (error.status === 404) return false; throw error; });
  if (!accepts) {
    throw new Error(`${what} is from ${itself ? `a branch of ${name} itself` : `${name}, not ${me}'s fork with Actions turned off`}, ` +
      `whose CI would run the pushed commit with its secrets: add ${OWNER_BRANCHES} naming ${name} to its default branch to accept that`);
  }
  return { repo: name, base: env.REPLACEMENT === 'true' ? await currentBase(env.REPO, pull, github) : null };
}

module.exports = { resolvePush, currentBase, pushTarget, OWNER_BRANCHES };
