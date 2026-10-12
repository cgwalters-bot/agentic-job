'use strict';

// A run that pushes to a pull request starts from that pull request's
// branch at the head read here, with the policy job's read-only token:
// the number is the caller's input, the branch and the head are the
// forge's answer, and nothing of either comes from the agent or the
// pull request's text. `agentic-job policy` checks the branch against
// the caller's bounds and pins the head the run starts from.
//
// The branch has to be in a fork: apply pushes only to the branch of a
// pull request it opened itself, from the fork of the identity it
// applies as, so that the target's CI runs the commit as a fork's, with
// a read-only token, no secrets and no OIDC token (#340, #430). Whose
// fork it is, only apply knows: it refuses any other than its own.
async function resolvePush(env, github) {
  const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
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
      data.head?.repo?.fork !== true || typeof data.head.repo.full_name !== 'string' || same(data.head.repo.full_name, env.REPO) ||
      !/^[0-9a-f]{40}$/.test(data.base?.sha ?? '') ||
      !/^[0-9a-f]{40}$/.test(data.head?.sha ?? '') || typeof data.head?.ref !== 'string') {
    throw new Error('A push needs an open pull request of the repository it works on from a branch of a fork, the one apply opened it from');
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

module.exports = { resolvePush, currentBase };
