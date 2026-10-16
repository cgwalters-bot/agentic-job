'use strict';

// With `require-safe-outputs-pat`, the policy call asks the forge about
// SAFE_OUTPUTS_PAT before the agent runs, so that a wrong secret costs a
// minute instead of a whole session: apply would only refuse it after.
// Only the pinned helper below holds the token, in a job of its own that
// runs nothing from the event and that the agent's machine never sees.
// It reads, and writes nothing.

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

const FIX = 'store a classic PAT of a bot account that does not own the output repository, with the repo scope, ' +
  'as SAFE_OUTPUTS_PAT (in the apply environment, if any), and pass it: `secrets: SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}`';

// `env.TOKEN_IS_PAT` is the workflow's `secrets.SAFE_OUTPUTS_PAT != ''`:
// a secret the caller did not pass, or one unset, reads as empty, so the
// two cannot be told apart, nor need be. `github` holds the PAT then.
async function checkApplyToken(env, github) {
  const repo = env.OUTPUT_REPO ?? '';
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error('the apply token check needs the output repository, OWNER/NAME');
  if (env.TOKEN_IS_PAT !== 'true') throw new Error(`SAFE_OUTPUTS_PAT is missing or empty: ${FIX}`);
  const user = await github.request('GET /user').catch(error => {
    throw new Error(`SAFE_OUTPUTS_PAT names no user (GET /user answered ${error.status ?? error.message}): ${FIX}`);
  });
  const me = user.data?.login;
  if (typeof me !== 'string' || me === '') throw new Error(`SAFE_OUTPUTS_PAT names no user: ${FIX}`);
  const [owner, name] = repo.split('/');
  // Apply opens a pull request from the token's fork, and an owner has
  // none; a caller whose repository accepts owner branches does not opt in.
  if (same(me, owner)) throw new Error(`SAFE_OUTPUTS_PAT is ${me}'s, who owns ${repo} and has no fork of it to open a pull request from: ${FIX}`);
  // A classic PAT lists its scopes; a fine-grained one lists none, and
  // what it may do is not asked here.
  const scopes = user.headers?.['x-oauth-scopes'];
  if (typeof scopes === 'string' && !scopes.split(',').map(scope => scope.trim()).some(scope => scope === 'repo' || scope === 'public_repo')) {
    throw new Error(`SAFE_OUTPUTS_PAT of ${me} has the scopes "${scopes}", not repo, which apply needs to fork ${repo} and push: ${FIX}`);
  }
  await github.rest.repos.get({ owner, repo: name }).catch(error => {
    throw new Error(`SAFE_OUTPUTS_PAT of ${me} cannot read ${repo} (${error.status ?? error.message}): ${FIX}`);
  });
  return me;
}

module.exports = { checkApplyToken };
