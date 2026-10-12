'use strict';

// This module is loaded only from the reusable workflow's trusted source.
// Never run a producer checkout's code/configuration to build or push a series.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function git(args, cwd) {
  return execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
    '-c', 'commit.gpgsign=false', ...args], {
    cwd, encoding: 'utf8', timeout: 120000, maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
  }).trim();
}

function trial(env) {
  const report = JSON.parse(fs.readFileSync(env.REPORT, 'utf8')).patch;
  const series = JSON.parse(fs.readFileSync(path.join(env.GH_AW_TMP, 'replacement.json'), 'utf8'));
  const config = JSON.parse(fs.readFileSync(path.join(env.GH_AW_TMP, 'config.json'), 'utf8')).push_to_pull_request_branch;
  if (!report?.commit_files || report.base_commit !== config?.replacement_base ||
      series.base_commit !== report.base_commit || !config.replacement_max_commits ||
      series.commits.length !== report.commit_files.length ||
      series.commits.length > config.replacement_max_commits) throw new Error('Unchecked replacement series');
  // Fetch the exact base seen by policy, not an arbitrary producer commit.
  git(['fetch', '--no-tags', `https://github.com/${env.REPO}`, report.base_commit]);
  return materialize(series, report.commit_files, env.RUNNER_TEMP);
}

function materialize(series, checkedFiles, temp, repo = process.cwd()) {
  const dir = path.join(temp, 'replacement-trial');
  git(['worktree', 'add', '--quiet', '--detach', dir, series.base_commit], repo);
  try {
    for (const [index, mail] of series.commits.entries()) {
      const before = git(['rev-parse', 'HEAD'], dir);
      const file = path.join(temp, 'replacement-mail.patch');
      fs.writeFileSync(file, mail);
      // Fixed committer identity and date make the reconstructed head stable
      // across attempts, including a re-run after a successful push.
      git(['-c', 'user.name=github-actions[bot]',
        '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
        'am', '--keep-cr', '--committer-date-is-author-date', file], dir);
      if (git(['show', '-s', '--format=%P', 'HEAD'], dir) !== before) throw new Error('Nonlinear replacement');
      const changed = git(['-c', 'core.quotePath=false', 'diff', '--name-only', '--no-renames', before, 'HEAD'], dir).split('\n').sort();
      if (JSON.stringify(changed) !== JSON.stringify([...checkedFiles[index]].sort())) {
        throw new Error(`Replacement commit ${index + 1} changed unchecked paths`);
      }
    }
    return { head: git(['rev-parse', 'HEAD'], dir), tree: git(['rev-parse', 'HEAD^{tree}'], dir) };
  } finally {
    git(['worktree', 'remove', '--force', dir], repo);
  }
}

function push(remote, branch, originalHead, replacementHead, repo = process.cwd()) {
  if (![originalHead, replacementHead].every(head => /^[0-9a-f]{40}$/.test(head))) throw new Error('Invalid replacement heads');
  git(['check-ref-format', `refs/heads/${branch}`], repo);
  const ref = `refs/heads/${branch}`;
  const current = git(['ls-remote', '--refs', remote, ref], repo).split('\t')[0];
  if (current === replacementHead) return; // Exact series, not just its tree.
  if (current !== originalHead) throw new Error('Replacement branch moved since the run started');
  git(['push', `--force-with-lease=${ref}:${originalHead}`, remote, `${replacementHead}:${ref}`], repo);
  if (git(['ls-remote', '--refs', remote, ref], repo).split('\t')[0] !== replacementHead) throw new Error('Replacement head was not pushed');
}

module.exports = { materialize, trial, push };

if (require.main === module) {
  const result = trial(process.env);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `head=${result.head}\ntree=${result.tree}\n`);
}
