'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { materialize, trial, push } = require('./replacement.cjs');

test('replacement rewords, squashes and rebases; exact reruns skip and moved heads refuse', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'replacement-'));
  const repo = path.join(temp, 'repo');
  const remote = path.join(temp, 'remote');
  fs.mkdirSync(repo);
  const git = (args, cwd = repo) => execFileSync('git', args, {
    cwd, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' },
  }).trim();
  const commit = (file, text, message) => {
    fs.writeFileSync(path.join(repo, file), text);
    git(['add', file]);
    git(['commit', '-qm', message]);
    return git(['rev-parse', 'HEAD']);
  };
  const mail = () => git(['format-patch', '--stdout', '--no-signature', '--no-renames', '-1', 'HEAD']) + '\n';
  try {
    git(['init', '-q', '--initial-branch=main']);
    git(['config', 'user.name', 'Test']);
    git(['config', 'user.email', 'test@example.com']);
    const base = commit('base.txt', 'base\n', 'base');
    git(['checkout', '-qb', 'agent-run-1']);
    commit('a.txt', 'a\n', 'original');
    const original = commit('b.txt', 'b\n', 'fixup');
    git(['init', '--bare', '-q', remote]);
    git(['push', remote, 'HEAD:refs/heads/agent-run-1']);
    git(['reset', '--soft', base]);
    git(['commit', '-qm', 'parser: Keep the last line\n\nWhy the original lost it.']);
    const squashed = mail();
    // Rebase the full squashed change on the moved base.
    git(['checkout', '-q', 'main']);
    const movedBase = commit('new-base.txt', 'new base\n', 'advance base');
    const series = { base_commit: movedBase, commits: [squashed] };
    const first = materialize(series, [['a.txt', 'b.txt']], temp, repo);
    const second = materialize(series, [['a.txt', 'b.txt']], temp, repo);
    assert.deepEqual(first, second);
    assert.equal(git(['show', '-s', '--format=%P', first.head]), movedBase);
    assert.match(git(['show', '-s', '--format=%B', first.head]), /parser: Keep the last line/);
    assert.throws(() => materialize(series, [['a.txt']], temp, repo), /unchecked paths/);
    git(['checkout', '-q', '--detach', first.head]);
    commit('c.txt', 'c\n', 'second retained commit');
    const multiple = materialize({ ...series, commits: [squashed, mail()] }, [['a.txt', 'b.txt'], ['c.txt']], temp, repo);
    assert.equal(git(['rev-list', '--count', `${movedBase}..${multiple.head}`]), '2');
    // Trial checks its trusted report/config binding before fetching anything.
    const report = path.join(temp, 'report.json');
    fs.writeFileSync(report, JSON.stringify({ patch: { base_commit: movedBase, commit_files: [['a.txt', 'b.txt']] } }));
    fs.writeFileSync(path.join(temp, 'replacement.json'), JSON.stringify(series));
    fs.writeFileSync(path.join(temp, 'config.json'), JSON.stringify({ push_to_pull_request_branch: { replacement_base: base, replacement_max_commits: 1 } }));
    assert.throws(() => trial({ REPORT: report, GH_AW_TMP: temp }), /Unchecked replacement/);
    git(['push', remote, `${movedBase}:refs/heads/main`]);
    const env = { REPORT: report, GH_AW_TMP: temp, RUNNER_TEMP: temp, CURRENT_BASE: movedBase };
    assert.deepEqual(trial(env, repo, remote), first);
    // Apply accepts only its own current resolution or the pinned snapshot.
    assert.throws(() => trial({ ...env, CURRENT_BASE: original }, repo, remote), /Unchecked replacement/);
    fs.writeFileSync(path.join(temp, 'config.json'), JSON.stringify({ push_to_pull_request_branch: { replacement_base: movedBase, replacement_max_commits: 1 } }));
    assert.deepEqual(trial({ ...env, CURRENT_BASE: original }, repo, remote), first);
    for (const change of [{ replacement_max_commits: 0 }, { replacement_base: undefined }]) {
      fs.writeFileSync(path.join(temp, 'config.json'), JSON.stringify({ push_to_pull_request_branch: { replacement_base: movedBase, replacement_max_commits: 1, ...change } }));
      assert.throws(() => trial(env, repo, remote), /Unchecked replacement/);
    }
    push(remote, 'agent-run-1', original, first.head, repo);
    push(remote, 'agent-run-1', original, first.head, repo); // idempotent
    assert.equal(git(['rev-parse', 'refs/heads/agent-run-1'], remote), first.head);
    // A different series, even with the same tree, is a concurrent write.
    git(['push', '--force', remote, `${original}:refs/heads/agent-run-1`]);
    git(['update-ref', 'refs/heads/agent-run-1', base], remote);
    assert.throws(() => push(remote, 'agent-run-1', original, first.head, repo), /moved/);
    assert.equal(git(['rev-parse', 'refs/heads/agent-run-1'], remote), base);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
