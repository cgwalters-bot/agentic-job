import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { check } from './workflows-check.mjs';

test('only base exemptions apply; head code is never executed', () => {
  const root = mkdtempSync(join(tmpdir(), 'workflow-test-'));
  const git = (...args) => execFileSync('git', ['-C', root, ...args]).toString().trim();
  const commit = () => {
    git('add', '.');
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture');
    return git('rev-parse', 'HEAD');
  };
  try {
    git('init', '-q');
    mkdirSync(join(root, '.github/workflows'), { recursive: true });
    mkdirSync(join(root, '.github/agentic-job'), { recursive: true });
    writeFileSync(join(root, '.github/workflows/bad.yml'), 'on: push\njobs:\n  bad:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: exit 0\n');
    const base = commit();
    writeFileSync(join(root, '.github/agentic-job/workflows.toml'), '[exempt]\n"bad.yml" = "head tries to exempt itself"\n');
    const marker = join(root, 'executed');
    writeFileSync(join(root, 'build.rs'), `fn main() { std::fs::write(${JSON.stringify(marker)}, "unsafe").unwrap(); }`);
    const head = commit();
    const binary = resolve('target/debug/agentic-job');
    assert.throws(() => check(root, base, head, binary));
    // Once the same policy is trusted base data, it exempts the file.
    check(root, head, head, binary);
    assert.equal(existsSync(marker), false);
    assert.throws(() => check(root, '--help', head, binary), /full base/);
    for (const gate of ['workflows-check.yml', 'workflows-check-required.yml']) {
      git('reset', '--hard', head);
      writeFileSync(join(root, '.github/workflows', gate), 'jobs: {}\n');
      const changed = commit();
      assert.throws(() => check(root, head, changed, binary), error => error.message.includes(`gate changed: .github/workflows/${gate}`));
      writeFileSync(join(root, '.github/workflows', gate), 'jobs: { changed: {} }\n');
      const modified = commit();
      assert.throws(() => check(root, changed, modified, binary), /gate changed/);
      rmSync(join(root, '.github/workflows', gate));
      const deleted = commit();
      assert.throws(() => check(root, changed, deleted, binary), /gate changed/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
