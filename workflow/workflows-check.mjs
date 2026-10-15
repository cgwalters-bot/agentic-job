// Proposed workflows are data, never a checkout (no hooks, actions or build files).
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export function check(repository, base, head, binary) {
  for (const sha of [base, head]) {
    if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error('expected full base and head commit IDs');
  }
  const git = (...args) => execFileSync('git', ['-C', repository, ...args], {
    maxBuffer: 2 * 1024 * 1024,
  });
  const root = mkdtempSync(join(tmpdir(), 'workflows-check-'));
  try {
    // Local reusable calls resolve at the merge-group commit. Refuse changes
    // to the gate itself during the trusted pull_request_target run, before
    // such a proposal can enter the queue. Gate upgrades need a maintainer's
    // ruleset bypass, not an exemption added by the proposal.
    for (const path of ['.github/workflows/workflows-check.yml', '.github/workflows/workflows-check-required.yml']) {
      if (!git('ls-tree', '-z', base, path).equals(git('ls-tree', '-z', head, path))) {
        throw new Error(`required workflow gate changed: ${path}; maintainer rollout required`);
      }
    }
    mkdirSync(join(root, '.github/workflows'), { recursive: true });
    const entries = git('ls-tree', '-z', head, '.github/workflows/').toString().split('\0').filter(Boolean);
    let count = 0;
    for (const entry of entries) {
      const match = /^(\d+) blob ([0-9a-f]{40})\t(.+)$/.exec(entry);
      if (!match) throw new Error('unexpected workflow tree entry');
      const [, mode, oid, path] = match;
      if (!/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) continue;
      if (++count > 500) throw new Error('more than 500 workflow files');
      if (mode !== '100644' && mode !== '100755') throw new Error('workflow is not a regular file');
      const size = Number(git('cat-file', '-s', oid).toString().trim());
      if (size > 1024 * 1024) throw new Error('workflow exceeds 1 MiB');
      writeFileSync(join(root, path), git('cat-file', 'blob', oid));
    }
    // A missing base policy means no exemptions. Never read the head's policy.
    const policy = '.github/agentic-job/workflows.toml';
    const entriesPolicy = git('ls-tree', '-z', base, policy).toString();
    let exemptions = '';
    if (entriesPolicy) {
      const match = /^100(?:644|755) blob ([0-9a-f]{40})\t[^\0]+\0$/.exec(entriesPolicy);
      if (!match) throw new Error('base exemptions are not a regular file');
      if (Number(git('cat-file', '-s', match[1]).toString()) > 64 * 1024) throw new Error('base exemptions exceed 64 KiB');
      exemptions = git('cat-file', 'blob', match[1]);
    }
    const policyPath = join(root, 'exemptions.toml');
    writeFileSync(policyPath, exemptions);
    execFileSync(binary, ['workflows', 'check', '--root', root, '--exemptions', policyPath], { stdio: 'inherit' });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  check(process.argv[2], process.env.BASE, process.env.HEAD, process.argv[3]);
}
