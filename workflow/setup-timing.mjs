import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// The walk's stages are gone: the world-write policy is loaded before setup.
export function checkSetupStages(log, filesystemView) {
  assert.ok(['true', 'false'].includes(filesystemView), 'invalid filesystem-view value');
  const view = filesystemView === 'true';
  for (const [stage, expected] of [
    ['privileged-binary-allowlist', true],
    ['world-write-and-setuid-walk', false],
    ['setuid-package-ownership', false],
    ['filesystem-view', view],
  ]) {
    const lines = log.split('\n').filter(line => line.startsWith(`Sandbox setup stage ${stage}:`));
    assert.equal(lines.length, expected ? 1 : 0, `unexpected setup stage: ${stage}`);
    if (expected) {
      assert.match(lines[0], /: \d+\.\d{3}s \(ok\)$/, `unsuccessful setup stage: ${stage}`);
    }
  }
}

// secure-host times setup and its probes with `agentic-job sandbox timed`.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.argv.length, 4, 'usage: setup-timing.mjs LOG FILESYSTEM_VIEW');
  checkSetupStages(readFileSync(process.argv[2], 'utf8'), process.argv[3]);
}
