import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkSetupStages, timedCommand, timingLine } from './setup-timing.mjs';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const stage = name => `Sandbox setup stage ${name}: 0.123s (ok)\n`;
const allowlist = stage('privileged-binary-allowlist');
const view = stage('filesystem-view') + allowlist;
const walk = stage('world-write-and-setuid-walk') + stage('setuid-package-ownership');

// The second argument is whether the configuration asks for the view.
for (const [name, log, mode, valid] of [
  ['view', view, 'true', true],
  ['no view', allowlist, 'false', true],
  ['view still walks', view + walk, 'true', false],
  ['no view still walks', allowlist + walk, 'false', false],
  ['no view has old setuid search', allowlist + stage('setuid-package-ownership'), 'false', false],
  ['view missing allowlist', stage('filesystem-view'), 'true', false],
  ['missing allowlist', '', 'false', false],
  ['missing view', allowlist, 'true', false],
  ['unasked view', view, 'false', false],
  ['failed stage', view.replace('(ok)', '(failed)'), 'true', false],
  ['duplicate stage', view + stage('filesystem-view'), 'true', false],
  ['invalid mode', view, 'invalid', false],
]) {
  test(name, () => {
    if (valid) {
      assert.doesNotThrow(() => checkSetupStages(log, mode));
    } else {
      assert.throws(() => checkSetupStages(log, mode));
    }
  });
}

test('summary includes only timing stages, including failures', () => {
  assert.equal(timingLine('setup', 1.234, 7,
    stage('packages') + 'untrusted **text**\nSandbox setup stage bad: NaNs (ok)\n' +
    'Sandbox setup stage create-user: 0.456s (failed)\n'),
  'Secure-host setup: 1.234s (exit 7); packages 0.123s, create-user 0.456s.\n');
  assert.equal(timingLine('probes', 2, 0, ''), 'Secure-host probes: 2.000s (exit 0).\n');
});

test('timed subprocess preserves success, failure and signal, and writes the summary', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'setup-timing-'));
  try {
    for (const [script, status] of [
      ["process.stdout.write('Sandbox setup stage packages: 0.123s (ok)\\n');", 0],
      ['process.exit(7)', 7],
      ["process.kill(process.pid, 'SIGTERM')", 1],
    ]) {
      const summary = join(directory, `summary-${status}`);
      assert.equal(await timedCommand('setup', process.execPath, ['-e', script], summary), status);
      const text = readFileSync(summary, 'utf8');
      assert.match(text, new RegExp(`Secure-host setup: \\d+\\.\\d{3}s \\(exit ${status}\\)`));
      if (status === 0) assert.match(text, /packages 0.123s/);
    }
    assert.equal(await timedCommand('probes', join(directory, 'absent'), [], ''), 1);
    for (const status of [0, 7]) {
      assert.equal(await timedCommand('setup', process.execPath,
        ['-e', `process.exit(${status})`], join(directory, 'absent', 'summary')), status);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
