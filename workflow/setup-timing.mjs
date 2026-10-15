import assert from 'node:assert/strict';
import { appendFileSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
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

export function timingLine(label, seconds, status, stages) {
  assert.ok(['setup', 'probes'].includes(label));
  assert.ok(Number.isFinite(seconds) && seconds >= 0);
  assert.ok(Number.isInteger(status) && status >= 0);
  const parts = [...stages.matchAll(/^Sandbox setup stage ([a-z-]+): (\d+\.\d{3})s \((?:ok|failed)\)$/gm)]
    .map(([, name, time]) => `${name} ${time}s`);
  return `Secure-host ${label}: ${seconds.toFixed(3)}s (exit ${status})${parts.length ? `; ${parts.join(', ')}` : ''}.\n`;
}

// Run as the runner, not root: only the fixed setup command uses sudo.
// Timing output is informational and never substitutes for a passing probe.
export async function timedCommand(label, program, args, summary = process.env.GITHUB_STEP_SUMMARY) {
  const start = performance.now();
  const child = spawn(program, args, { stdio: ['inherit', 'pipe', 'inherit'] });
  let pending = '', stages = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', text => {
    process.stdout.write(text);
    // Keep only bounded, complete setup timing lines, not subprocess output.
    for (const piece of text.split(/(?<=\n)/)) {
      pending = (pending + piece).slice(-1024);
      if (pending.endsWith('\n')) {
        if (/^Sandbox setup stage [a-z-]+: \d+\.\d{3}s \((?:ok|failed)\)\n$/.test(pending)) {
          stages = (stages + pending).slice(-16384);
        }
        pending = '';
      }
    }
  });
  const status = await new Promise(resolve => {
    child.on('error', error => { console.error(error.message); resolve(1); });
    child.on('close', code => resolve(code ?? 1));
  });
  const line = timingLine(label, (performance.now() - start) / 1000, status, stages);
  console.error(line.trimEnd());
  if (summary) {
    try {
      appendFileSync(summary, line);
    } catch (error) {
      console.error(`Cannot write secure-host timing summary: ${error.message}`);
    }
  }
  return status;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === '--run') {
    assert.equal(process.argv.length, 4, 'usage: setup-timing.mjs --run setup|probes');
    const label = process.argv[3];
    assert.ok(['setup', 'probes'].includes(label));
    const command = label === 'setup'
      ? ['sudo', ['agentic-job', 'sandbox', 'setup', '--config', `${process.env.RUNNER_TEMP}/secure-host/config.toml`]]
      : ['agentic-job', ['sandbox', 'check', '--record']];
    process.exitCode = await timedCommand(label, ...command);
  } else {
    assert.equal(process.argv.length, 4, 'usage: setup-timing.mjs LOG FILESYSTEM_VIEW');
    checkSetupStages(readFileSync(process.argv[2], 'utf8'), process.argv[3]);
  }
}
