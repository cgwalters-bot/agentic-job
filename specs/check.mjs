import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Stable v1.7.4, not the v1.8.0 prerelease whose jar upstream re-uploads. The
// v1.7.4 release notes publish SHA-1 bee4a54f3ee3d4afc347c3240ec2d9e93b075104;
// this is the SHA-256 of the download matching it, pinned in source and never
// fetched beside the executable. TLC 1.7.4 writes no SpecTE trace module unless
// asked to (-generateSpecTE), so the checkout stays clean.
const url = 'https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar';
const sha256 = '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88';
const directory = dirname(fileURLToPath(import.meta.url));
const results = mkdtempSync(join(tmpdir(), 'agentic-job-tlc-'));
console.log(`Full TLC reports: ${results}`);
const jar = join(results, 'tla2tools.jar');
const download = spawnSync('curl', ['--fail', '--location', '--silent', '--show-error',
  '--retry', '2', '--max-time', '120', url, '--output', jar], { stdio: 'inherit' });
if (download.status !== 0) throw new Error('Could not download tla2tools.jar');
if (createHash('sha256').update(readFileSync(jar)).digest('hex') !== sha256) {
  throw new Error('tla2tools.jar checksum mismatch; refusing to execute it');
}

const cases = [
  ['Pipeline', null],
  ['BrokenGuard', 'AtMostOnce'],
  ['BrokenMarker', 'NoFalseSkip'],
  ['BrokenName', 'AcceptedOnly'],
  ['BrokenWiring', 'AcceptedOnly'],
  ['BrokenCredential', 'CredentialIsolation'],
  ['BrokenBranch', 'BranchOnce'],
];
for (const [config, invariant] of cases) {
  const run = spawnSync(process.env.JAVA_BIN || 'java', [
    '-XX:+UseParallelGC', '-Xmx512m', '-cp', jar, 'tlc2.TLC',
    '-workers', '1', '-seed', '1', '-fp', '0', '-config', join(directory, `${config}.cfg`),
    '-metadir', join(results, config), join(directory, 'Pipeline.tla'),
  ], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  const output = (run.stdout || '') + (run.stderr || '');
  writeFileSync(join(results, `${config}.log`), output);
  console.log(`${config}: TLC exit ${run.status}`);
  console.log(output);
  const expected = invariant ? `Invariant ${invariant} is violated` : 'Model checking completed. No error';
  if (run.error || run.status !== (invariant ? 12 : 0) || !output.includes(expected)) {
    throw new Error(`${config}: expected ${expected}, not a tooling/parse failure`);
  }
}
