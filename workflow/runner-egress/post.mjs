import { appendFileSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { observations, MAX_BYTES } from './parse.mjs';

const trace = process.env.STATE_trace;
if (!trace) throw new Error('Missing outbound trace state');
writeFileSync(`${trace}.stop`, '');
// Wait for the collector's acknowledgement, not a racing snapshot of live files.
for (let i = 0; i < 100 && !existsSync(`${trace}.status`); i++) {
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!existsSync(`${trace}.status`)) throw new Error('Capture did not finish');
function bounded(path) {
  if (statSync(path).size > MAX_BYTES) throw new Error('Observation exceeds 4 MiB');
  return readFileSync(path, 'utf8');
}
const destinations = observations(bounded(trace), bounded(`${trace}.sockets`).trim().split('\n')
  .filter(Boolean).map(line => JSON.parse(line)), JSON.parse(bounded(`${trace}.addresses`)));
const report = { schema_version: 1, coverage: {
  packet_limit: 10000, duration_limit_s: 480, snaplen: 4096,
  packets_recorded: bounded(trace).split('\n').filter(Boolean).length,
  collector: JSON.parse(bounded(`${trace}.status`)),
  limitations: 'Starts after checkout and tool installation; ends before this post uploads JSON. Runner completion traffic after the last step is not observed. Caps, encrypted DNS/ECH, truncated or segmented TLS, and short-lived sockets leave gaps. Socket owners are sampled, not proven openers. DNS/SNI are unauthenticated claims, not an allowlist.',
}, destinations };
const json = JSON.stringify(report, null, 2);
const artifact = `${trace}.json`;
writeFileSync(artifact, json + '\n', { mode: 0o600 });
// No untrusted text becomes a workflow command or Markdown structure.
const preview = JSON.stringify({ ...report, destinations: destinations.slice(0, 100) }, null, 2);
const summary = `## Runner egress metadata\n\nFirst 100 destinations (full JSON in runner-egress-observations).\n\n` +
  `\`\`\`json\n${preview.slice(0, 100000)}\n\`\`\`\n`;
appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
// Reuse the pinned upload action's bundled runtime in this final post. An
// ordinary upload step runs too early to include other actions' post traffic.
execFileSync(process.execPath, [process.env.TRACE_UPLOAD_SCRIPT], { stdio: 'inherit', timeout: 60000,
  env: { ...process.env, INPUT_NAME: 'runner-egress-observations', INPUT_PATH: artifact,
    'INPUT_IF-NO-FILES-FOUND': 'error', 'INPUT_RETENTION-DAYS': '1',
    'INPUT_COMPRESSION-LEVEL': '6', INPUT_OVERWRITE: 'false', 'INPUT_INCLUDE-HIDDEN-FILES': 'false',
    INPUT_ARCHIVE: 'true' } });
// Preserve the diagnostic artifact even on collection failure, but never make
// missing coverage from a broken tool look like a successful observation job.
if (report.coverage.collector.collection_error) throw new Error(report.coverage.collector.collection_error);
if (!destinations.length) throw new Error('No outbound destinations observed');
