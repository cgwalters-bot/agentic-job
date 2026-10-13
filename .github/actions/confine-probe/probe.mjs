// What a step of a job secured by secure-host tries, as the runner's own
// user: the routes to root (sudo, the container daemon, a root-owned
// world-writable file) and to the cloud metadata service. The job in
// ci.yml runs it once before the action as the positive control, where
// each must work, and after it from a `run:` step and from this
// directory's probe imported by a JavaScript action's main step, where each must fail
// (docs/secure-host.md#one-trust-level-for-the-rest-of-the-job).
//
//   node probe.mjs control|confined LABEL
//
// It writes what it found to $RUNNER_TEMP/confine/LABEL.json for the
// job's artifact, and to its log. A post step is not yet proven by CI:
// https://github.com/cgwalters-forge/agentic-job/issues/513
// Booleans and group names, never a variable's value.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Root's, mode 0666, made before the action in a shared temporary
// directory on the root filesystem, which setup's walk and the check's
// search leave alone: only the access-time policy refuses a write to it.
export const FIXTURE = '/var/tmp/agentic-job-confine-root-file';

const METADATA_URL = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01';

const COMMAND_MS = 10_000;

const METADATA_MS = 5_000;

export const MODES = {
  // Before the lock: the job's user has each of these.
  control: ['sudo', 'docker', 'world-write', 'metadata'],
  // After it: none, and its own world-writable file still takes a write,
  // so the refusal of the root-owned one is the policy's, not every write's.
  confined: ['sudo', 'docker', 'world-write', 'metadata', 'owner-write'],
};

const WANT_SUCCESS = new Set(['owner-write']);

/** Whether a probe must succeed in `mode`: everything in control, and only the owner's own write once confined. */
export function wanted(mode, name) {
  return mode === 'control' || WANT_SUCCESS.has(name);
}

/** The probes of `mode` whose result is not what it must be, as messages. */
export function failures(mode, results) {
  const names = MODES[mode];
  if (!names) throw new Error(`unknown mode ${JSON.stringify(mode)}`);
  return names
    .filter(name => results[name] !== wanted(mode, name))
    .map(name => `${name}: ${results[name] === undefined ? 'not probed' : results[name] ? 'succeeded' : 'failed'}, must ${wanted(mode, name) ? 'succeed' : 'fail'}`);
}

/** Why `stat` of the fixture would make its refusal prove nothing, or null. */
export function fixtureProblem(stat) {
  if (!stat) return 'missing';
  if (!stat.isFile()) return 'not a regular file';
  if (stat.uid !== 0) return `owned by uid ${stat.uid}, not root`;
  if ((stat.mode & 0o7777) !== 0o666) return `mode ${(stat.mode & 0o7777).toString(8)}, not 666`;
  return null;
}

function runs(argv) {
  const result = spawnSync(argv[0], argv.slice(1), { stdio: 'ignore', timeout: COMMAND_MS });
  return result.status === 0;
}

function opensForWrite(file) {
  try {
    fs.closeSync(fs.openSync(file, 'r+'));
    return true;
  } catch (error) {
    if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error;
    return false;
  }
}

function reachesMetadata() {
  return new Promise(resolve => {
    const request = http.get(METADATA_URL, { headers: { Metadata: 'true' }, timeout: METADATA_MS }, response => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.on('timeout', () => request.destroy(new Error('timed out')));
    request.on('error', () => resolve(false));
  });
}

function fixture() {
  const problem = fixtureProblem(fs.statSync(FIXTURE, { throwIfNoEntry: false }));
  if (problem) throw new Error(`${FIXTURE}: ${problem}, so writing it proves nothing`);
  return FIXTURE;
}

function ownerFile(dir, label) {
  const file = path.join(dir, `confine-owner-${label}`);
  fs.writeFileSync(file, '');
  fs.chmodSync(file, 0o666);
  return file;
}

export async function probe(mode, label) {
  const temp = process.env.RUNNER_TEMP;
  if (!temp) throw new Error('RUNNER_TEMP is not set');
  if (!/^[a-z0-9-]+$/.test(label)) throw new Error(`label ${JSON.stringify(label)}`);
  const out = path.join(temp, 'confine');
  fs.mkdirSync(out, { recursive: true });
  const results = {
    sudo: runs(['sudo', '-n', 'true']),
    docker: runs(['docker', 'info']),
    'world-write': opensForWrite(fixture()),
    metadata: await reachesMetadata(),
  };
  if (mode === 'confined') {
    results['owner-write'] = opensForWrite(ownerFile(temp, label));
  }
  const problems = failures(mode, results);
  const record = {
    label,
    mode,
    results,
    // A running process keeps the groups it started with: the runner's
    // steps still carry docker's after the lock, with its daemon stopped.
    groups: spawnSync('id', ['-Gn'], { encoding: 'utf8' }).stdout.trim().split(/\s+/),
    // What the runner hands this kind of step, which no lock takes away.
    tokens: {
      ACTIONS_RUNTIME_TOKEN: Boolean(process.env.ACTIONS_RUNTIME_TOKEN),
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: Boolean(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN),
    },
    problems,
  };
  fs.writeFileSync(path.join(out, `${label}.json`), `${JSON.stringify(record, null, 2)}\n`);
  for (const name of MODES[mode]) {
    const ok = results[name] === wanted(mode, name);
    console.log(`${ok ? 'ok' : 'FAIL'}: [${label}] ${name} ${results[name] ? 'succeeded' : 'failed'}`);
  }
  console.log(`[${label}] record: ${JSON.stringify(record)}`);
  if (problems.length) {
    process.exitCode = 1;
  }
  return record;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [mode, label] = process.argv.slice(2);
  if (!MODES[mode] || !label) {
    console.error('usage: probe.mjs control|confined LABEL');
    process.exit(2);
  }
  await probe(mode, label);
}
