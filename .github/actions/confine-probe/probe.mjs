// What a step of a job secured by secure-host tries, as the runner's own
// user: the routes to root (sudo, the container daemon, a root-owned
// world-writable file), to the cloud metadata service, and to the
// environment of a process an earlier step left running, and to
// Runner.Worker's .NET diagnostic sockets (sandbox.unlink-worker-diagnostics),
// through which a step could have the Worker dump its memory. The job in
// ci.yml runs it once before the action as the positive control, where
// each must work, and after it from a `run:` step and from this
// directory's action, in its main step and its post step, where each must fail
// (docs/secure-host.md#one-trust-level-for-the-rest-of-the-job).
// Its `sandbox-user` and `no-user` modes probe, after the lock, the
// sandbox user setup makes by default, and a host that opted out of it
// (sandbox.create-user = false).
//
//   node probe.mjs control|confined|sandbox-user|no-user LABEL
//
// It writes what it found to $RUNNER_TEMP/confine/LABEL.json for the
// job's artifact, and to its log. The post step's record is only in its
// log: the upload is a main step, so it runs before any post step.
// Booleans and group names, never a variable's value.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Root's, mode 0666, made before the action in a shared temporary
// directory on the root filesystem, which setup's walk and the check's
// search leave alone: only the access-time policy refuses a write to it.
export const FIXTURE = '/var/tmp/agentic-job-confine-root-file';

// The pid of `sleep`, which a step before the control started and left
// running, so that every probe is a later step than it. Its environment
// is the earlier step's; only whether it can be read is recorded.
export const ORPHAN = 'confine-orphan.pid';

// The pid of the Worker, which the control finds among its ancestors and
// records here: after the lock, the runner-read rule and hidepid take
// every ancestor out of a step's /proc.
export const WORKER = 'confine-worker.pid';

const METADATA_URL = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01';

const COMMAND_MS = 10_000;

const METADATA_MS = 5_000;

// A run0 session's start, then the command: more than COMMAND_MS, so
// that a slow start is not taken for a refusal.
const ENTER_MS = 60_000;

const WORKER_COMM = 'Runner.Worker';

// A step's process is the Worker's child (an action's), or its grandchild
// (a `run:` step's shell's); far more than either, and then no Worker.
const MAX_ANCESTORS = 32;

const CONNECT_MS = 5_000;

export const MODES = {
  // Before the lock: the job's user has each of these.
  control: ['sudo', 'docker', 'world-write', 'metadata', 'environ', 'worker-diagnostics'],
  // After it: none, and its own world-writable file still takes a write,
  // so the refusal of the root-owned one is the policy's, not every write's.
  confined: ['sudo', 'docker', 'world-write', 'metadata', 'environ', 'worker-diagnostics', 'owner-write'],
  // After it, the sandbox user setup made by default, entered the one way
  // there is (`helper enter`, whose success is the control): no sudo, no
  // metadata service.
  'sandbox-user': ['user', 'user-enter', 'user-sudo', 'user-metadata'],
  // After it with sandbox.create-user = false: no such user, and the
  // runner's sudo is the helper's rule and nothing else.
  'no-user': ['user', 'sudo', 'sudo-true-listed', 'sudo-rules', 'helper'],
};

const WANT_SUCCESS = {
  confined: ['owner-write'],
  'sandbox-user': ['user', 'user-enter'],
  'no-user': ['sudo-rules', 'helper'],
};

/** Whether a probe must succeed in `mode`: everything in control, and only those `WANT_SUCCESS` names otherwise. */
export function wanted(mode, name) {
  return mode === 'control' || (WANT_SUCCESS[mode] ?? []).includes(name);
}

// The root-owned copy of agentic-job that the runner's one sudo rule names
// (sandbox::setup::SELF_COPY), and the user setup makes by default: the
// configurations CI probes name no other.
const HELPER = '/usr/local/libexec/agentic-job';

export const SANDBOX_USER = 'runner-sandbox';

/** The rules of a `sudo -l` listing, normalized as sandbox::check::runner::sudo_rules does. */
export function sudoRules(listing) {
  return listing.split('\n').map(line => line.trim()).filter(line => line.startsWith('('))
    .map(line => line.split(/\s+/).join(' '));
}

/** Whether `rules` end with the lock's deny rule and the helper's grant, which win over any before them. */
export function lockedRules(rules) {
  const want = ['(ALL : ALL) !ALL', `(root) NOPASSWD: ${HELPER} helper *`];
  return rules.length >= want.length && want.every((rule, i) => rules[rules.length - want.length + i] === rule);
}

/** The home of `user` from a `getent passwd` line, or null. */
export function homeOf(passwd) {
  const fields = passwd.trim().split(':');
  return fields.length === 7 && fields[5].startsWith('/') ? fields[5] : null;
}

function output(argv) {
  const result = spawnSync(argv[0], argv.slice(1), { encoding: 'utf8', timeout: COMMAND_MS });
  return result.status === 0 ? result.stdout : null;
}

/**
 * Whether ARGV succeeds as the sandbox user, entered through the helper in
 * HOME. Its streams are pipes, which libuv makes as socket pairs: run0 hands
 * them to PID 1, which refuses /dev/null (sandbox::enter::Entry::command).
 */
function runsAsSandbox(home, argv) {
  const command = ['sudo', '-n', '--', HELPER, 'helper', 'enter', '--chdir', home, '--', ...argv];
  const result = spawnSync(command[0], command.slice(1), { input: '', timeout: ENTER_MS });
  return result.status === 0;
}

// What the sandbox user does, or that there is none, as the runner's user.
function userResults(mode) {
  const passwd = output(['getent', 'passwd', SANDBOX_USER]);
  const home = passwd === null ? null : homeOf(passwd);
  if (mode === 'no-user') {
    const listing = output(['sudo', '-n', '-l']);
    return {
      user: passwd !== null,
      sudo: runs(['sudo', '-n', 'true']),
      // sudo's own answer for an ordinary command, which the lock refuses.
      'sudo-true-listed': runs(['sudo', '-n', '-l', '/usr/bin/true']),
      'sudo-rules': listing !== null && lockedRules(sudoRules(listing)),
      helper: runs(['sudo', '-n', '--', HELPER, 'helper', 'ping']),
    };
  }
  if (home === null) return { user: false };
  return {
    user: true,
    'user-enter': runsAsSandbox(home, ['true']),
    'user-sudo': runsAsSandbox(home, ['sudo', '-n', 'true']),
    // Around the egress proxy its environment names, whose refusal would
    // otherwise stand in for the rule on its uid.
    'user-metadata': runsAsSandbox(home, ['curl', '-sf', '--noproxy', '*', '-o', '/dev/null', '-m', String(METADATA_MS / 1000), '-H', 'Metadata: true', METADATA_URL]),
  };
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

/**
 * Why a refused read of the orphan's environment, or connection to the
 * Worker, would prove nothing, or null, by the error of `kill(pid, 0)`
 * (null when it succeeded): it must be running and this user's. A signal
 * needs no ptrace access, so this holds where setup's hidepid and the
 * runner-read rule hide it from /proc.
 */
export function orphanProblem(code) {
  if (code === null) return null;
  if (code === 'ESRCH') return 'not running';
  if (code === 'EPERM') return 'not this user\'s';
  return `kill(0) failed with ${code}`;
}

function signalError(pid) {
  try {
    process.kill(pid, 0);
    return null;
  } catch (error) {
    return error.code ?? String(error);
  }
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

// With hidepid=invisible, a process the rule refuses is not in /proc at
// all for this one: ENOENT, while the signal check says it is running.
function readsEnviron(pid) {
  try {
    fs.readFileSync(`/proc/${pid}/environ`);
    return true;
  } catch (error) {
    if (!['EACCES', 'EPERM', 'ENOENT'].includes(error.code)) throw error;
    return false;
  }
}

/** The pid recorded in `name` under `temp`, refused unless that process is running and this user's. */
function recordedPid(temp, name) {
  const pid = fs.readFileSync(path.join(temp, name), 'utf8').trim();
  if (!/^[1-9][0-9]*$/.test(pid)) throw new Error(`${name}: not a pid`);
  const problem = orphanProblem(signalError(Number(pid)));
  if (problem) throw new Error(`process ${pid} of ${name}: ${problem}, so probing it proves nothing`);
  return Number(pid);
}

/** Whether this user reads the orphan's environment, which must be running before and after. */
function readsOrphan(temp) {
  const pid = recordedPid(temp, ORPHAN);
  const read = readsEnviron(pid);
  recordedPid(temp, ORPHAN);
  return read;
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

/** The paths in `netUnix` (/proc/net/unix) of the diagnostic sockets the .NET runtime binds for `pid`. */
export function diagnosticSockets(netUnix, pid) {
  const name = new RegExp(`/dotnet-diagnostic-${pid}-[0-9]+-socket$`);
  // The path is the last column, and the only one with a `/` in it.
  const paths = netUnix.split('\n').filter(line => line.includes(' /')).map(line => line.slice(line.indexOf(' /') + 1));
  return [...new Set(paths.filter(file => name.test(file)))];
}

// The Worker that runs this step: the nearest ancestor of that name.
function ancestorWorker() {
  let pid = process.pid;
  for (let i = 0; i < MAX_ANCESTORS && pid > 1; i++) {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const comm = stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')'));
    if (comm === WORKER_COMM) return pid;
    pid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
  }
  throw new Error(`no ${WORKER_COMM} among this step's ancestors`);
}

function connects(file) {
  return new Promise(resolve => {
    const socket = net.createConnection({ path: file });
    socket.setTimeout(CONNECT_MS, () => { socket.destroy(); resolve(false); });
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('error', () => resolve(false));
  });
}

// The Worker's pid: found and recorded by the control, read back once confined.
function workerPid(mode, temp) {
  if (mode !== 'control') return recordedPid(temp, WORKER);
  const pid = ancestorWorker();
  fs.writeFileSync(path.join(temp, WORKER), `${pid}\n`);
  return pid;
}

// Whether this step connects to any diagnostic socket of its Worker. The
// listing keeps a path after it is unlinked, so the control proves the
// Worker had one to find.
export async function reachesWorker(mode, temp) {
  const sockets = diagnosticSockets(fs.readFileSync('/proc/net/unix', 'utf8'), workerPid(mode, temp));
  const reached = await Promise.all(sockets.map(connects));
  return reached.some(Boolean);
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
  let results;
  if (mode === 'sandbox-user' || mode === 'no-user') {
    results = userResults(mode);
  } else {
    results = {
      sudo: runs(['sudo', '-n', 'true']),
      docker: runs(['docker', 'info']),
      'world-write': opensForWrite(fixture()),
      metadata: await reachesMetadata(),
      environ: readsOrphan(temp),
      'worker-diagnostics': await reachesWorker(mode, temp),
    };
  }
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
    console.error(`usage: probe.mjs ${Object.keys(MODES).join('|')} LABEL`);
    process.exit(2);
  }
  await probe(mode, label);
}
