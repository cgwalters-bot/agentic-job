import { spawn, execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, writeFileSync } from 'node:fs';
import { FIELDS, sockets, MAX_BYTES } from './parse.mjs';

const trace = process.argv[2];
for (const path of [trace, `${trace}.sockets`]) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
// Keep timeout in the detached capture group. Its default separate group makes
// a group-wide stop race sudo/timeout's signal forwarding and kill-after timer.
const captureArgs = ['-n', 'timeout', '--foreground', '--signal=TERM', '--kill-after=5', '480',
  'tshark', '-n', '-l', '-i', 'any', '-a', 'duration:480', '-c', '10000',
  '-s', '4096', '-f', 'ip or ip6', '-T', 'fields',
  ...FIELDS.flatMap(field => ['-e', field])];
const child = spawn('sudo', captureArgs, { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
let traceBytes = 0;
let socketBytes = 0;
let reason = 'packet or duration limit';
let collection_error = null;
let stopping = false;
let stderr = '';
const MAX_STDERR = 4096;

function commandError(command, code, signal, detail) {
  // Diagnostics also reach Actions logs and a fenced Markdown summary. Escape
  // command delimiters and backticks as well as JSON's newlines/control bytes.
  const quoted = JSON.stringify(detail.slice(-MAX_STDERR))
    .replaceAll(':', '\\u003a').replaceAll('`', '\\u0060');
  return `${command}: exit ${code ?? 'null'}, signal ${signal ?? 'none'}; stderr ${quoted}`;
}

function stop(why) {
  if (stopping) return;
  stopping = true;
  reason = why;
  try {
    execFileSync('sudo', ['-n', 'kill', '-TERM', '--', `-${child.pid}`], { timeout: 2000, stdio: 'ignore' });
  } catch {
    // timeout still bounds a capture that has already exited or cannot be signalled.
  }
}

child.stdout.on('data', data => {
  traceBytes += data.length;
  if (traceBytes > MAX_BYTES) { stop('metadata size limit'); return; }
  appendFileSync(trace, data);
});
child.stderr.on('data', data => {
  stderr = (stderr + data.toString()).slice(-MAX_STDERR);
  if (stderr.includes('Capturing on') && !existsSync(`${trace}.ready`)) {
    writeFileSync(`${trace}.ready`, '', { mode: 0o600 });
  }
});
child.on('error', error => {
  reason = 'capture launch failed';
  collection_error = commandError(['sudo', ...captureArgs].join(' '), null, null, error.message);
});
const deadline = Date.now() + 480000;
const timer = setInterval(() => {
  if (existsSync(`${trace}.stop`)) return stop('final post snapshot');
  if (Date.now() >= deadline) return stop('duration limit');
  if (stopping) return;
  try {
    const text = execFileSync('sudo', ['-n', 'ss', '-Hntup'],
      { encoding: 'utf8', timeout: 2000, maxBuffer: 1024 * 1024 });
    const data = sockets(text, Date.now() / 1000).map(row => JSON.stringify(row) + '\n').join('');
    socketBytes += Buffer.byteLength(data);
    if (socketBytes > MAX_BYTES) return stop('socket metadata size limit');
    appendFileSync(`${trace}.sockets`, data);
  } catch (error) {
    collection_error = commandError('sudo -n ss -Hntup', error.status, error.signal,
      error.stderr?.toString() || error.message);
    stop('socket sampling failed');
  }
}, 500);
child.on('close', (code, signal) => {
  clearInterval(timer);
  if (code === 124 && Date.now() >= deadline - 1000) {
    stopping = true;
    reason = 'duration limit';
  }
  const expected = stopping && ([0, 124, 130, 143].includes(code) || ['SIGINT', 'SIGTERM'].includes(signal));
  if (code !== 0 && !expected && !collection_error) {
    reason = 'capture failed';
    collection_error = commandError(['sudo', ...captureArgs].join(' '), code, signal, stderr);
  }
  writeFileSync(`${trace}.status`, JSON.stringify({ reason, collection_error, capture_exit: code, capture_signal: signal }), { mode: 0o600 });
});
