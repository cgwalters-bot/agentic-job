import { spawn, execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, writeFileSync } from 'node:fs';
import { FIELDS, sockets, MAX_BYTES } from './parse.mjs';

const trace = process.argv[2];
for (const path of [trace, `${trace}.sockets`]) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
const child = spawn('sudo', ['-n', 'timeout', '--signal=INT', '--kill-after=5', '480',
  'tshark', '-n', '-l', '-i', 'any', '-a', 'duration:480', '-c', '10000',
  '-s', '4096', '-f', 'ip or ip6', '-T', 'fields',
  ...FIELDS.flatMap(field => ['-e', field])], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
let traceBytes = 0;
let socketBytes = 0;
let reason = 'packet or duration limit';
let collection_error = null;
let stopping = false;
let stderr = '';

function stop(why) {
  if (stopping) return;
  stopping = true;
  reason = why;
  try {
    execFileSync('sudo', ['-n', 'kill', '-INT', '--', `-${child.pid}`], { timeout: 2000, stdio: 'ignore' });
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
  stderr = (stderr + data.toString()).slice(-4096);
  if (stderr.includes('Capturing on') && !existsSync(`${trace}.ready`)) {
    writeFileSync(`${trace}.ready`, '', { mode: 0o600 });
  }
});
child.on('error', () => { collection_error = reason = 'capture launch failed'; });
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
  } catch {
    collection_error = 'socket sampling failed';
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
  if (code !== 0 && !expected && !collection_error) collection_error = reason = 'capture failed';
  writeFileSync(`${trace}.status`, JSON.stringify({ reason, collection_error, capture_exit: code, capture_signal: signal }), { mode: 0o600 });
});
