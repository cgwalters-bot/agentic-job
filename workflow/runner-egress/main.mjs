import { spawn } from 'node:child_process';
import { appendFileSync, closeSync, openSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const trace = join(process.env.RUNNER_TEMP, 'runner-outbound.txt');
const errors = `${trace}.stderr`;
const out = openSync(trace, 'wx', 0o600);
const err = openSync(errors, 'wx', 0o600);
// Metadata only: -q suppresses protocol payload decoding, -nn disables DNS
// lookups. Packet and wall-clock caps bound even an unexpectedly noisy host.
const child = spawn('sudo', ['-n', 'timeout', '480', 'tcpdump', '-i', 'any',
  '-Q', 'out', '-nn', '-q', '-t', '-l', '-s', '96', '-c', '10000',
  'ip or ip6'], { detached: true, stdio: ['ignore', out, err] });
closeSync(out);
closeSync(err);
let failure;
child.on('error', error => { failure = error; });
child.unref();
let ready = false;
for (let i = 0; i < 100; i++) {
  if (failure) throw failure;
  if (readFileSync(errors, 'utf8').includes('listening on')) {
    ready = true;
    break;
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!ready) throw new Error(`tcpdump did not start: ${readFileSync(errors, 'utf8')}`);
appendFileSync(process.env.GITHUB_STATE, `trace=${trace}\n`);
