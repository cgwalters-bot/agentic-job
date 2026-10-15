import { spawn, execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { networkInterfaces } from 'node:os';

// Installation precedes observation; do not capture or retain raw packets.
execFileSync('sudo', ['-n', 'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get',
  'install', '-y', '--no-install-recommends', 'tshark'], { stdio: 'inherit', timeout: 120000 });
const trace = join(process.env.RUNNER_TEMP, 'runner-outbound.tsv');
const child = spawn(process.execPath, [new URL('./observe.mjs', import.meta.url).pathname, trace],
  { detached: true, stdio: 'ignore' });
let failure;
child.on('error', error => { failure = error; });
child.unref();
let ready = false;
for (let i = 0; i < 100; i++) {
  if (failure) throw failure;
  if (existsSync(`${trace}.ready`)) {
    ready = true;
    break;
  }
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!ready) throw new Error('tshark did not start');
const addresses = Object.values(networkInterfaces()).flat().map(entry => entry.address);
writeFileSync(`${trace}.addresses`, JSON.stringify(addresses), { mode: 0o600 });
appendFileSync(process.env.GITHUB_STATE, `trace=${trace}\n`);
