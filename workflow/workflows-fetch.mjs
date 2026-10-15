// One authenticated fetch; credentials are neither persisted nor passed in argv.
import { execFileSync } from 'node:child_process';

const { BASE, HEAD, GH_TOKEN } = process.env;
if (![BASE, HEAD].every(value => /^[0-9a-f]{40}$/.test(value))) {
  throw new Error('expected full base and head commit IDs');
}
const env = { ...process.env };
if (GH_TOKEN) {
  env.GIT_CONFIG_COUNT = '1';
  env.GIT_CONFIG_KEY_0 = 'http.extraheader';
  env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${GH_TOKEN}`).toString('base64')}`;
}
delete env.GH_TOKEN;
execFileSync('git', ['-C', process.argv[2], 'fetch', '--no-tags', 'origin', BASE, HEAD], {
  env, stdio: 'inherit', timeout: 120_000,
});
