// Run only from trusted default-branch source, never from a pull request.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const source = 'crates/secure-host/src/egress.rs';
const limit = 16 * 1024 * 1024;

export function setting(text, name) {
  const matches = [...text.matchAll(new RegExp(`^const ${name}: &str = "([^"\\n]+)";`, 'gm'))];
  if (matches.length !== 1) throw new Error(`expected one ${name}`);
  return matches[0][1];
}

export function refresh(text, commit, bytes) {
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('invalid commit');
  if (!bytes.length || bytes.length > limit) throw new Error('invalid feed size');
  const lines = bytes.toString('utf8').split(/\r?\n/).filter(line => line && !line.startsWith('#'));
  // Refuse an HTML error page or a changed upstream format, not just an empty feed.
  if (!lines.length || lines.some(line => !/^(?:[a-z0-9_-]+\.)+[a-z0-9_-]+$/.test(line))) {
    throw new Error('invalid domain feed');
  }
  const hash = createHash('sha256').update(bytes).digest('hex');
  for (const [name, value] of [['DENYLIST_COMMIT', commit], ['DENYLIST_SHA256', hash]]) {
    const old = setting(text, name);
    text = text.replace(`const ${name}: &str = "${old}";`, `const ${name}: &str = "${value}";`);
  }
  return text;
}

async function download(url, maximum) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000), redirect: 'error' });
  if (!response.ok) throw new Error(`fetch ${url}: ${response.status}`);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > maximum) throw new Error('response too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function propose(text, downloadFile = download) {
  // The repository and path come from the runtime's own configuration, not dispatcher input.
  const upstream = new URL(setting(text, 'DENYLIST_REPOSITORY'));
  if (upstream.origin !== 'https://raw.githubusercontent.com' || !/^\/[\w.-]+\/[\w.-]+$/.test(upstream.pathname)) {
    throw new Error('unsupported feed repository');
  }
  const file = setting(text, 'DENYLIST_FILE');
  if (!/^[\w.-]+(?:\/[\w.-]+)*$/.test(file) || file.split('/').includes('..')) throw new Error('invalid feed path');
  const api = `https://api.github.com/repos${upstream.pathname}/commits?path=${encodeURIComponent(file)}&per_page=1`;
  const entries = JSON.parse((await downloadFile(api, 256 * 1024)).toString('utf8'));
  const commit = entries?.[0]?.sha;
  if (!/^[a-f0-9]{40}$/.test(commit ?? '')) throw new Error('invalid upstream commit');
  const bytes = await downloadFile(`${upstream.href}/${commit}/${file}`, limit);
  return refresh(text, commit, bytes);
}

export function publish(text, repo, run) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo ?? '')) throw new Error('missing repository');
  const commit = setting(text, 'DENYLIST_COMMIT');
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('invalid commit');
  const prefix = 'maintenance/threat-feed-';
  const branch = `${prefix}${commit}`;
  // One outstanding proposal at a time; never rewrite a branch under review.
  const open = JSON.parse(run('gh', ['pr', 'list', '--repo', repo, '--limit', '100', '--json', 'headRefName,isCrossRepository']));
  // A fork may choose any branch name; it cannot reserve our maintenance namespace.
  if (open.length === 100 || open.some(pr => pr.isCrossRepository === false && pr.headRefName.startsWith(prefix)) || !run('git', ['diff', '--', source])) return;
  run('git', ['switch', '-c', branch]);
  run('git', ['add', '--', source]);
  run('git', ['-c', 'user.name=feed maintenance', '-c', 'user.email=feed-maintenance@users.noreply.github.com',
    'commit', '-m', 'egress: Keep known malicious destinations covered\n\nRefresh the reviewed feed snapshot so newly listed threats are not missed.\n\nGenerated-by: AI']);
  // The checkout has no stored credentials. gh supplies the dedicated token only here.
  run('gh', ['auth', 'setup-git']);
  run('git', ['push', 'origin', `HEAD:refs/heads/${branch}`]);
  run('gh', ['pr', 'create', '--repo', repo, '--head', branch, '--draft',
    '--title', 'egress: Keep known malicious destinations covered', '--body',
    'Refresh the commit and checksum together so new threat-feed entries can be reviewed before runtime use. No runtime trust policy changes.\n\nVerified by the refresh job’s feed-format and checksum tests; normal PR CI remains required.']);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const text = await readFile(source, 'utf8');
  if (process.argv[2] === 'publish') {
    publish(text, process.env.GITHUB_REPOSITORY,
      (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8' }).trim());
  } else if (process.argv[2] === 'update') await writeFile(source, await propose(text));
  else throw new Error('expected update or publish');
}
