// Publish only bounded refusal evidence, never requests or patches for apply.
import { open, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 8 << 20;
const MAX_ERRORS = 100;
const MAX_REASON_CHARS = 1000;

async function readReport(path) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > MAX_BYTES) {
      throw new Error(`Diagnostic report is not a bounded regular file: ${path}`);
    }
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > MAX_BYTES) throw new Error(`Diagnostic report grew beyond its limit: ${path}`);
    return JSON.parse(buffer.subarray(0, length).toString('utf8'));
  } finally {
    await file.close();
  }
}

export async function refusalReasons(source) {
  const reasons = [];
  for (const name of ['agent_output.json', 'report.json']) {
    const report = await readReport(join(source, name));
    if (report === null) continue;
    if (!Array.isArray(report.errors) || !report.errors.every(e => typeof e === 'string')) {
      throw new Error(`Invalid diagnostic report: ${name}`);
    }
    reasons.push(...report.errors.slice(0, MAX_ERRORS));
  }
  return reasons.slice(0, MAX_ERRORS).map(neutralize);
}

// Paths, collector and handler errors can contain hostile text. Keep outputs
// on one line and neutralize Markdown/mentions before using them in a comment.
function neutralize(reason) {
  return reason.slice(0, MAX_REASON_CHARS)
    .replace(/[\x00-\x1f\x7f-\x9f]/g, ' ')
    .replace(/@/g, '@\u200b').replace(/[\\`*_\[\]<>]/g, '\\$&');
}

// What gh-aw's handler manager records when outputs fail (its
// safe_output_manifest.cjs, secrets redacted): each failed output's type
// and its handler's error, or the manager's own message when it failed
// before any output did. The requests and patch are not in it.
export async function handlerErrors(path) {
  const report = await readReport(path);
  if (report === null) return [];
  const failures = report.failures ?? [];
  if (!Array.isArray(failures) || !failures.every(f => typeof f?.type === 'string' && typeof (f.error ?? '') === 'string') ||
      (report.message !== undefined && typeof report.message !== 'string')) {
    throw new Error('Invalid handler error report');
  }
  const reasons = failures.length ? failures.slice(0, MAX_ERRORS).map(f => `${f.type}: ${f.error || 'no error given'}`)
    : [report.message].filter(Boolean);
  return reasons.map(neutralize);
}

export async function diagnostics(source, destination) {
  await mkdir(destination, { recursive: true });
  for (const name of ['agent_output.json', 'report.json']) {
    const report = await readReport(join(source, name));
    if (report === null) continue;
    if (!Array.isArray(report.errors) || !report.errors.every(e => typeof e === 'string') ||
        (name === 'report.json' && typeof report.ok !== 'boolean')) {
      throw new Error(`Invalid diagnostic report: ${name}`);
    }
    const errors = report.errors.slice(0, MAX_ERRORS).map(e =>
      e.length > MAX_REASON_CHARS ? `${e.slice(0, MAX_REASON_CHARS)} [truncated]` : e);
    if (report.errors.length > MAX_ERRORS) errors.push('[additional refusal reasons omitted]');
    const diagnostic = { errors, items: [] };
    if (name === 'report.json') diagnostic.ok = report.ok;
    await writeFile(join(destination, name), JSON.stringify(diagnostic) + '\n');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 4) throw new Error('Usage: diagnostics.mjs SOURCE DESTINATION');
  await diagnostics(process.argv[2], process.argv[3]);
}
