import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diagnostics, handlerErrors, refusalReasons } from './diagnostics.mjs';

for (const phase of ['collector', 'policy']) {
  test(`${phase} refusal produces a downloadable diagnostics-only layout`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'audit-diagnostics-'));
    try {
      await writeFile(join(dir, 'agent_output.json'), JSON.stringify({
        errors: phase === 'collector' ? ['collector refusal'] : [],
        items: [{ type: 'noop', message: 'must not be published' }],
      }));
      if (phase === 'policy') await writeFile(join(dir, 'report.json'), JSON.stringify({
        ok: false, errors: ['policy refusal'], items: [{ type: 'noop' }], patch: { file: 'rejected.patch' },
      }));
      const destination = join(dir, 'check-diagnostics');
      await diagnostics(dir, destination);
      const collector = JSON.parse(await readFile(join(destination, 'agent_output.json')));
      assert.deepEqual(collector, { errors: phase === 'collector' ? ['collector refusal'] : [], items: [] });
      if (phase === 'policy') assert.deepEqual(JSON.parse(await readFile(join(destination, 'report.json'))), {
        ok: false, errors: ['policy refusal'], items: [],
      });
      else await assert.rejects(readFile(join(destination, 'report.json')), { code: 'ENOENT' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test('diagnostics bounds input and refusal evidence', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'audit-diagnostics-'));
  try {
    const source = join(dir, 'agent_output.json');
    const destination = join(dir, 'check-diagnostics');
    await writeFile(source, JSON.stringify({ errors: Array(101).fill('x'.repeat(1001)), items: [] }));
    await diagnostics(dir, destination);
    const report = JSON.parse(await readFile(join(destination, 'agent_output.json')));
    assert.equal(report.errors.length, 101);
    assert.ok(report.errors[0].endsWith('[truncated]'));
    assert.ok(report.errors[100].includes('omitted'));
    await writeFile(source, ' '.repeat((8 << 20) + 1));
    await assert.rejects(diagnostics(dir, destination), /bounded regular file/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

for (const [name, errors, expected] of [
  ['agent_output.json', ['collector refusal'], ['collector refusal']],
  ['report.json', ['protected files: CONTRIBUTING.md'], ['protected files: CONTRIBUTING.md']],
  ['report.json', [], []],
  ['report.json', ['bad\n::error::\r@user [link](x) `code`'],
    ['bad ::error:: @\u200buser \\[link\\](x) \\`code\\`']],
]) {
  test(`refusal reasons: ${name} ${JSON.stringify(errors)}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'refusal-reasons-'));
    try {
      assert.deepEqual(await refusalReasons(dir), []);
      await writeFile(join(dir, name), JSON.stringify({ errors, items: [{ message: 'not a reason' }] }));
      assert.deepEqual(await refusalReasons(dir), expected);
      await writeFile(join(dir, name), JSON.stringify({ errors: [42] }));
      await assert.rejects(refusalReasons(dir), /Invalid diagnostic report/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test('refusal reasons bound report count and text', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'refusal-reasons-'));
  try {
    for (const name of ['agent_output.json', 'report.json']) {
      await writeFile(join(dir, name), JSON.stringify({ errors: Array(101).fill('x'.repeat(1001)) }));
    }
    const reasons = await refusalReasons(dir);
    assert.equal(reasons.length, 100);
    assert.ok(reasons.every(reason => reason.length === 1000));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// gh-aw's safe-output-errors.json, as its handler manager writes it.
for (const [report, expected] of [
  [{ status: 'failure', message: '1 safe output(s) failed:\n  - add_comment: E008: too many links',
     failures: [{ type: 'add_comment', errorCode: 'E099', error: 'E008: Comment contains 52 links, maximum is 50.' }] },
   ['add\\_comment: E008: Comment contains 52 links, maximum is 50.']],
  [{ failures: [{ type: 'add_comment', error: 'bad\n::error::\r@user [link](x) `code`' }, { type: 'create_issue' }] },
   ['add\\_comment: bad ::error:: @\u200buser \\[link\\](x) \\`code\\`', 'create\\_issue: no error given']],
  [{ message: 'Handler manager failed: boom', failures: [] }, ['Handler manager failed: boom']],
  [{ failures: Array(101).fill({ type: 'add_comment', error: 'x'.repeat(1001) }) }, Array(100).fill(`add\\_comment: ${'x'.repeat(987)}`)],
]) {
  test(`handler errors: ${JSON.stringify(report).slice(0, 80)}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'handler-errors-'));
    try {
      const file = join(dir, 'safe-output-errors.json');
      assert.deepEqual(await handlerErrors(file), []);
      await writeFile(file, JSON.stringify(report));
      assert.deepEqual(await handlerErrors(file), expected);
      await writeFile(file, JSON.stringify({ failures: [{ type: 42 }] }));
      await assert.rejects(handlerErrors(file), /Invalid handler error report/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}
