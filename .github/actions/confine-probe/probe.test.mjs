import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { MODES, failures, fixtureProblem } from './probe.mjs';

const all = value => Object.fromEntries(MODES.confined.map(name => [name, value]));

test('a confined step passes only when every route fails and its own file takes a write', () => {
  const confined = { ...all(false), 'owner-write': true };
  assert.deepEqual(failures('confined', confined), []);
  for (const name of MODES.confined) {
    const got = failures('confined', { ...confined, [name]: !confined[name] });
    assert.equal(got.length, 1, name);
    assert.match(got[0], new RegExp(`^${name}: `));
  }
  // Every write refused is not proof of the policy: the owner's control fails it.
  assert.deepEqual(failures('confined', all(false)), ['owner-write: failed, must succeed']);
  assert.deepEqual(failures('confined', {}).length, MODES.confined.length);
});

test('the control passes only when every route works before the lock', () => {
  assert.deepEqual(failures('control', all(true)), []);
  for (const name of MODES.control) {
    assert.deepEqual(failures('control', { ...all(true), [name]: false }), [`${name}: failed, must succeed`]);
  }
  assert.throws(() => failures('unlocked', {}), /unknown mode/);
});

test('a fixture that DAC would refuse anyway proves nothing', () => {
  const stat = (overrides = {}) => ({ isFile: () => true, uid: 0, mode: 0o100666, ...overrides });
  assert.equal(fixtureProblem(stat()), null);
  for (const [overrides, problem] of [
    [{ uid: 1001 }, 'owned by uid 1001, not root'],
    [{ mode: 0o100664 }, 'mode 664, not 666'],
    [{ mode: 0o104666 }, 'mode 4666, not 666'],
    [{ isFile: () => false }, 'not a regular file'],
  ]) {
    assert.equal(fixtureProblem(stat(overrides)), problem);
  }
  assert.equal(fixtureProblem(undefined), 'missing');
});

test('the action probes in both its main and its post step', () => {
  // Without a post entry the runner runs no post step, and the job passes
  // without the proof docs/secure-host.md claims.
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const action = fs.readFileSync(path.join(dir, 'action.yml'), 'utf8');
  for (const [key, file, label] of [['main', 'main.mjs', 'action'], ['post', 'post.mjs', 'post']]) {
    assert.match(action, new RegExp(`^  ${key}: ${file.replace('.', '\\.')}$`, 'm'));
    assert.match(fs.readFileSync(path.join(dir, file), 'utf8'), new RegExp(`^await probe\\('confined', '${label}'\\);$`, 'm'));
  }
  assert.match(action, /^  using: node\d+$/m);
});
