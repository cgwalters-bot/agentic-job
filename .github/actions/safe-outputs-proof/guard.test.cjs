const assert = require('node:assert/strict');
const { test } = require('node:test');
const { inspect, BODY } = require('./guard.cjs');

const proof = {
  id: 123,
  body: BODY,
  html_url: 'https://github.com/cgwalters-forge/agentic-job/issues/64#issuecomment-123',
  user: { id: 41898282, type: 'Bot' },
  performed_via_github_app: { id: 15368 },
};
const read = value => () => JSON.stringify(value);

test('first attempt can publish only after a complete empty lookup', () => {
  assert.deepEqual(inspect(read([]), '1'), { publish: true });
  assert.deepEqual(inspect(read([{ body: 'Unrelated scratch comment' }]), '1'), { publish: true });
});

test('existing proof is reused across attempts and verified without publication', () => {
  for (const attempt of ['1', '2', '3']) {
    for (const verify of [false, true]) {
      assert.deepEqual(inspect(read([proof]), attempt, verify), { publish: false, url: proof.html_url });
    }
  }
});

test('incomplete, malformed, spoofed and ambiguous lookup results refuse', () => {
  for (const value of [
    {}, null, Array(100).fill({ body: 'Unrelated' }), Array(101).fill(proof),
    [null], [{}], [{ body: null }], [proof, proof],
    [{ ...proof, user: { id: 1, type: 'Bot' } }],
    [{ ...proof, user: { id: 41898282, type: 'User' } }],
    [{ ...proof, performed_via_github_app: null }],
    [{ ...proof, performed_via_github_app: { id: 1 } }],
    [{ ...proof, body: `Quoted ${BODY}` }],
    [{ ...proof, html_url: 'https://example.invalid/' }],
    [{ ...proof, id: -1 }],
  ]) assert.throws(() => inspect(read(value), '1'));
  assert.throws(() => inspect(() => '{', '1'));
  assert.throws(() => inspect(() => { throw new Error('API/timeout/byte limit failure'); }, '1'));
});

test('missing proof never authorizes an ambiguous rerun or successful readback', () => {
  for (const attempt of ['2', '3', undefined, '', '0']) {
    assert.throws(() => inspect(read([]), attempt));
  }
  assert.throws(() => inspect(read([]), '1', true));
});
