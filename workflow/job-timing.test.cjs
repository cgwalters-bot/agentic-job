const assert = require('node:assert/strict');
const { test } = require('node:test');
const { setupSeconds, checkJobDuration } = require('./job-timing.cjs');
const job = { started_at: '2026-10-11T00:00:00Z', completed_at: '2026-10-11T00:02:00Z' };

test('setup includes all time before the first task dispatch', () => {
  assert.equal(setupSeconds(job, Date.parse(job.started_at) / 1000 + 45.5), 45.5);
  for (const value of [null, NaN, 0]) assert.throws(() => setupSeconds(job, value));
});

test('hosted job bound fails closed on missing or excessive durations', () => {
  assert.equal(checkJobDuration(job, 900), 120);
  assert.throws(() => checkJobDuration(job, 119));
  assert.throws(() => checkJobDuration({ ...job, completed_at: null }, 900));
});
