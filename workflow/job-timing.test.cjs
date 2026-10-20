const assert = require('node:assert/strict');
const { test } = require('node:test');
const { setupSeconds, checkJobDuration, checkCompletedJobDuration } = require('./job-timing.cjs');
const job = { started_at: '2026-10-11T00:00:00Z', completed_at: '2026-10-11T00:02:00Z' };

test('setup includes all time before the first task dispatch', () => {
  assert.equal(setupSeconds(job, Date.parse(job.started_at) / 1000 + 45.5), 45.5);
  for (const value of [null, NaN, 0]) assert.throws(() => setupSeconds(job, value));
});

test('completed listing with no completion timestamp is re-read by job id', async () => {
  const listing = { ...job, id: 42, name: 'hosted agent', status: 'completed', completed_at: null };
  const reads = [];
  const waits = [];
  const seconds = await checkCompletedJobDuration(listing, 900, async id => {
    reads.push(id);
    return reads.length === 1 ? listing : { ...listing, completed_at: job.completed_at };
  }, async ms => waits.push(ms));
  assert.equal(seconds, 120);
  assert.deepEqual(reads, [42, 42]);
  assert.deepEqual(waits, [5000, 5000]);
});

test('missing timing exhausts bounded retries and names the job', async () => {
  const listing = { ...job, id: 42, name: 'hosted agent', status: 'completed', completed_at: null };
  let reads = 0;
  let waited = 0;
  await assert.rejects(checkCompletedJobDuration(listing, 900, async () => {
    reads++;
    return listing;
  }, async ms => { waited += ms; }), /missing or invalid job duration for hosted agent/);
  assert.equal(reads, 3);
  assert.equal(waited, 15000);
});

test('valid and excessive durations are checked without retries', async () => {
  const noRetry = async () => assert.fail('unexpected retry');
  assert.equal(await checkCompletedJobDuration(job, 900, noRetry, noRetry), 120);
  await assert.rejects(checkCompletedJobDuration(job, 119, noRetry, noRetry), /bound 119s/);
  await assert.rejects(checkCompletedJobDuration({ ...job, status: 'in_progress', completed_at: null }, 900, noRetry, noRetry), /missing or invalid/);
});

test('re-read errors and excessive recovered durations still fail', async () => {
  const listing = { ...job, status: 'completed', completed_at: null };
  await assert.rejects(checkCompletedJobDuration(listing, 900, async () => { throw new Error('API unavailable'); }, async () => {}), /API unavailable/);
  await assert.rejects(checkCompletedJobDuration(listing, 119, async () => job, async () => {}), /bound 119s/);
});

test('hosted job bound fails closed on missing or excessive durations', () => {
  assert.equal(checkJobDuration(job, 900), 120);
  assert.throws(() => checkJobDuration(job, 119));
  assert.throws(() => checkJobDuration({ ...job, completed_at: null }, 900));
});
