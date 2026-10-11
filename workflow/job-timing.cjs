const assert = require('node:assert/strict');

function setupSeconds(job, firstStep) {
  const start = Date.parse(job.started_at) / 1000;
  assert.ok(Number.isFinite(start), 'missing job start');
  assert.ok(Number.isFinite(firstStep) && firstStep >= start, 'missing or invalid first agent step');
  return firstStep - start;
}

function checkJobDuration(job, limit) {
  const seconds = (Date.parse(job.completed_at) - Date.parse(job.started_at)) / 1000;
  assert.ok(Number.isFinite(seconds) && seconds >= 0, 'missing job duration');
  assert.ok(seconds <= limit, `hosted agent job took ${seconds}s (bound ${limit}s)`);
  return seconds;
}

module.exports = { setupSeconds, checkJobDuration };
