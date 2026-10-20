const assert = require('node:assert/strict');

function setupSeconds(job, firstStep) {
  const start = Date.parse(job.started_at) / 1000;
  assert.ok(Number.isFinite(start), 'missing job start');
  assert.ok(Number.isFinite(firstStep) && firstStep >= start, 'missing or invalid first agent step');
  return firstStep - start;
}

function checkJobDuration(job, limit) {
  const seconds = (Date.parse(job.completed_at) - Date.parse(job.started_at)) / 1000;
  assert.ok(Number.isFinite(seconds) && seconds >= 0, `missing or invalid job duration for ${job.name ?? job.id ?? 'unknown job'}`);
  assert.ok(seconds <= limit, `hosted agent job took ${seconds}s (bound ${limit}s)`);
  return seconds;
}

async function checkCompletedJobDuration(job, limit, readJob, sleep = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  // The jobs listing can report completion before its timestamps propagate.
  // Re-read this exact job, not a newer attempt, three times, five seconds apart.
  for (let retry = 0; retry < 3; retry++) {
    if (job.status !== 'completed' || Number.isFinite(Date.parse(job.completed_at) - Date.parse(job.started_at))) break;
    await sleep(5000);
    job = await readJob(job.id);
  }
  return checkJobDuration(job, limit);
}

module.exports = { setupSeconds, checkJobDuration, checkCompletedJobDuration };
