// Exercise the trusted workflow scripts without a forge or token.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const { join } = require('node:path');
const { homedir } = require('node:os');
const { test } = require('node:test');

const workflow = fs.readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
const checker = fs.readFileSync(join(__dirname, '../.github/workflows/check.yml'), 'utf8');

function script(name, key) {
  const source = name === 'How the run ended' ? workflow : checker;
  const section = source.split(`- name: ${name}\n`)[1].split(/\n      - /)[0];
  const indent = key === 'script' ? 12 : 10;
  return section.split(`${key}: |\n`)[1].split('\n')
    .filter(line => line.startsWith(' '.repeat(indent))).map(line => line.slice(indent)).join('\n');
}

for (const phase of ['collector', 'policy', 'review']) {
  test(`${phase} refusal reaches annotations and the conclusion comment`, async () => {
    const dir = fs.mkdtempSync(join(homedir(), 'workflow-refusal-'));
    const source = join(__dirname, '..');
    const env = { ...process.env, GH_AW_TMP: dir, SOURCE_DIR: source, TARGET: '12' };
    const errors = [];
    const outputs = {};
    const core = { error: text => errors.push(text), setFailed: text => errors.push(text),
      setOutput: (key, value) => { outputs[key] = value; } };
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    try {
      fs.writeFileSync(join(dir, 'agent_output.json'), JSON.stringify({
        errors: phase === 'collector' ? ['collector refused'] : [], items: [],
      }));
      if (phase === 'policy') fs.writeFileSync(join(dir, 'report.json'), JSON.stringify({
        ok: false, errors: ['protected files: CONTRIBUTING.md'],
      }));
      if (phase === 'review') {
        // A stand-in for `review verdict` refusing: it writes the report the
        // refusal step reads and fails the step (tests/review.rs covers why).
        const binary = join(dir, 'agentic-job');
        fs.writeFileSync(binary, '#!/bin/bash\nprintf %s \'{"ok":false,"errors":["Review must return exactly one comment or noop"]}\' > "$8"\nexit 1\n');
        fs.chmodSync(binary, 0o700);
        const result = spawnSync('bash', ['-eo', 'pipefail', '-c', script('Validate the review verdict', 'run')], {
          encoding: 'utf8', env: { ...env, JOB_DIR: dir, GITHUB_OUTPUT: join(dir, 'verdict-output') },
        });
        assert.equal(result.status, 1, result.stderr);
        assert.ok(!fs.existsSync(join(dir, 'verdict-output')));
      }
      const reasons = join(dir, 'reasons');
      fs.writeFileSync(reasons, '');
      const shown = spawnSync('bash', ['-eo', 'pipefail', '-c', script('Show why check refused the outputs', 'run')], {
        encoding: 'utf8', env: { ...env, JOB_DIR: join(__dirname, '../target/debug'), GITHUB_OUTPUT: reasons },
      });
      assert.equal(shown.status, 0, shown.stderr);
      assert.match(shown.stdout, /^::error::Refused by check: /);
      outputs.reason = fs.readFileSync(reasons, 'utf8').match(/^reason=(.+)\n$/)[1];
      const output = join(dir, 'step-output');
      const result = spawnSync('bash', ['-eo', 'pipefail', '-c', script('How the run ended', 'run')], {
        encoding: 'utf8', env: { ...env, RESULTS: 'success/failure/skipped', EXIT: '0', PR: '',
          REFUSAL: outputs.reason, WORKFLOW: 'test', RUN_URL: 'https://example.invalid/run', GITHUB_OUTPUT: output },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.ok(fs.readFileSync(output, 'utf8').includes(`refused by check: ${outputs.reason}`));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('conclusion reports refusal only through the opted-in status helper', () => {
  const conclude = workflow.split('\n  conclude:')[1];
  assert.match(conclude, /fromJSON\(inputs.policy\).notify != 'none' && fromJSON\(inputs.policy\).notified == 'true'/);
  assert.match(conclude, /REPO: \$\{\{ fromJSON\(inputs.policy\).notify-repo \}\}/);
  assert.match(conclude, /workflow\/status.cjs/);
  assert.doesNotMatch(conclude, /Post the refusal to the comment target/);
  assert.match(conclude, /STATUS_TOKEN: \$\{\{ secrets.SAFE_OUTPUTS_PAT \}\}/);
});

// The collector is agentic-job's, and gh-aw's is not set up; a line it
// refused fails the step after it, with the reason in agent_output.json,
// and an error of its own fails its own.
test('agentic-job collects, and its refusals reach the refusal step', () => {
  const dir = fs.mkdtempSync(join(homedir(), 'workflow-collector-'));
  try {
    const binary = join(dir, 'agentic-job');
    fs.writeFileSync(binary, '#!/bin/bash\nif [ "$STATUS" != 2 ]; then echo "$RESULT" > "$GH_AW_TMP/agent_output.json"; fi\nexit "$STATUS"\n');
    fs.chmodSync(binary, 0o700);
    const refusedNothing = checker.match(/- name: The collector refused nothing\n {8}run: (.*)\n/)[1];
    const run = (name, env) => spawnSync('bash', ['-eo', 'pipefail', '-c', name === null ? refusedNothing : script(name, 'run')], {
      encoding: 'utf8', env: { ...process.env, JOB_DIR: dir, GH_AW_TMP: dir, ...env },
    });
    assert.doesNotMatch(checker, /gh-aw\/actions\/setup@|collect_ndjson_output/);
    const refused = JSON.stringify({ items: [], errors: ["Line 1: add_comment requires a 'body' field (string)"] });
    for (const [name, status, result, ingested, accepted] of [
      ['accepted', '0', JSON.stringify({ items: [{ type: 'noop', message: 'm' }], errors: [] }), 0, 0],
      ['refused', '1', refused, 0, 1],
      ['an error of its own', '2', '', 1, null],
    ]) {
      fs.rmSync(join(dir, 'agent_output.json'), { force: true });
      const ingest = run('Ingest the outputs with agentic-job collect', { STATUS: status, RESULT: result });
      assert.equal(ingest.status, ingested, `${name}: ${ingest.stderr}`);
      if (accepted === null) continue;
      const check = run(null, {});
      assert.equal(check.status, accepted, `${name}: ${check.stderr}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('expected policy refusal succeeds only with a refusal report and a working summary writer', () => {
  const dir = fs.mkdtempSync(join(homedir(), 'workflow-expected-refusal-'));
  try {
    const binary = join(dir, 'agentic-job');
    fs.writeFileSync(binary, '#!/bin/bash\nif [ "$REPORT" != missing ]; then cp "$REPORT" "$GH_AW_TMP/report.json"; fi\nexit "$STATUS"\n');
    fs.chmodSync(binary, 0o700);
    const report = join(dir, 'fixture.json');
    for (const [name, expect, status, verdict, summary, code] of [
      ['expected refusal', 'true', '1', { ok: false, errors: ['wrong item'] }, 'summary', 0],
      ['unexpected acceptance', 'true', '0', { ok: true, errors: [] }, 'summary', 1],
      ['operational failure', 'true', '1', null, 'summary', 2],
      ['other exit', 'true', '2', { ok: false, errors: ['wrong item'] }, 'summary', 1],
      ['empty refusal', 'true', '1', { ok: false, errors: [] }, 'summary', 1],
      ['summary failure', 'true', '1', { ok: false, errors: ['wrong item'] }, 'missing/summary', 1],
      ['normal refusal', 'false', '1', { ok: false, errors: ['wrong item'] }, 'summary', 1],
      ['normal acceptance', 'false', '0', { ok: true, errors: [], patch: null }, 'summary', 0],
    ]) {
      fs.rmSync(join(dir, 'report.json'), { force: true });
      fs.writeFileSync(report, JSON.stringify(verdict));
      const result = spawnSync('bash', ['-eo', 'pipefail', '-c', script('Check the outputs against the policy', 'run')], {
        encoding: 'utf8', env: { ...process.env, JOB_DIR: dir, GH_AW_TMP: dir,
          COMMENT_TARGET: '64', COMMENT_REPO: 'owner/repo', EXPECT_REFUSAL: expect,
          STATUS: status, REPORT: verdict === null ? 'missing' : report,
          GITHUB_OUTPUT: join(dir, 'output'), GITHUB_STEP_SUMMARY: join(dir, summary) },
      });
      assert.equal(result.status, code, `${name}: ${result.stdout}${result.stderr}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('expected refusal never uploads applicable outputs or starts apply', async () => {
  assert.match(checker, /failure\(\) \|\| steps.checked.outputs.refused == 'true'/);
  for (const marker of ['- name: Put the patch beside the ingested outputs', '- id: upload']) {
    const check = checker.split('\n  check:')[1];
    assert.match(check.split(marker)[1], /^\n        if: \$\{\{ success\(\) && fromJSON\(inputs.policy\).expect-check-refusal != 'true' \}\}/);
  }
  assert.match(workflow.split('\n  apply:')[1], /&& fromJSON\(inputs.policy\).expect-check-refusal != 'true' \}\}/);
  const ci = fs.readFileSync(join(__dirname, '../.github/workflows/ci.yml'), 'utf8');
  assert.match(ci, /expect-check-refusal: true/);
  assert.match(ci, /test "\$REFUSED" = success/);
  assert.match(ci, /test -z "\$REFUSED_APPLIED"/);
  const dir = fs.mkdtempSync(join(homedir(), 'workflow-ci-refusal-'));
  try {
    fs.writeFileSync(join(dir, 'report.json'), JSON.stringify({ ok: false,
      errors: ["an add_comment with item_number outside the caller's fixed item"] }));
    fs.writeFileSync(join(dir, 'output'), '');
    const shown = spawnSync(join(__dirname, '../target/debug/agentic-job'),
      ['diagnostics', 'refusals', dir, '--output', join(dir, 'output')], { encoding: 'utf8' });
    assert.equal(shown.status, 0, shown.stderr);
    const reason = fs.readFileSync(join(dir, 'output'), 'utf8').match(/^reason=(.+)\n$/)[1];
    const assertion = ci.split('\n').find(line => line.includes('grep -F') && line.includes('$REFUSAL')).trim();
    for (const [value, code] of [[reason, 0], ['unrelated refusal', 1], ['', 1]]) {
      const result = spawnSync('bash', ['-eo', 'pipefail', '-c', assertion], {
        encoding: 'utf8', env: { ...process.env, REFUSAL: value },
      });
      assert.equal(result.status, code, result.stderr);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
