'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const { admit, activate } = require('./activation.cjs');

test('activation gates execution and consumes each admitted label application', async () => {
  for (const [kind, admitted, fail, writes, runs] of [
    ['issue', true, false, 2, 2],
    ['pull_request', true, false, 2, 2],
    ['issue', false, false, 0, 0],
    ['issue', true, true, 2, 0],
    ['discussion', true, false, 0, 0],
  ]) {
    let written = 0;
    let started = 0;
    const github = { rest: { issues: { removeLabel: async (request) => {
      written++;
      assert.deepEqual(request, { owner: 'octo', repo: 'repo', issue_number: 12, name: 'agent-review' });
      if (fail) throw new Error('permission denied');
    } } } };
    // A second labeled event models removing and reapplying the command.
    for (let attempt = 0; attempt < 2; attempt++) {
      const decision = { admitted, action: 'labeled', command: 'agent-review', item: { kind, number: 12 } };
      try {
        await activate(decision, github, { owner: 'octo', repo: 'repo' });
        if (admitted) started++;
      } catch (error) {
        assert.match(error.message, /permission denied|not supported/);
      }
    }
    assert.equal(written, writes, kind);
    assert.equal(started, runs, kind);
  }
});

test('workflow refuses discussions before routing and gates agent and notification on activation', () => {
  const workflow = fs.readFileSync('.github/workflows/policy.yml', 'utf8');
  assert.ok(workflow.indexOf('const decision = admit(') < workflow.indexOf('base=$BASE target='));
  assert.match(workflow, /notify:\n    needs: \[policy, activate\]/);
  assert.match(workflow, /await activate\(decision, github, context.repo\)/);
  assert.match(workflow, /ref: \$\{\{ job.workflow_sha \}\}\n          path: activation-source/);
  // An agent job needs the whole policy call, which ends after activate
  // and notify, and goes on only if that call succeeded.
  for (const file of ['agentic-job.yml', 'example-compose.yml']) {
    const agent = fs.readFileSync(`.github/workflows/${file}`, 'utf8').split('\n  agent:\n')[1].split('\n    steps:\n')[0];
    assert.match(agent, /^    needs: policy\n    (#[^\n]*\n    )*if: \$\{\{ [^\n]*needs.policy.outputs.admitted == 'true' \}\}$/m, file);
    assert.doesNotMatch(agent, /always\(\)|cancelled\(\)/, file);
  }
});

test('discussion boundary cannot write to an issue with the same number', async () => {
  const decision = admit({ admitted: true, action: 'labeled', command: 'agent-review', item: { kind: 'discussion', number: 12 } });
  assert.equal(decision.admitted, false);
  const github = { rest: { issues: { removeLabel: async () => assert.fail('discussion reached issue namespace') } } };
  await activate(decision, github, { owner: 'octo', repo: 'repo' });
});

test('documented label caller supplies every required reusable workflow input', () => {
  const workflow = fs.readFileSync('.github/workflows/agentic-job.yml', 'utf8');
  const inputs = workflow.split('    inputs:\n')[1].split('    secrets:')[0];
  const required = [...inputs.matchAll(/^      ([\w-]+):\n([\s\S]*?)(?=^      [\w-]+:|^    [\w-]+:|$(?![\s\S]))/gm)]
    .filter(([, , block]) => /^        required: true$/m.test(block))
    .map(([, name]) => name);
  assert.ok(required.includes('id') && required.includes('repo'));
  const example = fs.readFileSync('docs/events.md', 'utf8').split('```yaml\n')[1].split('```')[0];
  for (const name of required) {
    assert.match(example, new RegExp(`^      ${name}: .+`, 'm'), `missing required input ${name}`);
  }
  assert.match(example, /^      allow: workflow\/label-review\.toml$/m);
  for (const caller of [example, fs.readFileSync('.github/workflows/example-pull-request.yml', 'utf8')]) {
    for (const [input, value] of [
      ['kind', 'analysis'],
      ['outputs', 'add_comment,noop'],
      ['agent', 'fake'],
      ['setup', '.github/agentic-job/e2e/event.sh'],
    ]) {
      assert.ok(caller.split('\n').some(line => line.trim() === `${input}: ${value}`), `missing ${input}: ${value}`);
    }
    assert.match(caller, /^      contents: read$/m);
    assert.doesNotMatch(caller, /^      contents: write$/m);
  }
});

test('event caller copy lists include every referenced companion file', () => {
  const guide = fs.readFileSync('docs/workflow.md', 'utf8');
  const lists = guide.split('Copy each selected caller')[1].split('In each caller,')[0];
  for (const [label, workflow] of [
    ['Slash command', 'example-command.yml'],
    ['Label', 'example-pull-request.yml'],
    ['Schedule', 'example-schedule.yml'],
    ['Dedicated review', 'review.yml'],
  ]) {
    const list = lists.split(`- **${label}:**`)[1].split('\n- **')[0];
    const path = `.github/workflows/${workflow}`;
    assert.ok(list.includes(`](../${path})`), `missing caller ${path}`);
    const caller = fs.readFileSync(path, 'utf8');
    for (const [, value] of caller.matchAll(/^      (?:allow|config|setup|review-task): (.+)$/gm)) {
      // An expression choosing between files names each of them quoted,
      // as a path.
      const companions = value.startsWith('${{') ? [...value.matchAll(/'([^'/]*\/[^']*)'/g)].map(([, file]) => file) : [value];
      for (const companion of companions) {
        assert.ok(fs.statSync(companion).isFile(), `missing companion ${companion}`);
        assert.ok(list.includes(`](../${companion})`), `${workflow} copy list omits ${companion}`);
      }
    }
  }
});
