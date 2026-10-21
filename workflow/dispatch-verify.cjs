'use strict';

// Proposed CI code runs with read-only permissions; cleanup is a separate job.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const { GH_REPO: repo, RUN: run, PR: pr, REVIEW_HEAD: head, RESULT: result,
  COMPOSE_RESULT: composed, CONFIG: config } = process.env;
// Whether the configuration's `[setup.repo-packages]` gives `name` cargo:
// its own list, or else `default`'s, as config/compose.rs chooses. Only
// one-line entries are read, and any other line in the table is refused,
// so that reformatting the file fails here rather than skipping the check.
const cargoFor = name => {
  assert.ok(config, 'CONFIG must name the configuration the dispatch ran with');
  const sections = fs.readFileSync(config, 'utf8').split(/^\[setup\.repo-packages\][ \t]*(?:#.*)?$/m);
  assert.equal(sections.length, 2, `${config}: expected one [setup.repo-packages] table`);
  const lists = new Map();
  for (const line of sections[1].split(/^\[/m)[0].split('\n').map(line => line.trim())) {
    if (line === '' || line.startsWith('#')) continue;
    const entry = line.match(/^"?([\w./-]+)"?\s*=\s*\[([^\]]*)\]\s*(?:#.*)?$/);
    assert.ok(entry, `${config}: cannot read the setup.repo-packages line ${JSON.stringify(line)}`);
    lists.set(entry[1].toLowerCase(), entry[2]);
  }
  return /"cargo"/.test(lists.get(name.toLowerCase()) ?? lists.get('default') ?? '');
};
assert.equal(result, 'success', 'all shipped dispatch profiles must succeed');
assert.equal(composed, 'success', 'the composed example must succeed');
const api = endpoint => JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', endpoint], { encoding: 'utf8' })).flat();
const comments = item => api(`repos/${repo}/issues/${item}/comments`)
  .filter(comment => comment.user.login === 'github-actions[bot]' && comment.body.includes(run));
// Research and the composed example each comment once.
assert.equal(comments(64).filter(comment => comment.body.includes('Scripted dispatch completed.')).length, 2);
if (pr) {
  assert.match(head, /^[0-9a-f]{40}$/);
  const verdicts = comments(pr).filter(comment => comment.body.startsWith('VERDICT: APPROVE\nREASON: Scripted dispatch'));
  assert.equal(verdicts.length, 1);
  assert.ok(verdicts[0].body.includes(`Reviewed SHA: ${head}`));
  // Where the hosted configuration gives this repository cargo (a fork
  // is not listed), the scripted review ran `cargo metadata --locked`
  // before writing this. Read from the configuration, not a name here,
  // so another deployment's copy checks its own repository.
  if (cargoFor(repo)) {
    assert.match(verdicts[0].body, /\nToolchain: cargo \d/, 'the review sandbox must have a working cargo');
  }
}
