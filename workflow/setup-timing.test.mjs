import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkSetupStages } from './setup-timing.mjs';

const stage = name => `Sandbox setup stage ${name}: 0.123s (ok)\n`;
const allowlist = stage('privileged-binary-allowlist');
const view = stage('filesystem-view') + allowlist;
const walk = stage('world-write-and-setuid-walk') + stage('setuid-package-ownership');

// The second argument is whether the configuration asks for the view.
for (const [name, log, mode, valid] of [
  ['view', view, 'true', true],
  ['no view', allowlist, 'false', true],
  ['view still walks', view + walk, 'true', false],
  ['no view still walks', allowlist + walk, 'false', false],
  ['no view has old setuid search', allowlist + stage('setuid-package-ownership'), 'false', false],
  ['view missing allowlist', stage('filesystem-view'), 'true', false],
  ['missing allowlist', '', 'false', false],
  ['missing view', allowlist, 'true', false],
  ['unasked view', view, 'false', false],
  ['failed stage', view.replace('(ok)', '(failed)'), 'true', false],
  ['duplicate stage', view + stage('filesystem-view'), 'true', false],
  ['invalid mode', view, 'invalid', false],
]) {
  test(name, () => {
    if (valid) {
      assert.doesNotThrow(() => checkSetupStages(log, mode));
    } else {
      assert.throws(() => checkSetupStages(log, mode));
    }
  });
}
