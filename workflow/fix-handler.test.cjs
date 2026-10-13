'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { homedir } = require('node:os');
const { spawnSync } = require('node:child_process');
const { createRequire } = require('node:module');
const { runInNewContext } = require('node:vm');

// The real pinned handler, a scripted patch, mock forge reads and local git
// remotes. No write credential, sandbox setup or network service is needed.
test('scripted fix from a different caller layout reaches the target checkout and pushes only the fork',
  { skip: !process.env.GH_AW_JS }, async () => {
    const root = mkdtempSync(join(homedir(), 'fix-handler-'));
    const savedEnv = { ...process.env };
    const globals = ['core', 'github', 'context', 'exec'];
    const savedGlobals = globals.map(name => global[name]);
    try {
      const work = join(root, 'target');
      const caller = join(root, 'caller');
      const fork = join(root, 'fork.git');
      const origin = join(root, 'target.git');
      const outputs = join(root, 'outputs');
      mkdirSync(outputs);
      const command = (cwd, args, ignore = false) => {
        const result = spawnSync('git', args, { cwd, env: process.env, encoding: 'utf8' });
        if (!ignore) assert.equal(result.status, 0, `${args.join(' ')}: ${result.stderr}`);
        return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
      };
      const git = (cwd, ...args) => command(cwd, args).stdout.trim();
      git(root, 'init', '-q', '--bare', origin);
      git(root, 'init', '-q', '--bare', fork);
      git(root, 'init', '-q', caller);
      git(root, 'init', '-q', work);
      git(work, 'config', 'user.name', 'Test');
      git(work, 'config', 'user.email', 'test@example.invalid');
      git(work, 'checkout', '-qb', 'main');
      writeFileSync(join(work, 'target.txt'), 'before\n');
      git(work, 'add', '.');
      git(work, 'commit', '-qm', 'base');
      const head = git(work, 'rev-parse', 'HEAD');
      git(work, 'push', '-q', origin, 'HEAD:refs/heads/main');
      git(work, 'push', '-q', fork, 'HEAD:refs/heads/agent-run-7');
      writeFileSync(join(work, 'target.txt'), 'scripted fix\n');
      git(work, 'commit', '-qam', 'Fix the target');
      const tree = git(work, 'rev-parse', 'HEAD^{tree}');
      const patch = git(work, 'format-patch', '-1', '--stdout').replace('\nSubject:', `\nX-GH-AW-Base-Commit: ${head}\nSubject:`);
      writeFileSync(join(outputs, 'aw-agent-run-7.patch'), patch + '\n');
      git(work, 'reset', '--hard', head);
      git(work, 'remote', 'add', 'origin', origin);
      git(work, 'fetch', '-q', 'origin');
      Object.assign(process.env, {
        GITHUB_REPOSITORY: 'caller/control', GITHUB_WORKSPACE: work, GH_AW_TMP: outputs,
        GITHUB_SERVER_URL: 'https://github.com', GITHUB_RUN_ID: '7',
        GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: `url.${fork}.insteadOf`,
        GIT_CONFIG_VALUE_0: 'https://github.com/bot/target.git',
      });
      // Use the workflow's configuration step, not a second copy of its mapping.
      const workflow = readFileSync(join(__dirname, '../.github/workflows/apply.yml'), 'utf8');
      const section = workflow.split("- name: Write the handlers' configuration\n")[1].split('\n      - ')[0];
      const shell = section.split('run: |\n')[1].split('\n').filter(line => line.startsWith('          ')).map(line => line.slice(10)).join('\n');
      writeFileSync(join(outputs, 'config.json'), JSON.stringify({ push_to_pull_request_branch: { target: '42', head } }));
      const configResult = spawnSync('bash', ['-euo', 'pipefail', '-c', shell], { cwd: work, encoding: 'utf8',
        env: { ...process.env, GITHUB_ENV: join(root, 'env'), OUTPUT_REPO: 'Owner/Target', ITEM_REPO: 'Owner/Target', REPO: 'Owner/Target', BASE: 'agent-run-7',
          FORK: 'bot/target', BRANCH_PREFIX: '', PARTIAL: '', TITLE_PREFIX: '', COMMENT_TARGET: '', PULL_REQUEST: '{}',
          BASH_ENV: '',
          PUSH: '{"signed_commits":false,"fallback_as_pull_request":false,"if_no_changes":"error"}' } });
      assert.equal(configResult.status, 0, configResult.stderr);
      const config = JSON.parse(readFileSync(join(outputs, 'handler-config.json'), 'utf8')).push_to_pull_request_branch;
      const logs = [];
      global.core = Object.fromEntries(['info', 'warning', 'error', 'debug', 'setOutput'].map(name => [name, text => logs.push(String(text))]));
      global.core.summary = { addRaw: () => global.core.summary, write: async () => {} };
      global.context = { repo: { owner: 'caller', repo: 'control' }, payload: {}, runId: 7 };
      global.github = { rest: {
        pulls: { get: async () => ({ data: { number: 42, title: 'Target', labels: [],
          base: { repo: { full_name: 'Owner/Target' } },
          head: { ref: 'agent-run-7', sha: head, repo: { full_name: 'bot/target', fork: true } } } }) },
        repos: { get: async () => ({ data: { default_branch: 'main' } }),
          getBranchProtection: async () => { throw Object.assign(new Error('unprotected'), { status: 404 }); } },
      } };
      global.exec = {
        getExecOutput: async (program, args, options = {}) => {
          assert.equal(program, 'git');
          // Cross-repository git must use the mapped target, not the caller.
          assert.equal(options.cwd, work);
          return command(options.cwd, args, options.ignoreReturnCode);
        },
        exec: async (program, args, options = {}) => {
          assert.equal(program, 'git');
          assert.equal(options.cwd, work);
          return command(options.cwd, args, options.ignoreReturnCode).exitCode;
        },
      };
      const source = resolve(process.env.GH_AW_JS, 'push_to_pull_request_branch.cjs');
      const upstreamRequire = createRequire(source);
      const module = { exports: {} };
      // gh-aw hardcodes /tmp/gh-aw for transport. Keep scratch in our home;
      // no repository resolution, patch application or push helper is mocked.
      runInNewContext(readFileSync(source, 'utf8'), { module, process, console, Buffer,
        core: global.core, github: global.github, context: global.context, exec: global.exec,
        require: name => name === './resolve_transport_paths.cjs'
          ? { resolveTransportPaths: () => ({ patchPath: join(outputs, 'aw-agent-run-7.patch') }) }
          : upstreamRequire(name), global });
      const { main } = module.exports;
      const handler = await main(config);
      const request = { type: 'push_to_pull_request_branch', branch: 'agent-run-7' };
      const result = await handler(request, {});
      assert.equal(result.success, true, JSON.stringify({ result, logs }));
      assert.equal(git(root, '--git-dir', fork, 'show', '-s', '--format=%P', 'agent-run-7'), head);
      assert.equal(git(root, '--git-dir', fork, 'rev-parse', 'agent-run-7^{tree}'), tree);
      assert.equal(git(root, '--git-dir', origin, 'rev-parse', 'main'), head);
      assert.equal(git(caller, 'status', '--porcelain'), '');
      // Negative control: without #437's mapping this same caller layout
      // fails before git, since allowed_repos admits only the fork.
      const { checkout_mapping, ...withoutMapping } = config;
      assert.deepEqual(checkout_mapping, { 'owner/target': '.' });
      const broken = await (await main(withoutMapping))(request, {});
      assert.equal(broken.success, false);
      assert.match(broken.error, /not in the allowed-repos list/);
      // Re-running apply's existing guard recognizes the local fork's tree
      // and hands no push to the handler. Use real git, not fabricated OIDs.
      git(work, 'fetch', '-q', fork, '+refs/heads/agent-run-7:refs/agentic-job/target-base');
      writeFileSync(join(outputs, 'agent_output.json'), JSON.stringify({ items: [request], errors: [] }));
      const report = join(outputs, 'report.json');
      writeFileSync(report, JSON.stringify({ patch: { file: 'aw-agent-run-7.patch' } }));
      Object.assign(process.env, { OUTPUT_REPO: 'Owner/Target', ITEM_REPO: 'Owner/Target', TREE: tree, TOKEN_IS_PAT: 'false', REPORT: report });
      global.core.summary.addHeading = () => global.core.summary;
      global.core.summary.addList = () => global.core.summary;
      const guard = workflow.split('- name: Leave out what an earlier attempt applied\n')[1].split('\n      - ')[0]
        .split('script: |\n')[1].split('\n').filter(line => line.startsWith('            ')).map(line => line.slice(12)).join('\n');
      const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
      await new AsyncFunction('require', 'process', 'core', 'github', 'exec', guard)(require, process, global.core, global.github,
        { getExecOutput: async (program, args) => { assert.equal(program, 'git'); return command(work, args); } });
      assert.deepEqual(JSON.parse(readFileSync(join(outputs, 'agent_output.json'), 'utf8')).items, []);
      assert.deepEqual(JSON.parse(readFileSync(join(outputs, 'skipped.json'), 'utf8')),
        [{ type: request.type, url: 'https://github.com/Owner/Target/pull/42' }]);
    } finally {
      process.env = savedEnv;
      globals.forEach((name, index) => { if (savedGlobals[index] === undefined) delete global[name]; else global[name] = savedGlobals[index]; });
      rmSync(root, { recursive: true, force: true });
    }
  });
