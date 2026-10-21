'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Writable } = require('node:stream');
const { escaped, escapingCore, escapingExec, escapingStream } = require('./workflow-commands.cjs');

// The same cases as workflow_commands.rs's test: the two must agree.
test('escaping breaks both syntaxes, anywhere, and nothing else', () => {
  for (const [text, expected] of [
    ['::set-output name=a::b', ': :set-output name=a: :b'],
    ['::::add-mask::x\r\n', ': : : :add-mask: :x\r\n'],
    ['prefix ##[error]x', 'prefix ## [error]x'],
    ['###[x] #[y] ##x', '### [x] #[y] ##x'],
    // Only the two syntaxes: URLs, times and single `#` stay.
    ['https://x/#a 12:34', 'https://x/#a 12:34'],
    ['é::ü##[', 'é: :ü## ['],
  ]) {
    assert.equal(escaped(text), expected);
    assert.equal(escaped(expected), expected, 'idempotent');
  }
  assert.equal(escaped(new Error('##[warning]x')), 'Error: ## [warning]x');
});

// A `core` that records what each method was called with.
function recorder() {
  const calls = [];
  const core = {};
  for (const name of ['info', 'debug', 'notice', 'warning', 'error', 'setFailed', 'startGroup', 'endGroup', 'setOutput', 'setSecret']) {
    core[name] = (...args) => calls.push([name, ...args]);
  }
  core.group = async (name, fn) => { calls.push(['group', name]); return fn(); };
  core.summary = { addRaw: () => core.summary };
  return { core, calls };
}

test('the escaping core breaks what is logged and leaves outputs and the summary alone', async () => {
  const { core, calls } = recorder();
  const shown = escapingCore(core);
  const forged = '::set-output name=created_pr_url::https://attacker.example/';
  shown.info(forged);
  shown.warning('see ##[warning]legacy', { title: '##[x]' });
  shown.error(new Error('::add-mask::secret'));
  shown.debug('::stop-commands::token');
  shown.notice('a ::notice');
  shown.setFailed('##[error]failed');
  shown.startGroup('::group::name');
  shown.endGroup();
  assert.equal(await shown.group('##[group]', async () => 'ran'), 'ran');
  shown.setOutput('created_pr_url', forged);
  shown.setSecret(forged);
  assert.equal(shown.summary, core.summary);
  assert.deepEqual(calls, [
    ['info', ': :set-output name=created_pr_url: :https://attacker.example/'],
    // The annotation's properties are the handler's, not text.
    ['warning', 'see ## [warning]legacy', { title: '##[x]' }],
    ['error', 'Error: : :add-mask: :secret'],
    ['debug', ': :stop-commands: :token'],
    ['notice', 'a : :notice'],
    ['setFailed', '## [error]failed'],
    ['startGroup', ': :group: :name'],
    ['endGroup'],
    ['group', '## [group]'],
    ['setOutput', 'created_pr_url', forged],
    ['setSecret', forged],
  ]);
});

// A writable collecting what reaches it, as a string.
function sink() {
  const out = { text: '' };
  out.stream = new Writable({ write(chunk, _encoding, done) { out.text += chunk; done(); } });
  return out;
}

const write = (stream, chunk) => new Promise(resolve => stream.write(chunk, resolve));

test('the escaping stream breaks a syntax split across chunks and keeps multibyte text whole', async () => {
  const out = sink();
  const stream = escapingStream(out.stream);
  for (const chunk of ['Applying: :', ':set-output name=x::y\n#', '#[warning]z\n##', '[error]w ']) {
    await write(stream, chunk);
  }
  // A two-byte character written one byte at a time.
  const [first, second] = Buffer.from('é');
  await write(stream, Buffer.from([first]));
  await write(stream, Buffer.from([second]));
  await write(stream, ':');
  await write(stream, ':');
  assert.equal(out.text, 'Applying: : :set-output name=x: :y\n## [warning]z\n## [error]w é: :');
  assert.equal(escaped(out.text), out.text, 'nothing left to break');
});

// git's lines reach the log in order with what the handler logs directly.
test('the escaping stream keeps order with lines written past it', async () => {
  const out = sink();
  const stream = escapingStream(out.stream);
  stream.write('Applying: a\n');
  stream.write('Applying: b\n');
  out.stream.write('Patch applied successfully\n');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(out.text, 'Applying: a\nApplying: b\nPatch applied successfully\n');
});

// An `exec` writing its program's output the way @actions/exec does: to
// the given streams, or the process's, unless silent.
function fakeExec() {
  const seen = [];
  const run = async (program, args, options = {}) => {
    seen.push(options);
    const outStream = options.outStream ?? process.stdout;
    const errStream = options.errStream ?? process.stderr;
    if (!options.silent) {
      await write(outStream, `[command]${program} ${args.join(' ')}\n`);
      await write(outStream, `Applying: ${args[0]}\n`);
      await write(errStream, `error: patch failed: ${args[0]}\n`);
    }
    options.listeners?.stdout?.(Buffer.from(`Applying: ${args[0]}\n`));
    return 0;
  };
  return { seen, exec: { exec: run, getExecOutput: async (...args) => ({ exitCode: await run(...args), stdout: `Applying: ${args[1][0]}\n`, stderr: '' }) } };
}

test('the escaping exec breaks what a program writes to the log, and to the streams it was given', async () => {
  const subject = 'fix ##[set-output name=created_pr_url;]https://attacker.example/';
  const { seen, exec } = fakeExec();
  const shown = escapingExec(exec);
  const out = sink(), err = sink();
  const collected = [];
  assert.equal(await shown.exec('git', [subject], { cwd: '/x', outStream: out.stream, errStream: err.stream, listeners: { stdout: data => collected.push(String(data)) } }), 0);
  assert.equal(out.text, `[command]git ${escaped(subject)}\nApplying: ${escaped(subject)}\n`);
  assert.equal(err.text, `error: patch failed: ${escaped(subject)}\n`);
  // The handler's own options and listeners are kept, and read the text as it was.
  assert.equal(seen[0].cwd, '/x');
  assert.deepEqual(collected, [`Applying: ${subject}\n`]);
  const result = await shown.getExecOutput('git', [subject], { silent: true });
  assert.equal(result.stdout, `Applying: ${subject}\n`);
  assert.equal(seen[1].silent, true);
  // Without streams of the handler's, the process's take the escaped text.
  const stdout = process.stdout.write, stderr = process.stderr.write;
  const logged = [];
  // Recorded on the way through: the test runner reports through the same stdout.
  process.stdout.write = (chunk, ...rest) => { logged.push(['out', String(chunk)]); return stdout.call(process.stdout, chunk, ...rest); };
  process.stderr.write = (chunk, ...rest) => { logged.push(['err', String(chunk)]); return stderr.call(process.stderr, chunk, ...rest); };
  try {
    await shown.exec('git', [subject]);
  } finally {
    process.stdout.write = stdout;
    process.stderr.write = stderr;
  }
  assert.deepEqual(logged.filter(([, text]) => text.includes('attacker.example')), [
    ['out', `[command]git ${escaped(subject)}\n`],
    ['out', `Applying: ${escaped(subject)}\n`],
    ['err', `error: patch failed: ${escaped(subject)}\n`],
  ]);
});
