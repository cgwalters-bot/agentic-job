'use strict';

// Keep untrusted log text from becoming GitHub Actions workflow commands.
//
// The runner reads a command in every line a step writes, to stdout or
// stderr: `::name …::data` at the start of a line, after leading
// whitespace (`ActionCommand.TryParseV2`), and the older `##[name …]data`
// anywhere in one (`ActionCommand.TryParse`, with `IndexOf`). gh-aw's
// pinned handlers log the patch's first lines and stream git's output,
// both of which hold the agent's text: a commit message or a subject
// (git's `Applying: subject`) is free text, and `check` cannot refuse
// `##[` in the file content the preview prints too. A line of either
// that the runner read as a command could set this step's outputs where
// the handler writes none (`created_pr_url`, which conclude reports as
// the run's result), mask text from the log or stop command processing.
//
// This is the twin of crates/agentic-job/src/workflow_commands.rs, which
// `run` and the sandbox checks use for the agent's own log; keep the two
// in step.

// `text` with both syntaxes broken by a space: `: :` and `## [`. Breaking
// them anywhere, not only at the start of a line, is what keeps it
// complete: no filter, reordering or interleaving of whole lines
// downstream can form one, and no runner state (a `stop-commands` token)
// is left behind. The space goes before the character that completes a
// syntax, so escaping a prefix again changes nothing before new text.
const escaped = text => String(text).replace(/:(?=:)|##(?=\[)/g, '$& ');

// The methods of `core` that write their text to the step's output.
// `setOutput` and the others write to the runner's files, not the log.
const LOGGING = ['info', 'debug', 'notice', 'warning', 'error', 'setFailed', 'startGroup'];

// `core` with everything logged through it escaped; the rest, outputs
// and the summary among them, is the real module's.
function escapingCore(core) {
  const shown = Object.create(core);
  for (const name of LOGGING) {
    // `error` and the like take an Error as well as a string.
    shown[name] = (text, ...rest) => core[name](escaped(text), ...rest);
  }
  shown.group = (name, fn) => core.group(escaped(name), fn);
  return shown;
}

// A writable that escapes what is written through it to `target`. A
// syntax split across two chunks is broken too: the last two characters
// written are remembered, and the space they call for goes before the
// character of the next chunk that completes it.
function escapingStream(target) {
  const { Writable } = require('node:stream');
  const { StringDecoder } = require('node:string_decoder');
  const decoder = new StringDecoder('utf8');
  let tail = '';
  return new Writable({
    write(chunk, _encoding, done) {
      const text = decoder.write(chunk);
      const shown = escaped(tail + text).slice(escaped(tail).length);
      tail = (tail + text).slice(-2);
      // Handed to the target at once, in order with what the handler logs
      // past this stream: a writable's callback fires on a later tick, so
      // taking the next chunk only then would let a line logged directly
      // overtake git's.
      target.write(shown);
      done();
    },
  });
}

// `exec` with a program's output escaped on the way to the step's log,
// or to the streams the caller gave, as @actions/exec writes it there
// unless `silent`. What a listener or `getExecOutput` collects is the
// program's text as it was.
function escapingExec(exec) {
  const escaping = (options = {}) => ({
    ...options,
    outStream: escapingStream(options.outStream ?? process.stdout),
    errStream: escapingStream(options.errStream ?? process.stderr),
  });
  const shown = Object.create(exec);
  shown.exec = (program, args, options) => exec.exec(program, args, escaping(options));
  shown.getExecOutput = (program, args, options) => exec.getExecOutput(program, args, escaping(options));
  return shown;
}

module.exports = { escaped, escapingCore, escapingExec, escapingStream };
