// Keep CLI diagnostics visible on the run page without interpreting their text
// as workflow commands. This runs only on the read-only policy machine.
const { spawnSync } = require('node:child_process');
const { resolveContext } = require('./context.cjs');

function run(command, args) {
  if (args[0] === 'policy' && process.env.CONTEXT_REPOS) {
    try {
      args = [...args, '--context', JSON.stringify(resolveContext(process.env.CONTEXT_REPOS))];
    } catch (error) {
      process.stderr.write(`policy: context admission failed: ${JSON.stringify(error.message).replaceAll('##[', '# #[')}\n`);
      return 1;
    }
  }
  const result = spawnSync(command, args, { stdio: ['inherit', 'inherit', 'pipe'],
    encoding: 'utf8', maxBuffer: 1024 * 1024 });
  // The legacy runner parser searches for ##[ anywhere, even after a prefix.
  // Break that delimiter in both copies; prefix lines to block modern commands.
  const neutralize = text => text.replaceAll('##[', '# #[');
  const diagnostic = neutralize(result.stderr || result.error?.message || 'Command failed without a diagnostic');
  if (result.stderr) process.stderr.write(neutralize(result.stderr).split(/[\r\n]/)
    .map(line => `policy: ${line}`).join('\n') + '\n');
  if (result.status !== 0) {
    const escaped = diagnostic.trim().replaceAll('%', '%25')
      .replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    process.stderr.write(`::error::${escaped}\n`);
  }
  return result.status ?? 1;
}

if (require.main === module) process.exitCode = run(process.argv[2], process.argv.slice(3));

module.exports = { run };
