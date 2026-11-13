const fs = require('node:fs');

if (process.getuid() !== 1001 || process.getgid() !== 1001 ||
    fs.readFileSync('/proc/1/comm', 'utf8').trim() !== 'tail') {
  console.error('FAIL: JavaScript action identity or PID namespace');
  process.exit(1);
}
console.log('PASS: JavaScript action phase runs as UID/GID 1001 in the job container');
