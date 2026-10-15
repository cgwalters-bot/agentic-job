import assert from 'node:assert/strict';
import test from 'node:test';
import { FIELDS, MAX_BYTES, observations, sockets } from './parse.mjs';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

// Sanitized field-format samples: documentation addresses and no packet payload.
const fixture = JSON.parse(readFileSync(new URL('./samples.json', import.meta.url)));
const text = fixture.packets.map(row => row.join('\t')).join('\n') + '\n';
const samples = sockets(fixture.ss, 1700000000.5);

test('DNS answers, IPv4/IPv6, SNI, resolver queries and sampled process ownership', () => {
  assert.equal(fixture.packets.every(row => row.length === FIELDS.length), true);
  const list = observations(text, samples, fixture.local);
  const tls = list.find(row => row.address === '192.0.2.10');
  assert.deepEqual(tls, { address: '192.0.2.10', port: 443, transport: 'tcp', ip_protocol: 6,
    dns_names: ['artifact.example'], dns_queries: [], tls_sni: ['artifact.example'],
    processes: [{ pid: 42, name: 'node' }] });
  const ipv6 = list.find(row => row.address === '2001:db8::10');
  assert.deepEqual(ipv6.dns_names, ['artifact.example']);
  assert.deepEqual(ipv6.processes, [{ pid: 43, name: 'Runner.Worker' }]);
  const dns = list.find(row => row.port === 53);
  assert.deepEqual(dns.dns_names, []);
  assert.deepEqual(dns.dns_queries, ['artifact.example']);
  assert.equal(list.length, 3);
});

const nonPortPackets = [
  ['1700000001', '10.0.0.4', '', '192.0.2.20', '', '', '', '', '', '', '', '', '', '', '1', ''],
  ['1700000001', '', '2001:db8::4', '', '2001:db8::20', '', '', '', '', '', '', '', '', '', '', '58'],
  ['1700000001', '10.0.0.4', '', '192.0.2.30', '', '', '', '', '', '', '', '', '', '', '47', ''],
].map(row => row.join('\t')).join('\n') + '\n';

test('outbound ICMP, ICMPv6 and GRE retain destinations without inventing ports', () => {
  const list = observations(nonPortPackets, [], fixture.local);
  assert.equal(list.length, 3);
  assert.deepEqual(list.map(row => row.ip_protocol).sort((a, b) => a - b), [1, 47, 58]);
  assert.ok(list.every(row => row.port === null && row.transport === 'ip'));
});

test('missing names and missed or stale socket samples remain unknown, never guessed', () => {
  const list = observations(text, samples.map(row => ({ ...row, time: row.time + 10 })), fixture.local);
  assert.equal(list.every(row => row.processes.length === 0), true);
  const packet = [...fixture.packets[2]];
  packet[13] = '';
  const unknown = observations(packet.join('\t') + '\n', [], fixture.local);
  assert.deepEqual(unknown[0].dns_names, []);
  assert.deepEqual(unknown[0].tls_sni, []);
  assert.deepEqual(observations(text, samples, []), []);
});

test('mapped runner sockets match IPv4 packets; wrong tuples never match', () => {
  const mapped = sockets('tcp ESTAB 0 0 [::ffff:10.0.0.4]:51000 [::ffff:192.0.2.10]:443 users:(("Runner.Worker",pid=99,fd=3))', 1700000000.5);
  assert.deepEqual(observations(text, mapped, fixture.local).find(row => row.address === '192.0.2.10').processes,
    [{ pid: 99, name: 'Runner.Worker' }]);
  for (const change of [row => { row.local.port++; }, row => { row.remote.port++; },
    row => { row.transport = 'udp'; }, row => { row.local.address = '10.0.0.5'; }]) {
    const wrong = structuredClone(mapped);
    change(wrong[0]);
    assert.equal(observations(text, wrong, fixture.local).every(row => row.processes.length === 0), true);
  }
});

test('invalid, truncated, oversized and injection-bearing metadata', () => {
  for (const bad of ['', '::error::secret', '1\tIP']) assert.deepEqual(observations(bad, [], fixture.local), []);
  assert.throws(() => observations('x'.repeat(MAX_BYTES + 1), [], []), /4 MiB/);
  assert.throws(() => observations('x\n'.repeat(10001), [], []), /packet limit/);
  const packet = [...fixture.packets[2]];
  packet[13] = '::error::secret,https://secret.example/path,valid.example';
  assert.deepEqual(observations(packet.join('\t'), [], fixture.local)[0].tls_sni, ['valid.example']);
  assert.deepEqual(sockets('tcp ESTAB 0 0 invalid endpoint users:(("secret command",pid=1,fd=1))', 1), []);
});

test('post writes real JSON, invokes uploader, and propagates upload failures', () => {
  const dir = mkdtempSync(join(tmpdir(), 'runner-egress-'));
  try {
    const trace = join(dir, 'trace');
    const summary = join(dir, 'summary');
    const uploader = join(dir, 'upload.mjs');
    writeFileSync(uploader, `import { readFileSync } from 'node:fs';
      const report = JSON.parse(readFileSync(process.env.INPUT_PATH));
      if (process.env.INPUT_NAME !== 'runner-egress-observations' || report.destinations.length !== 6 ||
          process.env.INPUT_ARCHIVE !== 'true') process.exit(2);
      process.exit(Number(process.env.TEST_UPLOAD_EXIT || 0));`);
    const run = (extra = {}) => spawnSync(process.execPath, [new URL('./post.mjs', import.meta.url).pathname], {
      env: { ...process.env, STATE_trace: trace, GITHUB_STEP_SUMMARY: summary, TRACE_UPLOAD_SCRIPT: uploader, ...extra },
      encoding: 'utf8',
    });
    writeFileSync(`${trace}.status`, JSON.stringify({ reason: 'final post snapshot', capture_exit: 0 }));
    assert.notEqual(run().status, 0);
    writeFileSync(trace, text + nonPortPackets);
    writeFileSync(`${trace}.sockets`, samples.map(row => JSON.stringify(row)).join('\n'));
    writeFileSync(`${trace}.addresses`, JSON.stringify(fixture.local));
    assert.equal(run().status, 0);
    const report = JSON.parse(readFileSync(`${trace}.json`));
    assert.equal(report.destinations.length, 6);
    assert.equal(report.destinations.filter(row => row.port === null).length, 3);
    assert.match(readFileSync(summary, 'utf8'), /traffic after the last step is not observed/);
    assert.notEqual(run({ TEST_UPLOAD_EXIT: '1' }).status, 0);
    for (const error of ['socket sampling failed', 'capture failed']) {
      writeFileSync(`${trace}.status`, JSON.stringify({ collection_error: error }));
      const result = run();
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, new RegExp(error));
      assert.equal(JSON.parse(readFileSync(`${trace}.json`)).coverage.collector.collection_error, error);
    }
    writeFileSync(trace, 'x'.repeat(MAX_BYTES + 1));
    assert.notEqual(run().status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collector acknowledges snapshot and bounds output and failure diagnostics', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'runner-egress-'));
  const children = [];
  try {
    // Only the tool boundary is mocked; the detached collector, stream caps,
    // socket parser, stop handshake and final status run as in the action.
    writeFileSync(join(dir, 'sudo'), `#!${process.execPath}
      const args = process.argv.slice(2);
      if (args.includes('ss')) {
        if (process.env.TEST_FAILURE === 'ss') { process.stderr.write('ss unavailable'); process.exit(1); }
        process.stdout.write(${JSON.stringify(fixture.ss)});
      } else if (args.includes('kill')) {
        process.kill(Number(args.at(-1)), 'SIGTERM');
      } else {
        process.stderr.write('Capturing on any\\nSECRET STDERR\\n');
        process.stdout.write(process.env.TEST_CAP === 'yes' ? 'x'.repeat(5 * 1024 * 1024) : ${JSON.stringify(text)});
        if (process.env.TEST_FAILURE === 'capture') {
          process.stderr.write('x'.repeat(8192) + '\\ninvalid capture option ::error::' + String.fromCharCode(96).repeat(3)); process.exit(2);
        }
        setInterval(() => {}, 1000);
      }`, { mode: 0o700 });
    for (const mode of ['snapshot', 'capped', 'ss', 'capture']) {
      const capped = mode === 'capped';
      const trace = join(dir, mode);
      const child = spawn(process.execPath, [new URL('./observe.mjs', import.meta.url).pathname, trace], {
        env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, TEST_CAP: capped ? 'yes' : 'no', TEST_FAILURE: mode },
        stdio: 'ignore',
      });
      children.push(child);
      const exited = new Promise(resolve => child.once('exit', resolve));
      for (let i = 0; i < 100 && !existsSync(`${trace}.ready`); i++) {
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.ok(existsSync(`${trace}.ready`));
      if (mode === 'snapshot') {
        await new Promise(resolve => setTimeout(resolve, 700));
        writeFileSync(`${trace}.stop`, '');
      }
      let timer;
      try {
        await Promise.race([exited, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('Collector failed to stop')), 10000);
        })]);
      } finally {
        clearTimeout(timer);
      }
      const status = JSON.parse(readFileSync(`${trace}.status`));
      assert.equal(status.reason, { snapshot: 'final post snapshot', capped: 'metadata size limit',
        ss: 'socket sampling failed', capture: 'capture failed' }[mode]);
      assert.equal(Boolean(status.collection_error), ['ss', 'capture'].includes(mode));
      if (mode === 'capture') {
        assert.match(status.collection_error, /sudo -n timeout --foreground --signal=TERM/);
        assert.match(status.collection_error, /exit 2, signal none/);
        assert.match(status.collection_error, /invalid capture option/);
        assert.ok(status.collection_error.length < 6000);
        assert.doesNotMatch(status.collection_error, /\n/);
        assert.doesNotMatch(status.collection_error, /::|`/);
        assert.match(status.collection_error, /\\u003a\\u003aerror/);
      }
      if (mode === 'ss') assert.match(status.collection_error, /sudo -n ss -Hntup: exit 1.*ss unavailable/);
      assert.ok(readFileSync(trace).length <= MAX_BYTES);
      assert.doesNotMatch(readFileSync(trace, 'utf8'), /SECRET/);
      if (mode === 'snapshot') assert.ok(readFileSync(`${trace}.sockets`, 'utf8').includes('Runner.Worker'));
    }
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('snapshot stops a real timeout group with TERM without kill-after escalation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'runner-egress-'));
  let child;
  try {
    // Exercise GNU timeout and real process-group signalling without privileges
    // or packet capture. The capture stand-in ignores INT, but accepts TERM.
    writeFileSync(join(dir, 'sudo'), '#!/bin/sh\nshift\nexec "$@"\n', { mode: 0o700 });
    writeFileSync(join(dir, 'tshark'), `#!${process.execPath}
      process.on('SIGINT', () => {});
      process.stderr.write('Capturing on any\\n');
      setInterval(() => {}, 1000);`, { mode: 0o700 });
    const trace = join(dir, 'trace');
    child = spawn(process.execPath, [new URL('./observe.mjs', import.meta.url).pathname, trace], {
      env: { ...process.env, PATH: `${dir}:${process.env.PATH}` }, stdio: 'ignore',
    });
    const exited = new Promise(resolve => child.once('exit', resolve));
    for (let i = 0; i < 100 && !existsSync(`${trace}.ready`); i++) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(existsSync(`${trace}.ready`));
    writeFileSync(`${trace}.stop`, '');
    let timer;
    try {
      await Promise.race([exited, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Snapshot did not stop capture')), 4000);
      })]);
    } finally {
      clearTimeout(timer);
    }
    const status = JSON.parse(readFileSync(`${trace}.status`));
    assert.equal(status.reason, 'final post snapshot');
    assert.equal(status.collection_error, null);
    assert.notEqual(status.capture_exit, 137);
  } finally {
    if (child?.exitCode === null) child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('workflow is opt-in, observer registers first, and requested network paths are exercised', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/runner-egress.yml', import.meta.url), 'utf8');
  assert.match(workflow, /if: vars\.RUNNER_EGRESS_TRACE == 'true'/);
  assert.match(workflow, /runs-on: ubuntu-26\.04/);
  assert.match(workflow, /timeout-minutes: 10/);
  assert.equal(workflow.match(/- uses: (\S+)/)[1], './workflow/runner-egress');
  for (const path of ['upload-artifact', 'download-artifact', 'cache/save', 'cache/restore']) {
    assert.ok(workflow.includes(`uses: actions/${path}@`));
  }
  assert.match(workflow, /uses: \.\/workflow\/runner-egress\/exercise/);
  assert.match(workflow, /TRACE_UPLOAD_SCRIPT:.*\/dist\/upload\/index\.js/);
  assert.match(workflow, /fail-on-cache-miss: true/);
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /secrets\.|id-token:|contents: write|secure-host@/);
});
