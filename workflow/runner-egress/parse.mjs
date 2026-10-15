import { isIP } from 'node:net';

export const MAX_BYTES = 4 * 1024 * 1024;
export const MAX_PACKETS = 10000;
export const FIELDS = ['frame.time_epoch', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst',
  'tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport', 'dns.flags.response',
  'dns.qry.name', 'dns.a', 'dns.aaaa', 'tls.handshake.extensions_server_name', 'ip.proto', 'ipv6.nxt'];

// Never publish arbitrary dissector text, command lines, URLs or packet bytes.
function names(value) {
  return [...new Set(value.split(',').map(s => s.toLowerCase().replace(/\.$/, ''))
    .filter(s => s.length <= 253 && /^(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(s)))];
}

function endpoint(value) {
  const match = value.match(/^\[?([\da-fA-F:.]+?)\]?:(\d+)$/);
  if (!match || !isIP(match[1]) || +match[2] > 65535) return null;
  // .NET runner sockets commonly appear as IPv4-mapped IPv6 in ss while
  // the packets and interface inventory carry plain IPv4 addresses.
  const address = match[1].startsWith('::ffff:') && isIP(match[1].slice(7)) === 4
    ? match[1].slice(7) : match[1];
  return { address, port: +match[2] };
}

export function sockets(text, time) {
  return text.split('\n').flatMap(line => {
    const cols = line.trim().split(/\s+/);
    const local = endpoint(cols[4] ?? '');
    const remote = endpoint(cols[5] ?? '');
    if (!['tcp', 'udp'].includes(cols[0]) || !local || !remote) return [];
    return [...line.matchAll(/\("([a-zA-Z0-9_.+-]{1,32})",pid=(\d+),fd=\d+\)/g)]
      .map(m => ({ time, transport: cols[0], local, remote, process: m[1], pid: +m[2] }));
  });
}

export function observations(text, samples, localAddresses) {
  if (Buffer.byteLength(text) > MAX_BYTES) throw new Error('Trace exceeds 4 MiB');
  const rows = text.split('\n').filter(Boolean);
  if (rows.length > MAX_PACKETS) throw new Error('Trace exceeds packet limit');
  const answers = new Map();
  const found = new Map();
  const owners = new Map();
  const socketKey = (transport, source, sourcePort, address, port) =>
    `${transport}/${source}/${sourcePort}/${address}/${port}`;
  for (const sample of samples) {
    const key = socketKey(sample.transport, sample.local.address, sample.local.port,
      sample.remote.address, sample.remote.port);
    const list = owners.get(key) ?? [];
    list.push(sample);
    owners.set(key, list);
  }
  for (const line of rows) {
    const cells = line.split('\t');
    if (cells.length !== FIELDS.length) continue;
    const [timestamp, src4, src6, dst4, dst6, tcpSrc, udpSrc, tcpDst, udpDst,
      response, query, a, aaaa, sni, proto4, proto6] = cells;
    const time = Number(timestamp);
    if (!Number.isFinite(time) || !timestamp) continue;
    const source = src4 || src6;
    const address = dst4 || dst6;
    // Associate answers only with DNS traffic to this runner, not unrelated
    // host traffic. Names are observed claims, never authenticated identities.
    if (response === '1' && localAddresses.includes(address) && (tcpSrc || udpSrc) === '53') {
      for (const ip of `${a},${aaaa}`.split(',').filter(ip => isIP(ip))) {
        const previous = answers.get(ip) ?? [];
        answers.set(ip, [...new Set([...previous, ...names(query)])]);
      }
    }
    const portText = tcpDst || udpDst;
    if (!localAddresses.includes(source) || !isIP(address)) continue;
    if (portText && (!/^\d+$/.test(portText) || +portText > 65535)) continue;
    const protocolText = proto4 || proto6;
    if (!/^\d+$/.test(protocolText) || +protocolText > 255) continue;
    const ip_protocol = +protocolText;
    const transport = tcpDst ? 'tcp' : udpDst ? 'udp' : 'ip';
    const key = `${ip_protocol}/${address}/${portText}`;
    const record = found.get(key) ?? { address, port: portText ? +portText : null, transport, ip_protocol,
      dns_names: [], dns_queries: [], tls_sni: [], processes: [] };
    record.dns_names = [...new Set([...record.dns_names, ...(answers.get(address) ?? [])])];
    if (portText === '53' && response === '0') {
      record.dns_queries = [...new Set([...record.dns_queries, ...names(query)])];
    }
    record.tls_sni = [...new Set([...record.tls_sni, ...names(sni)])];
    // A sampled socket owner is evidence, not proof of the opener. Do not
    // guess from step timing or attribute a reused source port long afterwards.
    for (const sample of owners.get(socketKey(transport, source, +(tcpSrc || udpSrc), address, +portText)) ?? []) {
      if (Math.abs(sample.time - time) > 1) continue;
      const owner = { pid: sample.pid, name: sample.process };
      if (!record.processes.some(p => p.pid === owner.pid && p.name === owner.name)) record.processes.push(owner);
    }
    found.set(key, record);
  }
  return [...found.values()].sort((a, b) => a.address.localeCompare(b.address) || a.port - b.port);
}
