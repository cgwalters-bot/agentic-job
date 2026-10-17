// Node's own fetch, which reads no proxy setting unless NODE_USE_ENV_PROXY
// is set: whatever reaches the network does so through the redirection
// alone, and trusts the proxy's authority through NODE_EXTRA_CA_CERTS,
// which the action put in the job's environment.
const url = 'https://example.com/';

const fail = message => {
  console.log(`::error::${message}`);
  process.exitCode = 1;
};

const set = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NODE_USE_ENV_PROXY']
  .filter(name => process.env[name]);
if (set.length) {
  fail(`${set.join(', ')} set, so this proves nothing`);
} else {
  const read = await fetch(url);
  if (read.ok) {
    console.log(`GET ${url}: ${read.status}`);
  } else {
    fail(`GET ${url}: ${read.status}`);
  }
  const write = await fetch(url, { method: 'POST', body: 'probe' });
  const denied = write.headers.get('x-egress-denied');
  if (write.status === 403 && denied) {
    console.log(`POST ${url}: refused by the egress proxy (${denied})`);
  } else {
    fail(`POST ${url}: ${write.status}, not the egress proxy's refusal`);
  }
}
