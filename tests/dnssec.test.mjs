import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import packet from 'dns-packet';
import {
  classifyDnssec,
  probeDnssec,
  queryDnsOverTls,
} from '../server/probes/dnssec.mjs';

const temporaryDirectory = mkdtempSync(join(tmpdir(), 'hostcanvas-dot-'));
const keyPath = join(temporaryDirectory, 'key.pem');
const certificatePath = join(temporaryDirectory, 'cert.pem');
const generated = spawnSync(
  'openssl',
  [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    keyPath,
    '-out',
    certificatePath,
    '-days',
    '1',
    '-subj',
    '/CN=dns.fixture.test',
    '-addext',
    'subjectAltName=DNS:dns.fixture.test',
  ],
  { encoding: 'utf8' },
);
assert.equal(generated.status, 0, generated.stderr);
const ca = readFileSync(certificatePath);
const sockets = new Set();
const server = tls.createServer(
  { key: readFileSync(keyPath), cert: ca },
  (socket) => {
    sockets.add(socket);
    socket.on('error', () => undefined);
    socket.once('close', () => sockets.delete(socket));
    let input = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      input = Buffer.concat([input, chunk]);
      if (input.length < 2 || input.length < input.readUInt16BE(0) + 2) return;
      const query = packet.decode(input.subarray(2));
      assert.ok(query.flags & packet.AUTHENTIC_DATA);
      assert.ok(query.additionals[0].flags & packet.DNSSEC_OK);
      assert.equal(Boolean(query.flags & packet.CHECKING_DISABLED), false);
      const question = query.questions[0];
      if (question.name === 'timeout.example.com') return;
      if (question.name === 'partial.example.com')
        return socket.end(Buffer.from([0, 100, 0]));
      let flags = packet.RECURSION_AVAILABLE;
      if (question.name === 'secure.example.com' || question.name === '.')
        flags |= packet.AUTHENTIC_DATA;
      if (question.name === 'truncated.example.com')
        flags |= packet.TRUNCATED_RESPONSE;
      if (question.name === 'cd.example.com') flags |= packet.CHECKING_DISABLED;
      const bogus = question.name === 'bogus.example.com';
      if (bogus) flags |= 2; // SERVFAIL
      const encoded = packet.encode({
        type: 'response',
        flags,
        id:
          question.name === 'mismatch.example.com'
            ? (query.id + 1) % 65536
            : query.id,
        questions: query.questions,
        answers: bogus
          ? []
          : question.type === 'DNSKEY'
            ? [
                {
                  type: 'DNSKEY',
                  name: '.',
                  ttl: 300,
                  data: { flags: 257, algorithm: 13, key: Buffer.alloc(32) },
                },
              ]
            : [
                {
                  type: 'A',
                  name: question.name,
                  ttl: 300,
                  data: '93.184.216.34',
                },
              ],
        additionals: bogus
          ? [
              {
                type: 'OPT',
                name: '.',
                udpPayloadSize: 1232,
                options: [{ code: 15, data: Buffer.from([0, 6]) }],
              },
            ]
          : [],
      });
      const framed = Buffer.alloc(encoded.length + 2);
      framed.writeUInt16BE(encoded.length);
      encoded.copy(framed, 2);
      // Fragment both the two-byte prefix and the payload across writes.
      socket.write(framed.subarray(0, 1));
      setImmediate(() => socket.end(framed.subarray(1)));
    });
  },
);
server.on('tlsClientError', () => undefined);
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const target = {
  hostname: 'dns.fixture.test',
  address: '127.0.0.1',
  family: 4,
};
const connect = (options) => {
  assert.equal(options.host, target.address);
  assert.equal(options.servername, target.hostname);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.port, 853);
  return tls.connect({ ...options, port: server.address().port, ca });
};
const query = (name, type = 'A', options = {}) =>
  queryDnsOverTls(target, name, type, { connect, ...options });
after(async () => {
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => server.close(resolve));
  rmSync(temporaryDirectory, { recursive: true, force: true });
});

test('real TLS DNS frames authenticate the peer and classify signed, unsigned and bogus answers', async () => {
  const root = await query('.', 'DNSKEY');
  assert.equal(root.answers[0].name, '.');
  assert.equal(
    classifyDnssec(await query('secure.example.com'), root).status,
    'present',
  );
  assert.equal(
    classifyDnssec(await query('unsigned.example.com'), root).status,
    'missing',
  );
  const bogus = classifyDnssec(await query('bogus.example.com'), root);
  assert.equal(bogus.status, 'bogus');
  assert.deepEqual(bogus.extendedErrors, [6]);
});

test('DNS-over-TLS rejects mismatched, truncated, checking-disabled, partial and timed-out messages', async () => {
  for (const host of ['mismatch', 'truncated', 'cd']) {
    await assert.rejects(query(`${host}.example.com`), {
      code: 'DNSSEC_RESPONSE_MISMATCH',
    });
  }
  await assert.rejects(query('partial.example.com'), {
    code: 'DNSSEC_PREMATURE_CLOSE',
  });
  await assert.rejects(query('timeout.example.com', 'A', { timeoutMs: 30 }), {
    code: 'DNSSEC_TIMEOUT',
  });
});

test('DNS-over-TLS never silently accepts an untrusted server certificate', async () => {
  await assert.rejects(
    queryDnsOverTls(target, 'secure.example.com', 'A', {
      connect: (options) =>
        tls.connect({ ...options, port: server.address().port }),
    }),
    (failure) =>
      ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(
        failure.code,
      ),
  );
});

test('malformed or oversized DNS frames have hard bounds and close the connection', async () => {
  for (const bytes of [
    Buffer.alloc(65538),
    Buffer.from([0, 1, 0]),
    Buffer.from([0, 12, ...Array(12).fill(255)]),
  ]) {
    let destroyed = false;
    const fake = new EventEmitter();
    fake.authorized = true;
    fake.destroy = () => {
      destroyed = true;
    };
    fake.write = () => {
      queueMicrotask(() => fake.emit('data', bytes));
    };
    const connectFake = () => {
      queueMicrotask(() => fake.emit('secureConnect'));
      return fake;
    };
    await assert.rejects(
      queryDnsOverTls(target, 'secure.example.com', 'A', {
        connect: connectFake,
      }),
    );
    assert.equal(destroyed, true);
  }
});

test('DNSSEC uncertainty is not treated as missing signatures or successful validation', () => {
  const unsigned = {
    rcode: 'NOERROR',
    flags: packet.RECURSION_AVAILABLE,
    answers: [{ type: 'A' }],
  };
  assert.equal(
    classifyDnssec(unsigned, { rcode: 'NOERROR', flags: 0 }).status,
    'unknown',
  );
  assert.equal(
    classifyDnssec({ ...unsigned, rcode: 'SERVFAIL' }, null).status,
    'unknown',
  );
  assert.equal(
    classifyDnssec(
      { ...unsigned, rcode: 'NXDOMAIN', flags: packet.AUTHENTIC_DATA },
      null,
    ).status,
    'unknown',
  );
  assert.equal(
    classifyDnssec(
      { ...unsigned, answers: [], flags: packet.AUTHENTIC_DATA },
      null,
    ).status,
    'unknown',
  );
  assert.equal(
    classifyDnssec(
      {
        ...unsigned,
        flags: packet.AUTHENTIC_DATA,
        additionals: [
          { type: 'OPT', options: [{ code: 15, data: Buffer.from([0, 3]) }] },
        ],
      },
      null,
    ).status,
    'unknown',
  );
  for (const data of [Buffer.from([0]), Buffer.from([0, 3])]) {
    const additionals = [{ type: 'OPT', options: [{ code: 15, data }] }];
    const capability = {
      rcode: 'NOERROR',
      flags: packet.AUTHENTIC_DATA,
      answers: [{ type: 'DNSKEY', name: '.' }],
    };
    assert.equal(
      classifyDnssec({ ...unsigned, additionals }, capability).status,
      'unknown',
    );
    assert.equal(
      classifyDnssec(unsigned, { ...capability, additionals }).status,
      'unknown',
    );
  }
});

test('DNSSEC opt-in respects public resolver target policy and returns safe unknown on transport errors', async () => {
  let calls = 0;
  const blocked = await probeDnssec('secure.example.com', {
    resolverHostname: 'localhost',
    query: async () => {
      calls++;
    },
  });
  assert.equal(blocked.status, 'unknown');
  assert.equal(blocked.error, 'PRIVATE_TARGET_BLOCKED');
  assert.equal(calls, 0);
  const disabled = await probeDnssec('example.com', { resolverHostname: '' });
  assert.equal(disabled.status, 'disabled');
  const result = await probeDnssec('secure.example.com', {
    resolverHostname: 'dns.fixture.test',
    resolveTarget: async () => target,
    query: (resolved, name, type) =>
      queryDnsOverTls(resolved, name, type, { connect }),
  });
  assert.equal(result.status, 'present');
  assert.equal(result.transport, 'dns-over-tls');
  const failed = await probeDnssec('example.com', {
    resolverHostname: 'dns.fixture.test',
    resolveTarget: async () => target,
    query: async () => {
      throw Object.assign(new Error('failure'), { code: 'DNSSEC_TIMEOUT' });
    },
  });
  assert.equal(failed.status, 'unknown');
  assert.equal(failed.error, 'DNSSEC_TIMEOUT');
});
