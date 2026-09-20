import tls from 'node:tls';
import { randomInt } from 'node:crypto';
import packet from 'dns-packet';
import { DNSSEC_RESOLVER } from '../config.mjs';
import {
  normalizeHostname,
  resolveAndValidateTarget,
} from '../security/targets.mjs';

const error = (code) => Object.assign(new Error(code), { code });

// DNS-over-TLS to an explicitly selected validating resolver. This authenticates
// the resolver's report; it is not a local DNSSEC signature-chain validator.
export function queryDnsOverTls(target, name, type, options = {}) {
  return new Promise((resolve, reject) => {
    const id = randomInt(65536);
    const query = packet.encode({
      type: 'query',
      id,
      flags: packet.RECURSION_DESIRED | packet.AUTHENTIC_DATA,
      questions: [{ type, name, class: 'IN' }],
      additionals: [
        {
          type: 'OPT',
          name: '.',
          udpPayloadSize: 1232,
          flags: packet.DNSSEC_OK,
          options: [],
        },
      ],
    });
    const frame = Buffer.alloc(query.length + 2);
    frame.writeUInt16BE(query.length);
    query.copy(frame, 2);
    let socket;
    let settled = false;
    let bytes = Buffer.alloc(0);
    const finish = (failure, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      if (failure) reject(failure);
      else resolve(value);
    };
    const timer = setTimeout(
      () => finish(error('DNSSEC_TIMEOUT')),
      options.timeoutMs || 4000,
    );
    try {
      socket = (options.connect || tls.connect)({
        host: target.address,
        family: target.family,
        port: 853,
        servername: target.hostname,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      });
      socket.once('secureConnect', () => {
        if (!socket.authorized) return finish(error('DNSSEC_TLS_UNTRUSTED'));
        socket.write(frame);
      });
      socket.on('data', (chunk) => {
        if (settled) return;
        if (bytes.length + chunk.length > 65537)
          return finish(error('DNSSEC_RESPONSE_TOO_LARGE'));
        bytes = Buffer.concat([bytes, chunk]);
        if (bytes.length < 2) return;
        const length = bytes.readUInt16BE(0);
        if (length < 12) return finish(error('DNSSEC_MALFORMED_RESPONSE'));
        if (bytes.length < length + 2) return;
        if (bytes.length !== length + 2)
          return finish(error('DNSSEC_UNEXPECTED_FRAME'));
        try {
          const result = packet.decode(bytes.subarray(2));
          const question = result.questions?.[0];
          const canonical = (value) =>
            String(value).toLowerCase().replace(/\.$/, '');
          if (
            packet.decode.bytes !== length ||
            result.id !== id ||
            result.type !== 'response' ||
            result.questions.length !== 1 ||
            question.type !== type ||
            question.class !== 'IN' ||
            canonical(question.name) !== canonical(name) ||
            result.opcode !== 'QUERY' ||
            result.flags &
              (packet.TRUNCATED_RESPONSE | packet.CHECKING_DISABLED) ||
            !(result.flags & packet.RECURSION_AVAILABLE)
          )
            throw error('DNSSEC_RESPONSE_MISMATCH');
          finish(null, result);
        } catch (failure) {
          finish(error(failure.code || 'DNSSEC_MALFORMED_RESPONSE'));
        }
      });
      socket.once('error', (failure) =>
        finish(error(failure.code || 'DNSSEC_TRANSPORT_ERROR')),
      );
      socket.once('close', () => finish(error('DNSSEC_PREMATURE_CLOSE')));
    } catch (failure) {
      finish(error(failure.code || 'DNSSEC_TRANSPORT_ERROR'));
    }
  });
}

function extendedErrors(response) {
  return (response?.additionals || [])
    .filter((item) => item.type === 'OPT')
    .flatMap((item) => item.options || [])
    .filter((item) => item.code === 15);
}

export function classifyDnssec(response, capability) {
  const errors = extendedErrors(response);
  if (
    errors.some((item) => !Buffer.isBuffer(item.data) || item.data.length < 2)
  )
    return { status: 'unknown', reason: 'malformed_extended_error' };
  const codes = errors.map((item) => item.data.readUInt16BE(0));
  if (
    response.rcode === 'SERVFAIL' &&
    codes.some((code) => code >= 6 && code <= 12)
  ) {
    return {
      status: 'bogus',
      reason: 'resolver_reported_dnssec_failure',
      extendedErrors: codes.slice(0, 8),
    };
  }
  // Other DNS failures, stale/filtered answers and unexpected EDEs are not proof
  // that a zone is unsigned, nor proof of successful validation.
  if (response.rcode !== 'NOERROR' || codes.length)
    return { status: 'unknown', reason: 'inconclusive_dns_response' };
  const hasAnswer = (response.answers || []).some(
    (item) => item.type === 'A' || item.type === 'CNAME',
  );
  if (!hasAnswer) return { status: 'unknown', reason: 'no_address_evidence' };
  if (response.flags & packet.AUTHENTIC_DATA)
    return { status: 'present', reason: 'authenticated_data' };
  const capable =
    capability?.rcode === 'NOERROR' &&
    extendedErrors(capability).length === 0 &&
    capability.flags & packet.AUTHENTIC_DATA &&
    capability.answers?.some(
      (item) => item.type === 'DNSKEY' && item.name === '.',
    );
  if (!capable)
    return { status: 'unknown', reason: 'resolver_validation_not_confirmed' };
  return {
    status: 'missing',
    reason: 'unsigned_answer_from_validating_resolver',
  };
}

export async function probeDnssec(hostname, options = {}) {
  const resolver = options.resolverHostname ?? DNSSEC_RESOLVER;
  if (!resolver)
    return { status: 'disabled', reason: 'DNSSEC_RESOLVER_NOT_CONFIGURED' };
  try {
    const normalized = normalizeHostname(resolver);
    const resolved = await (options.resolveTarget || resolveAndValidateTarget)(
      normalized,
    );
    const target = { hostname: normalized, ...resolved };
    const query = options.query || queryDnsOverTls;
    const [response, capability] = await Promise.all([
      query(target, hostname, 'A'),
      query(target, '.', 'DNSKEY'),
    ]);
    return {
      ...classifyDnssec(response, capability),
      domain: hostname,
      resolver: normalized,
      transport: 'dns-over-tls',
    };
  } catch (failure) {
    return {
      status: 'unknown',
      domain: hostname,
      resolver,
      error: String(failure.code || 'DNSSEC_QUERY_FAILED').slice(0, 100),
    };
  }
}
