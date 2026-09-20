import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { APP_NAME, APP_VERSION, NATIVE_SCAN_TIMEOUT_MS } from '../config.mjs';

const HTTP_HEADER_ALLOWLIST = [
  'content-security-policy',
  'permissions-policy',
  'referrer-policy',
  'server',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
];

function summarizeCookie(rawCookie) {
  const parts = String(rawCookie)
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean);
  const name = (parts[0]?.split('=', 1)[0] || 'unnamed').slice(0, 100);
  const sameSitePart = parts.find((part) => /^samesite=/i.test(part));
  return {
    name,
    sameSite: sameSitePart?.split('=', 2)[1]?.toLowerCase() || null,
    secure: parts.some((part) => /^secure$/i.test(part)),
    httpOnly: parts.some((part) => /^httponly$/i.test(part)),
  };
}

function certificateDepth(certificate) {
  let depth = 0;
  let current = certificate;
  const fingerprints = new Set();
  while (current?.raw && depth < 16) {
    const fingerprint = current.fingerprint256 || current.fingerprint;
    if (fingerprint && fingerprints.has(fingerprint)) break;
    if (fingerprint) fingerprints.add(fingerprint);
    depth += 1;
    if (!current.issuerCertificate || current.issuerCertificate === current)
      break;
    current = current.issuerCertificate;
  }
  return depth;
}

function keyDetails(x509) {
  const key = x509.publicKey;
  const details = key.asymmetricKeyDetails || {};
  return {
    type: key.asymmetricKeyType || 'unknown',
    bits: details.modulusLength || details.namedCurve || null,
  };
}

function openTlsSocket(target, options = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({
      host: target.address,
      port: target.port,
      servername: target.hostname,
      rejectUnauthorized: false,
      minVersion: options.minVersion,
      maxVersion: options.maxVersion,
      ALPNProtocols: options.alpnProtocols || ['h2', 'http/1.1'],
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const error = new Error('TLS bağlantısı zaman aşımına uğradı.');
      error.code = 'TLS_TIMEOUT';
      reject(error);
    }, options.timeoutMs || NATIVE_SCAN_TIMEOUT_MS);

    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(socket);
    });

    socket.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(error);
    });
    socket.once('close', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(
        Object.assign(new Error('TLS bağlantısı tamamlanmadan kapandı.'), {
          code: 'TLS_PREMATURE_CLOSE',
        }),
      );
    });
  });
}

export function classifyProtocolProbeError(error) {
  const code = error?.code || null;
  const clientUnsupported = [
    'ERR_TLS_INVALID_PROTOCOL_VERSION',
    'ERR_SSL_NO_PROTOCOLS_AVAILABLE',
    'ERR_SSL_UNSUPPORTED_PROTOCOL',
  ].includes(code);
  const serverRejected = code === 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION';
  return {
    supported: serverRejected ? false : null,
    clientUnsupported,
    serverRejected,
    error: code || error?.message || 'TLS_PROTOCOL_PROBE_FAILED',
  };
}

async function probeProtocol(target, version) {
  try {
    const socket = await openTlsSocket(target, {
      minVersion: version,
      maxVersion: version,
      timeoutMs: Math.min(NATIVE_SCAN_TIMEOUT_MS, 5_000),
    });
    const negotiated = socket.getProtocol();
    socket.destroy();
    return { supported: true, negotiated };
  } catch (error) {
    return classifyProtocolProbeError(error);
  }
}

export async function probeTls(target) {
  const socket = await openTlsSocket(target);
  try {
    const peer = socket.getPeerCertificate(true);
    if (!peer?.raw) {
      socket.destroy();
      const error = new Error('Sunucu bir X.509 sertifikası göndermedi.');
      error.code = 'CERTIFICATE_MISSING';
      throw error;
    }

    const x509 = new X509Certificate(peer.raw);
    const hostnameError = tls.checkServerIdentity(target.hostname, peer);
    const observation = {
      protocol: socket.getProtocol(),
      cipher: socket.getCipher(),
      alpn: socket.alpnProtocol || null,
      ephemeralKey: socket.getEphemeralKeyInfo?.() || null,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError || null,
      certificate: {
        subject: x509.subject,
        issuer: x509.issuer,
        subjectAltName: x509.subjectAltName,
        serialNumber: x509.serialNumber,
        fingerprint256: x509.fingerprint256,
        validFrom: new Date(x509.validFrom).toISOString(),
        validTo: new Date(x509.validTo).toISOString(),
        signatureAlgorithm: x509.signatureAlgorithm || null,
        hostnameMatches: !hostnameError,
        hostnameError: hostnameError?.message || null,
        chainDepth: certificateDepth(peer),
        publicKey: keyDetails(x509),
      },
      protocols: {},
    };
    socket.destroy();

    const versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
    const results = await Promise.all(
      versions.map(async (version) => [
        version,
        await probeProtocol(target, version),
      ]),
    );
    observation.protocols = Object.fromEntries(results);
    return observation;
  } finally {
    socket.destroy();
  }
}

export async function probeHttpHeaders(target) {
  let socket;
  try {
    socket = await openTlsSocket(target, {
      timeoutMs: Math.min(NATIVE_SCAN_TIMEOUT_MS, 6_000),
      alpnProtocols: ['http/1.1'],
    });
    return await new Promise((resolve) => {
      let settled = false;
      let response = '';
      let responseBytes = 0;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(value);
      };
      const timer = setTimeout(
        () => finish({ status: 'unknown', error: 'HTTP_TIMEOUT' }),
        Math.min(NATIVE_SCAN_TIMEOUT_MS, 6_000),
      );

      socket.setEncoding('utf8');
      socket.on('data', (chunk) => {
        responseBytes += Buffer.byteLength(chunk, 'utf8');
        response += chunk;
        if (responseBytes > 64 * 1024) {
          finish({ status: 'unknown', error: 'HTTP_HEADERS_TOO_LARGE' });
          return;
        }
        const boundary = response.indexOf('\r\n\r\n');
        if (boundary === -1) return;
        const head = response.slice(0, boundary);
        const lines = head.split('\r\n');
        if (!/^HTTP\/\d(?:\.\d)?\s+\d{3}/i.test(lines[0] || '')) {
          finish({ status: 'not_http' });
          return;
        }
        const headers = {};
        const cookies = [];
        for (const line of lines.slice(1)) {
          const separator = line.indexOf(':');
          if (separator < 1) continue;
          const key = line.slice(0, separator).trim().toLowerCase();
          const value = line.slice(separator + 1).trim();
          if (key === 'set-cookie') {
            cookies.push(summarizeCookie(value));
            continue;
          }
          if (!HTTP_HEADER_ALLOWLIST.includes(key)) continue;
          const boundedValue = value.slice(0, 4_096);
          headers[key] = headers[key]
            ? `${headers[key]}, ${boundedValue}`.slice(0, 4_096)
            : boundedValue;
        }
        finish({
          status: 'complete',
          statusLine: lines[0],
          hsts: headers['strict-transport-security'] || null,
          headers: Object.fromEntries(
            HTTP_HEADER_ALLOWLIST.map((key) => [key, headers[key] || null]),
          ),
          cookies,
        });
      });
      socket.once('error', (error) =>
        finish({ status: 'unknown', error: error.code || error.message }),
      );
      socket.once('end', () => {
        if (!settled) finish({ status: 'not_http' });
      });
      socket.once('close', () => {
        if (!settled)
          finish({ status: 'unknown', error: 'HTTP_PREMATURE_CLOSE' });
      });
      socket.write(
        `HEAD / HTTP/1.1\r\nHost: ${target.hostname}${target.port === 443 ? '' : `:${target.port}`}\r\nUser-Agent: ${APP_NAME}/${APP_VERSION}\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      );
    });
  } catch (error) {
    socket?.destroy();
    return { status: 'unknown', error: error.code || error.message };
  }
}
