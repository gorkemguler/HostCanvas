import { spawn } from 'node:child_process';
import { mkdir, open, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';

import {
  ARTIFACT_DIRECTORY,
  MAX_SCANNER_OUTPUT_BYTES,
  TESTSSL_PATH,
  TESTSSL_TIMEOUT_MS,
} from '../config.mjs';

const escapeCharacter = String.fromCodePoint(27);
const ansiPattern = new RegExp(`${escapeCharacter}\\[[0-?]*[ -/]*[@-~]`, 'g');
const activeProcessKillers = new Set();
const MAX_TESTSSL_ARTIFACT_BYTES = 4 * 1024 * 1024;
const RESOURCE_MONITOR_INTERVAL_MS = 100;
const scannerEnvironmentKeys = [
  'PATH',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'SYSTEMROOT',
  'SystemRoot',
  'COMSPEC',
  'ComSpec',
  'PATHEXT',
];

const stripAnsi = (value) =>
  String(value ?? '')
    .replace(ansiPattern, '')
    .trim();

function scannerLimitError(message, code) {
  return Object.assign(new Error(message), { code });
}

export function buildScannerEnvironment(source = process.env) {
  const environment = {};
  for (const key of scannerEnvironmentKeys) {
    if (source[key] != null && source[key] !== '')
      environment[key] = source[key];
  }
  if (!environment.PATH && process.platform !== 'win32') {
    environment.PATH = '/usr/local/bin:/usr/bin:/bin';
  }
  return {
    ...environment,
    TERM: 'dumb',
    NO_COLOR: '1',
    PHONE_OUT: 'false',
    BASICAUTH: '',
    REQHEADER: '',
    DEBUG: '0',
    HEADER_MAXSLEEP: '1',
  };
}

async function artifactExceedsLimit(path, maximumBytes) {
  if (!path) return false;
  try {
    return (await stat(path)).size > maximumBytes;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export function spawnWithLimits(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const detached = process.platform !== 'win32';
    // testssl hardcodes /tmp on several versions. RLIMIT_FSIZE applies to its
    // entire process group, bounding each file without measuring unrelated
    // disk activity. Arguments are positional, never interpolated into shell.
    const child = spawn(
      detached ? '/bin/sh' : command,
      detached
        ? [
            '-c',
            'ulimit -f 16384 || exit 125; exec "$@"',
            'hostcanvas-scanner',
            command,
            ...args,
          ]
        : args,
      {
        cwd: options.cwd,
        env: options.env || buildScannerEnvironment(),
        shell: false,
        detached,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    let outputBytes = 0;
    let terminalError = null;
    let settled = false;
    let monitorRunning = false;

    let forceKillTimer;
    const kill = (signal = 'SIGKILL') => {
      if (!child.pid) return;
      try {
        if (detached) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch {
        child.kill(signal);
      }
    };
    const stop = () =>
      terminate(
        scannerLimitError('testssl.sh taraması durduruldu.', 'TESTSSL_STOPPED'),
      );
    activeProcessKillers.add(stop);

    let resourceMonitor;
    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(forceKillTimer);
      if (resourceMonitor) clearInterval(resourceMonitor);
    };
    const settle = (error, result) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(result);
    };
    const terminate = (error) => {
      if (settled || terminalError) return;
      terminalError = error;
      kill('SIGTERM');
      forceKillTimer = setTimeout(() => kill(), 300);
    };

    const timer = setTimeout(() => {
      const error = scannerLimitError(
        'testssl.sh taraması zaman aşımına uğradı.',
        'TESTSSL_TIMEOUT',
      );
      terminate(error);
    }, options.timeoutMs || TESTSSL_TIMEOUT_MS);

    const append = (current, chunk) => {
      if (terminalError) return current;
      const remaining = Math.max(0, MAX_SCANNER_OUTPUT_BYTES - outputBytes);
      outputBytes += chunk.length;
      if (outputBytes > MAX_SCANNER_OUTPUT_BYTES) {
        terminate(
          scannerLimitError(
            'testssl.sh çıktı limiti aşıldı.',
            'TESTSSL_OUTPUT_LIMIT',
          ),
        );
      }
      return current + chunk.subarray(0, remaining).toString('utf8');
    };
    child.stdout.on('data', (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = append(stderr, chunk);
    });

    if (options.artifactPath) {
      resourceMonitor = setInterval(() => {
        if (monitorRunning || settled || terminalError) return;
        monitorRunning = true;
        void (async () => {
          if (
            await artifactExceedsLimit(
              options.artifactPath,
              options.maximumArtifactBytes || MAX_TESTSSL_ARTIFACT_BYTES,
            )
          ) {
            terminate(
              scannerLimitError(
                'testssl.sh artifact boyut limiti aşıldı.',
                'TESTSSL_ARTIFACT_LIMIT',
              ),
            );
            return;
          }
        })()
          .catch((error) => terminate(error))
          .finally(() => {
            monitorRunning = false;
          });
      }, RESOURCE_MONITOR_INTERVAL_MS);
      resourceMonitor.unref?.();
    }

    child.once('error', (error) => {
      activeProcessKillers.delete(stop);
      settle(error);
    });
    child.once('close', (code, signal) => {
      // Descendants may outlive the direct child after SIGTERM.
      if (terminalError) kill();
      activeProcessKillers.delete(stop);
      if (settled) return;
      settle(terminalError, { code, signal, stdout, stderr });
    });
  });
}

export function stopTestsslProcesses() {
  for (const kill of activeProcessKillers) kill();
}

let engineInfoPromise;

export function getTestsslInfo() {
  if (!engineInfoPromise) {
    engineInfoPromise = spawnWithLimits(TESTSSL_PATH, ['--version'], {
      timeoutMs: 8_000,
    })
      .then((result) => {
        const output = stripAnsi(`${result.stdout}\n${result.stderr}`);
        const version =
          output.match(/testssl\.sh\s+version\s+([^\s]+)/i)?.[1] || null;
        return {
          available: result.code === 0,
          version,
          path: TESTSSL_PATH,
          error: result.code === 0 ? null : `Çıkış kodu ${result.code}`,
        };
      })
      .catch((error) => ({
        available: false,
        version: null,
        path: TESTSSL_PATH,
        error:
          error.code === 'ENOENT'
            ? 'testssl.sh PATH içinde bulunamadı.'
            : error.message,
      }));
  }
  return engineInfoPromise;
}

function collectFindingObjects(value, output = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectFindingObjects(item, output);
    return output;
  }
  if (!value || typeof value !== 'object') return output;

  if (
    typeof value.id === 'string' &&
    ('severity' in value || 'finding' in value)
  ) {
    output.push(value);
  }
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object')
      collectFindingObjects(child, output);
  }
  return output;
}

export function normalizeTestsslOutput(document) {
  const items = collectFindingObjects(document);
  const seen = new Set();
  const findings = [];
  for (const item of items) {
    const id = stripAnsi(item.id)
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '_');
    const severity = stripAnsi(item.severity || 'INFO').toUpperCase();
    const finding = stripAnsi(
      Array.isArray(item.finding) ? item.finding.join('; ') : item.finding,
    ).slice(0, 4_000);
    const key = `${id}:${finding}`;
    if (!id || seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id,
      severity,
      finding,
      cve: stripAnsi(item.cve || item.CVE || '') || null,
      cwe: stripAnsi(item.cwe || item.CWE || '') || null,
      ip: stripAnsi(item.ip || '') || null,
      port: Number(item.port) || null,
    });
  }
  return findings;
}

export function buildTestsslArguments(target, outputPath) {
  return [
    '--warnings',
    'batch',
    '--ids-friendly',
    '--ip',
    target.address,
    '--nodns',
    'none',
    ...(target.family === 6 ? ['-6'] : []),
    '-p',
    '-s',
    '-f',
    '-S',
    '-U',
    '--overwrite',
    '--jsonfile',
    outputPath,
    `${target.hostname}:${target.port}`,
  ];
}

export async function readBoundedTestsslArtifact(
  outputPath,
  maximumBytes = MAX_TESTSSL_ARTIFACT_BYTES,
) {
  const handle = await open(outputPath, 'r');
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.size > maximumBytes) {
      throw scannerLimitError(
        'testssl.sh artifact boyut limiti aşıldı.',
        'TESTSSL_ARTIFACT_LIMIT',
      );
    }
    // A bounded read also covers growth between stat and read.
    const contents = Buffer.alloc(maximumBytes + 1);
    let offset = 0;
    while (offset < contents.length) {
      const { bytesRead } = await handle.read(
        contents,
        offset,
        contents.length - offset,
        offset,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > maximumBytes)
      throw scannerLimitError(
        'testssl.sh artifact boyut limiti aşıldı.',
        'TESTSSL_ARTIFACT_LIMIT',
      );
    return JSON.parse(contents.subarray(0, offset).toString('utf8'));
  } finally {
    await handle.close();
  }
}

export async function runTestssl(target, scanId) {
  const engine = await getTestsslInfo();
  if (!engine.available) {
    const error = new Error(engine.error || 'testssl.sh kullanılamıyor.');
    error.code = 'TESTSSL_UNAVAILABLE';
    throw error;
  }

  if (
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(
      scanId,
    )
  ) {
    const error = new Error('Tarama artifact kimliği geçersiz.');
    error.code = 'TESTSSL_INVALID_SCAN_ID';
    throw error;
  }

  await mkdir(ARTIFACT_DIRECTORY, { recursive: true, mode: 0o700 });
  const outputPath = join(ARTIFACT_DIRECTORY, `${scanId}.json`);
  try {
    await unlink(outputPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const args = buildTestsslArguments(target, outputPath);

  let processResult;
  try {
    processResult = await spawnWithLimits(TESTSSL_PATH, args, {
      timeoutMs: TESTSSL_TIMEOUT_MS,
      artifactPath: outputPath,
      maximumArtifactBytes: MAX_TESTSSL_ARTIFACT_BYTES,
    });
  } catch (error) {
    await unlink(outputPath).catch(() => undefined);
    throw error;
  }

  let document;
  try {
    document = await readBoundedTestsslArtifact(outputPath);
  } catch (error) {
    if (error.code === 'TESTSSL_ARTIFACT_LIMIT') {
      await unlink(outputPath).catch(() => undefined);
      throw error;
    }
    const executionDetail = stripAnsi(processResult.stderr).slice(0, 500);
    const scannerError = new Error(
      processResult.code === 0
        ? `testssl.sh JSON çıktısı okunamadı: ${error.message}`
        : `testssl.sh tamamlanmadı (çıkış ${processResult.code}): ${executionDetail || error.message}`,
    );
    scannerError.code =
      processResult.code === 0 ? 'TESTSSL_PARSE_FAILED' : 'TESTSSL_EXEC_FAILED';
    throw scannerError;
  }

  return {
    status: processResult.code === 0 ? 'complete' : 'partial',
    exitCode: processResult.code,
    signal: processResult.signal,
    engineVersion: engine.version,
    artifact: `${scanId}.json`,
    findings: normalizeTestsslOutput(document),
    stderr: stripAnsi(processResult.stderr).slice(0, 2_000) || null,
  };
}
