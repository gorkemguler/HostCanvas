import { spawn } from 'node:child_process';
import { mkdir, readFile, unlink } from 'node:fs/promises';
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

const stripAnsi = (value) => String(value ?? '').replace(ansiPattern, '').trim();

function spawnWithLimits(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const detached = process.platform !== 'win32';
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...process.env, TERM: 'dumb', NO_COLOR: '1' },
      shell: false,
      detached,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let exceeded = false;
    let settled = false;

    const kill = () => {
      if (!child.pid) return;
      try {
        if (detached) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    activeProcessKillers.add(kill);

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      kill();
      const error = new Error('testssl.sh taraması zaman aşımına uğradı.');
      error.code = 'TESTSSL_TIMEOUT';
      reject(error);
    }, options.timeoutMs || TESTSSL_TIMEOUT_MS);

    const append = (current, chunk) => {
      if (exceeded) return current;
      const next = current + chunk.toString('utf8');
      if (Buffer.byteLength(next) > MAX_SCANNER_OUTPUT_BYTES) {
        exceeded = true;
        kill();
        return next.slice(0, MAX_SCANNER_OUTPUT_BYTES);
      }
      return next;
    };
    child.stdout.on('data', (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeProcessKillers.delete(kill);
      reject(error);
    });
    child.once('close', (code, signal) => {
      activeProcessKillers.delete(kill);
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (exceeded) {
        const error = new Error('testssl.sh çıktı limiti aşıldı.');
        error.code = 'TESTSSL_OUTPUT_LIMIT';
        reject(error);
        return;
      }
      resolve({ code, signal, stdout, stderr });
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
        const version = output.match(/testssl\.sh\s+version\s+([^\s]+)/i)?.[1] || null;
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
        error: error.code === 'ENOENT' ? 'testssl.sh PATH içinde bulunamadı.' : error.message,
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

  if (typeof value.id === 'string' && ('severity' in value || 'finding' in value)) {
    output.push(value);
  }
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') collectFindingObjects(child, output);
  }
  return output;
}

export function normalizeTestsslOutput(document) {
  const items = collectFindingObjects(document);
  const seen = new Set();
  const findings = [];
  for (const item of items) {
    const id = stripAnsi(item.id).toLowerCase().replace(/[^a-z0-9._-]+/g, '_');
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
    '-h',
    '-U',
    '--overwrite',
    '--jsonfile',
    outputPath,
    `${target.hostname}:${target.port}`,
  ];
}

export async function runTestssl(target, scanId) {
  const engine = await getTestsslInfo();
  if (!engine.available) {
    const error = new Error(engine.error || 'testssl.sh kullanılamıyor.');
    error.code = 'TESTSSL_UNAVAILABLE';
    throw error;
  }

  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(scanId)) {
    const error = new Error('Tarama artifact kimliği geçersiz.');
    error.code = 'TESTSSL_INVALID_SCAN_ID';
    throw error;
  }

  await mkdir(ARTIFACT_DIRECTORY, { recursive: true });
  const outputPath = join(ARTIFACT_DIRECTORY, `${scanId}.json`);
  try {
    await unlink(outputPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const args = buildTestsslArguments(target, outputPath);

  const processResult = await spawnWithLimits(TESTSSL_PATH, args, {
    timeoutMs: TESTSSL_TIMEOUT_MS,
  });

  let document;
  try {
    document = JSON.parse(await readFile(outputPath, 'utf8'));
  } catch (error) {
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
