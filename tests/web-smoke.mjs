import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const reservation = createServer();
await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve));
const port = reservation.address().port;
await new Promise((resolve) => reservation.close(resolve));
const child = spawn(process.execPath, ['scripts/start-web.mjs'], {
  env: {
    ...process.env,
    NODE_ENV: 'production',
    TLS_SENTINEL_WEB_HOST: '127.0.0.1',
    TLS_SENTINEL_WEB_PORT: String(port),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
child.stdout.on('data', (chunk) => {
  output += chunk;
});
child.stderr.on('data', (chunk) => {
  output += chunk;
});
const exited = new Promise((resolve) => child.once('exit', resolve));
const base = `http://127.0.0.1:${port}`;
try {
  let response;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(output);
    try {
      response = await fetch(base, { signal: AbortSignal.timeout(2_000) });
    } catch {
      /* server is starting */
    }
    if (response) break;
    await delay(100);
  }
  assert.equal(response?.status, 200, output);
  assert.match(await response.text(), /HostCanvas/);
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.match(
    response.headers.get('content-security-policy'),
    /frame-ancestors 'none'/,
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await fetch(`${base}/favicon.svg`)).status, 200);
  assert.equal(
    (await fetch(`${base}/cdn-cgi/local/explorer/api/local/workers`)).status,
    404,
  );
  console.log(
    'Production web smoke passed: page, favicon, security headers, no development explorer.',
  );
} finally {
  child.kill('SIGTERM');
  const killTimer = setTimeout(() => child.kill('SIGKILL'), 5_000);
  await exited;
  clearTimeout(killTimer);
}
