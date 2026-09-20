import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

test(
  'API shutdown drains requests and releases its data lock even with a stalled HTTP client',
  { timeout: 15_000 },
  async () => {
    const directory = mkdtempSync(join(tmpdir(), 'hostcanvas-shutdown-'));
    const reservation = createServer();
    await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const port = reservation.address().port;
    await new Promise((resolve) => reservation.close(resolve));
    const environment = {
      ...process.env,
      NODE_ENV: 'test',
      TLS_SENTINEL_DATA_DIR: directory,
      TLS_SENTINEL_API_HOST: '127.0.0.1',
      TLS_SENTINEL_API_PORT: String(port),
    };
    const child = spawn(process.execPath, ['server/index.mjs'], {
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
    });
    child.stderr.on('data', (chunk) => {
      output += chunk;
    });
    const exited = new Promise((resolve) =>
      child.once('exit', (code) => resolve(code)),
    );
    let socket;
    try {
      for (
        let attempt = 0;
        attempt < 60 && !output.includes('API:');
        attempt += 1
      )
        await delay(50);
      assert.match(output, /API:/);
      socket = connect(port, '127.0.0.1');
      socket.on('error', () => undefined);
      await new Promise((resolve) => socket.once('connect', resolve));
      socket.write(
        'POST /api/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{',
      );
      await delay(25);
      child.kill('SIGTERM');
      const code = await exited;
      assert.equal(code, 0, output);
      const reopened = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          "const db = await import('./server/db.mjs'); db.closeDatabase();",
        ],
        { env: environment, encoding: 'utf8' },
      );
      assert.equal(reopened.status, 0, reopened.stderr);
    } finally {
      socket?.destroy();
      if (child.exitCode === null && child.signalCode === null)
        child.kill('SIGKILL');
      await exited;
    }
  },
);
