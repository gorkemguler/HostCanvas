import { API_HOST, API_PORT, APP_NAME, APP_VERSION } from './config.mjs';
import { closeDatabase } from './db.mjs';
import { createApiServer, getSetupCodeForConsole } from './api.mjs';
import { startMaintenance, stopMaintenance } from './maintenance.mjs';
import { startScanner, stopScanner } from './scanner.mjs';

const server = createApiServer();
startScanner();
startMaintenance();

server.listen(API_PORT, API_HOST, () => {
  console.log(`${APP_NAME} ${APP_VERSION} API: http://${API_HOST}:${API_PORT}`);
  const setupCode = getSetupCodeForConsole();
  if (setupCode) {
    console.log(`İlk kurulum kodu: ${setupCode}`);
  }
});

let shuttingDown = false;
async function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${signal}: ${APP_NAME} durduruluyor…`);
  // Stop accepting work immediately, but let existing requests/backups finish
  // before closing SQLite. A stuck client cannot hold shutdown indefinitely.
  const deadline = setTimeout(() => process.exit(1), 35_000);
  deadline.unref();
  const drain = async () => {
    if (server.listening) {
      const forceClose = setTimeout(() => server.closeAllConnections(), 5_000);
      forceClose.unref();
      try {
        await new Promise((resolve) => server.close(resolve));
      } finally {
        clearTimeout(forceClose);
      }
    }
    await server.waitForRequests();
  };
  const results = await Promise.allSettled([
    drain(),
    stopScanner(),
    stopMaintenance(),
  ]);
  for (const result of results) {
    if (result.status === 'rejected') {
      console.error('[shutdown]', result.reason);
      exitCode = 1;
    }
  }
  try {
    closeDatabase();
  } finally {
    clearTimeout(deadline);
    process.exit(exitCode);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
server.on('error', (error) => {
  console.error(`[api] ${error.code || 'SERVER_ERROR'}: ${error.message}`);
  void shutdown('API_ERROR', 1);
});
