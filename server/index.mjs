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
  if (server.listening) {
    await new Promise((resolve) => server.close(resolve));
  }
  await stopScanner();
  stopMaintenance();
  closeDatabase();
  process.exit(exitCode);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
server.on('error', (error) => {
  console.error(`[api] ${error.code || 'SERVER_ERROR'}: ${error.message}`);
  void shutdown('API_ERROR', 1);
});
