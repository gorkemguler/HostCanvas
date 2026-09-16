import { spawn } from 'node:child_process';

const command = process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler';
const host = process.env.TLS_SENTINEL_WEB_HOST || '0.0.0.0';
const port = process.env.TLS_SENTINEL_WEB_PORT || '3000';
const environment = {
  ...process.env,
  WRANGLER_SEND_METRICS: process.env.WRANGLER_SEND_METRICS || 'false',
};
const child = spawn(
  command,
  ['dev', '--config', 'dist/server/wrangler.json', '--ip', host, '--port', port],
  { stdio: 'inherit', env: environment, shell: false },
);

child.once('error', (error) => {
  console.error('Web sunucusu başlatılamadı:', error.message);
  process.exit(1);
});
child.once('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code || 0);
});
process.on('SIGINT', () => child.kill('SIGINT'));
process.on('SIGTERM', () => child.kill('SIGTERM'));
