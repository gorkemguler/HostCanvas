import { spawn } from 'node:child_process';

const command = process.platform === 'win32' ? 'vinext.cmd' : 'vinext';
const host = process.env.TLS_SENTINEL_WEB_HOST || '0.0.0.0';
const port = process.env.TLS_SENTINEL_WEB_PORT || '3000';
const child = spawn(command, ['dev', '--hostname', host, '--port', port], {
  stdio: 'inherit',
  env: {
    ...process.env,
    WRANGLER_SEND_METRICS: process.env.WRANGLER_SEND_METRICS || 'false',
  },
  shell: false,
});

child.once('error', (error) => {
  console.error('Web geliştirme sunucusu başlatılamadı:', error.message);
  process.exit(1);
});
child.once('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code || 0);
});
process.on('SIGINT', () => child.kill('SIGINT'));
process.on('SIGTERM', () => child.kill('SIGTERM'));
