import { spawn } from 'node:child_process';
import {
  environmentForWeb,
  loadApplicationEnvironment,
} from './environment.mjs';

const mode = process.argv[2] || 'dev';
if (!['dev', 'start'].includes(mode)) {
  console.error('Kullanım: node scripts/run-processes.mjs <dev|start>');
  process.exit(1);
}
process.env.NODE_ENV ||= mode === 'start' ? 'production' : 'development';
loadApplicationEnvironment();

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const environment = {
  ...process.env,
  WRANGLER_SEND_METRICS: process.env.WRANGLER_SEND_METRICS || 'false',
};

const webEnvironment = environmentForWeb(environment);
const commands =
  mode === 'dev'
    ? [
        {
          name: 'web',
          command: npmCommand,
          args: ['run', 'dev:web'],
          environment: webEnvironment,
        },
        {
          name: 'api',
          command: process.execPath,
          args: ['--watch', 'server/index.mjs'],
          environment,
        },
      ]
    : [
        {
          name: 'web',
          command: npmCommand,
          args: ['run', 'start:web'],
          environment: webEnvironment,
        },
        {
          name: 'api',
          command: process.execPath,
          args: ['server/index.mjs'],
          environment,
        },
      ];

const children = commands.map((entry) => ({
  ...entry,
  process: spawn(entry.command, entry.args, {
    stdio: 'inherit',
    env: entry.environment,
    shell: false,
  }),
}));

let stopping = false;
function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (child.process.exitCode === null && child.process.signalCode === null) {
      child.process.kill('SIGINT');
    }
  }
  const timer = setTimeout(() => {
    for (const child of children) {
      if (
        child.process.exitCode === null &&
        child.process.signalCode === null
      ) {
        child.process.kill('SIGKILL');
      }
    }
    process.exit(exitCode);
  }, 40_000);
  timer.unref();
  void Promise.all(
    children.map((child) =>
      child.process.exitCode !== null || child.process.signalCode !== null
        ? Promise.resolve()
        : new Promise((resolve) => child.process.once('exit', resolve)),
    ),
  )
    .then(() => process.exit(exitCode))
    .catch(() => process.exit(1));
}

for (const child of children) {
  child.process.once('error', (error) => {
    console.error(`[${child.name}] başlatılamadı:`, error.message);
    stop(1);
  });
  child.process.once('exit', (code, signal) => {
    if (stopping) return;
    console.error(
      `[${child.name}] beklenmeden kapandı (${signal || `kod ${code ?? 1}`}).`,
    );
    stop(code || 1);
  });
}

process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
