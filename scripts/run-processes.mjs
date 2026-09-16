import { spawn } from 'node:child_process';

const mode = process.argv[2] || 'dev';
if (!['dev', 'start'].includes(mode)) {
  console.error('Kullanım: node scripts/run-processes.mjs <dev|start>');
  process.exit(1);
}

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const environment = {
  ...process.env,
  WRANGLER_SEND_METRICS: process.env.WRANGLER_SEND_METRICS || 'false',
};
const commands =
  mode === 'dev'
    ? [
        { name: 'web', command: npmCommand, args: ['run', 'dev:web'] },
        { name: 'api', command: process.execPath, args: ['--watch', 'server/index.mjs'] },
      ]
    : [
        { name: 'web', command: npmCommand, args: ['run', 'start:web'] },
        { name: 'api', command: process.execPath, args: ['server/index.mjs'] },
      ];

const children = commands.map((entry) => ({
  ...entry,
  process: spawn(entry.command, entry.args, {
    stdio: 'inherit',
    env: environment,
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
      if (child.process.exitCode === null && child.process.signalCode === null) {
        child.process.kill('SIGKILL');
      }
    }
    process.exit(exitCode);
  }, 5_000);
  timer.unref();
  void Promise.all(
    children.map(
      (child) =>
        new Promise((resolve) => child.process.once('exit', resolve)),
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
