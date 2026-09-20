import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

const projectDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
const publicServerVariables = new Set([
  'TLS_SENTINEL_WEB_HOST',
  'TLS_SENTINEL_WEB_PORT',
]);

export function readApplicationEnvironment(
  directory = projectDirectory,
  mode = process.env.NODE_ENV || 'development',
) {
  const environment = {};
  const files = [
    `.env.${mode}.local`,
    ...(mode === 'test' ? [] : ['.env.local']),
    `.env.${mode}`,
    '.env',
  ];
  for (const name of files) {
    let values;
    try {
      values = parseEnv(readFileSync(join(directory, name), 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }
    for (const [key, value] of Object.entries(values)) {
      if (key.startsWith('TLS_SENTINEL_') && !(key in environment))
        environment[key] = value;
    }
  }
  return environment;
}

export function loadApplicationEnvironment(
  directory = projectDirectory,
  environment = process.env,
) {
  for (const [key, value] of Object.entries(
    readApplicationEnvironment(
      directory,
      environment.NODE_ENV || 'development',
    ),
  )) {
    if (environment[key] === undefined) environment[key] = value;
  }
  return environment;
}

export function environmentForWeb(
  source = process.env,
  directory = projectDirectory,
) {
  const filtered = { ...source };
  const configured = readApplicationEnvironment(
    directory,
    source.NODE_ENV || 'development',
  );
  for (const name of new Set([
    ...Object.keys(configured),
    ...Object.keys(filtered),
  ])) {
    if (name.startsWith('TLS_SENTINEL_') && !publicServerVariables.has(name)) {
      // Vinext loads dotenv files itself. An empty defined value prevents it
      // from reintroducing API secrets after the launcher has scrubbed them.
      filtered[name] = '';
    }
  }
  return filtered;
}
