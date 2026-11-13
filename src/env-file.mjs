import { lstat, readFile } from 'node:fs/promises';

/**
 * Read a local env file into the supplied environment.
 * Existing keys are left unchanged. A missing file is ignored.
 * A symlink is refused. Values are not logged.
 * @param {string} file
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Promise<boolean>}
 */
export async function loadEnvFile(file, env = process.env) {
  let info;
  try {
    info = await lstat(file);
  } catch (err) {
    if (err.code === 'ENOENT') return false;
    throw err;
  }
  if (info.isSymbolicLink()) throw new Error('refusing to read a symlinked env file');
  if (!info.isFile()) throw new Error('env file is not a regular file');
  let text = await readFile(file, 'utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const body = trimmed.startsWith('export ') ? trimmed.slice(7).trim() : trimmed;
    const eq = body.indexOf('=');
    if (eq < 1) continue;
    const key = body.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (env[key] !== undefined) continue;
    let value = body.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2)
      || (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }
  return true;
}
