import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = process.cwd();
const ROOTS = ['src', 'scripts'];
const ALLOWED_IMPORT = /^(?:node:|\.{1,2}\/)/;
const PATTERNS = [
  { name: 'tls-verification-disabled', re: /rejectUnauthorized\s*:\s*false/ },
  { name: 'eval', re: /\beval\s*\(/ },
  { name: 'function-constructor', re: /new\s+Function\s*\(/ },
  { name: 'wildcard-redirect', re: /redirect_uri\s*\*\s*|redirectUris\s*\.\s*includes\(\s*['"]\*['"]\s*\)/ },
  { name: 'hardcoded-upstream-key', re: /UPSTREAM_API_KEY\s*=\s*['"][^'"]{8,}['"]/ },
];

/**
 * @param {string} root
 * @returns {Promise<string[]>}
 */
export async function sourceFiles(root = ROOT) {
  const files = [];
  for (const dir of ROOTS) {
    await walk(path.join(root, dir), files);
  }
  return files.filter((file) => file.endsWith('.mjs'));
}

/**
 * @param {string} dir
 * @param {string[]} files
 */
async function walk(dir, files) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, files);
    else files.push(full);
  }
}

/**
 * @param {string} root
 * @returns {Promise<{ file: string, line: number, name: string, text: string }[]>}
 */
export async function scanSource(root = ROOT) {
  const findings = [];
  for (const file of await sourceFiles(root)) {
    const text = await readFile(file, 'utf8');
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const pattern of PATTERNS) {
        if (pattern.re.test(line)) {
          findings.push({ file, line: index + 1, name: pattern.name, text: line.trim() });
        }
      }
    });
    const imports = [...text.matchAll(/from\s+['"]([^'"]+)['"]/g), ...text.matchAll(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/g)];
    for (const match of imports) {
      if (!ALLOWED_IMPORT.test(match[1])) {
        findings.push({ file, line: 1, name: 'non-native-import', text: match[1] });
      }
    }
  }
  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const deps = Object.keys(packageJson.dependencies || {});
  const dev = Object.keys(packageJson.devDependencies || {});
  if (deps.length || dev.length) {
    findings.push({ file: path.join(root, 'package.json'), line: 1, name: 'npm-dependency', text: [...deps, ...dev].join(',') });
  }
  const modules = path.join(root, 'node_modules');
  const modulesStat = await stat(modules).catch(() => null);
  if (modulesStat) findings.push({ file: modules, line: 1, name: 'node_modules', text: 'present' });
  return findings;
}

async function main() {
  const findings = await scanSource(ROOT);
  if (findings.length) {
    for (const finding of findings) {
      process.stderr.write(`${finding.file}:${finding.line} ${finding.name} ${finding.text}\n`);
    }
    process.exit(1);
  }
  process.stdout.write('security-check: pass\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
