import { createWriteStream } from 'node:fs';
import { mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import archiver from 'archiver';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const extensionDir = path.join(rootDir, 'extension');
const manifestPath = path.join(extensionDir, 'manifest.json');
const distDir = path.join(rootDir, 'dist');

async function ensureExtensionDir() {
  await stat(extensionDir);
}

function sanitizeName(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'extension';
}

async function createArchive(manifest) {
  const version = manifest.version;
  if (!version) {
    throw new Error('manifest.json is missing a version field.');
  }
  const baseName = sanitizeName(manifest.name || 'local-tab-suspender');
  const archiveName = `${baseName}-${version}.zip`;
  await mkdir(distDir, { recursive: true });
  const archivePath = path.join(distDir, archiveName);

  console.log(`Packaging ${manifest.name} v${version}`);

  await new Promise((resolve, reject) => {
    const output = createWriteStream(archivePath);
    output.on('close', resolve);
    output.on('error', reject);

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', reject);
    archive.pipe(output);
    archive.directory(extensionDir, false);
    archive.finalize();
  });

  console.log(`Created ${path.relative(rootDir, archivePath)}`);
}

async function main() {
  try {
    await ensureExtensionDir();
    const manifestRaw = await readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestRaw);
    await createArchive(manifest);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

main();
