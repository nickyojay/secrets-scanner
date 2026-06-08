import * as fs from 'fs';
import * as path from 'path';
import ignore from 'ignore';

export interface FileInfo {
  absolutePath: string;
  relativePath: string;
  extension: string;
  sizeBytes: number;
}

export type SkipReason = 'binary' | 'too_large' | 'ignored' | 'unreadable';

export interface TraversalResult {
  files: FileInfo[];
  skipped: Array<{ path: string; reason: SkipReason }>;
}

// Extensions we know are binary — skip immediately without reading
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
  '.mp4', '.mp3', '.wav', '.mov', '.avi',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.woff', '.woff2', '.ttf', '.eot',
  '.pyc', '.class', '.o',
  '.db', '.sqlite', '.sqlite3',
]);

// These files bypass .gitignore — they're too important to skip
const HIGH_VALUE_EXTENSIONS = new Set([
  '.env', '.pem', '.key', '.p12', '.pfx', '.p8',
]);

// Always ignore these regardless of what's in .gitignore
const DEFAULT_IGNORE_PATTERNS = [
  'node_modules/**',
  '.git/**',
  'dist/**',
  'build/**',
  '.next/**',
  'coverage/**',
  '*.min.js',
  '*.min.css',
  '*.map',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
];

const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1MB

// Detect binary files by looking for null bytes in the first 512 bytes.
// This catches files without extensions that are still binary.
function isBinaryFile(filePath: string): boolean {
  try {
    const buffer = Buffer.alloc(512);
    const fd = fs.openSync(filePath, 'r');
    const bytesRead = fs.readSync(fd, buffer, 0, 512, 0);
    fs.closeSync(fd);
    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0) return true;
    }
    return false;
  } catch {
    return true; // If we can't read it, treat as binary to be safe
  }
}

// Parse .gitignore from the target directory if it exists
function loadGitignore(targetPath: string): ReturnType<typeof ignore> {
  const ig = ignore();
  const gitignorePath = path.join(targetPath, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    try {
      ig.add(fs.readFileSync(gitignorePath, 'utf-8'));
    } catch {
      // Unreadable .gitignore — proceed without it
    }
  }
  return ig;
}

export function traverseDirectory(
  targetPath: string,
  maxFileSizeBytes: number = DEFAULT_MAX_FILE_SIZE,
  extraIgnorePatterns: string[] = [],
): TraversalResult {
  const result: TraversalResult = { files: [], skipped: [] };
  const absoluteTarget = path.resolve(targetPath);

  if (!fs.existsSync(absoluteTarget)) {
    throw new Error(`Target path does not exist: ${absoluteTarget}`);
  }

  // Handle single-file scans
  const stats = fs.statSync(absoluteTarget);
  if (stats.isFile()) {
    const fileResult = processFile(absoluteTarget, absoluteTarget, maxFileSizeBytes);
    if (fileResult.type === 'file') result.files.push(fileResult.file);
    else result.skipped.push({ path: absoluteTarget, reason: fileResult.reason });
    return result;
  }

  // Set up ignore rules
  const ig = loadGitignore(absoluteTarget);
  ig.add(DEFAULT_IGNORE_PATTERNS);
  ig.add(extraIgnorePatterns);

  function walk(currentPath: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      result.skipped.push({ path: currentPath, reason: 'unreadable' });
      return;
    }

    for (const entry of entries) {
      const absoluteEntryPath = path.join(currentPath, entry.name);
      const relativeEntryPath = path.relative(absoluteTarget, absoluteEntryPath);

      if (entry.isDirectory()) {
        if (ig.ignores(relativeEntryPath + '/')) {
          result.skipped.push({ path: absoluteEntryPath, reason: 'ignored' });
          continue;
        }
        walk(absoluteEntryPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name).toLowerCase();
      const isHighValue = HIGH_VALUE_EXTENSIONS.has(ext);

      // High-value files bypass ignore rules
      if (!isHighValue && ig.ignores(relativeEntryPath)) {
        result.skipped.push({ path: absoluteEntryPath, reason: 'ignored' });
        continue;
      }

      const fileResult = processFile(absoluteEntryPath, absoluteTarget, maxFileSizeBytes);
      if (fileResult.type === 'file') result.files.push(fileResult.file);
      else result.skipped.push({ path: absoluteEntryPath, reason: fileResult.reason });
    }
  }

  walk(absoluteTarget);
  return result;
}

type ProcessFileResult =
  | { type: 'file'; file: FileInfo }
  | { type: 'skipped'; reason: SkipReason };

function processFile(
  absolutePath: string,
  rootPath: string,
  maxFileSizeBytes: number,
): ProcessFileResult {
  const ext = path.extname(absolutePath).toLowerCase();

  if (BINARY_EXTENSIONS.has(ext)) return { type: 'skipped', reason: 'binary' };

  let stats: fs.Stats;
  try {
    stats = fs.statSync(absolutePath);
  } catch {
    return { type: 'skipped', reason: 'unreadable' };
  }

  if (stats.size > maxFileSizeBytes) return { type: 'skipped', reason: 'too_large' };
  if (isBinaryFile(absolutePath)) return { type: 'skipped', reason: 'binary' };

  return {
    type: 'file',
    file: {
      absolutePath,
      relativePath: path.relative(rootPath, absolutePath),
      extension: ext,
      sizeBytes: stats.size,
    },
  };
}