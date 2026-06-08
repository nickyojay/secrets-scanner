// src/web/server.ts

import express from 'express';
import multer from 'multer';
import * as path from 'path';
import * as fs from 'fs';
import * as unzipper from 'unzipper';
import { scan } from '../scanner/engine';
import { ScanConfig } from '../types';

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────────────

app.use(express.json());

// Serve the frontend files from src/web/public
app.use(express.static(path.join(__dirname, 'public')));

// ── File upload setup ─────────────────────────────────────────────────────

// Multer stores uploaded files in /tmp/scanner-uploads/
// We use disk storage (not memory) because zip files can be large
const uploadDir = path.join('/tmp', 'scanner-uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB max upload size
  },
  fileFilter: (_req, file, cb) => {
    // Only accept zip files
    if (file.mimetype === 'application/zip' ||
        file.originalname.endsWith('.zip')) {
      cb(null, true);
    } else {
      cb(new Error('Only .zip files are accepted'));
    }
  },
});

// ── Helper: extract zip to a temp directory ───────────────────────────────

async function extractZip(zipPath: string, extractTo: string): Promise<void> {
  return new Promise((resolve, reject) => {
    fs.createReadStream(zipPath)
      .pipe(unzipper.Extract({ path: extractTo }))
      .on('close', resolve)
      .on('error', reject);
  });
}

// Helper: recursively delete a directory (cleanup after scan)
function rimraf(dirPath: string): void {
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
  }
}

// ── Routes ────────────────────────────────────────────────────────────────

// GET / — serve the dashboard
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// POST /api/scan — main scan endpoint
// Accepts: multipart/form-data with a 'file' field (zip)
// Optional fields: severity, category, includeAll (all strings)
app.post('/api/scan', upload.single('file'), async (req, res) => {
  const uploadedFile = req.file;
  let extractDir: string | null = null;

  try {
    if (!uploadedFile) {
      res.status(400).json({ error: 'No file uploaded. Please upload a .zip file.' });
      return;
    }

    // Create a unique extraction directory for this scan
    extractDir = path.join('/tmp', `scanner-extract-${Date.now()}`);
    fs.mkdirSync(extractDir, { recursive: true });

    // Extract the zip
    await extractZip(uploadedFile.path, extractDir);

    // Parse optional filter parameters from the form
    const severities = req.body.severity
      ? req.body.severity.split(',').map((s: string) => s.trim())
      : undefined;

    const categories = req.body.category
      ? req.body.category.split(',').map((s: string) => s.trim())
      : undefined;

    const includeAll = req.body.includeAll === 'true';

    // Build scan config
    const config: ScanConfig = {
      targetPath: extractDir,
      severities,
      categories,
      includeHighFalsePositives: includeAll,
      maxFileSizeBytes: 1024 * 1024, // 1MB
    };

    // Run the scan
    const result = await scan(config);

    // Strip matchedText from findings before sending to browser
    // (same reason as jsonOutput.ts — we never send raw secrets over the wire)
    const safeFindings = result.findings.map(({ matchedText: _omit, ...rest }) => rest);

    res.json({
      meta: {
        scannedAt: result.scannedAt,
        targetPath: uploadedFile.originalname, // show original filename, not temp path
        durationMs: result.durationMs,
        filesScanned: result.filesScanned,
        filesSkipped: result.filesSkipped,
      },
      summary: result.summary,
      findings: safeFindings,
    });

  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    console.error('Scan error:', message);
    res.status(500).json({ error: `Scan failed: ${message}` });

  } finally {
    // Always clean up temp files, even if the scan failed
    if (uploadedFile?.path) rimraf(uploadedFile.path);
    if (extractDir) rimraf(extractDir);
  }
});

// GET /api/health — simple health check for Railway deployment later
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Start server ──────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nSecrets Scanner dashboard running at http://localhost:${PORT}\n`);
});

export default app;