const express = require('express');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');
const router = express.Router();
const Event = require('../../shared/schema/event');
const ScanJob = require('../../shared/schema/scanJob');
const { validate, scanRepoSchema } = require('../../shared/utils/validation');
const { scanLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('scan-repo-route');
const execFileAsync = promisify(execFile);

const SOURCE_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rs',
  '.c', '.cpp', '.h', '.cs', '.rb', '.php', '.swift', '.kt',
  '.scala', '.sh', '.bash', '.sql', '.html', '.css', '.vue', '.svelte'
]);

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', 'build', 'dist', '.git',
  '__pycache__', '.tox', 'venv', 'env', '.venv',
  'target', 'bin', 'obj', '.next', '.nuxt'
]);

const MAX_TOTAL_FILES = 500;
const MAX_FILE_SIZE = 100 * 1024;
const CHUNK_SIZE = 400;
const CHUNK_OVERLAP = 50;

function shouldIncludeFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const parts = filePath.split(path.sep);
  return SOURCE_EXTENSIONS.has(ext) && !parts.some(p => SKIP_DIRS.has(p));
}

function chunkCode(code, chunkSize = CHUNK_SIZE, overlap = CHUNK_OVERLAP) {
  const lines = code.split('\n');
  const chunks = [];
  let i = 0;

  while (i < lines.length) {
    const end = Math.min(i + chunkSize, lines.length);
    chunks.push({
      code: lines.slice(i, end).join('\n'),
      line_start: i + 1,
      line_end: end
    });
    if (end === lines.length) break;
    i += chunkSize - overlap;
  }

  return chunks;
}

async function cloneRepo(repoUrl, destDir) {
  const authUrl = repoUrl.replace('https://github.com/', `https://${getGithubToken()}@github.com/`);
  await execFileAsync('git', ['clone', '--depth', '1', '--single-branch', authUrl, destDir], {
    timeout: 60000
  });
}

function getGithubToken() {
  try {
    const { execSync } = require('child_process');
    const token = execSync('security find-generic-password -s "github.com" -w 2>/dev/null || echo ""', { encoding: 'utf-8' }).trim();
    if (token) return `oauth2:${token}`;
  } catch {}
  const envToken = process.env.GITHUB_TOKEN;
  if (envToken) return `oauth2:${envToken}`;
  return 'x-access-token:';
}

function collectSourceFiles(dir) {
  const files = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          files.push(...collectSourceFiles(fullPath));
        }
      } else if (entry.isFile()) {
        const stat = fs.statSync(fullPath);
        if (stat.size <= MAX_FILE_SIZE && shouldIncludeFile(fullPath)) {
          files.push(fullPath);
        }
      }
    }
  } catch {
    // skip unreadable dirs
  }
  return files;
}

module.exports = function(codeService, triageEngine, wss) {
  /**
   * @swagger
   * /api/code/scan-repo:
   *   post:
   *     summary: Clone and scan a GitHub repository
   *     description: Clones a public GitHub repository, scans each source file in chunks via the
   *       SAST code service, and persists findings as `scan_repo` events. Returns immediately with
   *       a job id; poll GET /api/code/scan-repo/{jobId} for progress.
   *     tags: [Repo Scan]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [repo_url]
   *             properties:
   *               repo_url:
   *                 type: string
   *                 description: Public GitHub repo URL (https)
   *                 example: https://github.com/octocat/Hello-World
   *     responses:
   *       '200':
   *         description: Scan job started
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 job_id: { type: string }
   *                 status:
   *                   type: string
   *                   enum: [cloning]
   *                 message: { type: string }
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   *   get:
   *     summary: List recent repo scan jobs
   *     description: Returns up to 50 most recent scan jobs, newest first.
   *     tags: [Repo Scan]
   *     security:
   *       - ApiKeyAuth: []
   *     responses:
   *       '200':
   *         description: Recent scan jobs
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 $ref: '#/components/schemas/ScanJob'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   *
   * /api/code/scan-repo/{jobId}:
   *   get:
   *     summary: Get a scan job's status and findings
   *     description: Returns the job plus its findings grouped by source file, sorted by confidence.
   *     tags: [Repo Scan]
   *     security:
   *       - ApiKeyAuth: []
   *     parameters:
   *       - name: jobId
   *         in: path
   *         required: true
   *         schema: { type: string }
   *         description: Scan job id
   *     responses:
   *       '200':
   *         description: Job and findings
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 job:
   *                   $ref: '#/components/schemas/ScanJob'
   *                 findings:
   *                   type: object
   *                   additionalProperties:
   *                     type: array
   *                     items:
   *                       $ref: '#/components/schemas/Event'
   *       '404':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/scan-repo', scanLimiter, validate(scanRepoSchema), async (req, res) => {
    const { repo_url } = req.body;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-sast-'));

    const job = new ScanJob({ repo_url, status: 'cloning' });
    await job.save();

    res.json({ job_id: job._id, status: 'cloning', message: 'Repository scan started' });

    (async () => {
      try {
        log.info({ repo_url, jobId: job._id, requestId: req.id }, 'Cloning repository');
        await cloneRepo(repo_url, tmpDir);

        job.status = 'scanning';
        await job.save();

        const sourceFiles = collectSourceFiles(tmpDir);
        job.file_count = sourceFiles.length;
        await job.save();

        log.info({ fileCount: sourceFiles.length, jobId: job._id }, 'Files collected for scanning');

        let findingCount = 0;

        for (const filePath of sourceFiles) {
          try {
            const code = fs.readFileSync(filePath, 'utf-8');
            if (!code.trim()) continue;

            const chunks = chunkCode(code);
            const relativePath = path.relative(tmpDir, filePath);

            for (const chunk of chunks) {
              try {
                const response = await fetch(`${codeService}/scan`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ code: chunk.code }),
                  signal: AbortSignal.timeout(60000)
                });

                if (!response.ok) continue;
                const result = await response.json();

                if (result.prediction === 'not_vulnerable') continue;

                const triageResult = triageEngine.classify(result.confidence, result);

                const explanation = result.explanation || {};
                const fileLocation = explanation.location
                  ? `${relativePath} — ${explanation.location}`
                  : `${relativePath}:${chunk.line_start}-${chunk.line_end}`;

                const event = new Event({
                  event_type: 'scan_repo',
                  source: repo_url,
                  prediction: result.prediction,
                  confidence: result.confidence,
                  certainty_type: 'inferred',
                  severity: triageResult.severity,
                  status: triageResult.status,
                  explanation: {
                    ...explanation,
                    location: fileLocation
                  },
                  suggested_fix: result.suggested_fix || null,
                  job_id: job._id,
                  file_path: relativePath,
                  line_range: { start: chunk.line_start, end: chunk.line_end }
                });

                await event.save();
                findingCount++;

                broadcastEvent(wss, event);
              } catch (err) {
                log.error({ err, filePath: relativePath }, 'Chunk scan failed');
              }
            }
          } catch (err) {
            log.error({ err, filePath }, 'Failed to read file');
          }
        }

        job.status = 'completed';
        job.completed_at = new Date();
        job.finding_count = findingCount;
        await job.save();

        log.info({ jobId: job._id, findingCount }, 'Scan completed');
      } catch (err) {
        log.error({ err, jobId: job._id }, 'Scan job failed');
        job.status = 'failed';
        job.completed_at = new Date();
        job.error = err.message;
        await job.save();
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    })();
  });

  router.get('/scan-repo/:jobId', async (req, res) => {
    try {
      const job = await ScanJob.findById(req.params.jobId);
      if (!job) return res.status(404).json({ error: 'Scan job not found' });

      const events = await Event.find({ job_id: job._id }).sort({ confidence: -1, file_path: 1 });

      const byFile = {};
      for (const evt of events) {
        const fp = evt.file_path || 'unknown';
        if (!byFile[fp]) byFile[fp] = [];
        byFile[fp].push(evt);
      }

      res.json({ job, findings: byFile });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch scan job');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.get('/scan-repo', async (req, res) => {
    try {
      const jobs = await ScanJob.find().sort({ started_at: -1 }).limit(50);
      res.json(jobs);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch scan jobs');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};

function broadcastEvent(wss, event) {
  const message = JSON.stringify({ type: 'new_event', data: event });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}
