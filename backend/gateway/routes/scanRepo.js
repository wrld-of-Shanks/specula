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
const AutoFixLog = require('../../shared/schema/autoFixLog');
const { validate, scanRepoSchema, autoFixSchema } = require('../../shared/utils/validation');
const { scanLimiter, autoFixLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');
const {
  getOctokit,
  extractOwnerRepo,
  getDefaultBranch,
  createBranch,
  resolveFix,
  newBranchName,
  buildPrBody,
  buildReportBody
} = require('./autofix-helpers');

const log = createChildLogger('scan-repo-route');
const execFileAsync = promisify(execFile);

const AUTO_FIX_ENABLED = process.env.AUTO_FIX_ENABLED !== 'false';
const MAX_AUTO_FIX_DAILY = Number(process.env.MAX_AUTO_FIX_DAILY || 50);
const CODE_SERVICE = process.env.CODE_SERVICE || 'http://localhost:5002';

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
  const parsed = new URL(repoUrl);
  if (parsed.hostname !== 'github.com') {
    throw new Error(`Clone rejected: only github.com is allowed (got ${parsed.hostname})`);
  }
  const token = getGithubToken();
  const args = ['clone', '--depth', '1', '--single-branch', repoUrl, destDir];
  if (token) {
    const authHeader = `Authorization: Basic ${Buffer.from('x-access-token:' + token).toString('base64')}`;
    args.unshift('-c', `http.extraHeader=${authHeader}`);
  }
  await execFileAsync('git', args, { timeout: 60000 });
}

function getGithubToken() {
  try {
    const { execSync } = require('child_process');
    const token = execSync('security find-generic-password -s "github.com" -w 2>/dev/null || echo ""', { encoding: 'utf-8' }).trim();
    if (token) return token;
  } catch {}
  const envToken = process.env.GITHUB_TOKEN;
  if (envToken) return envToken;
  return '';
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

  /**
   * @swagger
   * /api/code/scan-repo/{jobId}/fix:
   *   post:
   *     summary: Auto-fix a finding and open a pull request
   *     description: Generates a fix for a repo-scan finding (from the stored suggested fix or a
   *       fresh CodeT5 call), commits it to a new branch via the GitHub Contents API, and opens a
   *       pull request. If no fix can be generated, a report-only GitHub Issue is created instead.
   *       No client-supplied code is accepted — fixes are always generated or stored server-side.
   *     tags: [Repo Scan]
   *     security:
   *       - ApiKeyAuth: []
   *     parameters:
   *       - name: jobId
   *         in: path
   *         required: true
   *         schema: { type: string }
   *         description: Scan job id
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [finding_id]
   *             properties:
   *               finding_id:
   *                 type: string
   *                 description: MongoDB id of the scan_repo Event (finding) to fix
   *     responses:
   *       '200':
   *         description: Pull request or report-only issue created
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 success: { type: boolean }
   *                 pr_url: { type: string, nullable: true }
   *                 issue_url: { type: string, nullable: true }
   *                 branch: { type: string, nullable: true }
   *                 fallback: { type: boolean }
   *                 message: { type: string }
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '404':
   *         $ref: '#/components/schemas/Error'
   *       '503':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/scan-repo/:jobId/fix', autoFixLimiter, validate(autoFixSchema), async (req, res) => {
    const { finding_id } = req.body;
    const jobId = req.params.jobId;
    const userIp = req.ip || null;

    if (!AUTO_FIX_ENABLED) {
      return res.status(403).json({ error: 'Auto-fix is disabled (AUTO_FIX_ENABLED=false)' });
    }

    const octokit = await getOctokit();
    if (!octokit) {
      log.error({ requestId: req.id }, 'Auto-fix attempted without GITHUB_TOKEN');
      return res.status(503).json({
        error: 'Auto-fix is unavailable: GITHUB_TOKEN is not configured. Set GITHUB_TOKEN in your environment.'
      });
    }

    try {
      const [job, finding] = await Promise.all([
        ScanJob.findById(jobId),
        Event.findById(finding_id)
      ]);

      if (!job) {
        return res.status(404).json({ error: 'Scan job not found' });
      }
      if (!finding || (finding.job_id && String(finding.job_id) !== String(job._id))) {
        return res.status(404).json({ error: 'Finding not found for this scan job' });
      }
      if (!finding.file_path) {
        return res.status(400).json({ error: 'This finding does not reference a file (cannot auto-fix)' });
      }

      const { owner, repo } = extractOwnerRepo(job.repo_url);
      if (!owner || !repo) {
        log.error({ repo_url: job.repo_url, requestId: req.id }, 'Could not parse owner/repo from repo_url');
        return res.status(400).json({ error: `Could not parse owner/repo from repo_url: ${job.repo_url}` });
      }

      const dailyCount = await AutoFixLog.countDocuments({
        user_ip: userIp,
        created_at: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });
      if (dailyCount >= MAX_AUTO_FIX_DAILY) {
        return res.status(429).json({ error: `Auto-fix daily limit reached (max ${MAX_AUTO_FIX_DAILY} per day)` });
      }

      const audit = new AutoFixLog({
        job_id: job._id,
        finding_id: finding._id,
        repo_url: job.repo_url,
        file_path: finding.file_path,
        user_ip: userIp
      });

      // Fetch the current file from GitHub (validates the path exists and
      // provides the SHA needed for Contents API commits).
      let fileContent = null;
      let fileSha = null;
      try {
        const content = await octokit.rest.repos.getContent({ owner, repo, path: finding.file_path });
        const data = content.data;
        fileContent = Buffer.from(data.content, 'base64').toString('utf-8');
        fileSha = data.sha;
      } catch (err) {
        const status = err?.status;
        if (status === 404) {
          log.warn({ file_path: finding.file_path, requestId: req.id }, 'Finding file not found on GitHub');
          return await reportOnly(octokit, { owner, repo, finding, audit, userIp, res, reason: 'file-not-found' });
        }
        throw err;
      }

      // Resolve a fix: stored suggested_fix first, then a fresh CodeT5 call.
      const fix = await resolveFix(finding, fileContent);
      if (!fix) {
        return await reportOnly(octokit, { owner, repo, finding, audit, userIp, res, reason: 'no-fix' });
      }

      const baseBranch = await getDefaultBranch(octokit, owner, repo);
      const branchName = newBranchName();

      const headSha = await createBranch(octokit, owner, repo, baseBranch, branchName);
      await octokit.rest.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: finding.file_path,
        message: `[Auto-Fix] Patch ${finding.prediction} in ${finding.file_path}\n\nGenerated by Specula AI Security Scanner. Review before merging.`,
        content: Buffer.from(fix, 'utf-8').toString('base64'),
        sha: fileSha,
        branch: branchName
      });

      const prBody = buildPrBody(finding, finding.file_path, headSha);
      const pr = await octokit.rest.pulls.create({
        owner,
        repo,
        title: `[AI Auto-Fix] Patch ${finding.prediction} in ${finding.file_path}`,
        head: branchName,
        base: baseBranch,
        body: prBody
      });

      finding.status = 'human_review';
      await finding.save();

      audit.fix_generated = true;
      audit.status = 'success';
      audit.branch = branchName;
      audit.pr_url = pr.data.html_url;
      await audit.save();

      log.info({ prUrl: pr.data.html_url, findingId: finding._id, requestId: req.id }, 'Auto-fix PR created');
      return res.json({
        success: true,
        pr_url: pr.data.html_url,
        branch: branchName,
        fallback: false,
        message: 'Pull request created successfully'
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Auto-fix failed');
      return res.status(500).json({ error: 'Auto-fix failed: ' + (err?.message || 'Unknown error') });
    }
  });

  return router;
};

async function reportOnly(octokit, { owner, repo, finding, audit, res, reason }) {
  try {
    const title = `[Specula] Manual fix required: ${finding.prediction} in ${finding.file_path}`;
    const body = buildReportBody(finding, reason);
    const issue = await octokit.rest.issues.create({ owner, repo, title, body });

    audit.fallback_issue = true;
    audit.status = 'report_only';
    audit.issue_url = issue.data.html_url;
    await audit.save();

    log.info({ issueUrl: issue.data.html_url, findingId: finding._id }, 'Report-only issue created');
    return res.json({
      success: true,
      issue_url: issue.data.html_url,
      fallback: true,
      message: 'No auto-fix could be generated. A report-only issue with remediation steps was created.'
    });
  } catch (err) {
    log.error({ err }, 'Report-only issue creation failed');
    audit.status = 'failed';
    audit.error = err?.message || 'Unknown error';
    await audit.save();
    return res.status(500).json({ error: 'Failed to create report-only issue: ' + (err?.message || 'Unknown error') });
  }
}

function broadcastEvent(wss, event) {
  const message = JSON.stringify({ type: 'new_event', data: event });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}
