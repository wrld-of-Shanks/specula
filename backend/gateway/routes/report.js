const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();

const Event = require('../../shared/schema/event');
const ScanJob = require('../../shared/schema/scanJob');
const ReportLog = require('../../shared/schema/reportLog');
const { validate, reportGenerateSchema } = require('../../shared/utils/validation');
const { reportLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');
const { buildPdfReport, reportFilename } = require('./report-helpers');

const log = createChildLogger('report-route');

const REPORT_STORAGE_PATH = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '..', 'reports');
const REPORT_TTL_DAYS = Number(process.env.REPORT_TTL_DAYS || 7);
const PUBLIC_BASE = process.env.PUBLIC_REPORT_BASE_URL || '';

function rangeFor(reqBody) {
  const now = Date.now();
  const ranges = { '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000, '30d': 30 * 24 * 60 * 60 * 1000 };
  let start = null;
  let end = null;
  if (reqBody.time_range && ranges[reqBody.time_range]) {
    start = new Date(now - ranges[reqBody.time_range]);
    end = new Date(now);
  } else if (reqBody.start) {
    start = new Date(reqBody.start);
    end = reqBody.end ? new Date(reqBody.end) : new Date(now);
  }
  return { start, end };
}

async function findEvents(reqBody) {
  if (reqBody.job_id) {
    const events = await Event.find({ job_id: reqBody.job_id }).sort({ severity: 1, confidence: -1 });
    return { events, scope: `job:${reqBody.job_id}` };
  }
  const { start, end } = rangeFor(reqBody);
  const query = { event_type: { $in: ['code', 'dast', 'scan_repo', 'network'] } };
  if (start) query.timestamp = { ...(query.timestamp || {}), $gte: start };
  if (end) query.timestamp = { ...(query.timestamp || {}), $lte: end };
  const events = await Event.find(query).sort({ timestamp: -1 });
  return { events, scope: 'range' };
}

async function cleanupExpiredReports() {
  try {
    const logs = await ReportLog.find({ expires_at: { $lte: new Date() } });
    for (const rec of logs) {
      const filePath = path.join(REPORT_STORAGE_PATH, rec.filename);
      try {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch (err) {
        log.warn({ err, filename: rec.filename }, 'Failed to remove expired report file');
      }
    }
    if (logs.length) {
      await ReportLog.deleteMany({ _id: { $in: logs.map(r => r._id) } });
      log.info({ count: logs.length }, 'Cleaned up expired reports');
    }
  } catch (err) {
    log.error({ err }, 'Report TTL cleanup failed');
  }
}

module.exports = function() {
  /**
   * @swagger
   * /api/reports/generate:
   *   post:
   *     summary: Generate a PDF security report
   *     description: Aggregates scan findings for a job or a time range into a PDF and returns
   *       a link to the stored report. Include vulnerability details, severity distribution,
   *       CWE/OWASP references, and suggested fixes.
   *     tags: [Reports]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: []
   *             properties:
   *               job_id:
   *                 type: string
   *                 description: Scan job id (omit for a time-range report)
   *               format:
   *                 type: string
   *                 enum: [pdf]
   *                 default: pdf
   *               include_fixes:
   *                 type: boolean
   *                 default: true
   *               time_range:
   *                 type: string
   *                 enum: [24h, 7d, 30d]
   *               start:
   *                 type: string
   *                 format: date-time
   *               end:
   *                 type: string
   *                 format: date-time
   *     responses:
   *       '200':
   *         description: Report generated
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 success: { type: boolean }
   *                 report_url: { type: string }
   *                 download_link: { type: string }
   *                 message: { type: string }
   *       '404':
   *         $ref: '#/components/schemas/Error'
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/generate', reportLimiter, validate(reportGenerateSchema), async (req, res) => {
    try {
      const { events, scope } = await findEvents(req.body);
      let job = null;
      if (req.body.job_id) {
        job = await ScanJob.findById(req.body.job_id);
        if (!job) return res.status(404).json({ error: 'Scan job not found' });
      }

      if (!fs.existsSync(REPORT_STORAGE_PATH)) {
        fs.mkdirSync(REPORT_STORAGE_PATH, { recursive: true });
      }

      const filename = reportFilename(req.body.job_id || null);
      const filePath = path.join(REPORT_STORAGE_PATH, filename);

      const { bytes, stats } = await buildPdfReport({
        findings: events,
        job,
        start: scope === 'range' ? (rangeFor(req.body).start || null) : null,
        end: scope === 'range' ? (rangeFor(req.body).end || null) : null,
        includeFixes: req.body.include_fixes
      });

      fs.writeFileSync(filePath, bytes);

      const expiresAt = new Date(Date.now() + REPORT_TTL_DAYS * 24 * 60 * 60 * 1000);
      const reportLog = new ReportLog({
        job_id: req.body.job_id || null,
        filename,
        expires_at: expiresAt,
        size_bytes: bytes.length
      });
      await reportLog.save();

      const reportPath = `/api/reports/reports/${filename}`;
      const downloadLink = PUBLIC_BASE ? `${PUBLIC_BASE}${reportPath}` : reportPath;

      // Opportunistic TTL cleanup (does not block the response).
      cleanupExpiredReports();

      log.info({ filename, count: stats.total, requestId: req.id }, 'Report generated');
      return res.json({
        success: true,
        report_url: reportPath,
        download_link: downloadLink,
        message: `Report generated successfully (${stats.total} findings)`
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Report generation failed');
      return res.status(500).json({ error: 'Report generation failed: ' + (err && err.message ? err.message : 'Unknown error') });
    }
  });

  /**
   * @swagger
   * /api/reports/reports/{filename}:
   *   get:
   *     summary: Download a generated PDF report
   *     description: Serves a previously generated PDF report. Requires the API key.
   *       Reports expire after the configured TTL.
   *     tags: [Reports]
   *     security:
   *       - ApiKeyAuth: []
   *     parameters:
   *       - name: filename
   *         in: path
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       '200':
   *         description: PDF bytes
   *         content:
   *           application/pdf:
   *             schema: { type: string, format: binary }
   *       '404':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.get('/reports/:filename', async (req, res) => {
    const filename = req.params.filename;
    // Defensive: only allow our generated filenames to avoid path traversal.
    if (!/^[a-zA-Z0-9_]+_\d{14}_[a-f0-9]{6}\.pdf$/.test(filename)) {
      return res.status(400).json({ error: 'Invalid report filename' });
    }
    const filePath = path.join(REPORT_STORAGE_PATH, filename);
    try {
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Report not found or expired' });
      }
      const reportLog = await ReportLog.findOneAndUpdate(
        { filename },
        { $inc: { download_count: 1 } },
        { new: true }
      );
      if (!reportLog) {
        return res.status(404).json({ error: 'Report not found' });
      }
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.sendFile(filePath);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Report download failed');
      res.status(500).json({ error: 'Failed to download report' });
    }
  });

  return router;
};
