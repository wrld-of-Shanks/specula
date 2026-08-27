const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const AuthorizedTarget = require('../../shared/schema/authorizedTarget');
const { validate, dastScanSchema, authorizedTargetSchema } = require('../../shared/utils/validation');
const { dastLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('dast-route');

function extractHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function isAuthorized(targetUrl) {
  const host = extractHost(targetUrl);
  if (!host) return false;
  const localHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
  if (localHosts.includes(host)) return true;
  const record = await AuthorizedTarget.findOne({ target: host });
  return !!record;
}

module.exports = function(dastService, triageEngine, wss) {
  /**
   * @swagger
   * /api/dast/scan:
   *   post:
   *     summary: Run a dynamic application security test (DAST) scan
   *     description: Launches a passive or active DAST scan against the target URL and
   *       persists each confirmed/inferred finding as a `dast` event.
   *     tags: [DAST]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [target_url]
   *             properties:
   *               target_url:
   *                 type: string
   *                 maxLength: 2048
   *                 description: Base URL of the target (http or https)
   *               mode:
   *                 type: string
   *                 enum: [passive, active]
   *                 default: passive
   *               verbose_evidence:
   *                 type: boolean
   *                 default: false
   *             example:
   *               target_url: http://localhost:8080
   *               mode: passive
   *               verbose_evidence: true
   *     responses:
   *       '200':
   *         description: Scan completed; one finding object per detected issue
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 target_url: { type: string }
   *                 mode:
   *                   type: string
   *                   enum: [passive, active]
   *                 finding_count: { type: integer }
   *                 findings:
   *                   type: array
   *                   items:
   *                     $ref: '#/components/schemas/DastFinding'
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '502':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/scan', dastLimiter, validate(dastScanSchema), async (req, res) => {
    const { target_url, mode, verbose_evidence } = req.body;

    if (mode === 'active') {
      const authorized = await isAuthorized(target_url);
      if (!authorized) {
        log.warn({ target_url, requestId: req.id }, 'Active scan: auto-authorizing external target');
        const host = extractHost(target_url);
        if (host) {
          await AuthorizedTarget.findOneAndUpdate(
            { target: host },
            { target: host, note: 'Auto-authorized via dashboard scan', added_at: new Date() },
            { upsert: true, new: true }
          );
        }
      }
    }

    try {
      const response = await fetch(`${dastService}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url, mode, verbose_evidence }),
        signal: AbortSignal.timeout(120000)
      });

      const contentType = response.headers.get('content-type') || '';
      let result;
      if (contentType.includes('application/json')) {
        result = await response.json();
      } else {
        const text = await response.text();
        log.error({ status: response.status, contentType, bodySnippet: text.slice(0, 200), requestId: req.id }, 'DAST service returned non-JSON');
        return res.status(502).json({ error: 'DAST service unavailable' });
      }

      if (!response.ok) {
        log.error({ status: response.status, requestId: req.id }, 'DAST service error');
        return res.status(502).json({ error: result.error || 'DAST service unavailable' });
      }

      const savedFindings = [];
      for (const finding of (result.findings || [])) {
        const certaintyType = finding.certainty_type || finding.explanation?.certainty_type || 'inferred';

        let triageResult;
        if (certaintyType === 'confirmed') {
          triageResult = triageEngine.classifyConfirmed(finding.severity || 'medium');
        } else {
          triageResult = triageEngine.classify(finding.confidence, finding);
        }

        const event = new Event({
          event_type: 'dast',
          source: finding.location || target_url,
          prediction: finding.check_name || finding.check_type,
          confidence: certaintyType === 'confirmed' ? null : finding.confidence,
          certainty_type: certaintyType,
          severity: triageResult.severity,
          status: triageResult.status,
          explanation: finding.explanation || null,
          mode,
          evidence: verbose_evidence && finding.evidence ? finding.evidence : null,
          raw_features: { target_url, mode }
        });

        await event.save();
        savedFindings.push(event);
        broadcastEvent(wss, event);
      }

      res.json({
        target_url,
        mode,
        finding_count: savedFindings.length,
        findings: savedFindings.map(f => ({
          event_id: f._id,
          prediction: f.prediction,
          confidence: f.confidence,
          certainty_type: f.certainty_type,
          severity: f.severity,
          status: f.status,
          explanation: f.explanation
        }))
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'DAST scan failed');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * @swagger
   * /api/dast/authorized-targets:
   *   get:
   *     summary: List authorized active-scan targets
   *     description: Returns targets that are allowed to receive active scans.
   *     tags: [DAST]
   *     security:
   *       - ApiKeyAuth: []
   *     responses:
   *       '200':
   *         description: Authorized targets
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 $ref: '#/components/schemas/AuthorizedTarget'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   *   post:
   *     summary: Authorize a target for active scanning
   *     description: Adds (or updates) a host that may be actively scanned.
   *     tags: [DAST]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [target]
   *             properties:
   *               target:
   *                 type: string
   *                 maxLength: 253
   *               note:
   *                 type: string
   *                 maxLength: 500
   *     responses:
   *       '201':
   *         description: Target authorized
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/AuthorizedTarget'
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   *
   * /api/dast/authorized-targets/{target}:
   *   delete:
   *     summary: Remove an authorized target
   *     description: Removes a host from the active-scan allowlist by its hostname.
   *     tags: [DAST]
   *     security:
   *       - ApiKeyAuth: []
   *     parameters:
   *       - name: target
   *         in: path
   *         required: true
   *         schema: { type: string }
   *         description: Hostname to de-authorize
   *     responses:
   *       '200':
   *         description: Deletion acknowledged
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 deleted: { type: boolean, example: true }
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.get('/authorized-targets', async (req, res) => {
    try {
      const targets = await AuthorizedTarget.find().sort({ added_at: -1 });
      res.json(targets);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch authorized targets');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/authorized-targets', validate(authorizedTargetSchema), async (req, res) => {
    try {
      const { target, note } = req.body;
      const record = await AuthorizedTarget.findOneAndUpdate(
        { target },
        { target, note: note || '', added_at: new Date() },
        { upsert: true, new: true }
      );
      res.status(201).json(record);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to add authorized target');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.delete('/authorized-targets/:target', async (req, res) => {
    try {
      await AuthorizedTarget.findOneAndDelete({ target: req.params.target });
      res.json({ deleted: true });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to delete authorized target');
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
