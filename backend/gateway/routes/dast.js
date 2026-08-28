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
   *     description: |
   *       Launches a passive or active DAST scan against the target URL and
   *       persists each confirmed/inferred finding as a `dast` event.
   *
   *       **Scan Modes:**
   *       - `passive`: Analyzes HTTP responses, headers, and cookies without sending attack payloads. Safe for production.
   *       - `active`: Sends benign attack payloads to confirm vulnerabilities. Only for authorized targets.
   *
   *       **Passive Checks:**
   *       - Missing security headers (CSP, X-Frame-Options, HSTS, etc.)
   *       - Information disclosure in headers/server banners
   *       - Insecure cookie attributes
   *       - TLS/SSL configuration issues
   *
   *       **Active Checks (requires authorization):**
   *       - SQL injection via URL parameters
   *       - XSS via reflected parameters
   *       - Command injection patterns
   *       - Path traversal attempts
   *
   *       **Authorization:**
   *       - Localhost/127.0.0.1 targets are always authorized
   *       - External targets are auto-authorized on first scan
   *       - Use GET/POST /api/dast/authorized-targets to manage the allowlist
   *
   *       **Rate Limit:** 5 requests/minute
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
   *                 format: uri
   *                 maxLength: 2048
   *                 description: |
   *                   Base URL of the target application. Must be a valid HTTP/HTTPS URL.
   *                   Localhost targets are always allowed. External targets may require authorization.
   *                 example: http://localhost:8080
   *               mode:
   *                 type: string
   *                 enum: [passive, active]
   *                 default: passive
   *                 description: |
   *                   Scan mode:
   *                   - `passive`: Analyze responses without sending attack payloads (safe for production)
   *                   - `active`: Send benign attack payloads to confirm vulnerabilities (requires authorization)
   *               verbose_evidence:
   *                 type: boolean
   *                 default: false
   *                 description: |
   *                   Include raw evidence data in findings. When true, responses include
   *                   full HTTP responses, headers, and request details for each finding.
   *             example:
   *               target_url: http://localhost:8080
   *               mode: passive
   *               verbose_evidence: true
   *     responses:
   *       '200':
   *         description: Scan completed — one finding object per detected issue
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/DastScanResult'
   *             examples:
   *               findings_detected:
   *                 summary: Scan with findings
   *                 value:
   *                   target_url: "http://localhost:8080"
   *                   mode: "passive"
   *                   finding_count: 2
   *                   findings:
   *                     - event_id: "507f1f77bcf86cd799439011"
   *                       prediction: "missing_csp_header"
   *                       confidence: null
   *                       certainty_type: "confirmed"
   *                       severity: "medium"
   *                       status: "auto_flagged"
   *                       explanation:
   *                         what: "Content-Security-Policy header is missing"
   *                         why: "Allows XSS and data injection attacks"
   *                         where: "HTTP response headers"
   *                         reference:
   *                           cwe: "CWE-693"
   *                           owasp: "A05:2021-Security Misconfiguration"
   *                     - event_id: "507f1f77bcf86cd799439012"
   *                       prediction: "missing_hsts_header"
   *                       confidence: null
   *                       certainty_type: "confirmed"
   *                       severity: "low"
   *                       status: "human_review"
   *                       explanation:
   *                         what: "Strict-Transport-Security header is missing"
   *                         why: "Allows protocol downgrade attacks"
   *                         where: "HTTP response headers"
   *                         reference:
   *                           cwe: "CWE-319"
   *                           owasp: "A02:2021-Cryptographic Failures"
   *               no_findings:
   *                 summary: Clean scan
   *                 value:
   *                   target_url: "http://localhost:3000"
   *                   mode: "passive"
   *                   finding_count: 0
   *                   findings: []
   *       '400':
   *         description: Validation error — missing or invalid request body
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/ValidationError'
   *             examples:
   *               missing_url:
   *                 summary: Missing target_url
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"target_url\" is required"]
   *               invalid_url:
   *                 summary: Invalid URL format
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"target_url\" must be a valid uri"]
   *               invalid_mode:
   *                 summary: Invalid scan mode
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"mode\" must be one of [passive, active]"]
   *       '429':
   *         description: Rate limit exceeded (5 requests/minute for DAST scans)
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/RateLimitError'
   *             example:
   *               error: "Too many requests, please try again later"
   *       '502':
   *         description: DAST service is unreachable or returned an error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *             examples:
   *               service_unavailable:
   *                 summary: DAST service down
   *                 value:
   *                   error: "DAST service unavailable"
   *               service_error:
   *                 summary: DAST service returned an error
   *                 value:
   *                   error: "Target unreachable: connection refused"
   *       '500':
   *         description: Internal server error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *             example:
   *               error: "Internal server error"
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
