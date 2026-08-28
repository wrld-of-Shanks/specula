const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { validate, codeScanSchema } = require('../../shared/utils/validation');
const { scanLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('code-route');

module.exports = function(codeService, triageEngine, wss) {
  /**
   * @swagger
   * /api/code/scan:
   *   post:
   *     summary: Scan source code for vulnerabilities (SAST)
   *     description: |
   *       Submits a snippet of source code to the rule-based classifier, applies
   *       the triage engine, and persists the result as a `code` event.
   *
   *       **Detection Rules:**
   *       - SQL Injection (CWE-89): String concatenation/f-string/.format() in SQL queries
   *       - XSS (CWE-79): innerHTML, document.write, res.send() with concatenation
   *       - Command Injection (CWE-78): os.system, subprocess with concatenation/f-strings
   *       - Hardcoded Credentials (CWE-798): Direct password/api_key assignments
   *       - Path Traversal (CWE-22): open(), readFile with user-controlled paths
   *       - Insecure Deserialization (CWE-502): pickle.loads, yaml.load without SafeLoader
   *
   *       **Triage Rules:**
   *       - Confidence ≥ 0.95 → severity=critical, status=auto_flagged
   *       - Confidence ≥ 0.80 → severity=high, status=auto_flagged
   *       - Confidence ≥ 0.60 → severity=medium, status=human_review
   *       - Confidence < 0.60 → severity=low, status=ignored
   *
   *       **Rate Limit:** 10 requests/minute
   *     tags: [Code (SAST)]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [code]
   *             properties:
   *               code:
   *                 type: string
   *                 minLength: 1
   *                 maxLength: 50000
   *                 description: |
   *                   Source code snippet to analyze. Supports Python, JavaScript, TypeScript,
   *                   Java, Go, C, C++, Ruby, PHP, and other common languages.
   *                 example: |
   *                   username = input('user')
   *                   query = 'SELECT * FROM users WHERE name = "' + username + '"'
   *               source:
   *                 type: string
   *                 maxLength: 200
   *                 description: Optional label for the scan source (e.g., "editor", "ci-pipeline")
   *                 example: manual_scan
   *             example:
   *               code: |
   *                 username = input('user')
   *                 query = 'SELECT * FROM users WHERE name = "' + username + '"'
   *               source: manual_scan
   *     responses:
   *       '200':
   *         description: Scan completed successfully
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CodeScanResult'
   *             examples:
   *               sql_injection:
   *                 summary: SQL Injection detected
   *                 value:
   *                   event_id: "507f1f77bcf86cd799439011"
   *                   prediction: "sql_injection"
   *                   confidence: 0.92
   *                   certainty_type: "inferred"
   *                   severity: "high"
   *                   status: "auto_flagged"
   *                   explanation:
   *                     what: "SQL query uses string concatenation with user input"
   *                     why: "Allows SQL injection attacks that can read/modify/delete data"
   *                     where: "Line 2 in submitted code"
   *                     reference:
   *                       cwe: "CWE-89"
   *                       owasp: "A03:2021-Injection"
   *                     remediation:
   *                       guidance: "Use parameterized queries instead of string concatenation"
   *                       suggested_code_fix: "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
   *                   suggested_fix: "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
   *                   top_predictions:
   *                     - class: "sql_injection"
   *                       cwe: "CWE-89"
   *                       confidence: 0.92
   *                     - class: "not_vulnerable"
   *                       cwe: "N/A"
   *                       confidence: 0.05
   *                     - class: "xss"
   *                       cwe: "CWE-79"
   *                       confidence: 0.03
   *               not_vulnerable:
   *                 summary: No vulnerability detected
   *                 value:
   *                   event_id: "507f1f77bcf86cd799439012"
   *                   prediction: "not_vulnerable"
   *                   confidence: 0.95
   *                   certainty_type: "inferred"
   *                   severity: "critical"
   *                   status: "auto_flagged"
   *                   explanation:
   *                     what: "No vulnerability detected in the submitted code"
   *                     why: "Code follows secure coding practices"
   *                     where: "N/A"
   *                     reference:
   *                       cwe: "N/A"
   *                       owasp: "N/A"
   *                     remediation:
   *                       guidance: "No specific remediation guidance available."
   *                       suggested_code_fix: null
   *                   suggested_fix: null
   *                   top_predictions:
   *                     - class: "not_vulnerable"
   *                       cwe: "N/A"
   *                       confidence: 0.95
   *       '400':
   *         description: Validation error — missing or invalid request body
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/ValidationError'
   *             examples:
   *               missing_code:
   *                 summary: Missing code field
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"code\" is required"]
   *               empty_code:
   *                 summary: Empty code string
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"code\" is not allowed to be empty"]
   *               code_too_long:
   *                 summary: Code exceeds 50000 character limit
   *                 value:
   *                   error: "Validation failed"
   *                   details: ["\"code\" length must be less than or equal to 50000 characters"]
   *       '429':
   *         description: Rate limit exceeded (10 requests/minute for code scans)
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/RateLimitError'
   *             example:
   *               error: "Too many requests, please try again later"
   *       '502':
   *         description: Code service is unreachable or returned an error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *             example:
   *               error: "Code service unavailable"
   *       '500':
   *         description: Internal server error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *             example:
   *               error: "Internal server error"
   */
  router.post('/scan', scanLimiter, validate(codeScanSchema), async (req, res) => {
    try {
      const response = await fetch(`${codeService}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: req.body.code }),
        signal: AbortSignal.timeout(60000)
      });

      const result = await response.json();

      if (!response.ok) {
        log.error({ status: response.status, requestId: req.id }, 'Code service error');
        return res.status(502).json({ error: 'Code service unavailable' });
      }

      const triageResult = triageEngine.classify(result.confidence, result);

      const event = new Event({
        event_type: 'code',
        source: req.body.source || 'manual_scan',
        prediction: result.prediction,
        confidence: result.confidence,
        certainty_type: 'inferred',
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation,
        suggested_fix: result.suggested_fix || null,
        raw_features: { code: req.body.code }
      });

      await event.save();
      broadcastEvent(wss, event);

      res.json({
        event_id: event._id,
        prediction: result.prediction,
        confidence: result.confidence,
        certainty_type: 'inferred',
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation,
        suggested_fix: result.suggested_fix,
        top_predictions: result.top_predictions
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Code scan failed');
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
