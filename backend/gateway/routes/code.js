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
   *     description: Submits a snippet of source code to the rule-based classifier, applies
   *       the triage engine, and persists the result as a `code` event.
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
   *                 maxLength: 50000
   *                 description: Source code snippet to analyze
   *               source:
   *                 type: string
   *                 description: Optional label for the scan source
   *             example:
   *               code: "username = input('user')\nquery = 'SELECT * FROM users WHERE name = \"' + username + '\"'"
   *     responses:
   *       '200':
   *         description: Scan completed
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 event_id: { type: string }
   *                 prediction:
   *                   type: string
   *                   enum: [sql_injection, xss, command_injection, hardcoded_credentials, path_traversal, insecure_deserialization, not_vulnerable]
   *                 confidence: { type: number, nullable: true }
   *                 certainty_type: { type: string }
   *                 severity:
   *                   type: string
   *                   enum: [critical, high, medium, low, info]
   *                 status:
   *                   type: string
   *                   enum: [auto_flagged, human_review, ignored]
   *                 explanation: { type: object, nullable: true }
   *                 suggested_fix: { type: string, nullable: true }
   *                 top_predictions: { type: array, items: { type: object } }
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '502':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
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
