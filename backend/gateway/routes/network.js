const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { validate, networkAnalyzeSchema } = require('../../shared/utils/validation');
const { scanLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('network-route');

module.exports = function(networkService, triageEngine, wss) {
  /**
   * @swagger
   * /api/network/analyze:
   *   post:
   *     summary: Analyze network traffic features (NIDS)
   *     description: Submits feature values to the behavioral traffic-analysis model and
   *       persists the result as a `network` event.
   *     tags: [Network (NIDS)]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               protocol_type:
   *                 type: string
   *                 enum: [tcp, udp, icmp]
   *               service: { type: string, maxLength: 50 }
   *               flag: { type: string, maxLength: 10 }
   *               src_bytes: { type: integer, minimum: 0 }
   *               dst_bytes: { type: integer, minimum: 0 }
   *               duration: { type: number, minimum: 0 }
   *               count: { type: integer, minimum: 0 }
   *               srv_count: { type: integer, minimum: 0 }
   *               serror_rate: { type: number, minimum: 0, maximum: 1 }
   *               srv_serror_rate: { type: number, minimum: 0, maximum: 1 }
   *               rerror_rate: { type: number, minimum: 0, maximum: 1 }
   *               srv_rerror_rate: { type: number, minimum: 0, maximum: 1 }
   *               same_srv_rate: { type: number, minimum: 0, maximum: 1 }
   *               diff_srv_rate: { type: number, minimum: 0, maximum: 1 }
   *               dst_host_count: { type: integer, minimum: 0 }
   *               dst_host_srv_count: { type: integer, minimum: 0 }
   *               dst_host_same_srv_rate: { type: number, minimum: 0, maximum: 1 }
   *               dst_host_diff_srv_rate: { type: number, minimum: 0, maximum: 1 }
   *               dst_host_serror_rate: { type: number, minimum: 0, maximum: 1 }
   *               dst_host_rerror_rate: { type: number, minimum: 0, maximum: 1 }
   *               source: { type: string, maxLength: 200 }
   *             example:
   *               protocol_type: tcp
   *               service: http
   *               flag: SF
   *               src_bytes: 200
   *               dst_bytes: 500
   *               duration: 0
   *     responses:
   *       '200':
   *         description: Analysis completed
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 event_id: { type: string }
   *                 prediction:
   *                   type: string
   *                   enum: [anomaly, normal]
   *                 confidence: { type: number, nullable: true }
   *                 certainty_type: { type: string }
   *                 anomaly_score: { type: number, nullable: true }
   *                 severity:
   *                   type: string
   *                   enum: [critical, high, medium, low, info]
   *                 status:
   *                   type: string
   *                   enum: [auto_flagged, human_review, ignored]
   *                 explanation: { type: object, nullable: true }
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '502':
   *         $ref: '#/components/schemas/Error'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/analyze', scanLimiter, validate(networkAnalyzeSchema), async (req, res) => {
    try {
      const response = await fetch(`${networkService}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
        signal: AbortSignal.timeout(30000)
      });

      const result = await response.json();

      if (!response.ok) {
        log.error({ status: response.status, requestId: req.id }, 'Network service error');
        return res.status(502).json({ error: 'Network service unavailable' });
      }

      const triageResult = triageEngine.classify(result.confidence, result);

      const event = new Event({
        event_type: 'network',
        source: req.body.source || 'unknown',
        prediction: result.prediction,
        confidence: result.confidence,
        certainty_type: 'inferred',
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation || null,
        raw_features: req.body
      });

      await event.save();
      broadcastEvent(wss, event);

      res.json({
        event_id: event._id,
        prediction: result.prediction,
        confidence: result.confidence,
        certainty_type: 'inferred',
        anomaly_score: result.anomaly_score,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Network analysis failed');
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
