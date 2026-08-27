const express = require('express');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { validate, paginationSchema } = require('../../shared/utils/validation');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('events-route');

/**
 * @swagger
 * /api/events:
 *   get:
 *     summary: List security events
 *     description: Returns a paginated, filtered list of scored security events.
 *     tags: [Events]
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - name: page
 *         in: query
 *         schema: { type: integer, minimum: 1, default: 1 }
 *       - name: limit
 *         in: query
 *         schema: { type: integer, minimum: 1, maximum: 100, default: 50 }
 *       - name: event_type
 *         in: query
 *         schema: { type: string, enum: [network, code, dast, scan_repo] }
 *       - name: status
 *         in: query
 *         schema: { type: string, enum: [auto_flagged, human_review, ignored] }
 *       - name: since
 *         in: query
 *         schema: { type: string, format: date-time }
 *         description: Only events after this ISO timestamp
 *     responses:
 *       '200':
 *         description: Paginated events
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 events:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Event'
 *                 total: { type: integer }
 *                 page: { type: integer }
 *                 limit: { type: integer }
 *       '400':
 *         $ref: '#/components/schemas/ValidationError'
 *       '500':
 *         $ref: '#/components/schemas/Error'
 *
 * /api/events/stats/summary:
 *   get:
 *     summary: Get aggregate event statistics
 *     description: Groups events by event_type and status, with counts and average confidence.
 *     tags: [Events]
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       '200':
 *         description: Aggregated stats
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: object
 *                     properties:
 *                       event_type:
 *                         type: string
 *                         enum: [network, code, dast, scan_repo]
 *                       status:
 *                         type: string
 *                         enum: [auto_flagged, human_review, ignored]
 *                   count: { type: integer }
 *                   avg_confidence: { type: number, nullable: true }
 *       '500':
 *         $ref: '#/components/schemas/Error'
 *
 * /api/events/{id}:
 *   get:
 *     summary: Get a single security event
 *     description: Returns one event by its id.
 *     tags: [Events]
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema: { type: string }
 *         description: Event id
 *     responses:
 *       '200':
 *         description: The event
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Event'
 *       '404':
 *         $ref: '#/components/schemas/Error'
 *       '500':
 *         $ref: '#/components/schemas/Error'
 */

router.get('/', validate(paginationSchema, 'query'), async (req, res) => {
  try {
    const { event_type, status, limit = 50, page = 1, since } = req.query;
    const query = {};
    if (event_type) query.event_type = event_type;
    if (status) query.status = status;
    if (since) query.timestamp = { $gt: new Date(since) };

    const skip = (page - 1) * limit;
    const [events, total] = await Promise.all([
      Event.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit),
      Event.countDocuments(query)
    ]);

    res.json({ events, total, page, limit });
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch events');
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/stats/summary', async (req, res) => {
  try {
    const stats = await Event.aggregate([
      {
        $group: {
          _id: { event_type: '$event_type', status: '$status' },
          count: { $sum: 1 },
          avg_confidence: { $avg: '$confidence' }
        }
      }
    ]);
    res.json(stats);
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch stats');
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch event');
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
