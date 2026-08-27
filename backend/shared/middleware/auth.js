const crypto = require('crypto');
const { createChildLogger } = require('../utils/logger');

const log = createChildLogger('auth');

function apiKeyAuth(req, res, next) {
  // Read the API key from the environment at request time instead of caching it
  // at module load. This avoids a stale/empty key when the module is required
  // before process.env.API_KEY is populated (e.g. during test discovery when
  // multiple suites share one process), and prevents a throw-at-load crash.
  const API_KEY = process.env.API_KEY;

  if (!API_KEY) {
    log.error('API_KEY environment variable not set');
    return res.status(500).json({ error: 'API key configuration error' });
  }

  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    log.warn({ requestId: req.id }, 'Missing API key');
    return res.status(401).json({ error: 'API key required' });
  }

  if (apiKey.length !== API_KEY.length ||
      !crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(API_KEY))) {
    log.warn({ requestId: req.id }, 'Invalid API key');
    return res.status(403).json({ error: 'Invalid API key' });
  }

  next();
}

module.exports = { apiKeyAuth };
