const crypto = require('crypto');
const { createChildLogger } = require('../utils/logger');

const log = createChildLogger('auth');

const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  throw new Error('API_KEY environment variable is required. Set it before starting the gateway.');
}

function apiKeyAuth(req, res, next) {
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
