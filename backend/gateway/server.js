const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const { logger, createChildLogger } = require('../shared/utils/logger');
const { requestId } = require('../shared/middleware/requestId');
const { apiKeyAuth } = require('../shared/middleware/auth');
const { defaultLimiter } = require('../shared/middleware/rateLimiter');
const eventRoutes = require('./routes/events');
const networkRoutes = require('./routes/network');
const codeRoutes = require('./routes/code');
const scanRepoRoutes = require('./routes/scanRepo');
const dastRoutes = require('./routes/dast');
const { swaggerSpec, swaggerUiServe, swaggerUiSetup } = require('./swagger');
const { TriageEngine } = require('../shared/triage/engine');

const log = createChildLogger('gateway');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.GATEWAY_PORT || 3000;

// MongoDB is REQUIRED and must include credentials. Falling back to an
// unauthenticated localhost URI would silently disable auth in production.
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  throw new Error('MONGO_URI environment variable is required (e.g. mongodb://user:pass@mongodb:27017/specula?authSource=admin).');
}
if (!/@/.test(MONGO_URI)) {
  throw new Error('MONGO_URI must include credentials. Unauthenticated MongoDB connections are not allowed.');
}

const NETWORK_SERVICE = process.env.NETWORK_SERVICE || 'http://localhost:5001';
const CODE_SERVICE = process.env.CODE_SERVICE || 'http://localhost:5002';
const DAST_SERVICE = process.env.DAST_SERVICE || 'http://localhost:5003';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:3001').split(',');

const triageEngine = new TriageEngine();

app.use(requestId);
app.use(cors({
  origin: CORS_ORIGINS,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Api-Key', 'X-Request-Id'],
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(defaultLimiter);

app.use('/api-docs', swaggerUiServe, swaggerUiSetup);
app.get('/api-docs.json', (req, res) => res.json(swaggerSpec));

app.use('/api/events', apiKeyAuth, eventRoutes);
app.use('/api/network', apiKeyAuth, networkRoutes(NETWORK_SERVICE, triageEngine, wss));
app.use('/api/code', apiKeyAuth, codeRoutes(CODE_SERVICE, triageEngine, wss));
app.use('/api/code', apiKeyAuth, scanRepoRoutes(CODE_SERVICE, triageEngine, wss));
app.use('/api/dast', apiKeyAuth, dastRoutes(DAST_SERVICE, triageEngine, wss));

wss.on('connection', (ws, req) => {
  log.info({ requestId: req.id }, 'Client connected to WebSocket');
  ws.on('close', () => log.info('Client disconnected'));
});

app.get('/health', async (req, res) => {
  const checks = {
    gateway: 'ok',
    mongo: 'unknown',
    network_service: 'unknown',
    code_service: 'unknown',
    dast_service: 'unknown'
  };

  try {
    await mongoose.connection.db.admin().ping();
    checks.mongo = 'ok';
  } catch {
    checks.mongo = 'error';
  }

  const serviceChecks = [
    { name: 'network_service', url: `${NETWORK_SERVICE}/health` },
    { name: 'code_service', url: `${CODE_SERVICE}/health` },
    { name: 'dast_service', url: `${DAST_SERVICE}/health` }
  ];

  await Promise.allSettled(
    serviceChecks.map(async ({ name, url }) => {
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
        if (resp.ok) checks[name] = 'ok';
        else checks[name] = 'degraded';
      } catch {
        checks[name] = 'unreachable';
      }
    })
  );

  const allOk = Object.values(checks).every(v => v === 'ok');
  res.status(allOk ? 200 : 503).json({
    status: allOk ? 'healthy' : 'degraded',
    checks,
    timestamp: new Date().toISOString()
  });
});

app.use((err, req, res, _next) => {
  log.error({ err, requestId: req.id, method: req.method, url: req.url }, 'Unhandled error');
  res.status(500).json({ error: 'Internal server error' });
});

app.set('wss', wss);

async function start() {
  try {
    await mongoose.connect(MONGO_URI);
    log.info('Connected to MongoDB');
  } catch (err) {
    log.error({ err }, 'MongoDB connection error');
    process.exit(1);
  }

  server.listen(PORT, () => {
    log.info({ port: PORT }, 'Gateway running');
  });
}

start();

module.exports = { app, server, wss };
