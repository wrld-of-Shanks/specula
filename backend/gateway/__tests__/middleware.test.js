process.env.API_KEY = process.env.API_KEY || 'test-key';

const { apiKeyAuth } = require('../shared/middleware/auth');
const { createTestApp, startServer, stopServer, makeRequest } = require('./helpers');

describe('Auth Middleware', () => {
  let server, port;

  afterEach(async () => {
    await stopServer(server);
  });

  test('rejects request without API key', async () => {
    const app = createTestApp();
    app.use(apiKeyAuth);
    app.get('/test', (req, res) => res.json({ ok: true }));

    ({ server, port } = await startServer(app));
    const result = await makeRequest(port, 'GET', '/test', null, { 'X-Api-Key': '' });
    expect(result.status).toBe(401);
  });

  test('rejects request with wrong API key', async () => {
    const app = createTestApp();
    app.use(apiKeyAuth);
    app.get('/test', (req, res) => res.json({ ok: true }));

    ({ server, port } = await startServer(app));
    const result = await makeRequest(port, 'GET', '/test', null, { 'X-Api-Key': 'wrong-key' });
    expect(result.status).toBe(403);
  });

  test('allows request with correct API key', async () => {
    const app = createTestApp();
    app.use(apiKeyAuth);
    app.get('/test', (req, res) => res.json({ ok: true }));

    ({ server, port } = await startServer(app));
    const result = await makeRequest(port, 'GET', '/test', null, { 'X-Api-Key': 'test-key' });
    expect(result.status).toBe(200);
    expect(result.body.ok).toBe(true);
  });
});

describe('Request ID Middleware', () => {
  let server, port;

  afterEach(async () => {
    await stopServer(server);
  });

  test('adds request ID to response', async () => {
    const { requestId } = require('../shared/middleware/requestId');
    const app = createTestApp();
    app.use(requestId);
    app.get('/test', (req, res) => res.json({ id: req.id }));

    ({ server, port } = await startServer(app));
    const result = await makeRequest(port, 'GET', '/test');
    expect(result.status).toBe(200);
    expect(result.body.id).toBeDefined();
  });
});
