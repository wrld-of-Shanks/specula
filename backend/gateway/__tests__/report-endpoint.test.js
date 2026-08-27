const path = require('path');
const os = require('os');
const fs = require('fs');
const express = require('express');

const REPORT_DIR = path.join(os.tmpdir(), 'specula-report-test-' + Date.now());
process.env.REPORT_STORAGE_PATH = REPORT_DIR;

// ---- Mock mongoose models + helpers BEFORE requiring the router ----
const mockSave = jest.fn().mockResolvedValue({});
const mockReportLog = jest.fn(() => ({ save: mockSave }));
mockReportLog.find = jest.fn().mockResolvedValue([]);
mockReportLog.findOneAndUpdate = jest.fn().mockResolvedValue({ download_count: 1 });
mockReportLog.deleteMany = jest.fn().mockResolvedValue({});

jest.mock('../routes/report-helpers', () => ({
  buildPdfReport: jest.fn().mockResolvedValue({ bytes: Buffer.from('%PDF-1.4 mock'), stats: { total: 2 } }),
  reportFilename: jest.fn(() => 'repo__test_20260101120000_abcdef.pdf')
}));
jest.mock('../shared/middleware/rateLimiter', () => ({
  reportLimiter: (req, res, next) => next(),
  notificationLimiter: (req, res, next) => next()
}));
jest.mock('../../shared/schema/reportLog', () => mockReportLog);
jest.mock('../../shared/schema/event', () => ({
  find: jest.fn(() => ({
    sort: jest.fn().mockResolvedValue([
      { severity: 'critical', prediction: 'sql_injection', confidence: 0.95, status: 'auto_flagged', file_path: 'a.py' },
      { severity: 'high', prediction: 'xss', confidence: 0.8, status: 'human_review', file_path: 'b.js' }
    ])
  }))
}));
jest.mock('../../shared/schema/scanJob', () => ({
  findById: jest.fn().mockResolvedValue({ _id: '507f1f77bcf86cd799439011', repo_url: 'https://github.com/x/y' })
}));

const reportRoutes = require('../routes/report');

function createServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/reports', reportRoutes());
  return app;
}

let server;
beforeAll(() => {
  server = createServer().listen(0);
});
afterAll((done) => {
  try { fs.rmSync(REPORT_DIR, { recursive: true, force: true }); } catch (e) {}
  server.close(done);
});

async function post(body) {
  const port = server.address().port;
  const res = await fetch(`http://127.0.0.1:${port}/api/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': 'test-key' },
    body: JSON.stringify(body)
  });
  return { status: res.status, body: await res.json() };
}

describe('Report endpoint: POST /generate', () => {
  test('generates a report for a job id', async () => {
    const { status, body } = await post({ job_id: '507f1f77bcf86cd799439011' });
    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.report_url).toContain('/api/reports/reports/');
    expect(body.download_link).toBe(body.report_url);
    expect(mockReportLog).toHaveBeenCalled();
    expect(mockSave).toHaveBeenCalled();
  });

  test('validates missing scope (400)', async () => {
    const { status, body } = await post({ format: 'pdf' });
    expect(status).toBe(400);
    expect(body).toHaveProperty('error');
  });

  test('validates bad job id (400)', async () => {
    const { status } = await post({ job_id: 'not-a-valid-id' });
    expect(status).toBe(400);
  });
});

describe('Report endpoint: GET /reports/:filename', () => {
  test('rejects invalid filenames (path traversal)', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/reports/reports/..%2F..%2Fsecret.pdf`);
    expect(res.status).toBe(400);
  });

  test('returns 404 for a valid but missing file', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/reports/reports/repo_test_20260101120000_abcdef.pdf`);
    expect(res.status).toBe(404);
  });
});
