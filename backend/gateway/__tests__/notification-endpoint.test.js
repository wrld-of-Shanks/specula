process.env.SLACK_CHANNEL = '#sec';
process.env.NOTIFICATION_EMAIL_RECIPIENTS = 'default@corp.com';

const express = require('express');

// ---- Mock models + helpers BEFORE requiring the router ----
const mockNotificationLogCreate = jest.fn().mockResolvedValue({});
const mockNotificationLog = { create: mockNotificationLogCreate };

// nodemailer's internal "../shared/url" require collides with the jest
// moduleNameMapper, so stub the whole module (sendEmail is mocked in helpers).
jest.mock('nodemailer', () => ({
  createTransport: jest.fn(() => ({}))
}));

jest.mock('../routes/notification-helpers', () => ({
  buildSummary: jest.fn(() => ({ text: 'summary', html: '<p>h</p>', stats: { total: 3 } })),
  buildSlackPayload: jest.fn((summary, channel) => ({ channel, text: summary.text })),
  sendSlackNotification: jest.fn().mockResolvedValue({ ok: true }),
  sendEmail: jest.fn().mockResolvedValue({ ok: true, messageId: 'm1' }),
  fromAddress: jest.fn(() => 'security@specula.io')
}));
jest.mock('../shared/middleware/rateLimiter', () => ({
  reportLimiter: (req, res, next) => next(),
  notificationLimiter: (req, res, next) => next()
}));
jest.mock('../../shared/schema/notificationLog', () => mockNotificationLog);
jest.mock('../../shared/schema/scanJob', () => ({
  findById: jest.fn().mockResolvedValue({ _id: '507f1f77bcf86cd799439011', repo_url: 'https://github.com/x/y' })
}));
jest.mock('../../shared/schema/event', () => ({
  find: jest.fn().mockResolvedValue([
    { severity: 'critical', prediction: 'sql_injection', confidence: 0.95 },
    { severity: 'low', prediction: 'info_leak', confidence: 0.4 }
  ])
}));
jest.mock('../../shared/schema/reportLog', () => ({
  findOne: jest.fn().mockResolvedValue({ filename: 'repo_test_20260101120000_abcdef.pdf' })
}));

const { buildSummary, sendSlackNotification, sendEmail } = require('../routes/notification-helpers');
const notificationRoutes = require('../routes/notification');

function createServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/notifications', notificationRoutes());
  return app;
}

let server;
beforeAll(() => {
  server = createServer().listen(0);
});
afterAll((done) => { server.close(done); });
beforeEach(() => jest.clearAllMocks());
// Ensure mock resolved values are restored for each test.
beforeAll(() => {
  sendSlackNotification.mockResolvedValue({ ok: true });
  sendEmail.mockResolvedValue({ ok: true, messageId: 'm1' });
});

async function post(body) {
  const port = server.address().port;
  const res = await fetch(`http://127.0.0.1:${port}/api/notifications/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': 'test-key' },
    body: JSON.stringify(body)
  });
  return { status: res.status, body: await res.json() };
}

const JOB = '507f1f77bcf86cd799439011';

describe('Notification endpoint: POST /send', () => {
  test('validates missing channels (400)', async () => {
    const { status } = await post({ job_id: JOB });
    expect(status).toBe(400);
  });

  test('validates invalid channel (400)', async () => {
    const { status } = await post({ job_id: JOB, channels: ['sms'] });
    expect(status).toBe(400);
  });

  test('sends Slack and email successfully', async () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/x';
    process.env.SMTP_HOST = 'smtp.corp.com';
    const { status, body } = await post({
      job_id: JOB,
      channels: ['slack', 'email'],
      recipients: ['#sec', 'person@corp.com']
    });
    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.slack_sent).toBe(true);
    expect(body.email_sent).toBe(true);
    expect(buildSummary).toHaveBeenCalled();
    expect(sendSlackNotification).toHaveBeenCalled();
    expect(sendEmail).toHaveBeenCalled();
    expect(mockNotificationLogCreate).toHaveBeenCalled();
    delete process.env.SLACK_WEBHOOK_URL;
    delete process.env.SMTP_HOST;
  });

  test('reports failure when Slack webhook is not configured', async () => {
    delete process.env.SLACK_WEBHOOK_URL;
    process.env.SMTP_HOST = 'smtp.corp.com';
    const { status, body } = await post({ job_id: JOB, channels: ['slack', 'email'] });
    expect(status).toBe(200);
    expect(body.slack_sent).toBe(false);
    expect(body.email_sent).toBe(true);
    expect(sendSlackNotification).not.toHaveBeenCalled();
    delete process.env.SMTP_HOST;
  });

  test('returns 404 when job not found', async () => {
    const ScanJob = require('../../shared/schema/scanJob');
    ScanJob.findById.mockResolvedValue(null);
    const { status } = await post({ job_id: JOB, channels: ['slack'] });
    expect(status).toBe(404);
    ScanJob.findById.mockResolvedValue({ _id: JOB, repo_url: 'https://github.com/x/y' });
  });
});
