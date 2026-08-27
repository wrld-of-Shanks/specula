const {
  buildSummary,
  sendSlackNotification,
  buildSlackPayload,
  sendEmail,
  fromAddress
} = require('../routes/notification-helpers');

const FINDINGS = [
  { severity: 'critical', prediction: 'sql_injection', confidence: 0.95, status: 'auto_flagged', file_path: 'a.py' },
  { severity: 'high', prediction: 'xss', confidence: 0.8, status: 'human_review', file_path: 'b.js' },
  { severity: 'low', prediction: 'info_leak', confidence: 0.5, status: 'ignored', file_path: 'c.py' }
];

describe('buildSummary', () => {
  test('includes counts and top vulnerabilities', () => {
    const s = buildSummary(FINDINGS);
    expect(s.text).toContain('Total findings: 3');
    expect(s.text).toContain('Critical: 1');
    expect(s.text).toContain('sql injection');
    expect(s.stats.total).toBe(3);
  });

  test('includes report link when provided', () => {
    const s = buildSummary(FINDINGS, { reportUrl: '/api/reports/reports/x.pdf' });
    expect(s.text).toContain('/api/reports/reports/x.pdf');
    expect(s.html).toContain('/api/reports/reports/x.pdf');
  });

  test('adds report link only when provided', () => {
    const s = buildSummary([]);
    expect(s.text).not.toContain('Full report');
  });

  test('html includes a severity table', () => {
    const s = buildSummary(FINDINGS);
    expect(s.html).toContain('<table');
    expect(s.html).toContain('<tr><td>Critical</td><td>1</td></tr>');
  });
});

describe('sendSlackNotification', () => {
  test('posts JSON payload to the webhook URL', async () => {
    const fetcher = jest.fn().mockResolvedValue({ ok: true });
    const result = await sendSlackNotification('https://hooks.slack.com/x', { text: 'hi' }, fetcher);
    expect(result.ok).toBe(true);
    expect(fetcher).toHaveBeenCalledWith('https://hooks.slack.com/x', expect.objectContaining({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }));
  });

  test('returns failure when webhook responds non-2xx', async () => {
    const fetcher = jest.fn().mockResolvedValue({ ok: false, status: 403 });
    const result = await sendSlackNotification('https://hooks.slack.com/x', {}, fetcher);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('403');
  });

  test('returns failure when fetch throws', async () => {
    const fetcher = jest.fn().mockRejectedValue(new Error('network down'));
    const result = await sendSlackNotification('https://hooks.slack.com/x', {}, fetcher);
    expect(result.ok).toBe(false);
  });

  test('returns failure when no fetch is available', async () => {
    const result = await sendSlackNotification('https://hooks.slack.com/x', {}, null);
    expect(result.ok).toBe(false);
  });
});

describe('buildSlackPayload', () => {
  test('includes channel when provided', () => {
    const p = buildSlackPayload({ text: 'summary' }, '#sec');
    expect(p.channel).toBe('#sec');
    expect(p.text).toBe('summary');
  });

  test('omits channel when not provided', () => {
    const p = buildSlackPayload({ text: 'summary' }, null);
    expect(p.channel).toBeUndefined();
  });
});

describe('sendEmail', () => {
  test('returns success with message id', async () => {
    const transporter = { sendMail: jest.fn().mockResolvedValue({ messageId: 'm1' }) };
    const result = await sendEmail(transporter, { to: 'a@b.com', subject: 's', html: '<p>h</p>' });
    expect(result.ok).toBe(true);
    expect(result.messageId).toBe('m1');
    expect(transporter.sendMail).toHaveBeenCalledWith(expect.objectContaining({ to: 'a@b.com' }));
  });

  test('returns failure on transporter error', async () => {
    const transporter = { sendMail: jest.fn().mockRejectedValue(new Error('SMTP auth failed')) };
    const result = await sendEmail(transporter, { to: 'a@b.com', subject: 's', html: 'h' });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('SMTP auth failed');
  });
});

describe('fromAddress', () => {
  const original = process.env.SMTP_FROM;
  afterEach(() => {
    if (original === undefined) delete process.env.SMTP_FROM;
    else process.env.SMTP_FROM = original;
  });

  test('defaults to security@specula.io when unset', () => {
    delete process.env.SMTP_FROM;
    expect(fromAddress()).toBe('security@specula.io');
  });

  test('uses SMTP_FROM when set', () => {
    process.env.SMTP_FROM = 'alerts@company.com';
    expect(fromAddress()).toBe('alerts@company.com');
  });
});
