const express = require('express');
const router = express.Router();

const Event = require('../../shared/schema/event');
const ScanJob = require('../../shared/schema/scanJob');
const NotificationLog = require('../../shared/schema/notificationLog');
const ReportLog = require('../../shared/schema/reportLog');
const { validate, sendNotificationSchema } = require('../../shared/utils/validation');
const { notificationLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');
const { buildSummary, sendSlackNotification, buildSlackPayload, sendEmail } = require('./notification-helpers');

const log = createChildLogger('notification-route');

const SlackChannel = process.env.SLACK_CHANNEL || '#security-alerts';
const EmailRecipients = (process.env.NOTIFICATION_EMAIL_RECIPIENTS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

function slackTransportConfig() {
  return {
    url: process.env.SLACK_WEBHOOK_URL || '',
    channel: SlackChannel
  };
}

function emailTransportConfig() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const auth = user && pass ? { user, pass } : undefined;
  return { host, port, auth, secure: port === 465 };
}

async function selectReportUrl(jobId) {
  try {
    const report = await ReportLog.findOne({ job_id: jobId }).sort({ generated_at: -1 });
    if (!report) return null;
    return `/api/reports/reports/${report.filename}`;
  } catch (err) {
    return null;
  }
}

async function sendToSlack(summary, requestedChannel, jobId) {
  const cfg = slackTransportConfig();
  if (!cfg.url) return { channel: 'slack', recipient: requestedChannel || cfg.channel, status: 'failed', error: 'SLACK_WEBHOOK_URL not configured' };

  const channel = requestedChannel || cfg.channel;
  const payload = buildSlackPayload(summary, channel);
  const result = await sendSlackNotification(cfg.url, payload);

  await NotificationLog.create({
    job_id: jobId || null,
    channel: 'slack',
    recipient: channel,
    sent_at: new Date(),
    status: result.ok ? 'success' : 'failed',
    error: result.ok ? null : result.error || null
  });
  return { channel: 'slack', recipient: channel, status: result.ok ? 'success' : 'failed', error: result.ok ? null : result.error || null };
}

async function sendToEmail(summary, requestedRecipients, jobId) {
  const cfg = emailTransportConfig();
  if (!cfg) return { channel: 'email', recipient: (requestedRecipients || []).join(','), status: 'failed', error: 'SMTP_HOST not configured' };

  const recipients = (requestedRecipients && requestedRecipients.length ? requestedRecipients : EmailRecipients);
  if (!recipients.length) return { channel: 'email', recipient: '', status: 'failed', error: 'No email recipients configured' };

  // Lazily require nodemailer (its internal lib/shared requires would otherwise
  // collide with the jest moduleNameMapper when loading the router).
  const nodemailer = require('nodemailer');

  const transporter = nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: cfg.auth
  });

  // Send individually so one failure doesn't block the others.
  const results = [];
  for (const to of recipients) {
    const result = await sendEmail(transporter, {
      to,
      subject: `${summary.stats.total} security finding(s) — Specula report`,
      html: summary.html
    });
    await NotificationLog.create({
      job_id: jobId || null,
      channel: 'email',
      recipient: to,
      sent_at: new Date(),
      status: result.ok ? 'success' : 'failed',
      error: result.ok ? null : result.error || null
    });
    results.push({ channel: 'email', recipient: to, status: result.ok ? 'success' : 'failed', error: result.ok ? null : result.error || null });
  }
  return results.length === 1 ? results[0] : { channel: 'email', recipients: recipients.join(','), results };
}

module.exports = function() {
  /**
   * @swagger
   * /api/notifications/send:
   *   post:
   *     summary: Send a security summary notification (Slack and/or email)
   *     description: Fetches a scan job's findings, builds a summary, and sends a Slack message
   *       and/or email with a link to the generated report. All attempts are written to the
   *       notification_logs collection.
   *     tags: [Notifications]
   *     security:
   *       - ApiKeyAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [job_id, channels]
   *             properties:
   *               job_id:
   *                 type: string
   *               channels:
   *                 type: array
   *                 items: { type: string, enum: [slack, email] }
   *               recipients:
   *                 type: array
   *                 items: { type: string }
   *     responses:
   *       '200':
   *         description: Notifications sent
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 success: { type: boolean }
   *                 slack_sent: { type: boolean }
   *                 email_sent: { type: boolean }
   *                 message: { type: string }
   *       '404':
   *         $ref: '#/components/schemas/Error'
   *       '400':
   *         $ref: '#/components/schemas/ValidationError'
   *       '500':
   *         $ref: '#/components/schemas/Error'
   */
  router.post('/send', notificationLimiter, validate(sendNotificationSchema), async (req, res) => {
    try {
      const { job_id, channels, recipients } = req.body;
      const job = await ScanJob.findById(job_id);
      if (!job) return res.status(404).json({ error: 'Scan job not found' });

      const findings = await Event.find({ job_id: job._id });
      const reportUrl = await selectReportUrl(job_id);
      const summary = buildSummary(findings, { reportUrl });

      const results = {};
      if (channels.includes('slack')) {
        const slackRecipient = recipients && recipients.find(r => r && r.startsWith('#')) ?
          recipients.find(r => r && r.startsWith('#')) : null;
        results.slack = await sendToSlack(summary, slackRecipient, job_id);
      }
      if (channels.includes('email')) {
        const emailRecipients = (recipients || []).filter(r => r && r.indexOf('@') !== -1);
        results.email = await sendToEmail(summary, emailRecipients, job_id);
      }

      const slackSent = results.slack ? results.slack.status === 'success' : false;
      const emailSent = results.email ? (Array.isArray(results.email.results)
        ? results.email.results.every(r => r.status === 'success')
        : results.email.status === 'success') : false;

      log.info({ jobId: job_id, channels, requestId: req.id }, 'Notifications dispatched');
      return res.json({
        success: slackSent || emailSent,
        slack_sent: slackSent,
        email_sent: emailSent,
        message: 'Notifications sent successfully',
        details: results
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Notification send failed');
      return res.status(500).json({ error: 'Failed to send notifications: ' + (err && err.message ? err.message : 'Unknown error') });
    }
  });

  return router;
};
