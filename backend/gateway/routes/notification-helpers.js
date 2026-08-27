const { aggregateFindings } = require('./report-helpers');

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function buildSummary(findings, { reportUrl = null } = {}) {
  const stats = aggregateFindings(findings);
  const bySev = stats.bySeverity;

  const severityLines = [
    `Critical: ${bySev.critical}`,
    `High: ${bySev.high}`,
    `Medium: ${bySev.medium}`,
    `Low: ${bySev.low}`,
    `Info: ${bySev.info}`
  ];

  const topLines = stats.topCritical.map(
    (t, i) => `${i + 1}. ${(t.prediction || 'unknown').replace(/_/g, ' ')} [${t.severity}] ` +
      `conf ${t.confidence != null ? Math.round(t.confidence * 100) : 'n/a'}%`
  );

  const text = [
    `🔒 Specula Security Report`,
    `Total findings: ${stats.total} (active: ${stats.active})`,
    ``,
    ...severityLines,
    ``,
    `Top vulnerabilities:`,
    ...(topLines.length ? topLines : ['- None detected']),
    ...(reportUrl ? [``, `Full report: ${reportUrl}`] : [])
  ].join('\n');

  const rows = stats.topCritical.map(t =>
    `<li><b>${(t.prediction || 'unknown').replace(/_/g, ' ')}</b> — ${t.severity} (conf ${t.confidence != null ? Math.round(t.confidence * 100) : 'n/a'}%)</li>`
  ).join('');

  const html = [
    `<h2>🔒 Specula Security Report</h2>`,
    `<p>Total findings: <b>${stats.total}</b> (active: ${stats.active})</p>`,
    `<table border="1" cellpadding="6" cellspacing="0">`,
    `<tr><th>Severity</th><th>Count</th></tr>`,
    `<tr><td>Critical</td><td>${bySev.critical}</td></tr>`,
    `<tr><td>High</td><td>${bySev.high}</td></tr>`,
    `<tr><td>Medium</td><td>${bySev.medium}</td></tr>`,
    `<tr><td>Low</td><td>${bySev.low}</td></tr>`,
    `<tr><td>Info</td><td>${bySev.info}</td></tr>`,
    `</table>`,
    `<p><b>Top vulnerabilities:</b></p>`,
    `<ul>${rows || '<li>None detected</li>'}</ul>`,
    reportUrl ? `<p><a href="${reportUrl}">📄 Download full report</a></p>` : ''
  ].join('\n');

  return { text, html, stats };
}

async function sendSlackNotification(webhookUrl, payload, fetcher) {
  const doFetch = fetcher !== undefined ? fetcher : (typeof fetch === 'function' ? fetch : null);
  if (!doFetch) return { ok: false, error: 'No fetch implementation available' };
  try {
    const resp = await doFetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!resp.ok) {
      return { ok: false, error: `Slack webhook returned ${resp.status}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : 'Unknown error' };
  }
}

function buildSlackPayload(summary, channel) {
  const payload = {
    text: summary.text
  };
  if (channel) payload.channel = channel;
  return payload;
}

async function sendEmail(transporter, { to, subject, html }) {
  try {
    const info = await transporter.sendMail({ from: fromAddress(), to, subject, html });
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : 'Unknown SMTP error' };
  }
}

function fromAddress() {
  return process.env.SMTP_FROM || process.env.SMTP_USER || 'security@specula.io';
}

module.exports = {
  buildSummary,
  sendSlackNotification,
  buildSlackPayload,
  sendEmail,
  fromAddress,
  SEVERITY_RANK
};
