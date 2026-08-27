const crypto = require('crypto');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function aggregateFindings(findings) {
  const bySeverity = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0
  };
  const byPrediction = {};
  const byStatus = {
    auto_flagged: 0, human_review: 0, ignored: 0
  };

  for (const f of findings || []) {
    const sev = f.severity;
    if (bySeverity[sev] != null) bySeverity[sev]++;
    else bySeverity[sev] = 1;

    const pred = f.prediction || 'unknown';
    byPrediction[pred] = (byPrediction[pred] || 0) + 1;

    const st = f.status;
    if (byStatus[st] != null) byStatus[st]++;
    else byStatus[st] = 1;
  }

  const total = (findings || []).length;
  const active = (findings || []).filter(f => f.status !== 'ignored').length;

  const topCritical = [...(findings || [])]
    .filter(f => f.prediction && f.prediction !== 'not_vulnerable')
    .sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) ||
      (b.confidence || 0) - (a.confidence || 0))
    .slice(0, 5);

  return {
    total,
    active,
    bySeverity,
    byPrediction,
    byStatus,
    topCritical
  };
}

function reportFilename(jobId) {
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const suffix = crypto.randomBytes(3).toString('hex');
  return `${jobId ? String(jobId) : 'range'}_${stamp}_${suffix}.pdf`;
}

// Remove characters pdf-lib's WinAnsi encoding cannot encode (emoji, etc.)
function sanitizeForPdf(text) {
  return String(text == null ? '' : text)
    .replace(/[^\x00-\xFF]/g, '?')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, ' ');
}

// Split a string into lines that fit the available width using the given font.
function wrapText(font, text, fontSize, maxWidth) {
  text = sanitizeForPdf(text);
  const words = text.split(/\s+/);
  const lines = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, fontSize) <= maxWidth || !current) {
      current = candidate;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

async function buildPdfReport({ findings, job = null, start = null, end = null, includeFixes = true }) {
  const stats = aggregateFindings(findings);

  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.addPage();
  const { width, height } = page.getSize();

  const margin = 50;
  const contentWidth = width - margin * 2;
  const title = 'Specula — HORUS Security Scan Report';
  let y = height - 60;

  page.drawText(title, { x: margin, y, size: 20, font: bold, color: rgb(0.1, 0.8, 0.4) });
  y -= 24;
  page.drawText(`Generated: ${new Date().toISOString()}`, { x: margin, y, size: 10, font });
  y -= 16;
  if (job) {
    page.drawText(`Repository: ${job.repo_url || 'N/A'}`, { x: margin, y, size: 10, font });
    y -= 14;
    page.drawText(`Job ID: ${String(job._id || '')}  ·  Status: ${job.status || 'N/A'}`, { x: margin, y, size: 10, font });
    y -= 14;
  } else if (start && end) {
    page.drawText(`Time range: ${new Date(start).toISOString()} to ${new Date(end).toISOString()}`, { x: margin, y, size: 10, font });
    y -= 14;
  }

  y -= 12;
  page.drawText(`Total findings: ${stats.total}   |   Active (not ignored): ${stats.active}`, { x: margin, y, size: 12, font: bold });
  y -= 22;

  // Severity distribution
  page.drawText('Severity Distribution', { x: margin, y, size: 12, font: bold });
  y -= 16;
  const barMaxWidth = contentWidth * 0.6;
  const severityColors = {
    critical: rgb(0.9, 0.2, 0.2),
    high: rgb(0.95, 0.5, 0.1),
    medium: rgb(0.95, 0.8, 0.1),
    low: rgb(0.2, 0.7, 0.9),
    info: rgb(0.5, 0.5, 0.7)
  };
  const maxCount = Math.max(1, ...Object.values(stats.bySeverity));
  for (const sev of SEVERITY_ORDER) {
    const count = stats.bySeverity[sev] || 0;
    page.drawText(`${sev}: ${count}`, { x: margin, y, size: 9, font });
    const barW = (count / maxCount) * barMaxWidth;
    page.drawRectangle({
      x: margin + 130,
      y: y - 2,
      width: Math.max(barW, count ? 2 : 0),
      height: 8,
      color: severityColors[sev] || rgb(0.5, 0.5, 0.5)
    });
    y -= 16;
  }

  y -= 14;
  page.drawText('Top Vulnerabilities', { x: margin, y, size: 12, font: bold });
  y -= 16;
  if (stats.topCritical.length === 0) {
    page.drawText('No vulnerabilities detected.', { x: margin, y, size: 10, font });
    y -= 14;
  } else {
    for (const t of stats.topCritical) {
      page.drawText(`• ${sanitizeForPdf((t.prediction || 'unknown').replace(/_/g, ' '))}  [${t.severity}]  conf ${t.confidence != null ? Math.round(t.confidence * 100) : 'n/a'}%`, {
        x: margin, y, size: 9, font
      });
      y -= 14;
      const lines = wrapText(font, t.file_path || '', 9, contentWidth - 20);
      for (const ln of lines) {
        page.drawText(`    ${ln}`, { x: margin, y, size: 9, font, color: rgb(0.4, 0.4, 0.4) });
        y -= 12;
      }
    }
  }

  // Findings detail table / sections
  y -= 18;
  const sorted = [...(findings || [])].sort(
    (a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
  );
  for (const f of sorted) {
    if (y < 140) {
      const np = pdfDoc.addPage();
      np.drawText(`${title} — continued`, { x: margin, y: np.getSize().height - 50, size: 12, font: bold });
      y = np.getSize().height - 80;
    }

    page.drawText(`[${f.severity}] ${sanitizeForPdf((f.prediction || 'unknown').replace(/_/g, ' '))}`, { x: margin, y, size: 11, font: bold });
    y -= 14;
    page.drawText(`File: ${sanitizeForPdf(f.file_path || f.source || 'N/A')}`, { x: margin, y, size: 9, font, color: rgb(0.3, 0.3, 0.3) });
    y -= 12;
    if (f.line_range && f.line_range.start) {
      page.drawText(`Lines: ${f.line_range.start}-${f.line_range.end || f.line_range.start}   Status: ${f.status}`, { x: margin, y, size: 9, font, color: rgb(0.3, 0.3, 0.3) });
      y -= 12;
    }

    const exp = f.explanation || {};
    const ref = exp.reference || {};
    if (ref.cwe || ref.owasp) {
      page.drawText(`CWE: ${ref.cwe || 'N/A'}   OWASP: ${ref.owasp || 'N/A'}`, { x: margin, y, size: 9, font, color: rgb(0.3, 0.3, 0.3) });
      y -= 12;
    }

    const what = exp.what || exp.description || '';
    if (what) {
      for (const ln of wrapText(font, what, 9, contentWidth)) {
        page.drawText(ln, { x: margin + 12, y, size: 9, font });
        y -= 11;
      }
    }

    if (includeFixes) {
      const fix = f.suggested_fix || (exp.remediation && exp.remediation.suggested_code_fix);
      if (fix) {
        page.drawText('Suggested fix:', { x: margin + 12, y, size: 9, font: bold, color: rgb(0.1, 0.7, 0.4) });
        y -= 11;
        for (const ln of wrapText(font, fix, 8, contentWidth)) {
          page.drawText(ln, { x: margin + 20, y, size: 8, font, color: rgb(0.15, 0.15, 0.15) });
          y -= 10;
        }
      } else {
        page.drawText('Suggested fix: not available (manual remediation required).', { x: margin + 12, y, size: 8, font, color: rgb(0.5, 0.5, 0.5) });
        y -= 12;
      }
    }

    y -= 16;
  }

  const bytes = await pdfDoc.save();
  return { bytes: Buffer.from(bytes), stats };
}

module.exports = {
  aggregateFindings,
  reportFilename,
  buildPdfReport,
  wrapText,
  sanitizeForPdf,
  SEVERITY_ORDER
};
