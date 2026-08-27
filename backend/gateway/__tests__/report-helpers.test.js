const {
  aggregateFindings,
  reportFilename,
  buildPdfReport,
  wrapText
} = require('../routes/report-helpers');

const SAMPLE = [
  { severity: 'critical', prediction: 'sql_injection', confidence: 0.95, status: 'auto_flagged', file_path: 'src/app.py', explanation: { reference: { cwe: 'CWE-89', owasp: 'A03:2021' }, what: 'SQL injection' }, suggested_fix: 'parameterize' },
  { severity: 'high', prediction: 'xss', confidence: 0.8, status: 'human_review', file_path: 'src/v.js', explanation: { what: 'XSS' } },
  { severity: 'low', prediction: 'info_leak', confidence: 0.6, status: 'ignored', file_path: 'cfg.py', explanation: {} },
  { severity: 'critical', prediction: 'command_injection', confidence: 0.99, status: 'auto_flagged', file_path: 'src/run.sh', explanation: {} }
];

describe('aggregateFindings', () => {
  test('counts by severity, status, and prediction', () => {
    const s = aggregateFindings(SAMPLE);
    expect(s.total).toBe(4);
    expect(s.active).toBe(3);
    expect(s.bySeverity).toEqual({ critical: 2, high: 1, medium: 0, low: 1, info: 0 });
    expect(s.byStatus.auto_flagged).toBe(2);
    expect(s.byStatus.ignored).toBe(1);
    expect(s.byPrediction.sql_injection).toBe(1);
  });

  test('handles empty input', () => {
    const s = aggregateFindings([]);
    expect(s.total).toBe(0);
    expect(s.topCritical).toEqual([]);
  });

  test('sorts top critical by severity then confidence', () => {
    const s = aggregateFindings(SAMPLE);
    expect(s.topCritical[0].prediction).toBe('command_injection');
    expect(s.topCritical.length).toBeLessThanOrEqual(5);
  });

  test('excludes not_vulnerable from top list', () => {
    const withBenign = [...SAMPLE, { severity: 'info', prediction: 'not_vulnerable', confidence: 1 }];
    const s = aggregateFindings(withBenign);
    expect(s.topCritical.some(t => t.prediction === 'not_vulnerable')).toBe(false);
  });
});

describe('reportFilename', () => {
  test('produces a unique .pdf filename embedding the job id', () => {
    const a = reportFilename('abc123');
    const b = reportFilename('abc123');
    expect(a).toMatch(/^abc123_\d{14}_[a-f0-9]{6}\.pdf$/);
    expect(a).not.toBe(b);
  });

  test('uses range prefix when no job id', () => {
    expect(reportFilename(null)).toMatch(/^range_\d{14}_[a-f0-9]{6}\.pdf$/);
  });
});

describe('wrapText', () => {
  test('produces the same number of words split across lines', () => {
    const pdf = require('pdf-lib');
    // Since wrapText needs a font-like object, mock the width function.
    const fakeFont = { widthOfTextAtSize: () => 10 };
    const out = wrapText(fakeFont, 'one two three', 10, 15);
    expect(out.join(' ').split(' ').sort()).toEqual(['one', 'two', 'three'].sort());
  });
});

describe('buildPdfReport', () => {
  test('produces valid PDF bytes with finding details', async () => {
    const { bytes, stats } = await buildPdfReport({
      findings: SAMPLE,
      job: { _id: 'abc', repo_url: 'https://github.com/x/y', status: 'completed' },
      includeFixes: true
    });
    expect(bytes.slice(0, 5).toString()).toBe('%PDF-');
    expect(stats.total).toBe(4);
    expect(bytes.length).toBeGreaterThan(1000);
  });

  test('works with no job and a time range', async () => {
    const { bytes } = await buildPdfReport({
      findings: SAMPLE,
      job: null,
      start: new Date('2024-01-01'),
      end: new Date('2024-01-02'),
      includeFixes: false
    });
    expect(bytes.slice(0, 5).toString()).toBe('%PDF-');
  });

  test('renders a page for many findings without error', async () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      severity: 'medium', prediction: 'xss', confidence: 0.5, status: 'auto_flagged',
      file_path: `f${i}.js`, explanation: { what: 'X ' + 'word '.repeat(50) }
    }));
    const { bytes } = await buildPdfReport({ findings: many, includeFixes: true });
    expect(bytes.slice(0, 5).toString()).toBe('%PDF-');
  });
});
