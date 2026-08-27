process.env.API_KEY = process.env.API_KEY || 'test-key';

// Confirms the new report/notification routers (and their shared require chain)
// load correctly under Jest's module resolution.
describe('Routes load', () => {
  test('report router factory is a function and returns a router', () => {
    const report = require('../routes/report');
    expect(typeof report).toBe('function');
    const r = report();
    expect(r).toBeTruthy();
    expect(typeof r.post).toBe('function');
  });

  test('notification router factory is a function and returns a router', () => {
    const notification = require('../routes/notification');
    expect(typeof notification).toBe('function');
    const r = notification();
    expect(r).toBeTruthy();
    expect(typeof r.post).toBe('function');
  });

  test('report helpers expose buildPdfReport', () => {
    const helpers = require('../routes/report-helpers');
    expect(typeof helpers.buildPdfReport).toBe('function');
    expect(typeof helpers.aggregateFindings).toBe('function');
  });

  test('notification helpers expose buildSummary', () => {
    const helpers = require('../routes/notification-helpers');
    expect(typeof helpers.buildSummary).toBe('function');
    expect(typeof helpers.sendSlackNotification).toBe('function');
  });
});
