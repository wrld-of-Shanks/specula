const { TriageEngine } = require('../shared/triage/engine');

describe('TriageEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new TriageEngine();
  });

  test('auto_flags high confidence results', () => {
    const result = engine.classify(0.95);
    expect(result.status).toBe('auto_flagged');
    expect(result.severity).toBe('critical');
  });

  test('flags for human review medium confidence', () => {
    const result = engine.classify(0.70);
    expect(result.status).toBe('human_review');
    expect(result.severity).toBe('medium');
  });

  test('ignores low confidence results', () => {
    const result = engine.classify(0.30);
    expect(result.status).toBe('ignored');
    expect(result.severity).toBe('info');
  });

  test('boundary at 0.90 is auto_flagged', () => {
    const result = engine.classify(0.90);
    expect(result.status).toBe('auto_flagged');
  });

  test('boundary at 0.89 is human_review', () => {
    const result = engine.classify(0.89);
    expect(result.status).toBe('human_review');
  });

  test('boundary at 0.50 is human_review', () => {
    const result = engine.classify(0.50);
    expect(result.status).toBe('human_review');
  });

  test('boundary at 0.49 is ignored', () => {
    const result = engine.classify(0.49);
    expect(result.status).toBe('ignored');
  });

  test('severity levels are correct', () => {
    expect(engine.classify(0.97).severity).toBe('critical');
    expect(engine.classify(0.92).severity).toBe('high');
    expect(engine.classify(0.80).severity).toBe('medium');
    expect(engine.classify(0.55).severity).toBe('low');
  });

  test('custom thresholds', () => {
    const custom = new TriageEngine({ auto_flag: 0.80, human_review: 0.40 });
    expect(custom.classify(0.80).status).toBe('auto_flagged');
    expect(custom.classify(0.40).status).toBe('human_review');
    expect(custom.classify(0.39).status).toBe('ignored');
  });

  test('getThresholds returns copy', () => {
    const t = engine.getThresholds();
    t.auto_flag = 0.50;
    expect(engine.getThresholds().auto_flag).toBe(0.90);
  });

  test('updateThresholds updates values', () => {
    engine.updateThresholds({ auto_flag: 0.85 });
    expect(engine.getThresholds().auto_flag).toBe(0.85);
    expect(engine.getThresholds().human_review).toBe(0.50);
  });
});
