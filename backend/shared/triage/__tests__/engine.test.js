const { TriageEngine } = require('../engine');

describe('TriageEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new TriageEngine();
  });

  describe('classify()', () => {
    test('auto_flags high confidence results', () => {
      const result = engine.classify(0.95);
      expect(result.status).toBe('auto_flagged');
      expect(result.severity).toBe('critical');
    });

    test('flags for human review at medium confidence', () => {
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
      expect(engine.classify(0.90).status).toBe('auto_flagged');
    });

    test('boundary at 0.89 is human_review', () => {
      expect(engine.classify(0.89).status).toBe('human_review');
    });

    test('boundary at 0.50 is human_review', () => {
      expect(engine.classify(0.50).status).toBe('human_review');
    });

    test('boundary at 0.49 is ignored', () => {
      expect(engine.classify(0.49).status).toBe('ignored');
    });

    test('severity levels are correct', () => {
      expect(engine.classify(0.97).severity).toBe('critical');
      expect(engine.classify(0.92).severity).toBe('high');
      expect(engine.classify(0.80).severity).toBe('medium');
      expect(engine.classify(0.55).severity).toBe('low');
    });

    test('classify ignores the result argument value for status thresholds', () => {
      // classify() is purely confidence-driven.
      expect(engine.classify(0.40, { severity: 'critical' }).status).toBe('ignored');
    });

    test('custom thresholds are honored', () => {
      const custom = new TriageEngine({ auto_flag: 0.80, human_review: 0.40 });
      expect(custom.classify(0.80).status).toBe('auto_flagged');
      expect(custom.classify(0.40).status).toBe('human_review');
      expect(custom.classify(0.39).status).toBe('ignored');
    });
  });

  describe('classifyConfirmed()', () => {
    test.each([
      ['critical', 'auto_flagged'],
      ['high', 'auto_flagged'],
      ['medium', 'human_review'],
      ['low', 'human_review'],
      ['info', 'ignored'],
    ])('maps severity %s to status %s', (severity, expectedStatus) => {
      const result = engine.classifyConfirmed(severity);
      expect(result.status).toBe(expectedStatus);
      expect(result.severity).toBe(severity);
    });

    test('falls back to human_review for unknown severity', () => {
      const result = engine.classifyConfirmed('unknown-severity');
      expect(result.status).toBe('human_review');
      expect(result.severity).toBe('unknown-severity');
    });
  });

  describe('thresholds', () => {
    test('default thresholds', () => {
      expect(engine.getThresholds()).toEqual({ auto_flag: 0.90, human_review: 0.50 });
    });

    test('getThresholds returns a copy', () => {
      const t = engine.getThresholds();
      t.auto_flag = 0.50;
      expect(engine.getThresholds().auto_flag).toBe(0.90);
    });

    test('updateThresholds updates only provided values', () => {
      engine.updateThresholds({ auto_flag: 0.85 });
      expect(engine.getThresholds()).toEqual({ auto_flag: 0.85, human_review: 0.50 });
    });

    test('updateThresholds ignores unknown keys', () => {
      engine.updateThresholds({ bogus: 0.10 });
      expect(engine.getThresholds()).toEqual({ auto_flag: 0.90, human_review: 0.50 });
    });
  });
});
