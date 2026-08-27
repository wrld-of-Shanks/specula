const {
  networkAnalyzeSchema,
  codeScanSchema,
  scanRepoSchema,
  dastScanSchema,
  authorizedTargetSchema,
  validate
} = require('../shared/utils/validation');

function runValidation(schema, data) {
  return schema.validate(data, { abortEarly: false, stripUnknown: true });
}

describe('Validation Schemas', () => {
  describe('networkAnalyzeSchema', () => {
    test('accepts valid network data', () => {
      const { error } = runValidation(networkAnalyzeSchema, {
        protocol_type: 'tcp',
        service: 'http',
        src_bytes: 100
      });
      expect(error).toBeUndefined();
    });

    test('rejects invalid protocol_type', () => {
      const { error } = runValidation(networkAnalyzeSchema, {
        protocol_type: 'invalid'
      });
      expect(error).toBeDefined();
    });

    test('strips unknown fields', () => {
      const { value } = runValidation(networkAnalyzeSchema, {
        protocol_type: 'tcp',
        malicious_field: 'test'
      });
      expect(value.malicious_field).toBeUndefined();
    });
  });

  describe('codeScanSchema', () => {
    test('accepts valid code', () => {
      const { error } = runValidation(codeScanSchema, { code: 'console.log("hello")' });
      expect(error).toBeUndefined();
    });

    test('rejects empty code', () => {
      const { error } = runValidation(codeScanSchema, { code: '' });
      expect(error).toBeDefined();
    });

    test('rejects missing code', () => {
      const { error } = runValidation(codeScanSchema, {});
      expect(error).toBeDefined();
    });
  });

  describe('scanRepoSchema', () => {
    test('accepts valid GitHub URL', () => {
      const { error } = runValidation(scanRepoSchema, {
        repo_url: 'https://github.com/user/repo'
      });
      expect(error).toBeUndefined();
    });

    test('rejects non-GitHub URL', () => {
      const { error } = runValidation(scanRepoSchema, {
        repo_url: 'https://gitlab.com/user/repo'
      });
      expect(error).toBeDefined();
    });

    test('rejects http URL', () => {
      const { error } = runValidation(scanRepoSchema, {
        repo_url: 'http://github.com/user/repo'
      });
      expect(error).toBeDefined();
    });
  });

  describe('dastScanSchema', () => {
    test('accepts valid passive scan', () => {
      const { error, value } = runValidation(dastScanSchema, {
        target_url: 'https://example.com',
        mode: 'passive'
      });
      expect(error).toBeUndefined();
      expect(value.mode).toBe('passive');
    });

    test('defaults mode to passive', () => {
      const { value } = runValidation(dastScanSchema, {
        target_url: 'https://example.com'
      });
      expect(value.mode).toBe('passive');
    });

    test('rejects invalid mode', () => {
      const { error } = runValidation(dastScanSchema, {
        target_url: 'https://example.com',
        mode: 'aggressive'
      });
      expect(error).toBeDefined();
    });

    test('accepts verbose_evidence', () => {
      const { value } = runValidation(dastScanSchema, {
        target_url: 'https://example.com',
        verbose_evidence: true
      });
      expect(value.verbose_evidence).toBe(true);
    });
  });

  describe('authorizedTargetSchema', () => {
    test('accepts valid target', () => {
      const { error } = runValidation(authorizedTargetSchema, { target: 'example.com' });
      expect(error).toBeUndefined();
    });

    test('accepts target with note', () => {
      const { error } = runValidation(authorizedTargetSchema, {
        target: 'example.com',
        note: 'Test target'
      });
      expect(error).toBeUndefined();
    });

    test('rejects missing target', () => {
      const { error } = runValidation(authorizedTargetSchema, {});
      expect(error).toBeDefined();
    });
  });
});

describe('validate middleware', () => {
  test('calls next with valid data', () => {
    const req = { body: { code: 'test' }, id: '123' };
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();

    validate(codeScanSchema)(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('returns 400 with invalid data', () => {
    const req = { body: {}, id: '123' };
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();

    validate(codeScanSchema)(req, res, next);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});
