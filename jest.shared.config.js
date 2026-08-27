// Jest config for the shared runtime modules (e.g. the triage engine).
// Run with: npx jest --config jest.shared.config.js backend/shared/triage
module.exports = {
  testEnvironment: 'node',
  rootDir: __dirname,
  roots: ['<rootDir>/backend/shared'],
  testMatch: ['**/__tests__/**/*.test.js'],
  collectCoverageFrom: [
    '<rootDir>/backend/shared/triage/**/*.js',
    '!**/node_modules/**',
    '!**/__tests__/**'
  ],
  coverageDirectory: '<rootDir>/coverage/shared',
  coverageThreshold: {
    global: {
      lines: 80,
      statements: 80,
      functions: 80,
      branches: 80
    }
  }
};
