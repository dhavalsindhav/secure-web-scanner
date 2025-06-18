/**
 * Configuration for Jest
 */
module.exports = {
  testEnvironment: 'node',
  testTimeout: 10000,
  collectCoverage: true,
  collectCoverageFrom: [
    'lib/**/*.js',
    '!lib/browser.js', // Skip browser-dependent code
    '!**/node_modules/**'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  },
  testMatch: [
    '**/tests/**/*.js'
  ],
  verbose: true
};
