module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/cli/index.ts', // Entry point
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@core/(.*)$': '<rootDir>/src/core/$1',
    '^@mcp-servers/(.*)$': '<rootDir>/src/mcp-servers/$1',
    '^@cli/(.*)$': '<rootDir>/src/cli/$1',
    '^@monitoring/(.*)$': '<rootDir>/src/monitoring/$1',
    '^@web/(.*)$': '<rootDir>/src/web/$1',
  },
};