import type { Config } from '@jest/types';

const config: Config.InitialOptions = {
  coveragePathIgnorePatterns: ['__tests__', 'node_modules'],
  preset: 'ts-jest',
  reporters: ['default', ['jest-junit', { outputName: 'test-report.xml' }]],
  setupFilesAfterEnv: ['./src/__tests__/test-setup.ts'],
  silent: true,
  testEnvironment: 'node',
  testMatch: ['**/?(*.)+(spec|test).ts?(x)'],
  testPathIgnorePatterns: ['node_modules'],
  testTimeout: 30000,
  verbose: true,
};

export default config;
