import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // The transport tests spawn a real server process.
    testTimeout: 20_000
  }
});
