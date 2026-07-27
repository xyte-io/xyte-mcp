import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // The protocol smoke test spawns a real server process.
    testTimeout: 20_000
  }
});
