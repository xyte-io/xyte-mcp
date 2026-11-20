import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // vitest.config.ts sits outside the tsconfig projects, and the old explicit
    // folder list never linted it either.
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/tests/fixtures/**',
      '**/vitest.config.ts'
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname }
    }
  },

  {
    // On stdio, stdout carries the JSON-RPC frames. A single stray console.log
    // corrupts the stream and the host drops the connection. Diagnostics must
    // go through packages/mcp/src/log.ts, which writes to stderr.
    files: ['packages/*/src/**/*.ts'],
    rules: {
      'no-console': 'error'
    }
  },

  {
    // Tools must be pure functions of (args, ctx). Keeping environment access
    // and transport knowledge out of them is what lets a future HTTP/OAuth
    // transport supply per-request credentials without touching tool code.
    files: ['packages/*/src/tools/**/*.ts'],
    rules: {
      'no-restricted-properties': [
        'error',
        {
          object: 'process',
          property: 'env',
          message:
            'Tools must not read the environment. Take what you need from ToolContext instead.'
        }
      ],
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/transports/**', '**/config.js', '../config.js'],
              message:
                'Tools must stay transport- and configuration-agnostic. Use ToolContext instead.'
            }
          ]
        }
      ]
    }
  },

  {
    files: ['packages/*/tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off'
    }
  },

  {
    files: ['packages/*/scripts/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked
  },
  {
    // Maintainer scripts are plain Node ESM: console/process are expected here.
    files: ['packages/*/scripts/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        fetch: 'readonly',
        AbortSignal: 'readonly'
      }
    }
  }
);
