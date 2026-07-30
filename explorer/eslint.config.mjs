// ESLint configuration for the explorer (explorer contract §17).
//
// The DOM/injection-safety rules enforce §14.1 mechanically: no HTML
// sinks, no eval, no dynamic code, in production application code.
import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'build.mjs', 'generate-schemas.mjs', 'tests/**/*.mjs', 'tests/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        crypto: 'readonly',
        document: 'readonly',
        fetch: 'readonly',
        globalThis: 'readonly',
        localStorage: 'readonly',
        navigator: 'readonly',
        window: 'readonly',
        structuredClone: 'readonly',
        Blob: 'readonly',
        DataTransfer: 'readonly',
        File: 'readonly',
        Response: 'readonly',
        SubtleCrypto: 'readonly',
        TextDecoder: 'readonly',
        TextEncoder: 'readonly',
        URL: 'readonly',
        Worker: 'readonly',
        process: 'readonly',
      },
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Untrusted values must never reach HTML sinks (explorer §14.1).' },
        { property: 'outerHTML', message: 'Untrusted values must never reach HTML sinks (explorer §14.1).' },
        { property: 'insertAdjacentHTML', message: 'Untrusted values must never reach HTML sinks (explorer §14.1).' },
        { object: 'document', property: 'write', message: 'document.write is forbidden (explorer §14.1).' },
        { object: 'document', property: 'writeln', message: 'document.writeln is forbidden (explorer §14.1).' },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.object.name='document'][callee.property.name='createElement'][arguments.0.value='script']",
          message: 'Dynamic script creation is forbidden (explorer §14.1).',
        },
      ],
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      eqeqeq: ['error', 'always'],
      'prefer-const': 'error',
    },
  },
];
