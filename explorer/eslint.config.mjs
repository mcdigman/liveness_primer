// ESLint configuration for the explorer (explorer contract §8, §10).
//
// The DOM/injection-safety rules enforce §8 mechanically: no HTML sinks,
// no eval, no dynamic code in project application code. Library internals
// under node_modules are outside this boundary.
import js from '@eslint/js';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';

const sharedGlobals = {
  Blob: 'readonly',
  File: 'readonly',
  FileReader: 'readonly',
  Response: 'readonly',
  TextDecoder: 'readonly',
  TextEncoder: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  Worker: 'readonly',
  AbortController: 'readonly',
  console: 'readonly',
  crypto: 'readonly',
  document: 'readonly',
  fetch: 'readonly',
  getComputedStyle: 'readonly',
  globalThis: 'readonly',
  localStorage: 'readonly',
  matchMedia: 'readonly',
  navigator: 'readonly',
  requestAnimationFrame: 'readonly',
  self: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  structuredClone: 'readonly',
  window: 'readonly',
  CustomEvent: 'readonly',
  process: 'readonly',
  Buffer: 'readonly',
};

const safetyRules = {
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-restricted-properties': [
    'error',
    { property: 'innerHTML', message: 'Untrusted values must never reach HTML sinks (explorer §8).' },
    { property: 'outerHTML', message: 'Untrusted values must never reach HTML sinks (explorer §8).' },
    { property: 'insertAdjacentHTML', message: 'Untrusted values must never reach HTML sinks (explorer §8).' },
    { property: 'dangerouslySetInnerHTML', message: 'Raw HTML rendering is forbidden (explorer §8).' },
    { object: 'document', property: 'write', message: 'document.write is forbidden (explorer §8).' },
    { object: 'document', property: 'writeln', message: 'document.writeln is forbidden (explorer §8).' },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'Raw HTML rendering is forbidden (explorer §8).',
    },
    {
      selector:
        "CallExpression[callee.object.name='document'][callee.property.name='createElement'][arguments.0.value='script']",
      message: 'Dynamic script creation is forbidden (explorer §8).',
    },
  ],
  'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  eqeqeq: ['error', 'always'],
  'prefer-const': 'error',
};

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'playwright-report/**',
      'test-results/**',
      'src/generated/validators.js',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'src/**/*.jsx', 'build.mjs', 'generate-validators.mjs', 'tests/**', '*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: sharedGlobals,
    },
    rules: safetyRules,
  },
  {
    files: ['src/**/*.jsx'],
    plugins: { react, 'react-hooks': reactHooks },
    rules: {
      'react/jsx-uses-vars': 'error',
      'react/jsx-key': 'error',
      'react/jsx-no-target-blank': 'error',
      'react/no-danger': 'error',
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
    },
    settings: { react: { version: 'detect' } },
  },
];
