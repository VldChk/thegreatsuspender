import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';

const recommended = js.configs.recommended;

export default [
  {
    ignores: ['dist/**'],
  },
  recommended,
  {
    files: ['extension/**/*.js'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        chrome: 'readonly',
      },
    },
    rules: {
      'no-console': 'off',
      'no-unused-vars': [
        'error',
        { vars: 'all', args: 'none', ignoreRestSiblings: false, caughtErrors: 'none' },
      ],
      'no-undef': ['error'],
      'no-proto': ['error'],
      'prefer-spread': ['warn'],
      'padded-blocks': ['off', { blocks: 'never' }],
      'one-var': ['off', 'never'],
      'spaced-comment': ['off', 'always'],
    },
  },
  {
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',
    },
  },
  eslintConfigPrettier,
];
