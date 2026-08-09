module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2022: true,
    node: true,
    jest: true
  },
  extends: [
    'eslint:recommended',
    'prettier'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    'indent': ['error', 2],
    'linebreak-style': ['error', 'unix'],
    'quotes': ['error', 'single', { avoidEscape: true }],
    'semi': ['error', 'always'],
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    'no-console': ['warn', { allow: ['warn', 'error'] }],
    'prefer-const': 'error',
    'no-var': 'error',
    'object-shorthand': 'error',
    'prefer-arrow-callback': 'error',
    'arrow-spacing': 'error',
    'no-trailing-spaces': 'error',
    'eol-last': 'error',
    'max-len': ['warn', { code: 120 }],
    'complexity': ['warn', 15],
    'max-depth': ['warn', 4],
    'max-nested-callbacks': ['warn', 4]
  },
  overrides: [
    {
      files: ['client/**/*.js'],
      env: {
        browser: true,
        es2022: true
      },
      rules: {
        'no-console': 'off',
        'no-unused-vars': 'warn'
      }
    },
    {
      files: ['__tests__/**/*.test.js'],
      env: {
        jest: true
      },
      rules: {
        'no-unused-vars': 'off'
      }
    }
  ],
  ignorePatterns: ['node_modules/', 'dist/', 'coverage/', 'client/', 'python-ai/', '*.pkl']
};