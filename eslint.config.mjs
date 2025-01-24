/* eslint-disable @typescript-eslint/naming-convention */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fixupConfigRules, fixupPluginRules } from '@eslint/compat';
import { FlatCompat } from '@eslint/eslintrc';
import js from '@eslint/js';
import tsParser from '@typescript-eslint/parser';
import jest from 'eslint-plugin-jest';
import perfectionist from 'eslint-plugin-perfectionist';
import prettier from 'eslint-plugin-prettier';
import security from 'eslint-plugin-security';
import globals from 'globals';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
  allConfig: js.configs.all,
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
});

export default [
  {
    ignores: ['**/node_modules', '**/bin'],
  },
  ...fixupConfigRules(
    compat.extends(
      'airbnb-base',
      'airbnb-typescript/base',
      'plugin:jest/recommended',
      'plugin:security/recommended',
      'plugin:import/errors',
      'plugin:import/warnings',
      'plugin:import/typescript',
      'plugin:@typescript-eslint/recommended',
      'plugin:prettier/recommended',
    ),
  ),
  {
    languageOptions: {
      ecmaVersion: 2018,

      globals: {
        ...globals.node,
        ...globals.jest,
        process: true,
      },
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.json',
      },
      sourceType: 'module',
    },
    plugins: {
      jest: fixupPluginRules(jest),
      perfectionist,
      prettier: fixupPluginRules(prettier),
      security: fixupPluginRules(security),
    },

    rules: {
      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_'}],
      'consistent-return': 'off',
      'func-names': 'off',
      'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
      'import/no-import-module-exports': 'off',
      'import/order': [
        'error',
        {
          alphabetize: {
            caseInsensitive: true,
            order: 'asc',
          },
          groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index'],

          'newlines-between': 'always',
        },
      ],
      'import/prefer-default-export': 'off',
      'jest/expect-expect': 'off',
      'no-console': 'error',
      'no-underscore-dangle': 'off',
      'perfectionist/sort-objects': [
        'error',
        {
          'custom-groups': {
            id: 'id',
          },
          groups: ['id', 'unknown'],
          order: 'asc',
          'partition-by-comment': 'Part:**',
        },
      ],
      'security/detect-object-injection': 'off',
      'sort-keys': 0,
    },

    settings: {
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts', '.tsx'],
      },
      'import/resolver': {
        node: {
          extensions: ['.js', '.jsx', '.ts', '.tsx'],
          moduleDirectory: ['node_modules', 'src/'],
        },
        typescript: {
          alwaysTryTypes: true,
        },
      },
    },
  },
];
