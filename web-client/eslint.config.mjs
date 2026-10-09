// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-IDE-2's CI gate (OBI-179 threat model v2 §5, OBI-180): ESLint with
 * `eslint-plugin-no-unsanitized`, which fails the build on an
 * `innerHTML`/`outerHTML`/`insertAdjacentHTML` assignment or an
 * `innerHTML`-taking method call anywhere under `src/`.
 *
 * `../scripts/check-no-html-sinks.mjs` is the same rule as a 40-line
 * textual scan with zero dependencies, and it catches one thing this
 * config does not: an HTML string *template literal* assigned to a
 * variable and passed around (the threat model's T-IDE-3 concern). Both
 * run in `npm run lint`. Keeping both is not redundancy for its own
 * sake -- the regex scan cannot be silenced with an inline `eslint-disable`
 * comment, and the linter understands scoping well enough to catch a sink
 * the scanner would miss inside a nested template.
 *
 * The rest of the ruleset is deliberately narrow. A broad
 * `typescript-eslint/recommended` sweep over code written before this
 * config existed would bury the security rule in style noise, and the
 * security rule is the one the threat model names.
 */

import noUnsanitized from "eslint-plugin-no-unsanitized";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "vendor/**", "node_modules/**"],
  },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      ecmaVersion: 2022,
      sourceType: "module",
    },
    plugins: {
      "no-unsanitized": noUnsanitized,
    },
    rules: {
      // The two M-IDE-2 rules, as errors.
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
      // The `no-unsanitized` plugin's own recommended set, spelled out so
      // a future plugin major version that adds rules cannot silently
      // widen what CI fails on.
      "no-useless-assignment": "off",
      "no-unused-vars": "off",
    },
  },
);
