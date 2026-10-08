// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The `loom-lpc` language definition (OBI-180 M-IDE-4: "edit the object
 * source"). Registering a language is the one thing that must happen
 * before the first model is created, so it lives apart from the widget
 * in ./editor.ts and is testable on its own -- the tokenizer is pure
 * data-in/text-out.
 *
 * LPC here means the dialect `loom-syntax` parses (the driver's own
 * parser, not a third-party MUD's): `#include`/`#define` preprocessor
 * lines, `object`/`string`/`int`/`mixed`/`mapping` types, `::` scope
 * resolution, `->$()` dynamic calls, and the mudlib's `this_object()` /
 * `this_player()` efuns.
 *
 * The keyword and efun lists are *display* data only -- nothing here
 * decides what is legal, the compiler does. Which is also why the
 * `monarch` tokenizer is fine: it needs to be fast and good enough to
 * colour a file, not to parse it. A real grammar would duplicate
 * `loom-syntax` in TypeScript and drift; the diagnostics come from the
 * driver (`POST /api/v1/files/compile`) and, once PR #122 is merged,
 * from `loom-lsp` over `/lsp` (M-LSP-3).
 */

/** The language id every model in the IDE uses. */
export const LPC_LANGUAGE = "loom-lpc";

/** `language/loom-lpc` keyword list, from `loom-syntax`'s parser. */
export const LPC_KEYWORDS = [
  "break",
  "case",
  "catch",
  "continue",
  "default",
  "do",
  "else",
  "foreach",
  "for",
  "if",
  "in",
  "inherit",
  "new",
  "return",
  "sizeof",
  "spawn",
  "switch",
  "while",
] as const;

export const LPC_TYPES = [
  "int",
  "string",
  "object",
  "mapping",
  "mixed",
  "float",
  "closure",
  "symbol",
  "status",
  "void",
  "static",
  "private",
  "protected",
  "public",
  "var",
] as const;

/** The efuns a builder sees most often. A subset, on purpose: the full
 * table is `crates/loom-compiler/src/efuns.rs`, and the IDE's colouring
 * must not become a second copy of that list to keep in sync. Hover and
 * completion are `loom-lsp`'s job (M-LSP-3). */
export const LPC_EFUNS = [
  "this_object",
  "this_player",
  "previous_object",
  "file_name",
  "load_object",
  "clone_object",
  "destruct",
  "catch",
  "error",
  "printf",
  "write",
  "sprintf",
  "allocate",
  "members",
  "export_vars",
  "query_verb",
  "add_action",
  "present",
  "environment",
  "all_inventory",
  "shadow",
  "unshadow",
  "remove_object",
  "set_heart_beat",
  "call_other",
  "call_out",
  "time",
  "ctime",
  "random",
  "to_int",
  "to_string",
  "to_float",
  "sizeof",
  "explode",
  "implode",
  "reply",
  "input_to",
  "get_char",
] as const;

/** Monaco's `languageConfiguration` shape, restated locally for the same
 * reason as `./editor-port.ts`: the AMD build is not typed-imported. */
export interface LanguageConfiguration {
  comments: { lineComment: string; blockComment: [string, string] };
  brackets: [string, string][];
  autoClosingPairs: { open: string; close: string; notIn?: string[] }[];
  surroundingPairs: { open: string; close: string }[];
}

export function lpcLanguageConfiguration(): LanguageConfiguration {
  return {
    comments: { lineComment: "//", blockComment: ["/*", "*/"] },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    // `#include <telnet.h>` would otherwise auto-close the `<` into
    // `<telnet.h>>`; `notIn` excludes preprocessor lines.
    autoClosingPairs: [
      { open: "{", close: "}", notIn: ["string", "comment"] },
      { open: "[", close: "]", notIn: ["string", "comment"] },
      { open: "(", close: ")", notIn: ["string", "comment"] },
      { open: '"', close: '"', notIn: ["comment"] },
      { open: "'", close: "'", notIn: ["comment", "string"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
  };
}

/**
 * The monarch tokenizer. Kept as data so `./lpc.test.ts` can run it
 * through a fake tokenizer helper instead of needing Monaco: `rules` is
 * `[regex, actions]` in first-match order, exactly what monarch expects.
 */
/** `regex` is `string | RegExp` because monarch accepts both, and a
 * `RegExp` literal is checked by TypeScript at the definition site -- a
 * malformed character class in a *string* rule would only surface as a
 * silent tokenizer failure in the browser. */
export type MonarchRule =
  | [string | RegExp, unknown]
  // The three-element form is monarch's action list: `[regex, action,
  // "@pop"]` pushes/pops a state, which `comment` and `preprocessor` need.
  | [string | RegExp, unknown, string];

export interface MonarchRules {
  readonly tokenizer: {
    readonly root: readonly MonarchRule[];
    readonly comment: readonly MonarchRule[];
    readonly preprocessor: readonly MonarchRule[];
  };
}

export function lpcTokenizer(): MonarchRules {
  return {
    tokenizer: {
      root: [
        [/#\s*\w+/, "@preprocessor"],
        [/\/\/.*$/, "comment"],
        [/\/\*/, "comment", "@comment"],
        [/\\"/, "string.escape"],
        [/"(?:[^"\\\n]|\\.)*"/, "string"],
        [/'(?:[^'\\\n]|\\.)*'/, "string"],
        [/\b\d[\d_]*\b/, "number"],
        [/\b0[xX][\da-fA-F]+/, "number.hex"],
        [/[a-zA-Z_]\w*/, {
          cases: {
            // `(?:...)` matters: `^a|b$` parses as `(^a)|(b$)`, which
            // would colour any identifier ending in a keyword.
            [`^(?:${LPC_KEYWORDS.join("|")})$`]: "keyword",
            [`^(?:${LPC_TYPES.join("|")})$`]: "type",
            [`^(?:${LPC_EFUNS.join("|")})$`]: "keyword.predefined",
            "@default": "identifier",
          },
        }],
        [/[{}()[\]]/, "@brackets"],
        [/::|->|\.\.\.|[=<>!*/%&|^~?:;+-]/, "delimiter"],
      ],
      comment: [
        [/[^\/*]+/, "comment"],
        [/\*\//, "comment", "@pop"],
        [/[\/*]/, "comment"],
      ],
      preprocessor: [
        [/[^\n]+/, "metatag"],
        [/\n/, "", "@pop"],
      ],
    },
  };
}
