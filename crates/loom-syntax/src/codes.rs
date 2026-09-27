// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The `W####` diagnostic code registry (OBI-49, design spec v2 §5.9).
//!
//! Every diagnostic `loom-syntax` and `loom-compiler` (and the loom-vm
//! Phase 0 linker/gate) emit carries one of these codes, attached to the
//! [`crate::Diagnostic`] struct so both the ariadne-style text rendering
//! (`error[W0201]: ...`) and the future LSP JSON (spec §5.9) carry it.
//! Severity is a separate field on the diagnostic, not part of the code.
//!
//! Numbers are assigned by phase and are never reused or renumbered:
//! - `00xx` -- lexer / parser (`loom-syntax`)
//! - `01xx` -- resolver / imports / inherit (`loom-compiler`)
//! - `02xx` -- gradual type checker (`loom-compiler`)
//! - `03xx` -- link: efun arity, redeclaration, unknown names (`loom-vm`
//!   Phase 0 linker; this becomes the Phase 1 bytecode linker later)
//! - `04xx` -- Phase 0 evaluator gates ("not yet supported")
//! - `09xx` -- warnings and lints
//!
//! A code that stops being emitted is retired, not deleted or reused: see
//! [`RETIRED`]. `tests::no_duplicate_codes` fails the build on a collision.
//!
//! This file is generated from the call sites by a one-off script
//! (`assign_codes.py`, since removed); new codes are added by hand from
//! here on -- pick the next unused number in the right range.

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $desc:literal;)*) => {
        $(
            $(#[$doc])*
            pub const $name: &str = $code;
        )*
        /// Every live code with its one-line description, in declaration order.
        pub const REGISTRY: &[(&str, &str)] = &[
            $(($name, $desc)),*
        ];
    };
}

codes! {
    // 00xx -- lexer / parser
    LEX_UNTERMINATED_BLOCK_COMMENT = "W0001", "unterminated block comment";
    LEX_INVALID_WHAT_LITERAL = "W0002", "invalid {what} literal";
    LEX_FLOAT_LITERAL_OUT_RANGE_FLOAT = "W0003", "float literal is out of range for `float` (64-bit)";
    LEX_INTEGER_LITERAL_TOO_LARGE_INT = "W0004", "integer literal is too large for `int` (64-bit)";
    LEX_UNKNOWN_ESCAPE_SEQUENCE = "W0005", "unknown escape sequence";
    LEX_UNCLOSED_INTERPOLATED_STRING = "W0006", "unclosed `{` in interpolated string";
    LEX_EMPTY_INTERPOLATED_STRING = "W0007", "empty `{}` in interpolated string";
    LEX_UNTERMINATED_STRING_LITERAL = "W0008", "unterminated string literal";
    LEX_UNEXPECTED_CHARACTER_LPC_C_STYLE = "W0009", "unexpected character (LPC/C-style syntax not used by Weft)";
    PARSE_EXPECTED = "W0030", "expected one syntactic construct but found another token";
    PARSE_EXPECTED_WHAT_FOUND_KEYWORD_KW = "W0032", "expected {what}, found keyword {kw}";
    PARSE_CODE_NESTED_TOO_DEEPLY = "W0033", "code is nested too deeply";
    PARSE_LIGHTWEIGHT_DECLARED_TWICE = "W0034", "`lightweight` is declared twice";
    PARSE_WHAT_MUST_COME_BEFORE_ANY = "W0035", "`{what}` must come before any declarations";
    PARSE_WHAT_PATHS_NOT_QUOTED = "W0036", "{what} paths are not quoted";
    PARSE_EXPECTED_PATH_SEGMENT_AFTER = "W0037", "expected a path segment after `/`";
    PARSE_INHERIT_PATHS_HAVE_NO_FILE = "W0038", "inherit paths have no file extension";
    PARSE_EMPTY_IMPORT_LIST = "W0039", "empty import list";
    PARSE_IMPORT_PATHS_HAVE_NO_FILE = "W0040", "import paths have no file extension";
    PARSE_DUPLICATE_MODIFIER_NAME = "W0041", "duplicate modifier `{name}`";
    PARSE_DECLARATION_CANNOT_BE_BOTH_FIRST = "W0042", "a declaration cannot be both `{first}` and `{second}`";
    PARSE_NAME_APPLIES_APPLIES_NOT = "W0043", "`{name}` applies to {applies}, not {}";
    PARSE_PROGRAM_VARIABLE_NEEDS_TYPE_OR = "W0044", "a program variable needs a type or an initial value";
    PARSE_CONSTANT_NEEDS_VALUE = "W0045", "a constant needs a value";
    PARSE_TOP_LEVEL_FUNCTION_NEEDS_NAME = "W0046", "a top-level function needs a name";
    PARSE_WHAT_TAKES_NO_MODIFIERS = "W0047", "{what} takes no modifiers";
    PARSE_LET_ONLY_ALLOWED_INSIDE_FUNCTIONS = "W0048", "`let` is only allowed inside functions";
    PARSE_UNMATCHED = "W0049", "unmatched `}`";
    PARSE_NEVER_CLOSED = "W0050", "this `{` is never closed";
    PARSE_NOT_CLOSED_BEFORE_NEXT_DECLARATION = "W0051", "this `{` is not closed before the next declaration";
    PARSE_PARAMETER_MUST_BE_LAST = "W0052", "the `...{}` parameter must be last";
    PARSE_REST_PARAMETER_CANNOT_HAVE_DEFAULT = "W0053", "a `...rest` parameter cannot have a default";
    PARSE_NEVER_CLOSED_2 = "W0054", "this `{` is never closed";
    PARSE_NOT_CLOSED_BEFORE_NEXT_DECLARATION_2 = "W0055", "this `{` is not closed before the next declaration";
    PARSE_EXPECTED_END_STATEMENT_FOUND_FOUND = "W0056", "expected end of statement, found {found}";
    PARSE_LET_NEEDS_INITIAL_VALUE = "W0057", "`let` needs an initial value";
    PARSE_WHILE_LET_NOT_PART_WEFT = "W0058", "`while let` is not part of Weft";
    PARSE_THROW_NEEDS_ERROR_VALUE = "W0059", "`throw` needs an error value";
    PARSE_TRY_NEEDS_CATCH_BLOCK = "W0060", "`try` needs a `catch` block";
    PARSE_CATCH_WITHOUT_MATCHING_TRY = "W0061", "`catch` without a matching `try`";
    PARSE_ELSE_WITHOUT_MATCHING_IF = "W0062", "`else` without a matching `if`";
    PARSE_WHAT_ONLY_ALLOWED_AT_TOP = "W0063", "{what} is only allowed at the top level of a file";
    PARSE_CANNOT_ASSIGN_EXPRESSION = "W0064", "cannot assign to this expression";
    PARSE_EXPECTED_START_KW_BODY_FOUND = "W0065", "expected `{{` to start the `{kw}` body, found {found}";
    PARSE_EXPECTED_AFTER_CONDITION_FOUND = "W0066", "expected `{{` after the condition, found {}";
    PARSE_EXPECTED_OR_IF_AFTER_ELSE = "W0067", "expected `{{` or `if` after `else`, found {}";
    PARSE_NOT_CALL_OPERATOR_WEFT = "W0068", "`->` is not a call operator in Weft";
    PARSE_UNEXPECTED_EXPRESSION = "W0069", "unexpected `|` in an expression";
    PARSE_COMPARISON_OPERATORS_CANNOT_BE_CHAINED = "W0070", "comparison operators cannot be chained";
    PARSE_AMBIGUOUS = "W0071", "`{}` is ambiguous";
    PARSE_NAMED_FUNCTION_CANNOT_BE_DECLARED = "W0072", "a named function cannot be declared inside an expression";
    PARSE_FUNCTION_NAME_AFTER_SCOPE = "W0073", "a function name after `{scope}::`";
    PARSE_SCOPE_MUST_BE_CALLED = "W0074", "`{scope}::{}` must be called";
    PARSE_ENUM_VARIANTS_NOT_WRITTEN = "W0075", "enum variants are not written with `::`";
    PARSE_N_NOT_PATTERN = "W0076", "`{n}(…)` is not a pattern";
    PARSE_INTERPOLATED_STRINGS_CANNOT_BE_PATTERNS = "W0077", "interpolated strings cannot be patterns";
    PARSE_STRUCT_FIELD_NEEDS_TYPE = "W0078", "struct field `{}` needs a type";
    PARSE_ENUM_VARIANT_NO_EXPLICIT_VALUES = "W0079", "enum variants have no explicit values";
    PARSE_FN_TYPE_PARAM_NAMES_NOT_ALLOWED = "W0080", "function types list parameter types only";
    PARSE_POSITIONAL_ARG_AFTER_NAMED = "W0081", "positional argument after a named argument";
    PARSE_STRUCT_LIT_FIELD_NEEDS_COLON = "W0082", "expected `:` after field `{}`";

    // 01xx -- resolver / imports / inherit
    IFACE_INHERIT_LABEL_L_USED_TWICE = "W0100", "inherit label `{l}` is used twice";
    IFACE_INHERITED_TWICE = "W0101", "`{}` is inherited twice";
    IFACE_VARIABLE_NAME_INHERITED_FROM_BOTH = "W0102", "variable `{name}` is inherited from both {} and {}";
    IFACE_CONST_NAME_INHERITED_FROM_BOTH = "W0103", "const `{name}` is inherited from both {} and {}";
    IFACE_TYPE_INHERITED_WITH_DIFFERENT_SHAPES = "W0104", "type `{name}` is inherited from more than one parent with different shapes";
    MUDLIB_INVALID_PROGRAM_PATH_NOT_ABSOLUTE = "W0110", "invalid program path (not absolute, or a bad segment)";
    MUDLIB_WHAT_CHAIN_TOO_DEEP = "W0111", "{what} chain is too deep";
    MUDLIB_WHAT_CYCLE_THROUGH_PPATH = "W0112", "{what} cycle through {ppath}";
    MUDLIB_CANNOT_WHAT_PPATH_HAS_ERRORS = "W0113", "cannot {what} {ppath}: it has errors";
    MUDLIB_CANNOT_WHAT_PPATH_PPATH_WF = "W0114", "cannot {what} {ppath}: {ppath}.wf does not exist";

    // 02xx -- gradual type checker
    CHECK_HAS_TYPE_T_BUT_NO = "W0200", "`{}` has type `{t}` but no initial value";
    CHECK_NEEDS_TYPE = "W0201", "`{}` needs a type";
    CHECK_DOES_NOT_EXPORT_CONST_NAMED = "W0202", "`{}` does not export a const named `{n}`";
    CHECK_IMPORTED_FROM_BOTH_AND = "W0203", "`{}` is imported from both {} and {}";
    CHECK_DECLARED_TWICE_PROGRAM = "W0204", "`{}` is declared twice in this program";
    CHECK_VARIABLE_ALREADY_DECLARED = "W0205", "variable `{}` is already declared in {}";
    CHECK_DECLARED_TWICE_PROGRAM_2 = "W0206", "`{}` is declared twice in this program";
    CHECK_CONST_ALREADY_DECLARED = "W0207", "const `{}` is already declared in {}";
    CHECK_DECLARED_TWICE_PROGRAM_3 = "W0210", "`{}` is declared twice in this program";
    CHECK_FUNCTION_NAME_INHERITED_FROM_BOTH = "W0211", "function `{name}` is inherited from both {}";
    CHECK_PARAMETER_DECLARED_TWICE = "W0212", "parameter `{}` is declared twice";
    CHECK_PARAMETER_NEEDS_TYPE = "W0213", "parameter `{}` needs a type";
    CHECK_PARAMETER_WITHOUT_DEFAULT_FOLLOWS_ONE = "W0214", "a parameter without a default follows one with a default";
    CHECK_PRIVATE_FN_NAME_CANNOT_BE = "W0215", "`private fn {name}` cannot be an `override`";
    CHECK_OVERRIDE_FN_NAME_OVERRIDES_NOTHING = "W0216", "`override fn {name}` overrides nothing";
    CHECK_NAME_REDEFINES_FUNCTION_INHERITED_FROM = "W0217", "`{name}` redefines a function inherited from {}";
    CHECK_NAME_FINAL_AND_CANNOT_BE = "W0218", "`{name}` is `final` in {} and cannot be overridden";
    CHECK_OVERRIDE_FN_NAME_DOES_NOT = "W0219", "`override fn {name}` does not match the inherited signature `{}` from {}";
    CHECK_OVERRIDE_FN_NAME_MUST_STAY = "W0220", "`override fn {name}` must stay `pub` like the inherited function";
    CHECK_ERROR_TYPE_NOT_IMPLEMENTED_YET = "W0221", "the `error` type is not implemented yet";
    CHECK_UNKNOWN_TYPE_N = "W0222", "unknown type `{n}`";
    CHECK_MAY_REACH_ITS_END_WITHOUT = "W0223", "`{}` may reach its end without returning a value";
    CHECK_UNKNOWN_VARIABLE_N = "W0224", "unknown variable `{n}`";
    CHECK_CALL_RETURNS_NO_VALUE = "W0225", "this call returns no value";
    CHECK_MISMATCHED_TYPES_EXPECTED_ONE_TYPE = "W0226", "mismatched types: expected one type, found another";
    CHECK_WHAT_MUST_BE_BOOL_FOUND = "W0228", "{what} must be `bool`, found `{ty}`";
    CHECK_CANNOT_INFER_TYPE_NAME_FROM = "W0229", "cannot infer a type for `{name}` from `null`";
    CHECK_HAS_TYPE_T_BUT_NO_2 = "W0230", "`{}` has type `{t}` but no initial value";
    CHECK_NEEDS_TYPE_OR_INITIAL_VALUE = "W0231", "`{}` needs a type or an initial value";
    CHECK_CANNOT_ITERATE_OVER_T_MAY = "W0232", "cannot iterate over `{t}`: it may be null";
    CHECK_CANNOT_ITERATE_OVER_T = "W0233", "cannot iterate over `{t}`";
    CHECK_RETURN_OUTSIDE_FUNCTION = "W0234", "`return` outside a function";
    CHECK_FNAME_HAS_NO_RETURN_TYPE = "W0235", "`{fname}` has no return type, so it cannot return a value";
    CHECK_FNAME_MUST_RETURN_VALUE_TYPE = "W0236", "`{fname}` must return a value of type `{t}`";
    CHECK_IF_LET_NOT_IMPLEMENTED_TYPE = "W0237", "`if let` is not implemented by the type checker yet";
    CHECK_BREAK_AND_CONTINUE_NOT_IMPLEMENTED = "W0238", "`break` and `continue` are not implemented by the type checker yet";
    CHECK_CANNOT_ASSIGN_N_WAS_DECLARED = "W0241", "cannot assign to `{n}`: it was declared with `let`";
    CHECK_CANNOT_ASSIGN_N_CONST = "W0242", "cannot assign to `{n}`: it is a `const`";
    CHECK_CANNOT_ASSIGN_SELF = "W0243", "cannot assign to `self`";
    CHECK_CANNOT_ASSIGN_FUNCTION_N = "W0244", "cannot assign to function `{n}`";
    CHECK_CANNOT_ASSIGN_INTO_STRING = "W0245", "cannot assign into a string";
    CHECK_CANNOT_ASSIGN_EXPRESSION = "W0246", "cannot assign to this expression";
    CHECK_MISMATCHED_TYPES_ASSIGNMENT_EXPECTED_PTY = "W0247", "mismatched types in the assignment: expected `{pty}`, found `{rty}`";
    CHECK_CANNOT_NEGATE_VALUE_TYPE_T = "W0248", "cannot negate a value of type `{t}`";
    CHECK_CANNOT_CALL_ON_VALUE_MAY = "W0249", "cannot call `.{}()` on a value that may be null (`object?`)";
    CHECK_CANNOT_CALL_ON_VALUE_TYPE = "W0250", "cannot call `.{}()` on a value of type `{t}`";
    CHECK_SLICES_LO_HI_NOT_IMPLEMENTED = "W0251", "slices (`a[lo..hi]`) are not implemented by the type checker yet";
    CHECK_FIELD_ACCESS_NOT_IMPLEMENTED_TYPE = "W0252", "field access is not implemented by the type checker yet";
    CHECK_MATCH_NOT_IMPLEMENTED_TYPE_CHECKER = "W0253", "`match` is not implemented by the type checker yet";
    CHECK_STRUCT_LITERALS_NOT_IMPLEMENTED_TYPE = "W0254", "struct literals are not implemented by the type checker yet";
    CHECK_ENUM_VARIANTS_NOT_IMPLEMENTED_TYPE = "W0255", "enum variants are not implemented by the type checker yet";
    CHECK_NAMED_ARGUMENTS_NOT_IMPLEMENTED_TYPE = "W0256", "named arguments are not implemented by the type checker yet";
    CHECK_SPREAD_ARGUMENTS_EXPR_NOT_IMPLEMENTED = "W0257", "spread arguments (`...expr`) are not implemented by the type checker yet";
    CHECK_CANNOT_CAST_AS = "W0258", "cannot cast `{}` as `{to}`";
    CHECK_CANNOT_CAST_FROM_AS = "W0259", "cannot cast `{from}` as `{to}`";
    CHECK_CLOSURE_PARAMETER_NEEDS_TYPE_ANNOTATION = "W0260", "closure parameter `{}` needs a type annotation";
    CHECK_CLOSURE_PARAMETERS_CANNOT_HAVE_DEFAULTS = "W0261", "closure parameters cannot have defaults";
    CHECK_CLOSURE_MAY_REACH_ITS_END = "W0262", "this closure may reach its end without returning a value";
    CHECK_ARRAY_ELEMENTS_HAVE_DIFFERENT_TYPES = "W0263", "array elements have different types: `{prev}` and `{t}` (element {})";
    CHECK_T_CANNOT_BE_MAP_KEY = "W0264", "`{t}` cannot be a map key";
    CHECK_WHAT_HAVE_DIFFERENT_TYPES_PREV = "W0265", "{what} have different types: `{prev}` and `{t}`";
    CHECK_CANNOT_INDEX_VALUE_MAY_BE = "W0266", "cannot index a value that may be null (`{t}`)";
    CHECK_CANNOT_INDEX_VALUE_TYPE_T = "W0267", "cannot index a value of type `{t}`";
    CHECK_CANNOT_APPLY_ARITHMETIC_COMPARISON_OPERATOR = "W0268", "cannot apply an arithmetic/comparison operator to these two types";
    CHECK_MISMATCHED_TYPES_LEFT_SIDE_LT = "W0270", "mismatched types in `??`: the left side is `{lt}`, the fallback is `{rt}`";
    CHECK_ORDERING_WORKS_ON_TWO_INTS = "W0271", "ordering works on two ints, two floats or two strings";
    CHECK_ON_STRING_NEEDS_STRING_ON = "W0272", "`in` on a string needs a string on the left, found `{t}`";
    CHECK_NEEDS_ARRAY_MAP_OR_STRING = "W0273", "`in` needs an array, map or string on the right, found `{t}`";
    CHECK_CANNOT_COMPARE_B_USING_SYM = "W0274", "cannot compare `{a}` with `{b}` using `{sym}`";
    CHECK_FNAME_TAKES_BUT = "W0275", "`{fname}` takes {}, but {}";
    CHECK_UNKNOWN_FUNCTION_N = "W0276", "unknown function `{n}`";
    CHECK_WHAT_HAS_TYPE_T_WHICH = "W0277", "`{what}` has type `{t}`, which is not a function";
    CHECK_N_TAKES_BUT = "W0278", "`{n}` takes {}, but {}";
    CHECK_MISMATCHED_TYPES_WHAT_EXPECTED_STRING = "W0279", "mismatched types in {what}: expected a string, array or map, found `{t}`";
    CHECK_MISMATCHED_TYPES_WHAT_EXPECTED_MAP = "W0280", "mismatched types in {what}: expected a map, found `{t}`";
    CHECK_NO_INHERIT_LABELLED = "W0281", "no inherit is labelled `{}`";
    CHECK_NO_INHERITED_FUNCTION_NAME = "W0282", "`{}{}`: no inherited function with this name";
    CHECK_AMBIGUOUS_INHERITED_FROM = "W0283", "`{}{}` is ambiguous: it is inherited from {}";
    CHECK_VAR_STORES_OBJECT_MUST_BE_NULLABLE = "W0284", "program variable `{}` stores an object reference, so its type must be `object?`";
    CHECK_CONST_STORES_OBJECT_MUST_BE_NULLABLE = "W0285", "const `{}` stores an object reference, so its type must be `object?`";
    CHECK_STRUCT_OR_ENUM_DECLARED_TWICE = "W0286", "`{}` is declared twice in this program";
    CHECK_FIELD_DECLARED_TWICE_IN_STRUCT = "W0287", "field `{}` is declared twice in struct `{}`";
    CHECK_VARIANT_DECLARED_TWICE_IN_ENUM = "W0288", "variant `{}` is declared twice in enum `{}`";
    CHECK_STRUCT_OR_ENUM_CYCLE = "W0289", "`{}` refers to itself through {}, which is not allowed: structs and enums cannot be recursive without going through an array, map, or `object`";
    CHECK_STRUCT_DEFAULT_NOT_A_CONSTANT = "W0290", "a field's default must be a constant literal";
    CHECK_TYPE_IMPORTED_FROM_BOTH_AND = "W0292", "`{}` is imported from both {} and {}";

    // 03xx -- link (efun arity, applies, unknown names)
    LINK_DECLARED_TWICE_PROGRAM = "W0300", "`{}` is declared twice in this program";
    LINK_VARIABLE_ALREADY_DECLARED = "W0301", "variable `{}` is already declared in {}";
    LINK_DECLARED_TWICE_PROGRAM_2 = "W0302", "`{}` is declared twice in this program";
    LINK_REDEFINES_FUNCTION_INHERITED_FROM = "W0303", "`{}` redefines a function inherited from {}";
    LINK_OVERRIDE_FN_OVERRIDES_NOTHING = "W0304", "`override fn {}` overrides nothing";
    LINK_PARAMETER_DECLARED_TWICE = "W0305", "parameter `{}` is declared twice";
    LINK_PARAMETER_WITHOUT_DEFAULT_FOLLOWS_ONE = "W0306", "a parameter without a default follows one with a default";
    LINK_UNKNOWN_TYPE_N = "W0307", "unknown type `{n}`";
    LINK_CANNOT_ASSIGN_N_WAS_DECLARED = "W0308", "cannot assign to `{n}`: it was declared with `let`";
    LINK_CANNOT_ASSIGN_SELF = "W0309", "cannot assign to `self`";
    LINK_UNKNOWN_VARIABLE_N = "W0310", "unknown variable `{n}`";
    LINK_N_TAKES_WANT_ARGUMENT_BUT = "W0311", "`{n}` takes {want} argument{}, but {} were given";
    LINK_UNKNOWN_FUNCTION_N = "W0312", "unknown function `{n}`";
    LINK_SUPER_NO_INHERITED_FUNCTION_NAME = "W0313", "`super::{}`: no inherited function with this name";

    // 04xx -- Phase 0 evaluator gates (\"not yet supported\")
    GATE_PHASE_0_GATE_LIGHTWEIGHT_PROGRAMS = "W0400", "Phase 0 gate: `lightweight` programs is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_LABELLED_INHERIT = "W0401", "Phase 0 gate: labelled `inherit` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_MULTIPLE_INHERITANCE = "W0402", "Phase 0 gate: multiple inheritance is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_IMPORT_NOT = "W0403", "Phase 0 gate: `import` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_PROTECTED_VISIBILITY = "W0404", "Phase 0 gate: `protected` visibility is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_FINAL_NOT = "W0405", "Phase 0 gate: `final` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_ATOMIC_FUNCTIONS = "W0406", "Phase 0 gate: `atomic` functions is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_CONST_NOT = "W0407", "Phase 0 gate: `const` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_STRUCT_NOT = "W0408", "Phase 0 gate: `struct` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_ENUM_NOT = "W0409", "Phase 0 gate: `enum` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_REST_PARAMETERS = "W0410", "Phase 0 gate: `...rest` parameters is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_FLOAT_TYPE = "W0411", "Phase 0 gate: the `float` type is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_ERROR_TYPE = "W0412", "Phase 0 gate: the `error` type is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_FUNCTION_TYPES = "W0413", "Phase 0 gate: function types is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_AND_NOT = "W0414", "Phase 0 gate: `*=`, `/=` and `%=` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_IF_LET = "W0415", "Phase 0 gate: `if let` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_BREAK_AND = "W0416", "Phase 0 gate: `break` and `continue` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_TRY_CATCH = "W0417", "Phase 0 gate: `try`/`catch` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_THROW_NOT = "W0418", "Phase 0 gate: `throw` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_NAMED_ARGUMENTS = "W0419", "Phase 0 gate: named arguments is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_SPREAD_ARGUMENTS = "W0420", "Phase 0 gate: `...` spread arguments is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_FLOAT_LITERALS = "W0421", "Phase 0 gate: float literals is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_SLICES_NOT = "W0422", "Phase 0 gate: slices is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_FIELD_ACCESS = "W0423", "Phase 0 gate: field access is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_AS_CASTS = "W0424", "Phase 0 gate: `as` casts is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_LABELLED_CALLS = "W0425", "Phase 0 gate: labelled calls `label::fn()` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_CALLING_COMPUTED = "W0426", "Phase 0 gate: calling a computed value is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_CLOSURES_NOT = "W0427", "Phase 0 gate: closures is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_MATCH_NOT = "W0428", "Phase 0 gate: `match` is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_STRUCT_LITERALS = "W0429", "Phase 0 gate: struct literals is not yet supported by the tree-walking evaluator";
    GATE_PHASE_0_GATE_ENUM_VARIANTS = "W0430", "Phase 0 gate: enum variants is not yet supported by the tree-walking evaluator";

    // 09xx -- warnings and lints
    LINT_LITERAL_SETTER_IN_CREATE = "W0900", "a `set_*` call in `create()` with only literal arguments is not re-applied on `upgrade()` (D-P1.4)";

}

/// Codes that used to be emitted but no longer are. A retired number is
/// never reassigned; new codes always take the next free number in range.
pub const RETIRED: &[(&str, &str)] = &[
    (
        "W0239",
        "`try`/`catch` is not implemented by the type checker yet",
    ),
    (
        "W0240",
        "`throw` is not implemented by the type checker yet",
    ),
    (
        "W0208",
        "`struct` is not implemented by the type checker yet",
    ),
    ("W0209", "`enum` is not implemented by the type checker yet"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_codes() {
        let mut seen = HashSet::new();
        for (code, _) in REGISTRY {
            assert!(seen.insert(*code), "duplicate diagnostic code {code}");
        }
        for (code, _) in RETIRED {
            assert!(
                !seen.contains(code),
                "retired code {code} is also live in REGISTRY"
            );
        }
    }

    #[test]
    fn codes_are_well_formed() {
        for (code, desc) in REGISTRY.iter().chain(RETIRED) {
            assert!(
                code.len() == 5
                    && code.starts_with('W')
                    && code[1..].chars().all(|c| c.is_ascii_digit()),
                "{code} is not `W` + 4 digits"
            );
            assert!(!desc.is_empty(), "{code} has no description");
        }
    }
}
