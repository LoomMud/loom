// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft static types (spec §5.2) and the gradual assignability relation.
//!
//! The relation is *consistent subtyping* (Siek & Taha): `any` is consistent
//! with every type in both directions, `T` is a subtype of `T?`, and `null`
//! is a subtype of every `T?`. Containers are invariant up to `any`, because
//! arrays and maps have reference semantics (a `[string]` must not be
//! writable through a `[int]` alias). Wherever a value flows from `any` into a
//! more precise type the checker inserts an explicit [`crate::hir::ExprKind::Cast`]
//! so codegen emits the runtime check: that is the gradual boundary.

use std::fmt;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ty {
    Int,
    Float,
    Bool,
    String,
    /// A (non-null) object reference.
    Object,
    /// The type of the `null` literal.
    Null,
    /// Dynamic: checked at use.
    Any,
    /// "No value": the result of a function without `-> T`.
    Void,
    /// The type of an expression that never completes (reserved for `throw`,
    /// and used for error recovery in unreachable code).
    Never,
    Array(Rc<Ty>),
    Map(Rc<Ty>, Rc<Ty>),
    /// `T?`. Never nested, never wraps `any`/`null`/`void` (see [`Ty::optional`]).
    Optional(Rc<Ty>),
    Fn(Rc<FnTy>),
    /// Poison: an expression that already produced a diagnostic. Consistent
    /// with everything so one mistake reports once.
    Error,
}

/// `fn(A, B) -> R`: a closure or function-reference type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FnTy {
    pub params: Vec<Ty>,
    pub ret: Ty,
}

impl Ty {
    pub fn array(elem: Ty) -> Ty {
        Ty::Array(Rc::new(elem))
    }

    pub fn map(k: Ty, v: Ty) -> Ty {
        Ty::Map(Rc::new(k), Rc::new(v))
    }

    /// `T?`, normalised: `T??` = `T?`, `any?` = `any`, `null?` = `null`.
    pub fn optional(t: Ty) -> Ty {
        match t {
            Ty::Optional(_) | Ty::Any | Ty::Null | Ty::Error | Ty::Void => t,
            Ty::Never => Ty::Null,
            t => Ty::Optional(Rc::new(t)),
        }
    }

    /// True if `null` is a valid value of this type.
    pub fn is_nullable(&self) -> bool {
        matches!(self, Ty::Optional(_) | Ty::Null | Ty::Any | Ty::Error)
    }

    /// `T` for `T?`, otherwise the type itself.
    pub fn non_null(&self) -> Ty {
        match self {
            Ty::Optional(t) => (**t).clone(),
            t => t.clone(),
        }
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, Ty::Any | Ty::Error)
    }

    /// Does not produce a diagnostic when used anywhere (any/poison/never).
    pub fn is_lenient(&self) -> bool {
        matches!(self, Ty::Any | Ty::Error | Ty::Never)
    }

    /// Can a value of type `self` be stored where `to` is expected?
    pub fn assignable_to(&self, to: &Ty) -> bool {
        use Ty::*;
        match (self, to) {
            (Error, _) | (_, Error) | (Never, _) => true,
            (Void, _) | (_, Void) => false,
            (Any, _) | (_, Any) => true,
            (Null, t) => t.is_nullable(),
            (Optional(a), Optional(b)) => a.assignable_to(b),
            (Optional(_), _) => false,
            (a, Optional(b)) => a.assignable_to(b),
            (Array(a), Array(b)) => a.consistent(b),
            (Map(ka, va), Map(kb, vb)) => ka.consistent(kb) && va.consistent(vb),
            (Fn(a), Fn(b)) => {
                a.params.len() == b.params.len()
                    && a.params
                        .iter()
                        .zip(&b.params)
                        .all(|(x, y)| y.assignable_to(x))
                    && a.ret.assignable_to(&b.ret)
            }
            (a, b) => a == b,
        }
    }

    /// Type consistency (`~`): equality up to `any`. Used for invariant
    /// positions (container elements).
    pub fn consistent(&self, other: &Ty) -> bool {
        use Ty::*;
        match (self, other) {
            (Error, _) | (_, Error) | (Any, _) | (_, Any) => true,
            (Array(a), Array(b)) | (Optional(a), Optional(b)) => a.consistent(b),
            (Map(ka, va), Map(kb, vb)) => ka.consistent(kb) && va.consistent(vb),
            (Fn(a), Fn(b)) => {
                a.params.len() == b.params.len()
                    && a.params.iter().zip(&b.params).all(|(x, y)| x.consistent(y))
                    && a.ret.consistent(&b.ret)
            }
            (a, b) => a == b,
        }
    }

    /// True when storing a `self` into a `to` needs a runtime check, i.e. the
    /// static type is less precise than the target (the gradual boundary).
    pub fn needs_cast_to(&self, to: &Ty) -> bool {
        match (self, to) {
            (Ty::Any, t) => !matches!(t, Ty::Any | Ty::Error),
            (Ty::Array(a), Ty::Array(b)) => **a == Ty::Any && **b != Ty::Any,
            (Ty::Map(ka, va), Ty::Map(kb, vb)) => {
                (**ka == Ty::Any && **kb != Ty::Any) || (**va == Ty::Any && **vb != Ty::Any)
            }
            (Ty::Optional(a), Ty::Optional(b)) => a.needs_cast_to(b),
            (a, Ty::Optional(b)) => a.needs_cast_to(b),
            _ => false,
        }
    }

    /// Least upper bound for branches/literal elements; `None` if the types
    /// have no common type other than `any` (the caller reports it).
    pub fn join(&self, other: &Ty) -> Option<Ty> {
        use Ty::*;
        match (self, other) {
            (Error, _) | (_, Error) => Some(Error),
            (Never, t) | (t, Never) => Some(t.clone()),
            (Any, _) | (_, Any) => Some(Any),
            (Null, t) | (t, Null) => Some(Ty::optional(t.clone())),
            (Optional(a), b) | (b, Optional(a)) => a.join(&b.non_null()).map(Ty::optional),
            (a, b) if a.assignable_to(b) && !a.needs_cast_to(b) => Some(b.clone()),
            (a, b) if b.assignable_to(a) && !b.needs_cast_to(a) => Some(a.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::Int => f.write_str("int"),
            Ty::Float => f.write_str("float"),
            Ty::Bool => f.write_str("bool"),
            Ty::String => f.write_str("string"),
            Ty::Object => f.write_str("object"),
            Ty::Null => f.write_str("null"),
            Ty::Any => f.write_str("any"),
            Ty::Void => f.write_str("no value"),
            Ty::Never => f.write_str("never"),
            Ty::Array(t) => write!(f, "[{t}]"),
            Ty::Map(k, v) => write!(f, "{{{k}: {v}}}"),
            Ty::Optional(t) => match **t {
                Ty::Fn(_) => write!(f, "({t})?"),
                _ => write!(f, "{t}?"),
            },
            Ty::Fn(ft) => {
                f.write_str("fn(")?;
                for (i, p) in ft.params.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{p}")?;
                }
                f.write_str(")")?;
                if ft.ret != Ty::Void {
                    write!(f, " -> {}", ft.ret)?;
                }
                Ok(())
            }
            Ty::Error => f.write_str("{error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullability() {
        let so = Ty::optional(Ty::String);
        assert!(Ty::String.assignable_to(&so));
        assert!(Ty::Null.assignable_to(&so));
        assert!(!so.assignable_to(&Ty::String));
        assert!(!Ty::Null.assignable_to(&Ty::Object));
        assert_eq!(Ty::optional(so.clone()), so);
        assert_eq!(Ty::optional(Ty::Any), Ty::Any);
    }

    #[test]
    fn any_is_consistent_both_ways() {
        assert!(Ty::Any.assignable_to(&Ty::Int));
        assert!(Ty::Int.assignable_to(&Ty::Any));
        assert!(Ty::Any.needs_cast_to(&Ty::Int));
        assert!(!Ty::Int.needs_cast_to(&Ty::Any));
        assert!(Ty::array(Ty::Any).assignable_to(&Ty::array(Ty::String)));
        assert!(Ty::array(Ty::Any).needs_cast_to(&Ty::array(Ty::String)));
    }

    #[test]
    fn containers_are_invariant() {
        let a = Ty::array(Ty::String);
        let b = Ty::array(Ty::optional(Ty::String));
        assert!(!a.assignable_to(&b));
        assert!(!b.assignable_to(&a));
        assert!(!Ty::map(Ty::String, Ty::Int).assignable_to(&Ty::map(Ty::String, Ty::Bool)));
    }

    #[test]
    fn fn_types_are_contravariant_in_params() {
        let takes_any = Ty::Fn(Rc::new(FnTy {
            params: vec![Ty::optional(Ty::Object)],
            ret: Ty::Int,
        }));
        let takes_obj = Ty::Fn(Rc::new(FnTy {
            params: vec![Ty::Object],
            ret: Ty::optional(Ty::Int),
        }));
        assert!(takes_any.assignable_to(&takes_obj));
        assert!(!takes_obj.assignable_to(&takes_any));
        assert_eq!(takes_obj.to_string(), "fn(object) -> int?");
    }

    #[test]
    fn joins() {
        assert_eq!(Ty::Int.join(&Ty::Null), Some(Ty::optional(Ty::Int)));
        assert_eq!(Ty::Int.join(&Ty::Int), Some(Ty::Int));
        assert_eq!(Ty::Int.join(&Ty::String), None);
        assert_eq!(
            Ty::optional(Ty::Int).join(&Ty::Int),
            Some(Ty::optional(Ty::Int))
        );
    }
}
