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
use std::hash::{Hash, Hasher};
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
    /// A nominal `struct` (spec r5 §7.3, D27, [OBI-52]): fields carry their
    /// declared source order (positional layout for codegen/HIR), but see
    /// [`Ty::schema_hash`] for the order-independent identity hot reload
    /// compares across versions.
    ///
    /// [OBI-52]: /OBI/issues/OBI-52
    Struct(Rc<StructTy>),
    /// A nominal `enum`: see [`Ty::Struct`] for the schema-hash rationale.
    Enum(Rc<EnumTy>),
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

/// `[vis] struct Name { field: T [= default], … }` (spec r5 §7.3).
/// Identity for assignability/equality is *nominal*: two `StructTy`s are
/// the same type iff `module` + `name` + every field match (derived
/// `PartialEq`), which is exactly what changes between compiles of the
/// same declaration — see [`Ty::schema_hash`] for the hot-reload-facing
/// notion of "the same shape, maybe reordered".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StructTy {
    /// Declaring program's path, e.g. `/std/item`.
    pub module: Rc<str>,
    pub name: Rc<str>,
    /// Declaration order (positional layout); [`Ty::schema_hash`] sorts by
    /// name internally so this order does not affect the hash.
    pub fields: Vec<FieldTy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldTy {
    pub name: Rc<str>,
    pub ty: Ty,
    /// A compile-time-constant default (`= expr` where `expr` is a
    /// literal), used to fill this field when an older value being
    /// migrated does not have it (spec r5 §7.3 by-name struct conversion:
    /// "every added field has a default"). `None` means the field is
    /// mandatory at construction and has no fallback for migration.
    pub default: Option<ConstVal>,
}

/// `[vis] enum Name { A, B(int), … }`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EnumTy {
    pub module: Rc<str>,
    pub name: Rc<str>,
    /// Declaration order; [`Ty::schema_hash`] sorts by name internally.
    pub variants: Vec<VariantTy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VariantTy {
    pub name: Rc<str>,
    /// Positional payload types; empty for a plain tag.
    pub payload: Vec<Ty>,
}

/// A compile-time-constant value: what a struct field's `= default` may be
/// (literals only, so migration can fill a missing field without running
/// any code — see [`FieldTy::default`]). Manual `Eq`/`Hash` because `f64`
/// has neither; two `ConstVal::Float`s compare/hash by bit pattern, which
/// is fine here (these are frozen source-literal defaults, never the
/// result of arithmetic that could produce distinct NaNs worth conflating).
#[derive(Clone, Debug)]
pub enum ConstVal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Array(Rc<[ConstVal]>),
}

impl PartialEq for ConstVal {
    fn eq(&self, other: &Self) -> bool {
        use ConstVal::*;
        match (self, other) {
            (Null, Null) => true,
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Float(a), Float(b)) => a.to_bits() == b.to_bits(),
            (Str(a), Str(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for ConstVal {}
impl Hash for ConstVal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            ConstVal::Null => {}
            ConstVal::Bool(b) => b.hash(state),
            ConstVal::Int(n) => n.hash(state),
            ConstVal::Float(f) => f.to_bits().hash(state),
            ConstVal::Str(s) => s.hash(state),
            ConstVal::Array(a) => a.iter().for_each(|c| c.hash(state)),
        }
    }
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

    /// Is this type a function type, or does it contain one (in an array,
    /// a map's key or value, or `T?`)? Spec r5 §5.2.2 rule 4: a `persistent`
    /// variable's type can never be or contain `fn(...)` — function values
    /// pin a code version and a principal that may not survive a reboot.
    /// Struct fields are not checked yet: V1 structs are not implemented by
    /// the type checker (`W0208`), so `Ty` has no struct variant to recurse
    /// into; add that arm here when structs land.
    pub fn contains_fn(&self) -> bool {
        match self {
            Ty::Fn(_) => true,
            Ty::Array(t) | Ty::Optional(t) => t.contains_fn(),
            Ty::Map(k, v) => k.contains_fn() || v.contains_fn(),
            Ty::Int
            | Ty::Float
            | Ty::Bool
            | Ty::String
            | Ty::Object
            | Ty::Null
            | Ty::Any
            | Ty::Void
            | Ty::Never
            | Ty::Error => false,
        }
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
            Ty::Struct(s) => f.write_str(&s.name),
            Ty::Enum(e) => f.write_str(&e.name),
        }
    }
}

impl Ty {
    /// Recursive type schema hash (spec r5 §7.3, D27, [OBI-52]): stable
    /// under struct-field/enum-variant *reordering*, sensitive to any type
    /// change anywhere in the type's structure (including a nested
    /// struct/enum reached through an array/map/optional/fn type). Two
    /// `struct`/`enum` declarations that only reordered their
    /// fields/variants hash equal; changing a field's/variant's type, name,
    /// arity, or the type's own module+name changes the hash.
    ///
    /// [OBI-52]: /OBI/issues/OBI-52
    pub fn schema_hash(&self) -> u64 {
        let mut h = SchemaHasher::new();
        self.hash_schema(&mut h);
        h.0
    }

    fn hash_schema(&self, h: &mut SchemaHasher) {
        // A leading discriminant tag keeps e.g. `Ty::Array(Ty::Int)` from
        // colliding with a differently-shaped type that happens to hash the
        // same parts in the same order.
        match self {
            Ty::Int => h.tag(0),
            Ty::Float => h.tag(1),
            Ty::Bool => h.tag(2),
            Ty::String => h.tag(3),
            Ty::Object => h.tag(4),
            Ty::Null => h.tag(5),
            Ty::Any => h.tag(6),
            Ty::Void => h.tag(7),
            Ty::Never => h.tag(8),
            Ty::Error => h.tag(9),
            Ty::Array(e) => {
                h.tag(10);
                e.hash_schema(h);
            }
            Ty::Map(k, v) => {
                h.tag(11);
                k.hash_schema(h);
                v.hash_schema(h);
            }
            Ty::Optional(t) => {
                h.tag(12);
                t.hash_schema(h);
            }
            Ty::Fn(ft) => {
                h.tag(13);
                h.len(ft.params.len());
                for p in &ft.params {
                    p.hash_schema(h);
                }
                ft.ret.hash_schema(h);
            }
            Ty::Struct(s) => {
                h.tag(20);
                h.str(&s.module);
                h.str(&s.name);
                let mut fields: Vec<&FieldTy> = s.fields.iter().collect();
                fields.sort_by(|a, b| a.name.cmp(&b.name));
                h.len(fields.len());
                for f in fields {
                    h.str(&f.name);
                    f.ty.hash_schema(h);
                }
            }
            Ty::Enum(e) => {
                h.tag(21);
                h.str(&e.module);
                h.str(&e.name);
                let mut variants: Vec<&VariantTy> = e.variants.iter().collect();
                variants.sort_by(|a, b| a.name.cmp(&b.name));
                h.len(variants.len());
                for v in variants {
                    h.str(&v.name);
                    h.len(v.payload.len());
                    for p in &v.payload {
                        p.hash_schema(h);
                    }
                }
            }
        }
    }
}

/// FNV-1a (64-bit) over an explicit, platform-independent byte encoding.
/// Schema hashes are compared across compiles, processes, and (via
/// `loom-persist`'s `schema_hash` column, once OBI-34 folds these in)
/// across restarts and toolchain upgrades, so they must not depend on
/// `std`'s `DefaultHasher` (algorithm unspecified across Rust releases) or
/// on `usize` width / `Hash` impl details. Every length is encoded as a
/// little-endian `u64`; every string as its length followed by its UTF-8
/// bytes. Changing this encoding changes every persisted schema hash.
struct SchemaHasher(u64);

impl SchemaHasher {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        SchemaHasher(Self::OFFSET)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn tag(&mut self, t: u8) {
        self.bytes(&[t]);
    }

    fn len(&mut self, n: usize) {
        self.bytes(&(n as u64).to_le_bytes());
    }

    fn str(&mut self, s: &str) {
        self.len(s.len());
        self.bytes(s.as_bytes());
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

    fn field(name: &str, ty: Ty) -> FieldTy {
        FieldTy {
            name: Rc::from(name),
            ty,
            default: None,
        }
    }

    fn variant(name: &str, payload: Vec<Ty>) -> VariantTy {
        VariantTy {
            name: Rc::from(name),
            payload,
        }
    }

    fn struct_ty(fields: Vec<FieldTy>) -> Ty {
        Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Stats"),
            fields,
        }))
    }

    fn enum_ty(variants: Vec<VariantTy>) -> Ty {
        Ty::Enum(Rc::new(EnumTy {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variants,
        }))
    }

    #[test]
    fn struct_schema_hash_is_stable_under_field_reorder() {
        let a = struct_ty(vec![field("hp", Ty::Int), field("name", Ty::String)]);
        let b = struct_ty(vec![field("name", Ty::String), field("hp", Ty::Int)]);
        assert_eq!(a.schema_hash(), b.schema_hash());
        // But the two `Ty`s are still distinct values (field order is the
        // codegen layout, not just cosmetic).
        assert_ne!(a, b);
    }

    #[test]
    fn struct_schema_hash_changes_with_a_field_type() {
        let a = struct_ty(vec![field("hp", Ty::Int)]);
        let b = struct_ty(vec![field("hp", Ty::Float)]);
        assert_ne!(a.schema_hash(), b.schema_hash());
    }

    #[test]
    fn struct_schema_hash_recurses_through_containers() {
        let inner_a = struct_ty(vec![field("hp", Ty::Int)]);
        let inner_b = struct_ty(vec![field("hp", Ty::Float)]);
        let outer_a = Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![field("stats", Ty::array(inner_a))],
        }));
        let outer_b = Ty::Struct(Rc::new(StructTy {
            module: Rc::from("/std/item"),
            name: Rc::from("Loadout"),
            fields: vec![field("stats", Ty::array(inner_b))],
        }));
        assert_ne!(
            outer_a.schema_hash(),
            outer_b.schema_hash(),
            "a change to a nested struct reached through `[T]` must change the outer hash"
        );
    }

    #[test]
    fn enum_schema_hash_is_stable_under_variant_reorder() {
        let a = enum_ty(vec![
            variant("Slash", vec![]),
            variant("Fire", vec![Ty::Int]),
        ]);
        let b = enum_ty(vec![
            variant("Fire", vec![Ty::Int]),
            variant("Slash", vec![]),
        ]);
        assert_eq!(a.schema_hash(), b.schema_hash());
    }

    #[test]
    fn enum_schema_hash_changes_with_a_variant_payload_type() {
        let a = enum_ty(vec![variant("Fire", vec![Ty::Int])]);
        let b = enum_ty(vec![variant("Fire", vec![Ty::Float])]);
        assert_ne!(a.schema_hash(), b.schema_hash());
    }
}
