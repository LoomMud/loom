// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Resolver + gradual type checker: AST (+ parent interfaces) → typed HIR.
//!
//! Two passes per program:
//! 1. **Declarations.** Merge the parents' interfaces (inherit graph), lower
//!    declared types, build the program's own function/variable tables and
//!    check override/redeclaration rules.
//! 2. **Bodies.** Resolve every name, type every expression (bidirectionally:
//!    an expected type flows into literals), apply flow narrowing for
//!    nullability, and emit HIR.
//!
//! Strict by default: every value has a static type and mismatches are
//! errors. `any` is the only escape hatch; values leaving `any` get an
//! explicit runtime [`hir::ExprKind::Cast`].

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use loom_syntax::ast::{self, BinOp, ExprKind as E, StmtKind as S, UnOp};
use loom_syntax::{Diagnostic, Span};

use crate::efuns::{self, Param as EP, Ret as ER};
use crate::hir::{self, Callee, IndexKind, IterKind, LocalId, OpKind, Visibility};
use crate::interface::{
    FnInfo, Inherited, ParamInfo, ParentInfo, ProgramInfo, VarInfo, merge_parents,
};
use crate::ty::Ty;

/// A successfully checked program: its HIR and the interface it exports.
pub struct Checked {
    pub hir: hir::Program,
    pub info: Rc<ProgramInfo>,
}

/// Check one program against its (already checked) parents.
pub fn check_program(
    path: &str,
    ast: &ast::Program,
    parents: Vec<ParentInfo>,
) -> Result<Checked, Vec<Diagnostic>> {
    let path: Rc<str> = Rc::from(path);
    let mut diags = Vec::new();
    let inh = merge_parents(&parents, &mut diags);
    let decls = declare(&path, ast, &inh, &parents, &mut diags);

    let mut cx = Cx {
        path: path.clone(),
        decls: &decls,
        inh: &inh,
        parents: &parents,
        diags: &mut diags,
        var_tys: HashMap::new(),
        locals: Vec::new(),
        scopes: Vec::new(),
        facts: Facts::default(),
        ret: Ty::Void,
        fn_name: Rc::from(""),
    };

    let mut vars = Vec::new();
    for v in &decls.vars {
        let d = v.decl;
        cx.reset_fn(Ty::Void, "");
        let init = d.init.as_ref().map(|e| cx.expr(e, v.ty.as_ref()));
        let ty = match (&v.ty, init) {
            (Some(t), Some(e)) => {
                let e = cx.coerce(e, t, &format!("the initialiser of `{}`", v.name));
                vars.push((t.clone(), Some(e)));
                t.clone()
            }
            (Some(t), None) => {
                if !t.is_nullable() {
                    cx.diags.push(
                        Diagnostic::error(
                            d.name.span,
                            format!("`{}` has type `{t}` but no initial value", v.name),
                        )
                        .with_hint(format!(
                            "give it one (`var {}: {t} = …`), or make the type nullable (`{t}?`)",
                            v.name
                        )),
                    );
                }
                vars.push((t.clone(), None));
                t.clone()
            }
            (None, Some(e)) => {
                let t = cx.infer_binding(&e, &v.name, d.name.span);
                vars.push((t.clone(), Some(e)));
                t
            }
            (None, None) => {
                cx.diags.push(
                    Diagnostic::error(d.name.span, format!("`{}` needs a type", v.name))
                        .with_hint(format!("write `var {}: T`", v.name)),
                );
                vars.push((Ty::Error, None));
                Ty::Error
            }
        };
        cx.var_tys.insert(v.name.clone(), ty);
    }

    let mut fns = Vec::new();
    for f in &decls.fns {
        fns.push(cx.function(f));
    }

    if !diags.is_empty() {
        diags.sort_by_key(|d| d.span.start);
        return Err(diags);
    }

    let hir_vars = decls
        .vars
        .iter()
        .zip(vars)
        .map(|(v, (ty, init))| hir::Var {
            name: v.name.clone(),
            ty,
            vis: v.vis,
            persistent: v.decl.mods.persistent,
            init,
            span: v.decl.span,
        })
        .collect::<Vec<_>>();

    // Export: inherited interface overlaid with our own non-private items.
    let mut efns = inh.fns.clone();
    for f in &decls.fns {
        if f.info.vis != Visibility::Private {
            efns.insert(f.info.name.clone(), f.info.clone());
        }
    }
    let mut evars = inh.vars.clone();
    for v in &hir_vars {
        if v.vis != Visibility::Private {
            evars.insert(
                v.name.clone(),
                Rc::new(VarInfo {
                    name: v.name.clone(),
                    owner: path.clone(),
                    ty: v.ty.clone(),
                    persistent: v.persistent,
                }),
            );
        }
    }
    let mut linearization = inh.linearization.clone();
    linearization.push(path.clone());
    let info = Rc::new(ProgramInfo {
        path: path.clone(),
        parents: parents.clone(),
        linearization: linearization.clone(),
        ancestors: inh.ancestors.clone(),
        fns: efns,
        vars: evars,
    });
    let hir = hir::Program {
        path,
        inherits: parents
            .iter()
            .map(|p| hir::Inherit {
                label: p.label.clone(),
                path: p.info.path.clone(),
                span: p.span,
            })
            .collect(),
        linearization,
        vars: hir_vars,
        fns,
    };
    Ok(Checked { hir, info })
}

// ---- pass 1: declarations -------------------------------------------------

struct VarDecl<'a> {
    name: Rc<str>,
    decl: &'a ast::VarDecl,
    /// Declared type (`None`: inferred from the initialiser in pass 2).
    ty: Option<Ty>,
    vis: Visibility,
}

struct FnDecl<'a> {
    decl: &'a ast::FnDecl,
    info: Rc<FnInfo>,
}

struct Decls<'a> {
    vars: Vec<VarDecl<'a>>,
    fns: Vec<FnDecl<'a>>,
    fn_index: HashMap<Rc<str>, usize>,
    var_index: HashMap<Rc<str>, usize>,
}

fn visibility(m: &ast::Modifiers) -> Visibility {
    if m.is_private {
        Visibility::Private
    } else if m.is_pub {
        Visibility::Public
    } else {
        Visibility::Internal
    }
}

fn declare<'a>(
    path: &Rc<str>,
    ast: &'a ast::Program,
    inh: &Inherited,
    parents: &[ParentInfo],
    diags: &mut Vec<Diagnostic>,
) -> Decls<'a> {
    let mut d = Decls {
        vars: Vec::new(),
        fns: Vec::new(),
        fn_index: HashMap::new(),
        var_index: HashMap::new(),
    };
    let mut names: HashSet<&str> = HashSet::new();
    for item in &ast.items {
        match item {
            ast::Item::Var(v) => {
                if !names.insert(&v.name.name) {
                    diags.push(Diagnostic::error(
                        v.name.span,
                        format!("`{}` is declared twice in this program", v.name.name),
                    ));
                    continue;
                }
                if let Some(prev) = inh.vars.get(v.name.name.as_str()) {
                    diags.push(
                        Diagnostic::error(
                            v.name.span,
                            format!(
                                "variable `{}` is already declared in {}",
                                v.name.name, prev.owner
                            ),
                        )
                        .with_hint("use the inherited variable, or pick another name"),
                    );
                }
                let ty = v.ty.as_ref().map(|t| lower_type(t, diags));
                let name: Rc<str> = Rc::from(v.name.name.as_str());
                d.var_index.insert(name.clone(), d.vars.len());
                d.vars.push(VarDecl {
                    name,
                    decl: v,
                    ty,
                    vis: visibility(&v.mods),
                });
            }
            ast::Item::Fn(f) => {
                if !names.insert(&f.name.name) {
                    diags.push(Diagnostic::error(
                        f.name.span,
                        format!("`{}` is declared twice in this program", f.name.name),
                    ));
                    continue;
                }
                let info = Rc::new(fn_info(path, f, diags));
                check_override(f, &info, inh, parents, diags);
                d.fn_index.insert(info.name.clone(), d.fns.len());
                d.fns.push(FnDecl { decl: f, info });
            }
        }
    }
    // Ambiguous inherited functions the program does not override.
    let mut amb: Vec<_> = inh
        .ambiguous_fns
        .iter()
        .filter(|(n, _)| !d.fn_index.contains_key(*n))
        .collect();
    amb.sort_by(|a, b| a.0.cmp(b.0));
    for (name, versions) in amb {
        let span = parents.first().map(|p| p.span).unwrap_or_default();
        let owners: Vec<&str> = versions.iter().map(|f| &*f.owner).collect();
        diags.push(
            Diagnostic::error(
                span,
                format!(
                    "function `{name}` is inherited from both {}",
                    owners.join(" and ")
                ),
            )
            .with_hint(format!(
                "write `override fn {name}(…)` in this program and call the version you want with `label::{name}()`"
            )),
        );
    }
    d
}

fn fn_info(path: &Rc<str>, f: &ast::FnDecl, diags: &mut Vec<Diagnostic>) -> FnInfo {
    let mut seen_default = false;
    let mut pnames = HashSet::new();
    let mut params = Vec::new();
    for p in &f.params {
        if !pnames.insert(&p.name.name) {
            diags.push(Diagnostic::error(
                p.name.span,
                format!("parameter `{}` is declared twice", p.name.name),
            ));
        }
        let ty = match &p.ty {
            Some(t) => lower_type(t, diags),
            None => {
                diags.push(
                    Diagnostic::error(
                        p.name.span,
                        format!("parameter `{}` needs a type", p.name.name),
                    )
                    .with_hint(format!(
                        "write `{}: T`, or `{}: any` to opt out of static checking",
                        p.name.name, p.name.name
                    )),
                );
                Ty::Error
            }
        };
        if p.default.is_some() {
            seen_default = true;
        } else if seen_default {
            diags.push(
                Diagnostic::error(
                    p.name.span,
                    "a parameter without a default follows one with a default",
                )
                .with_hint("put parameters with defaults last"),
            );
        }
        params.push(ParamInfo {
            name: Rc::from(p.name.name.as_str()),
            ty,
            has_default: p.default.is_some(),
        });
    }
    let ret = f
        .ret
        .as_ref()
        .map(|t| lower_type(t, diags))
        .unwrap_or(Ty::Void);
    FnInfo {
        name: Rc::from(f.name.name.as_str()),
        owner: path.clone(),
        vis: visibility(&f.mods),
        is_final: false,
        params,
        ret,
    }
}

fn check_override(
    f: &ast::FnDecl,
    info: &FnInfo,
    inh: &Inherited,
    parents: &[ParentInfo],
    diags: &mut Vec<Diagnostic>,
) {
    let inherited = inh.fns.get(&info.name);
    let span = f.name.span;
    let name = &info.name;
    if info.vis == Visibility::Private {
        if f.mods.is_override {
            diags.push(
                Diagnostic::error(span, format!("`private fn {name}` cannot be an `override`"))
                    .with_hint("private functions are not virtual; remove `private` or `override`"),
            );
        }
        return;
    }
    let Some(parent) = inherited else {
        if f.mods.is_override {
            diags.push(
                Diagnostic::error(span, format!("`override fn {name}` overrides nothing"))
                    .with_hint(if parents.is_empty() {
                        "this program has no `inherit`; remove `override`"
                    } else {
                        "no inherited function has this name; remove `override`"
                    }),
            );
        }
        return;
    };
    if !f.mods.is_override {
        diags.push(
            Diagnostic::error(
                span,
                format!(
                    "`{name}` redefines a function inherited from {}",
                    parent.owner
                ),
            )
            .with_hint(format!("write `override fn {name}(…)`")),
        );
        return;
    }
    if parent.is_final {
        diags.push(
            Diagnostic::error(
                span,
                format!(
                    "`{name}` is `final` in {} and cannot be overridden",
                    parent.owner
                ),
            )
            .with_hint("pick another name for this function"),
        );
    }
    let same_params = parent.params.len() == info.params.len()
        && parent
            .params
            .iter()
            .zip(&info.params)
            .all(|(a, b)| a.ty.consistent(&b.ty));
    let ret_ok = match (&info.ret, &parent.ret) {
        (Ty::Void, Ty::Void) => true,
        (Ty::Void, _) | (_, Ty::Void) => false,
        (a, b) => a.assignable_to(b),
    };
    if !same_params || !ret_ok {
        diags.push(
            Diagnostic::error(
                span,
                format!(
                    "`override fn {name}` does not match the inherited signature `{}` from {}",
                    signature(parent),
                    parent.owner
                ),
            )
            .with_hint(format!(
                "this declaration is `{}`; overrides must take the same parameter types and return a compatible type",
                signature(info)
            )),
        );
    }
    if parent.vis == Visibility::Public && info.vis != Visibility::Public {
        diags.push(
            Diagnostic::error(
                span,
                format!("`override fn {name}` must stay `pub` like the inherited function"),
            )
            .with_hint(format!("write `pub override fn {name}(…)`")),
        );
    }
}

fn signature(f: &FnInfo) -> String {
    let ps: Vec<String> = f
        .params
        .iter()
        .map(|p| format!("{}: {}", p.name, p.ty))
        .collect();
    let mut s = format!("fn {}({})", f.name, ps.join(", "));
    if f.ret != Ty::Void {
        s.push_str(&format!(" -> {}", f.ret));
    }
    s
}

/// Lower a syntactic type; unknown names report and become `Ty::Error`.
pub fn lower_type(t: &ast::Type, diags: &mut Vec<Diagnostic>) -> Ty {
    use ast::TypeKind as T;
    match &t.kind {
        T::Int => Ty::Int,
        T::Bool => Ty::Bool,
        T::String => Ty::String,
        T::Object => Ty::Object,
        T::Any => Ty::Any,
        T::Null => Ty::Null,
        T::Array(e) => Ty::array(lower_type(e, diags)),
        T::Map(k, v) => Ty::map(lower_type(k, diags), lower_type(v, diags)),
        T::Optional(e) => Ty::optional(lower_type(e, diags)),
        T::Named(n) if n == "float" => Ty::Float,
        T::Named(n) => {
            let hint = match n.as_str() {
                "str" | "String" => "did you mean `string`?".to_string(),
                "mapping" | "map" => "maps are written `{K: V}`".to_string(),
                "array" => "arrays are written `[T]`".to_string(),
                "void" => "leave out `-> T` for a function that returns nothing".to_string(),
                "mixed" => "the dynamic type is `any`".to_string(),
                _ => match suggest(n, TYPE_NAMES.iter().copied()) {
                    Some(s) => format!("did you mean `{s}`?"),
                    None => "types: int, float, bool, string, object, any, null, [T], {K: V}, T?"
                        .to_string(),
                },
            };
            diags.push(Diagnostic::error(t.span, format!("unknown type `{n}`")).with_hint(hint));
            Ty::Error
        }
    }
}

const TYPE_NAMES: &[&str] = &["int", "float", "bool", "string", "object", "any", "null"];

/// The closest candidate within a small edit distance, for "did you mean".
fn suggest<'a>(name: &str, cands: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let max = (name.chars().count() / 3).clamp(1, 3);
    cands
        .filter(|c| *c != name)
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, _)| *d <= max)
        .min_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)))
        .map(|(_, c)| c)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

// ---- pass 2: bodies --------------------------------------------------------

/// Flow facts valid at the current program point.
#[derive(Clone, Default)]
struct Facts {
    /// Locals whose type is narrowed (e.g. `object?` → `object` after a
    /// `!= null` test).
    narrow: HashMap<LocalId, Ty>,
    /// `(map, key)` pairs with `key in map` known true. The key is a local;
    /// the map a local or program variable. Only a hint: indexing under this
    /// fact becomes [`IndexKind::MapPresent`], which is still checked at
    /// runtime, so a call that removes the key cannot break soundness.
    present: HashSet<(MapRef, LocalId)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum MapRef {
    Local(LocalId),
    Global(hir::GlobalRef),
}

impl MapRef {
    fn of(e: &hir::Expr) -> Option<MapRef> {
        match &e.kind {
            hir::ExprKind::Local(id) => Some(MapRef::Local(*id)),
            hir::ExprKind::Global(g) => Some(MapRef::Global(g.clone())),
            _ => None,
        }
    }
}

enum Fact {
    Narrow(LocalId, Ty),
    Present(MapRef, LocalId),
}

struct Cx<'a> {
    path: Rc<str>,
    decls: &'a Decls<'a>,
    inh: &'a Inherited,
    parents: &'a [ParentInfo],
    diags: &'a mut Vec<Diagnostic>,
    /// Final types of own program variables (filled in declaration order).
    var_tys: HashMap<Rc<str>, Ty>,
    locals: Vec<hir::Local>,
    scopes: Vec<Vec<(Rc<str>, LocalId)>>,
    facts: Facts,
    ret: Ty,
    fn_name: Rc<str>,
}

enum Resolved {
    Local(LocalId),
    Global(hir::GlobalRef, Ty),
    SelfObj,
    Fn(Callee, Rc<FnInfo>),
}

fn given(n: usize) -> String {
    if n == 1 {
        "1 was given".to_string()
    } else {
        format!("{n} were given")
    }
}

fn arity_text(min: usize, max: usize) -> String {
    let want = if min == max {
        format!("{min}")
    } else {
        format!("{min} to {max}")
    };
    format!("{want} argument{}", if max == 1 { "" } else { "s" })
}

impl Cx<'_> {
    fn err(&mut self, span: Span, msg: impl Into<String>) {
        self.diags.push(Diagnostic::error(span, msg));
    }

    fn err_hint(&mut self, span: Span, msg: impl Into<String>, hint: impl Into<String>) {
        self.diags
            .push(Diagnostic::error(span, msg).with_hint(hint));
    }

    fn reset_fn(&mut self, ret: Ty, name: &str) {
        self.locals.clear();
        self.scopes.clear();
        self.facts = Facts::default();
        self.ret = ret;
        self.fn_name = Rc::from(name);
    }

    fn function(&mut self, f: &FnDecl<'_>) -> hir::Function {
        let d = f.decl;
        self.reset_fn(f.info.ret.clone(), &d.name.name);
        self.scopes.push(Vec::new());
        let mut params = Vec::new();
        for (p, pi) in d.params.iter().zip(&f.info.params) {
            let id = self.declare(&pi.name, pi.ty.clone(), false, p.name.span);
            params.push(id);
        }
        let params = params
            .into_iter()
            .zip(&d.params)
            .zip(&f.info.params)
            .map(|((local, p), pi)| hir::Param {
                local,
                default: p.default.as_ref().map(|e| {
                    let x = self.expr(e, Some(&pi.ty));
                    self.coerce(x, &pi.ty, &format!("the default of `{}`", pi.name))
                }),
            })
            .collect();
        let (body, diverges) = self.block(&d.body);
        self.scopes.pop();
        if f.info.ret != Ty::Void && !diverges {
            let ret = f.info.ret.clone();
            self.err_hint(
                d.name.span,
                format!(
                    "`{}` may reach its end without returning a value",
                    d.name.name
                ),
                format!("it is declared `-> {ret}`; add a `return` on every path"),
            );
        }
        hir::Function {
            name: f.info.name.clone(),
            vis: f.info.vis,
            is_override: d.mods.is_override,
            params,
            ret: f.info.ret.clone(),
            locals: std::mem::take(&mut self.locals),
            body,
            span: d.span,
        }
    }

    fn declare(&mut self, name: &str, ty: Ty, mutable: bool, span: Span) -> LocalId {
        let id = self.locals.len() as LocalId;
        let name: Rc<str> = Rc::from(name);
        self.locals.push(hir::Local {
            name: name.clone(),
            ty,
            mutable,
            span,
        });
        if let Some(s) = self.scopes.last_mut() {
            s.push((name, id));
        }
        id
    }

    fn lookup_local(&self, name: &str) -> Option<LocalId> {
        self.scopes
            .iter()
            .rev()
            .flat_map(|s| s.iter().rev())
            .find(|(n, _)| &**n == name)
            .map(|(_, id)| *id)
    }

    fn lookup_fn(&self, name: &str) -> Option<(Callee, Rc<FnInfo>)> {
        if let Some(&i) = self.decls.fn_index.get(name) {
            let info = self.decls.fns[i].info.clone();
            let callee = if info.vis == Visibility::Private {
                Callee::Static {
                    program: self.path.clone(),
                    name: info.name.clone(),
                }
            } else {
                Callee::Virtual {
                    name: info.name.clone(),
                }
            };
            return Some((callee, info));
        }
        self.inh.fns.get(name).map(|f| {
            (
                Callee::Virtual {
                    name: f.name.clone(),
                },
                f.clone(),
            )
        })
    }

    fn resolve(&self, name: &str) -> Option<Resolved> {
        if let Some(id) = self.lookup_local(name) {
            return Some(Resolved::Local(id));
        }
        if let Some(&i) = self.decls.var_index.get(name) {
            let v = &self.decls.vars[i];
            let ty = self
                .var_tys
                .get(&v.name)
                .cloned()
                .or_else(|| v.ty.clone())
                .unwrap_or(Ty::Error);
            return Some(Resolved::Global(
                hir::GlobalRef {
                    owner: self.path.clone(),
                    name: v.name.clone(),
                },
                ty,
            ));
        }
        if let Some(v) = self.inh.vars.get(name) {
            return Some(Resolved::Global(
                hir::GlobalRef {
                    owner: v.owner.clone(),
                    name: v.name.clone(),
                },
                v.ty.clone(),
            ));
        }
        if name == "self" {
            return Some(Resolved::SelfObj);
        }
        self.lookup_fn(name).map(|(c, f)| Resolved::Fn(c, f))
    }

    fn local_ty(&self, id: LocalId) -> Ty {
        self.facts
            .narrow
            .get(&id)
            .cloned()
            .unwrap_or_else(|| self.locals[id as usize].ty.clone())
    }

    fn value_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .scopes
            .iter()
            .flat_map(|s| s.iter().map(|(n, _)| n.to_string()))
            .collect();
        v.extend(self.decls.var_index.keys().map(|k| k.to_string()));
        v.extend(self.inh.vars.keys().map(|k| k.to_string()));
        v
    }

    fn fn_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.decls.fn_index.keys().map(|k| k.to_string()).collect();
        v.extend(self.inh.fns.keys().map(|k| k.to_string()));
        v.extend(efuns::names().map(str::to_string));
        v
    }

    fn unknown_var(&mut self, n: &str, span: Span) {
        let mut d = Diagnostic::error(span, format!("unknown variable `{n}`"));
        let names = self.value_names();
        if efuns::lookup(n).is_some() {
            d = d.with_hint(format!(
                "`{n}` is an efun; call it with `{n}()` (efuns are not values)"
            ));
        } else if let Some(s) = suggest(n, names.iter().map(String::as_str)) {
            d = d.with_hint(format!("did you mean `{s}`?"));
        } else {
            d = d.with_hint("declare it with `let`, `var`, or as a program variable");
        }
        self.diags.push(d);
    }

    fn mk(kind: hir::ExprKind, ty: Ty, span: Span) -> hir::Expr {
        hir::Expr { kind, ty, span }
    }

    fn poison(span: Span) -> hir::Expr {
        Self::mk(hir::ExprKind::Null, Ty::Error, span)
    }

    /// Reject `void` in value position.
    fn value(&mut self, e: hir::Expr) -> hir::Expr {
        if e.ty == Ty::Void {
            self.err_hint(
                e.span,
                "this call returns no value",
                "the function has no `-> T`, so its result cannot be used",
            );
            return Self::poison(e.span);
        }
        e
    }

    /// Check that `e` can be stored where `to` is expected; insert the
    /// runtime cast at the gradual boundary.
    fn coerce(&mut self, e: hir::Expr, to: &Ty, what: &str) -> hir::Expr {
        let e = self.value(e);
        if e.ty.assignable_to(to) {
            if e.ty.needs_cast_to(to) {
                let span = e.span;
                return Self::mk(hir::ExprKind::Cast(Box::new(e)), to.clone(), span);
            }
            return e;
        }
        let from = e.ty.clone();
        let msg = format!("mismatched types in {what}: expected `{to}`, found `{from}`");
        let hint = match (&from, to) {
            (Ty::Null, _) => Some(format!(
                "`{to}` cannot hold `null`; declare it as `{}` if null is a valid value",
                Ty::optional(to.clone())
            )),
            (Ty::Optional(inner), _) if inner.assignable_to(to) => Some(
                "this value may be null: check it with `if x != null { … }` first, or give a fallback with `?? value`"
                    .to_string(),
            ),
            (_, Ty::String) => Some("build strings with interpolation: `$\"{x}\"`".to_string()),
            (Ty::Int, Ty::Float) | (Ty::Float, Ty::Int) => {
                Some("Weft has no implicit int/float conversion".to_string())
            }
            _ => None,
        };
        match hint {
            Some(h) => self.err_hint(e.span, msg, h),
            None => self.err(e.span, msg),
        }
        Self::poison(e.span)
    }

    /// A condition: must be `bool` (or `any`, checked at runtime).
    fn cond(&mut self, e: &ast::Expr, what: &str) -> hir::Expr {
        let x = self.expr(e, Some(&Ty::Bool));
        let x = self.value(x);
        if x.ty == Ty::Bool || x.ty.is_lenient() {
            return self.coerce(x, &Ty::Bool, what);
        }
        let hint = match &x.ty {
            Ty::Int | Ty::Float => "Weft has no truthiness; compare explicitly, e.g. `x != 0`",
            Ty::String => "Weft has no truthiness; compare explicitly, e.g. `s != \"\"`",
            Ty::Array(_) | Ty::Map(..) => {
                "Weft has no truthiness; compare explicitly, e.g. `len(xs) > 0`"
            }
            Ty::Optional(_) | Ty::Object | Ty::Null => {
                "Weft has no truthiness; compare explicitly, e.g. `x != null`"
            }
            _ => "conditions must be `bool`",
        };
        let ty = x.ty.clone();
        self.err_hint(x.span, format!("{what} must be `bool`, found `{ty}`"), hint);
        Self::poison(x.span)
    }

    fn infer_binding(&mut self, e: &hir::Expr, name: &str, span: Span) -> Ty {
        match &e.ty {
            Ty::Null => {
                self.err_hint(
                    span,
                    format!("cannot infer a type for `{name}` from `null`"),
                    format!("annotate it: `{name}: T? = null`"),
                );
                Ty::Error
            }
            Ty::Void => {
                self.value(e.clone());
                Ty::Error
            }
            Ty::Never => Ty::Error,
            t => t.clone(),
        }
    }

    // ---- statements --------------------------------------------------------

    /// Returns the HIR block and whether control never reaches its end.
    fn block(&mut self, b: &ast::Block) -> (hir::Block, bool) {
        self.scopes.push(Vec::new());
        let mut stmts = Vec::new();
        let mut diverges = false;
        for s in &b.stmts {
            let (h, d) = self.stmt(s);
            stmts.push(h);
            diverges |= d;
        }
        self.scopes.pop();
        (
            hir::Block {
                stmts,
                span: b.span,
            },
            diverges,
        )
    }

    fn stmt(&mut self, s: &ast::Stmt) -> (hir::Stmt, bool) {
        let span = s.span;
        let (kind, diverges) = match &s.kind {
            S::Local {
                mutable,
                name,
                ty,
                init,
            } => {
                let declared = ty.as_ref().map(|t| lower_type(t, self.diags));
                let init = init.as_ref().map(|e| {
                    let x = self.expr(e, declared.as_ref());
                    match &declared {
                        Some(t) => {
                            self.coerce(x, t, &format!("the initialiser of `{}`", name.name))
                        }
                        None => x,
                    }
                });
                let lty = match (&declared, &init) {
                    (Some(t), _) => {
                        if init.is_none() && !t.is_nullable() {
                            self.err_hint(
                                name.span,
                                format!("`{}` has type `{t}` but no initial value", name.name),
                                format!(
                                    "give it one (`{} {}: {t} = …`), or make the type nullable (`{t}?`)",
                                    if *mutable { "var" } else { "let" },
                                    name.name
                                ),
                            );
                        }
                        t.clone()
                    }
                    (None, Some(e)) => {
                        let e = e.clone();
                        self.infer_binding(&e, &name.name, name.span)
                    }
                    (None, None) => {
                        self.err_hint(
                            name.span,
                            format!("`{}` needs a type or an initial value", name.name),
                            format!("write `var {}: T` or `var {} = …`", name.name, name.name),
                        );
                        Ty::Error
                    }
                };
                let init_ty = init.as_ref().map(|e| e.ty.clone());
                let id = self.declare(&name.name, lty.clone(), *mutable, name.span);
                if let Some(t) = init_ty
                    && lty.is_nullable()
                    && !t.is_nullable()
                    && !t.is_lenient()
                    && t != Ty::Void
                {
                    self.facts.narrow.insert(id, t);
                }
                (hir::StmtKind::Let { local: id, init }, false)
            }
            S::Assign { target, op, value } => (self.assign(target, *op, value), false),
            S::If { cond, then, els } => {
                let c = self.cond(cond, "an `if` condition");
                let before = self.facts.clone();
                self.apply(self.facts_of(&c, true));
                let (then_b, then_div) = self.block(then);
                let after_then = std::mem::replace(&mut self.facts, before.clone());
                self.apply(self.facts_of(&c, false));
                let (els_b, els_div) = match els.as_deref() {
                    Some(ast::Else::Block(b)) => {
                        let (b, d) = self.block(b);
                        (Some(b), d)
                    }
                    Some(ast::Else::If(s)) => {
                        let (h, d) = self.stmt(s);
                        (
                            Some(hir::Block {
                                span: h.span,
                                stmts: vec![h],
                            }),
                            d,
                        )
                    }
                    None => (None, false),
                };
                let after_else = std::mem::take(&mut self.facts);
                self.facts = match (then_div, els_div) {
                    (true, false) => after_else,
                    (false, true) => after_then,
                    (true, true) => after_then,
                    (false, false) => meet(&after_then, &after_else),
                };
                (
                    hir::StmtKind::If {
                        cond: c,
                        then: then_b,
                        els: els_b,
                    },
                    then_div && els_div,
                )
            }
            S::While { cond, body } => {
                self.forget_assigned(&body.stmts);
                let c = self.cond(cond, "a `while` condition");
                let before = self.facts.clone();
                self.apply(self.facts_of(&c, true));
                let (b, _) = self.block(body);
                self.facts = before;
                let infinite = matches!(cond.kind, E::Bool(true));
                if !infinite {
                    self.apply(self.facts_of(&c, false));
                }
                (hir::StmtKind::While { cond: c, body: b }, infinite)
            }
            S::For { var, iter, body } => {
                let it = self.expr(iter, None);
                let it = self.value(it);
                let (ety, kind) = match &it.ty {
                    Ty::Array(t) => ((**t).clone(), IterKind::Array),
                    Ty::Map(k, _) => ((**k).clone(), IterKind::MapKeys),
                    t if t.is_lenient() => (Ty::Any, IterKind::Dyn),
                    Ty::Optional(_) => {
                        let t = it.ty.clone();
                        self.err_hint(
                            it.span,
                            format!("cannot iterate over `{t}`: it may be null"),
                            "check it with `if xs != null { … }` first",
                        );
                        (Ty::Error, IterKind::Dyn)
                    }
                    t => {
                        let t = t.clone();
                        self.err_hint(
                            it.span,
                            format!("cannot iterate over `{t}`"),
                            "`for` works on arrays (elements) and maps (keys)",
                        );
                        (Ty::Error, IterKind::Dyn)
                    }
                };
                self.forget_assigned(&body.stmts);
                let before = self.facts.clone();
                self.scopes.push(Vec::new());
                let id = self.declare(&var.name, ety, false, var.span);
                let (b, _) = self.block(body);
                self.scopes.pop();
                self.facts = before;
                (
                    hir::StmtKind::For {
                        local: id,
                        iter: it,
                        kind,
                        body: b,
                    },
                    false,
                )
            }
            S::Return(e) => {
                let ret = self.ret.clone();
                let fname = self.fn_name.clone();
                let v = match (e, &ret) {
                    (Some(e), Ty::Void) => {
                        let x = self.expr(e, None);
                        let ty = x.ty.clone();
                        if fname.is_empty() {
                            self.err(x.span, "`return` outside a function");
                        } else {
                            self.err_hint(
                                x.span,
                                format!(
                                    "`{fname}` has no return type, so it cannot return a value"
                                ),
                                format!("declare one: `fn {fname}(…) -> {ty}`"),
                            );
                        }
                        Some(x)
                    }
                    (Some(e), t) => {
                        let x = self.expr(e, Some(t));
                        Some(self.coerce(x, t, "the return value"))
                    }
                    (None, Ty::Void) => None,
                    (None, t) => {
                        self.err_hint(
                            span,
                            format!("`{fname}` must return a value of type `{t}`"),
                            if t.is_nullable() {
                                "write `return null` to return nothing"
                            } else {
                                "return a value of the declared type"
                            },
                        );
                        None
                    }
                };
                (hir::StmtKind::Return(v), true)
            }
            S::Expr(e) => (hir::StmtKind::Expr(self.expr(e, None)), false),
        };
        (hir::Stmt { kind, span }, diverges)
    }

    fn assign(
        &mut self,
        target: &ast::Expr,
        op: ast::AssignOp,
        value: &ast::Expr,
    ) -> hir::StmtKind {
        let (place, pty, local) = match &target.kind {
            E::Ident(n) => match self.resolve(n) {
                Some(Resolved::Local(id)) => {
                    if !self.locals[id as usize].mutable {
                        self.err_hint(
                            target.span,
                            format!("cannot assign to `{n}`: it was declared with `let`"),
                            format!("declare it with `var {n}` to make it mutable"),
                        );
                    }
                    let ty = if op == ast::AssignOp::Set {
                        self.locals[id as usize].ty.clone()
                    } else {
                        self.local_ty(id)
                    };
                    (hir::Place::Local(id), ty, Some(id))
                }
                Some(Resolved::Global(g, ty)) => (hir::Place::Global(g), ty, None),
                Some(Resolved::SelfObj) => {
                    self.err(target.span, "cannot assign to `self`");
                    (hir::Place::Local(0), Ty::Error, None)
                }
                Some(Resolved::Fn(..)) => {
                    self.err_hint(
                        target.span,
                        format!("cannot assign to function `{n}`"),
                        "functions are not variables",
                    );
                    (hir::Place::Local(0), Ty::Error, None)
                }
                None => {
                    self.unknown_var(n, target.span);
                    (hir::Place::Local(0), Ty::Error, None)
                }
            },
            E::Index { base, index } => {
                let b = self.expr(base, None);
                let b = self.value(b);
                let (i, kind, ety) = match b.ty.clone() {
                    Ty::Array(t) => {
                        let i = self.expr(index, Some(&Ty::Int));
                        (
                            self.coerce(i, &Ty::Int, "an array index"),
                            IndexKind::Array,
                            (*t).clone(),
                        )
                    }
                    Ty::Map(k, v) => {
                        let i = self.expr(index, Some(&k));
                        (
                            self.coerce(i, &k, "a map key"),
                            IndexKind::Map,
                            (*v).clone(),
                        )
                    }
                    t if t.is_lenient() => {
                        let i = self.expr(index, None);
                        (self.value(i), IndexKind::Dyn, Ty::Any)
                    }
                    Ty::String => {
                        let i = self.expr(index, None);
                        self.err_hint(
                            target.span,
                            "cannot assign into a string",
                            "strings are immutable; build a new one with interpolation or `+`",
                        );
                        (i, IndexKind::String, Ty::Error)
                    }
                    t => {
                        let i = self.expr(index, None);
                        self.index_error(&t, b.span);
                        (i, IndexKind::Dyn, Ty::Error)
                    }
                };
                (
                    hir::Place::Index {
                        base: Box::new(b),
                        index: Box::new(i),
                        kind,
                    },
                    ety,
                    None,
                )
            }
            _ => {
                self.err_hint(
                    target.span,
                    "cannot assign to this expression",
                    "assign to a variable (`x = …`) or an element (`xs[i] = …`)",
                );
                (hir::Place::Local(0), Ty::Error, None)
            }
        };
        let (v, kind) = if op == ast::AssignOp::Set {
            let v = self.expr(value, Some(&pty));
            (self.coerce(v, &pty, "the assignment"), OpKind::Dyn)
        } else {
            let bop = if op == ast::AssignOp::Add {
                BinOp::Add
            } else {
                BinOp::Sub
            };
            let v = self.expr(value, Some(&pty));
            let v = self.value(v);
            let lhs = Self::mk(hir::ExprKind::Null, pty.clone(), target.span);
            let (kind, rty) = self.arith(bop, &lhs, &v, target.span.to(v.span));
            if !rty.assignable_to(&pty) {
                self.err(
                    target.span.to(v.span),
                    format!("mismatched types in the assignment: expected `{pty}`, found `{rty}`"),
                );
            }
            (v, kind)
        };
        if let hir::Place::Global(g) = &place {
            let m = MapRef::Global(g.clone());
            self.facts.present.retain(|(pm, _)| *pm != m);
        }
        if let Some(id) = local {
            self.invalidate(id);
            let decl = self.locals[id as usize].ty.clone();
            if op == ast::AssignOp::Set
                && decl.is_nullable()
                && !v.ty.is_nullable()
                && !v.ty.is_lenient()
            {
                self.facts.narrow.insert(id, v.ty.clone());
            }
        }
        hir::StmtKind::Assign {
            place,
            op,
            kind,
            value: v,
        }
    }

    // ---- flow facts ----------------------------------------------------------

    fn facts_of(&self, e: &hir::Expr, when: bool) -> Vec<Fact> {
        use hir::ExprKind as H;
        match &e.kind {
            H::Binary { op, lhs, rhs, .. } if matches!(op, BinOp::Eq | BinOp::Ne) => {
                let nonnull = (*op == BinOp::Ne) == when;
                let local = match (&lhs.kind, &rhs.kind) {
                    (H::Local(id), H::Null) => Some((*id, &lhs.ty)),
                    (H::Null, H::Local(id)) => Some((*id, &rhs.ty)),
                    _ => None,
                };
                match local {
                    Some((id, Ty::Optional(t))) if nonnull => vec![Fact::Narrow(id, (**t).clone())],
                    _ => vec![],
                }
            }
            H::Binary {
                op: BinOp::In,
                lhs,
                rhs,
                ..
            } if when => match (&lhs.kind, MapRef::of(rhs), &rhs.ty) {
                (H::Local(k), Some(m), Ty::Map(..)) => vec![Fact::Present(m, *k)],
                _ => vec![],
            },
            H::Unary {
                op: UnOp::Not,
                expr,
                ..
            } => self.facts_of(expr, !when),
            H::And(a, b) if when => {
                let mut v = self.facts_of(a, true);
                v.extend(self.facts_of(b, true));
                v
            }
            H::Or(a, b) if !when => {
                let mut v = self.facts_of(a, false);
                v.extend(self.facts_of(b, false));
                v
            }
            _ => vec![],
        }
    }

    fn apply(&mut self, facts: Vec<Fact>) {
        for f in facts {
            match f {
                Fact::Narrow(id, t) => {
                    self.facts.narrow.insert(id, t);
                }
                Fact::Present(m, k) => {
                    self.facts.present.insert((m, k));
                }
            }
        }
    }

    fn invalidate(&mut self, id: LocalId) {
        self.facts.narrow.remove(&id);
        self.facts
            .present
            .retain(|(m, k)| *m != MapRef::Local(id) && *k != id);
    }

    /// Before a loop: drop facts about locals the body assigns.
    fn forget_assigned(&mut self, stmts: &[ast::Stmt]) {
        let mut names = HashSet::new();
        assigned_names(stmts, &mut names);
        for n in names {
            if let Some(id) = self.lookup_local(&n) {
                self.invalidate(id);
            }
        }
    }

    // ---- expressions ---------------------------------------------------------

    fn expr(&mut self, e: &ast::Expr, expected: Option<&Ty>) -> hir::Expr {
        use hir::ExprKind as H;
        let span = e.span;
        match &e.kind {
            E::Int(n) => Self::mk(H::Int(*n), Ty::Int, span),
            E::Str(s) => Self::mk(H::Str(Rc::from(s.as_str())), Ty::String, span),
            E::Bool(b) => Self::mk(H::Bool(*b), Ty::Bool, span),
            E::Null => Self::mk(H::Null, Ty::Null, span),
            E::Error => Self::poison(span),
            E::Interp(parts) => {
                let parts = parts
                    .iter()
                    .map(|p| match p {
                        ast::InterpPart::Lit(s) => hir::InterpPart::Lit(Rc::from(s.as_str())),
                        ast::InterpPart::Expr(e) => {
                            let x = self.expr(e, None);
                            hir::InterpPart::Expr(self.value(x))
                        }
                    })
                    .collect();
                Self::mk(H::Interp(parts), Ty::String, span)
            }
            E::Array(es) => self.array_lit(es, expected, span),
            E::Map(kvs) => self.map_lit(kvs, expected, span),
            E::Ident(n) => match self.resolve(n) {
                Some(Resolved::Local(id)) => Self::mk(H::Local(id), self.local_ty(id), span),
                Some(Resolved::Global(g, ty)) => Self::mk(H::Global(g), ty, span),
                Some(Resolved::SelfObj) => Self::mk(H::SelfObj, Ty::Object, span),
                Some(Resolved::Fn(c, f)) => Self::mk(H::FnRef(c), f.fn_ty(), span),
                None => {
                    self.unknown_var(n, span);
                    Self::poison(span)
                }
            },
            E::Index { base, index } => self.index(base, index, span),
            E::Unary { op, expr } => match op {
                UnOp::Not => {
                    let x = self.cond(expr, "the operand of `not`");
                    let kind = if x.ty == Ty::Bool {
                        OpKind::Bool
                    } else {
                        OpKind::Dyn
                    };
                    Self::mk(
                        H::Unary {
                            op: UnOp::Not,
                            kind,
                            expr: Box::new(x),
                        },
                        Ty::Bool,
                        span,
                    )
                }
                UnOp::Neg => {
                    let x = self.expr(expr, None);
                    let x = self.value(x);
                    let (kind, ty) = match &x.ty {
                        Ty::Int => (OpKind::Int, Ty::Int),
                        Ty::Float => (OpKind::Float, Ty::Float),
                        t if t.is_lenient() => (OpKind::Dyn, t.clone()),
                        t => {
                            let t = t.clone();
                            self.err(x.span, format!("cannot negate a value of type `{t}`"));
                            (OpKind::Dyn, Ty::Error)
                        }
                    };
                    Self::mk(
                        H::Unary {
                            op: UnOp::Neg,
                            kind,
                            expr: Box::new(x),
                        },
                        ty,
                        span,
                    )
                }
            },
            E::Binary { op, lhs, rhs } => self.binary(*op, lhs, rhs, span, expected),
            E::Call { name, args } => self.call(name, args, span),
            E::SuperCall { name, args } => self.super_call(name, args, span),
            E::Method {
                recv,
                name,
                args,
                safe,
            } => {
                let r = self.expr(recv, None);
                let r = self.value(r);
                match &r.ty {
                    Ty::Object => {}
                    t if t.is_lenient() => {}
                    Ty::Optional(t) if **t == Ty::Object || t.is_lenient() => {
                        if !safe {
                            self.err_hint(
                                name.span,
                                format!(
                                    "cannot call `.{}()` on a value that may be null (`object?`)",
                                    name.name
                                ),
                                format!(
                                    "use `?.{}()` to skip the call when it is null, or check `!= null` first",
                                    name.name
                                ),
                            );
                        }
                    }
                    t => {
                        let t = t.clone();
                        self.err_hint(
                            name.span,
                            format!("cannot call `.{}()` on a value of type `{t}`", name.name),
                            "`.fn()` calls a function in another object; it needs an `object`",
                        );
                    }
                }
                let args = args
                    .iter()
                    .map(|a| {
                        let x = self.expr(a, None);
                        self.value(x)
                    })
                    .collect();
                Self::mk(
                    H::CallOther {
                        recv: Box::new(r),
                        name: Rc::from(name.name.as_str()),
                        args,
                        safe: *safe,
                    },
                    Ty::Any,
                    span,
                )
            }
        }
    }

    fn array_lit(&mut self, es: &[ast::Expr], expected: Option<&Ty>, span: Span) -> hir::Expr {
        let want = match expected.map(Ty::non_null) {
            Some(Ty::Array(t)) => Some((*t).clone()),
            _ => None,
        };
        let mut items = Vec::new();
        let mut elem: Option<Ty> = want.clone();
        for (i, e) in es.iter().enumerate() {
            let x = self.expr(e, want.as_ref());
            let x = self.value(x);
            match &want {
                Some(t) => items.push(self.coerce(x, t, "an array element")),
                None => {
                    elem = match &elem {
                        None => Some(x.ty.clone()),
                        Some(prev) => match prev.join(&x.ty) {
                            Some(j) => Some(j),
                            None => {
                                let t = x.ty.clone();
                                self.err_hint(
                                    x.span,
                                    format!(
                                        "array elements have different types: `{prev}` and `{t}` (element {})",
                                        i + 1
                                    ),
                                    "annotate the binding to allow mixed values, e.g. `let xs: [any] = …`",
                                );
                                Some(Ty::Error)
                            }
                        },
                    };
                    items.push(x);
                }
            }
        }
        let elem = match elem {
            Some(Ty::Null) | None => Ty::Any,
            Some(t) => t,
        };
        Self::mk(hir::ExprKind::Array(items), Ty::array(elem), span)
    }

    fn map_lit(
        &mut self,
        kvs: &[(ast::Expr, ast::Expr)],
        expected: Option<&Ty>,
        span: Span,
    ) -> hir::Expr {
        let want = match expected.map(Ty::non_null) {
            Some(Ty::Map(k, v)) => Some(((*k).clone(), (*v).clone())),
            _ => None,
        };
        let mut items = Vec::new();
        let (mut kt, mut vt): (Option<Ty>, Option<Ty>) = match &want {
            Some((k, v)) => (Some(k.clone()), Some(v.clone())),
            None => (None, None),
        };
        for (k, v) in kvs {
            let kx = self.expr(k, want.as_ref().map(|w| &w.0));
            let kx = self.value(kx);
            let vx = self.expr(v, want.as_ref().map(|w| &w.1));
            let vx = self.value(vx);
            match &want {
                Some((wk, wv)) => {
                    let kx = self.coerce(kx, wk, "a map key");
                    let vx = self.coerce(vx, wv, "a map value");
                    items.push((kx, vx));
                }
                None => {
                    kt = self.join_elem(kt, &kx, "map keys");
                    vt = self.join_elem(vt, &vx, "map values");
                    items.push((kx, vx));
                }
            }
        }
        for (k, _) in &items {
            if !matches!(
                k.ty.non_null(),
                Ty::Int | Ty::String | Ty::Bool | Ty::Object | Ty::Any | Ty::Error
            ) {
                let t = k.ty.clone();
                self.err_hint(
                    k.span,
                    format!("`{t}` cannot be a map key"),
                    "map keys must be int, string, bool or object",
                );
            }
        }
        let norm = |t: Option<Ty>| match t {
            Some(Ty::Null) | None => Ty::Any,
            Some(t) => t,
        };
        Self::mk(hir::ExprKind::Map(items), Ty::map(norm(kt), norm(vt)), span)
    }

    fn join_elem(&mut self, acc: Option<Ty>, x: &hir::Expr, what: &str) -> Option<Ty> {
        match acc {
            None => Some(x.ty.clone()),
            Some(prev) => match prev.join(&x.ty) {
                Some(j) => Some(j),
                None => {
                    let t = x.ty.clone();
                    self.err_hint(
                        x.span,
                        format!("{what} have different types: `{prev}` and `{t}`"),
                        "annotate the binding to allow mixed values, e.g. `{string: any}`",
                    );
                    Some(Ty::Error)
                }
            },
        }
    }

    fn index_error(&mut self, t: &Ty, span: Span) {
        if let Ty::Optional(_) = t {
            self.err_hint(
                span,
                format!("cannot index a value that may be null (`{t}`)"),
                "check it with `if x != null { … }` first",
            );
        } else {
            self.err_hint(
                span,
                format!("cannot index a value of type `{t}`"),
                "only arrays, maps and strings can be indexed",
            );
        }
    }

    fn index(&mut self, base: &ast::Expr, index: &ast::Expr, span: Span) -> hir::Expr {
        let b = self.expr(base, None);
        let b = self.value(b);
        let (i, kind, ty) = match b.ty.clone() {
            Ty::Array(t) => {
                let i = self.expr(index, Some(&Ty::Int));
                (
                    self.coerce(i, &Ty::Int, "an array index"),
                    IndexKind::Array,
                    (*t).clone(),
                )
            }
            Ty::String => {
                let i = self.expr(index, Some(&Ty::Int));
                (
                    self.coerce(i, &Ty::Int, "a string index"),
                    IndexKind::String,
                    Ty::String,
                )
            }
            Ty::Map(k, v) => {
                let i = self.expr(index, Some(&k));
                let i = self.coerce(i, &k, "a map key");
                let present = match (MapRef::of(&b), &i.kind) {
                    (Some(m), hir::ExprKind::Local(key)) => self.facts.present.contains(&(m, *key)),
                    _ => false,
                };
                if present {
                    (i, IndexKind::MapPresent, (*v).clone())
                } else {
                    (i, IndexKind::Map, Ty::optional((*v).clone()))
                }
            }
            t if t.is_lenient() => {
                let i = self.expr(index, None);
                (self.value(i), IndexKind::Dyn, Ty::Any)
            }
            t => {
                let i = self.expr(index, None);
                self.index_error(&t, b.span);
                (i, IndexKind::Dyn, Ty::Error)
            }
        };
        Self::mk(
            hir::ExprKind::Index {
                base: Box::new(b),
                index: Box::new(i),
                kind,
            },
            ty,
            span,
        )
    }

    /// Type an arithmetic operator; returns the operand kind and result type.
    fn arith(&mut self, op: BinOp, l: &hir::Expr, r: &hir::Expr, span: Span) -> (OpKind, Ty) {
        use Ty::*;
        let sym = binop_sym(op);
        match (&l.ty, &r.ty) {
            (Error, _) | (_, Error) => (OpKind::Dyn, Error),
            (Any, _) | (_, Any) | (Never, _) | (_, Never) => (OpKind::Dyn, Any),
            (Int, Int) => (OpKind::Int, Int),
            (Float, Float) => (OpKind::Float, Float),
            (String, String) if op == BinOp::Add => (OpKind::Str, String),
            (Array(a), Array(b)) if op == BinOp::Add && a.consistent(b) => {
                let t = if **a == Any {
                    (**b).clone()
                } else {
                    (**a).clone()
                };
                (OpKind::Array, Ty::array(t))
            }
            (a, b) => {
                let msg = format!("cannot apply `{sym}` to `{a}` and `{b}`");
                let hint = match (a, b) {
                    (String, _) | (_, String) if op == BinOp::Add => {
                        Some("build mixed strings with interpolation: `$\"{a}{b}\"`")
                    }
                    (Int, Float) | (Float, Int) => {
                        Some("Weft has no implicit int/float conversion")
                    }
                    (Optional(_), _) | (_, Optional(_)) => {
                        Some("a value may be null: check it first, or give a fallback with `??`")
                    }
                    _ => None,
                };
                match hint {
                    Some(h) => self.err_hint(span, msg, h),
                    None => self.err(span, msg),
                }
                (OpKind::Dyn, Error)
            }
        }
    }

    fn binary(
        &mut self,
        op: BinOp,
        lhs: &ast::Expr,
        rhs: &ast::Expr,
        span: Span,
        expected: Option<&Ty>,
    ) -> hir::Expr {
        use hir::ExprKind as H;
        match op {
            BinOp::And | BinOp::Or => {
                let what = if op == BinOp::And {
                    "an operand of `and`"
                } else {
                    "an operand of `or`"
                };
                let l = self.cond(lhs, what);
                let saved = self.facts.clone();
                self.apply(self.facts_of(&l, op == BinOp::And));
                let r = self.cond(rhs, what);
                self.facts = saved;
                let kind = if op == BinOp::And {
                    H::And(Box::new(l), Box::new(r))
                } else {
                    H::Or(Box::new(l), Box::new(r))
                };
                Self::mk(kind, Ty::Bool, span)
            }
            BinOp::Coalesce => {
                let l = self.expr(lhs, expected.map(|t| Ty::optional(t.clone())).as_ref());
                let l = self.value(l);
                let want = l.ty.non_null();
                let r = self.expr(rhs, Some(expected.unwrap_or(&want)));
                let r = self.value(r);
                let ty = match want.join(&r.ty) {
                    Some(t) if l.ty.is_nullable() => t,
                    Some(_) => l.ty.clone(),
                    None => {
                        let (lt, rt) = (l.ty.clone(), r.ty.clone());
                        self.err(
                            r.span,
                            format!("mismatched types in `??`: the left side is `{lt}`, the fallback is `{rt}`"),
                        );
                        Ty::Error
                    }
                };
                Self::mk(H::Coalesce(Box::new(l), Box::new(r)), ty, span)
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => {
                let l = self.expr(lhs, None);
                let l = self.value(l);
                let r = self.expr(rhs, Some(&l.ty));
                let r = self.value(r);
                let (kind, ty) = self.arith(op, &l, &r, span);
                Self::mk(
                    H::Binary {
                        op,
                        kind,
                        lhs: Box::new(l),
                        rhs: Box::new(r),
                    },
                    ty,
                    span,
                )
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let l = self.expr(lhs, None);
                let l = self.value(l);
                let r = self.expr(rhs, None);
                let r = self.value(r);
                let kind = match (&l.ty, &r.ty) {
                    (Ty::Int, Ty::Int) => OpKind::Int,
                    (Ty::Float, Ty::Float) => OpKind::Float,
                    (Ty::String, Ty::String) => OpKind::Str,
                    (a, b) if a.is_lenient() || b.is_lenient() => OpKind::Dyn,
                    (a, b) => {
                        let msg =
                            format!("cannot compare `{a}` and `{b}` with `{}`", binop_sym(op));
                        self.err_hint(
                            span,
                            msg,
                            "ordering works on two ints, two floats or two strings",
                        );
                        OpKind::Dyn
                    }
                };
                Self::mk(
                    H::Binary {
                        op,
                        kind,
                        lhs: Box::new(l),
                        rhs: Box::new(r),
                    },
                    Ty::Bool,
                    span,
                )
            }
            BinOp::Eq | BinOp::Ne => {
                let l = self.expr(lhs, None);
                let l = self.value(l);
                let r = self.expr(rhs, Some(&l.ty));
                let r = self.value(r);
                let kind = self.eq_kind(&l.ty, &r.ty, span, binop_sym(op));
                Self::mk(
                    H::Binary {
                        op,
                        kind,
                        lhs: Box::new(l),
                        rhs: Box::new(r),
                    },
                    Ty::Bool,
                    span,
                )
            }
            BinOp::In => {
                let l = self.expr(lhs, None);
                let l = self.value(l);
                let r = self.expr(rhs, None);
                let r = self.value(r);
                let kind = match r.ty.clone() {
                    Ty::Array(t) => {
                        self.eq_kind(&l.ty, &t, span, "in");
                        OpKind::Array
                    }
                    Ty::Map(k, _) => {
                        self.eq_kind(&l.ty, &k, span, "in");
                        OpKind::Map
                    }
                    Ty::String => {
                        if !l.ty.is_lenient() && l.ty != Ty::String {
                            let t = l.ty.clone();
                            self.err(
                                l.span,
                                format!("`in` on a string needs a string on the left, found `{t}`"),
                            );
                        }
                        OpKind::Str
                    }
                    t if t.is_lenient() => OpKind::Dyn,
                    t => {
                        self.err_hint(
                            r.span,
                            format!("`in` needs an array, map or string on the right, found `{t}`"),
                            if t.is_nullable() {
                                "the value may be null; check it first"
                            } else {
                                "`x in xs` tests array elements, map keys, or substrings"
                            },
                        );
                        OpKind::Dyn
                    }
                };
                Self::mk(
                    H::Binary {
                        op,
                        kind,
                        lhs: Box::new(l),
                        rhs: Box::new(r),
                    },
                    Ty::Bool,
                    span,
                )
            }
        }
    }

    /// Operand kind for `==`/`!=`/`in`; reports incomparable types.
    fn eq_kind(&mut self, a: &Ty, b: &Ty, span: Span, sym: &str) -> OpKind {
        if a.is_lenient() || b.is_lenient() {
            return OpKind::Dyn;
        }
        if a == b {
            return match a {
                Ty::Int => OpKind::Int,
                Ty::Float => OpKind::Float,
                Ty::String => OpKind::Str,
                Ty::Bool => OpKind::Bool,
                Ty::Object => OpKind::Object,
                Ty::Array(_) => OpKind::Array,
                Ty::Map(..) => OpKind::Map,
                _ => OpKind::Generic,
            };
        }
        let comparable = matches!(a, Ty::Null)
            || matches!(b, Ty::Null)
            || a.assignable_to(b)
            || b.assignable_to(a);
        if !comparable {
            self.err_hint(
                span,
                format!("cannot compare `{a}` with `{b}` using `{sym}`"),
                "values of these types are never equal; convert one side first",
            );
        }
        OpKind::Generic
    }

    fn check_args(
        &mut self,
        fname: &str,
        f: &FnInfo,
        args: &[ast::Expr],
        span: Span,
    ) -> Vec<hir::Expr> {
        let (min, max) = (f.required_args(), f.params.len());
        if args.len() < min || args.len() > max {
            self.err(
                span,
                format!(
                    "`{fname}` takes {}, but {}",
                    arity_text(min, max),
                    given(args.len())
                ),
            );
        }
        args.iter()
            .enumerate()
            .map(|(i, a)| match f.params.get(i) {
                Some(p) => {
                    let x = self.expr(a, Some(&p.ty));
                    self.coerce(x, &p.ty, &format!("argument {} of `{fname}`", i + 1))
                }
                None => {
                    let x = self.expr(a, None);
                    self.value(x)
                }
            })
            .collect()
    }

    fn call(&mut self, name: &ast::Ident, args: &[ast::Expr], span: Span) -> hir::Expr {
        use hir::ExprKind as H;
        let n = name.name.as_str();
        // A local of function type shadows functions and efuns.
        if let Some(id) = self.lookup_local(n) {
            let callee = Self::mk(H::Local(id), self.local_ty(id), name.span);
            return self.call_value(callee, args, span);
        }
        if let Some((callee, f)) = self.lookup_fn(n) {
            let args = self.check_args(n, &f, args, span);
            return Self::mk(H::Call { callee, args }, f.ret.clone(), span);
        }
        if let Some(sig) = efuns::lookup(n) {
            return self.efun(sig, args, span);
        }
        let names = self.fn_names();
        let hint = match suggest(n, names.iter().map(String::as_str)) {
            Some(s) => format!("did you mean `{s}`?"),
            None => "it is not declared in this program, inherited, or an efun; \
                     to call another object use `ob.fn()`"
                .to_string(),
        };
        self.err_hint(name.span, format!("unknown function `{n}`"), hint);
        for a in args {
            self.expr(a, None);
        }
        Self::poison(span)
    }

    fn call_value(&mut self, callee: hir::Expr, args: &[ast::Expr], span: Span) -> hir::Expr {
        let (args, ret) = match callee.ty.clone() {
            Ty::Fn(ft) => {
                let fi = FnInfo {
                    name: Rc::from("<fn>"),
                    owner: self.path.clone(),
                    vis: Visibility::Internal,
                    is_final: false,
                    params: ft
                        .params
                        .iter()
                        .map(|t| ParamInfo {
                            name: Rc::from("_"),
                            ty: t.clone(),
                            has_default: false,
                        })
                        .collect(),
                    ret: ft.ret.clone(),
                };
                let what = self.describe(&callee);
                (self.check_args(&what, &fi, args, span), ft.ret.clone())
            }
            t if t.is_lenient() => (
                args.iter()
                    .map(|a| {
                        let x = self.expr(a, None);
                        self.value(x)
                    })
                    .collect(),
                Ty::Any,
            ),
            t => {
                let what = self.describe(&callee);
                self.err_hint(
                    callee.span,
                    format!("`{what}` has type `{t}`, which is not a function"),
                    "only values of type `fn(…)` can be called",
                );
                for a in args {
                    self.expr(a, None);
                }
                (Vec::new(), Ty::Error)
            }
        };
        Self::mk(
            hir::ExprKind::CallValue {
                callee: Box::new(callee),
                args,
            },
            ret,
            span,
        )
    }

    fn describe(&self, e: &hir::Expr) -> String {
        match &e.kind {
            hir::ExprKind::Local(id) => self.locals[*id as usize].name.to_string(),
            _ => "this value".to_string(),
        }
    }

    fn efun(&mut self, sig: efuns::EfunSig, args: &[ast::Expr], span: Span) -> hir::Expr {
        use hir::ExprKind as H;
        let n = sig.name;
        let (min, max) = (sig.min_args, sig.params.len());
        if args.len() < min || args.len() > max {
            self.err(
                span,
                format!(
                    "`{n}` takes {}, but {}",
                    arity_text(min, max),
                    given(args.len())
                ),
            );
        }
        let mut hargs = Vec::new();
        for (i, a) in args.iter().enumerate() {
            let what = format!("argument {} of `{n}`", i + 1);
            let x = match sig.params.get(i) {
                Some(EP::Ty(t)) => {
                    let x = self.expr(a, Some(t));
                    self.coerce(x, t, &what)
                }
                Some(EP::Sized) => {
                    let x = self.expr(a, None);
                    let x = self.value(x);
                    if !matches!(x.ty, Ty::String | Ty::Array(_) | Ty::Map(..))
                        && !x.ty.is_lenient()
                    {
                        let t = x.ty.clone();
                        self.err(x.span, format!("mismatched types in {what}: expected a string, array or map, found `{t}`"));
                    }
                    x
                }
                Some(EP::AnyMap) => {
                    let x = self.expr(a, None);
                    let x = self.value(x);
                    if !matches!(x.ty, Ty::Map(..)) && !x.ty.is_lenient() {
                        let t = x.ty.clone();
                        self.err(
                            x.span,
                            format!("mismatched types in {what}: expected a map, found `{t}`"),
                        );
                    }
                    x
                }
                None => {
                    let x = self.expr(a, None);
                    self.value(x)
                }
            };
            hargs.push(x);
        }
        if n == "self" {
            return Self::mk(H::SelfObj, Ty::Object, span);
        }
        let ret = match sig.ret {
            ER::Ty(t) => t,
            ER::KeysOf => match hargs.first().map(|a| &a.ty) {
                Some(Ty::Map(k, _)) => Ty::array((**k).clone()),
                _ => Ty::array(Ty::Any),
            },
        };
        Self::mk(
            H::CallEfun {
                name: n,
                privilege: sig.privilege,
                args: hargs,
            },
            ret,
            span,
        )
    }

    fn super_call(&mut self, name: &ast::Ident, args: &[ast::Expr], span: Span) -> hir::Expr {
        let mut found: Vec<Rc<FnInfo>> = Vec::new();
        for p in self.parents {
            if let Some(f) = p.info.fns.get(name.name.as_str())
                && !found.iter().any(|g| g.owner == f.owner)
            {
                found.push(f.clone());
            }
        }
        match found.len() {
            0 => {
                self.err(
                    name.span,
                    format!(
                        "`super::{}`: no inherited function with this name",
                        name.name
                    ),
                );
                for a in args {
                    self.expr(a, None);
                }
                Self::poison(span)
            }
            1 => {
                let f = found.remove(0);
                let args = self.check_args(&format!("super::{}", name.name), &f, args, span);
                Self::mk(
                    hir::ExprKind::Call {
                        callee: Callee::Static {
                            program: f.owner.clone(),
                            name: f.name.clone(),
                        },
                        args,
                    },
                    f.ret.clone(),
                    span,
                )
            }
            _ => {
                let owners: Vec<&str> = found.iter().map(|f| &*f.owner).collect();
                self.err_hint(
                    name.span,
                    format!(
                        "`super::{}` is ambiguous: it is inherited from {}",
                        name.name,
                        owners.join(" and ")
                    ),
                    format!("label the inherits and call `label::{}()`", name.name),
                );
                for a in args {
                    self.expr(a, None);
                }
                Self::poison(span)
            }
        }
    }
}

/// Facts valid after both branches of an `if`: the intersection.
fn meet(a: &Facts, b: &Facts) -> Facts {
    Facts {
        narrow: a
            .narrow
            .iter()
            .filter(|(k, v)| b.narrow.get(*k) == Some(*v))
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
        present: a.present.intersection(&b.present).cloned().collect(),
    }
}

fn assigned_names(stmts: &[ast::Stmt], out: &mut HashSet<String>) {
    for s in stmts {
        match &s.kind {
            S::Assign { target, .. } => {
                if let E::Ident(n) = &target.kind {
                    out.insert(n.clone());
                }
            }
            S::If { then, els, .. } => {
                assigned_names(&then.stmts, out);
                match els.as_deref() {
                    Some(ast::Else::Block(b)) => assigned_names(&b.stmts, out),
                    Some(ast::Else::If(s)) => assigned_names(std::slice::from_ref(s), out),
                    None => {}
                }
            }
            S::While { body, .. } | S::For { body, .. } => assigned_names(&body.stmts, out),
            _ => {}
        }
    }
}

fn binop_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Rem => "%",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Le => "<=",
        BinOp::Gt => ">",
        BinOp::Ge => ">=",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::In => "in",
        BinOp::Coalesce => "??",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions() {
        assert_eq!(suggest("strng", TYPE_NAMES.iter().copied()), Some("string"));
        assert_eq!(suggest("xyzzy", TYPE_NAMES.iter().copied()), None);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }
}
