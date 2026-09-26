// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Program interfaces and the inherit graph (spec §5.4).
//!
//! A [`ProgramInfo`] is what a checked program exports to programs that
//! inherit it: its visible functions and variables (own and inherited),
//! with types and declaring program. Children are checked against their
//! parents' interfaces only, never their bodies.
//!
//! Multiple inheritance is *virtual*: a program reachable along several
//! paths contributes one copy of its variables and one version of each
//! function. When two paths offer different versions of a function, the one
//! whose declaring program inherits the other's wins (dominance); if neither
//! dominates, the child must `override` it.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use loom_syntax::{Diagnostic, Span};

use crate::hir::Visibility;
use crate::ty::Ty;

#[derive(Debug)]
pub struct ProgramInfo {
    pub path: Rc<str>,
    pub parents: Vec<ParentInfo>,
    /// Root first, each program once, ending with this program.
    pub linearization: Vec<Rc<str>>,
    /// Strict ancestors.
    pub ancestors: HashSet<Rc<str>>,
    /// Functions an inheritor sees (non-private), resolved by dominance.
    pub fns: HashMap<Rc<str>, Rc<FnInfo>>,
    /// Variables an inheritor sees (non-private).
    pub vars: HashMap<Rc<str>, Rc<VarInfo>>,
}

#[derive(Debug, Clone)]
pub struct ParentInfo {
    pub label: Option<Rc<str>>,
    pub info: Rc<ProgramInfo>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FnInfo {
    pub name: Rc<str>,
    pub owner: Rc<str>,
    pub vis: Visibility,
    pub is_final: bool,
    pub params: Vec<ParamInfo>,
    pub ret: Ty,
}

impl FnInfo {
    pub fn required_args(&self) -> usize {
        self.params.iter().filter(|p| !p.has_default).count()
    }

    pub fn fn_ty(&self) -> Ty {
        Ty::Fn(Rc::new(crate::ty::FnTy {
            params: self.params.iter().map(|p| p.ty.clone()).collect(),
            ret: self.ret.clone(),
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParamInfo {
    pub name: Rc<str>,
    pub ty: Ty,
    pub has_default: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VarInfo {
    pub name: Rc<str>,
    pub owner: Rc<str>,
    pub ty: Ty,
    pub persistent: bool,
}

/// What a program inherits, merged from all parents.
#[derive(Debug, Default)]
pub struct Inherited {
    pub linearization: Vec<Rc<str>>,
    pub ancestors: HashSet<Rc<str>>,
    pub fns: HashMap<Rc<str>, Rc<FnInfo>>,
    /// Functions offered by more than one non-dominated program: the child
    /// must override them. Value: the competing versions.
    pub ambiguous_fns: HashMap<Rc<str>, Vec<Rc<FnInfo>>>,
    pub vars: HashMap<Rc<str>, Rc<VarInfo>>,
}

/// Merge the interfaces of `parents` (in source order). Diagnostics are for
/// conflicts that no declaration in the child can fix (duplicate labels,
/// the same program inherited twice directly, variable clashes).
pub fn merge_parents(parents: &[ParentInfo], diags: &mut Vec<Diagnostic>) -> Inherited {
    let mut out = Inherited::default();
    let mut by_path: HashMap<Rc<str>, Rc<ProgramInfo>> = HashMap::new();
    let mut labels: HashSet<Rc<str>> = HashSet::new();
    let mut direct: HashSet<Rc<str>> = HashSet::new();
    for p in parents {
        if let Some(l) = &p.label
            && !labels.insert(l.clone())
        {
            diags.push(
                Diagnostic::error(p.span, format!("inherit label `{l}` is used twice"))
                    .with_hint("give each labelled inherit a distinct label"),
            );
        }
        if !direct.insert(p.info.path.clone()) {
            diags.push(
                Diagnostic::error(p.span, format!("`{}` is inherited twice", p.info.path))
                    .with_hint("remove the duplicate `inherit`"),
            );
        }
        collect(&p.info, &mut by_path);
        for q in &p.info.linearization {
            if !out.linearization.contains(q) {
                out.linearization.push(q.clone());
            }
            out.ancestors.insert(q.clone());
        }
    }

    // Functions: candidates per name, deduplicated by declaring program, then
    // dominated versions dropped.
    let mut cands: HashMap<Rc<str>, Vec<Rc<FnInfo>>> = HashMap::new();
    for p in parents {
        for (name, f) in &p.info.fns {
            let v = cands.entry(name.clone()).or_default();
            if !v.iter().any(|g| g.owner == f.owner) {
                v.push(f.clone());
            }
        }
    }
    for (name, v) in cands {
        let dominated = |c: &FnInfo| {
            v.iter().any(|d| {
                d.owner != c.owner
                    && by_path
                        .get(&d.owner)
                        .is_some_and(|dp| dp.ancestors.contains(&c.owner))
            })
        };
        let mut live: Vec<Rc<FnInfo>> = v.iter().filter(|c| !dominated(c)).cloned().collect();
        if live.len() == 1 {
            out.fns.insert(name, live.remove(0));
        } else {
            live.sort_by(|a, b| a.owner.cmp(&b.owner));
            out.fns.insert(name.clone(), live[0].clone());
            out.ambiguous_fns.insert(name, live);
        }
    }

    // Variables: one copy per declaring program; different owners clash.
    for p in parents {
        for (name, v) in &p.info.vars {
            match out.vars.get(name) {
                Some(prev) if prev.owner != v.owner => diags.push(
                    Diagnostic::error(
                        p.span,
                        format!(
                            "variable `{name}` is inherited from both {} and {}",
                            prev.owner, v.owner
                        ),
                    )
                    .with_hint("rename the variable in one of the parents"),
                ),
                Some(_) => {}
                None => {
                    out.vars.insert(name.clone(), v.clone());
                }
            }
        }
    }
    out
}

fn collect(p: &Rc<ProgramInfo>, out: &mut HashMap<Rc<str>, Rc<ProgramInfo>>) {
    if out.contains_key(&p.path) {
        return;
    }
    out.insert(p.path.clone(), p.clone());
    for q in &p.parents {
        collect(&q.info, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(
        path: &str,
        parents: Vec<Rc<ProgramInfo>>,
        fns: &[&str],
        vars: &[&str],
    ) -> Rc<ProgramInfo> {
        let path: Rc<str> = Rc::from(path);
        let parents: Vec<ParentInfo> = parents
            .into_iter()
            .map(|info| ParentInfo {
                label: None,
                info,
                span: Span::default(),
            })
            .collect();
        let mut diags = Vec::new();
        let mut inh = merge_parents(&parents, &mut diags);
        assert!(diags.is_empty(), "{diags:?}");
        for f in fns {
            inh.fns.insert(
                Rc::from(*f),
                Rc::new(FnInfo {
                    name: Rc::from(*f),
                    owner: path.clone(),
                    vis: Visibility::Public,
                    is_final: false,
                    params: vec![],
                    ret: Ty::Void,
                }),
            );
            inh.ambiguous_fns.remove(*f);
        }
        for v in vars {
            inh.vars.insert(
                Rc::from(*v),
                Rc::new(VarInfo {
                    name: Rc::from(*v),
                    owner: path.clone(),
                    ty: Ty::Int,
                    persistent: false,
                }),
            );
        }
        let mut lin = inh.linearization.clone();
        lin.push(path.clone());
        Rc::new(ProgramInfo {
            path,
            parents,
            linearization: lin,
            ancestors: inh.ancestors,
            fns: inh.fns,
            vars: inh.vars,
        })
    }

    #[test]
    fn diamond_shares_one_copy_and_dominance_picks_override() {
        let a = prog("/a", vec![], &["f", "g"], &["x"]);
        let b = prog("/b", vec![a.clone()], &["f"], &[]);
        let c = prog("/c", vec![a.clone()], &[], &[]);
        let mut diags = Vec::new();
        let parents = [b, c]
            .into_iter()
            .map(|info| ParentInfo {
                label: None,
                info,
                span: Span::default(),
            })
            .collect::<Vec<_>>();
        let inh = merge_parents(&parents, &mut diags);
        assert!(diags.is_empty());
        let lin: Vec<&str> = inh.linearization.iter().map(|s| &**s).collect();
        assert_eq!(lin, ["/a", "/b", "/c"]);
        assert_eq!(&*inh.fns["f"].owner, "/b", "B's override dominates A's f");
        assert_eq!(&*inh.fns["g"].owner, "/a");
        assert!(inh.ambiguous_fns.is_empty());
        assert_eq!(&*inh.vars["x"].owner, "/a", "one shared copy of x");
    }

    #[test]
    fn unrelated_versions_are_ambiguous() {
        let a = prog("/a", vec![], &["f"], &["x"]);
        let b = prog("/b", vec![], &["f"], &["x"]);
        let mut diags = Vec::new();
        let parents = [a, b]
            .into_iter()
            .map(|info| ParentInfo {
                label: None,
                info,
                span: Span::default(),
            })
            .collect::<Vec<_>>();
        let inh = merge_parents(&parents, &mut diags);
        assert_eq!(inh.ambiguous_fns["f"].len(), 2);
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0]
                .message
                .contains("variable `x` is inherited from both")
        );
    }
}
