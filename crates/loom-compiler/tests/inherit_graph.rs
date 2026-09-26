// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Multiple, labelled and virtual (diamond) inheritance through the
//! resolver. The Phase 0 parser only produces a single unlabelled `inherit`,
//! so these tests hand `check_program` the parent list directly; once V0
//! (OBI-23) parses `inherit label = /path` they move to golden mudlibs.

use std::rc::Rc;

use loom_compiler::hir::{Callee, ExprKind, StmtKind};
use loom_compiler::interface::{ParentInfo, ProgramInfo};
use loom_compiler::{Checked, check_program};
use loom_syntax::Span;

fn compile(
    path: &str,
    src: &str,
    parents: &[(Option<&str>, &Rc<ProgramInfo>)],
) -> Result<Checked, Vec<String>> {
    let (ast, d) = loom_syntax::parse(src);
    assert!(d.is_empty(), "{d:?}");
    let parents = parents
        .iter()
        .map(|(l, info)| ParentInfo {
            label: l.map(Rc::from),
            info: (*info).clone(),
            span: Span::default(),
        })
        .collect();
    check_program(path, &ast, parents).map_err(|ds| ds.into_iter().map(|d| d.message).collect())
}

fn ok(path: &str, src: &str, parents: &[(Option<&str>, &Rc<ProgramInfo>)]) -> Checked {
    compile(path, src, parents).unwrap_or_else(|e| panic!("{path}: {e:?}"))
}

/// A: base with a variable and two functions; B overrides `f`; C does not.
fn diamond() -> (Rc<ProgramInfo>, Rc<ProgramInfo>, Rc<ProgramInfo>) {
    let a = ok(
        "/a",
        "var x: int = 1\npub fn f() -> int {\n    return x\n}\npub fn g() -> int {\n    return 2\n}\n",
        &[],
    )
    .info;
    let b = ok(
        "/b",
        "pub override fn f() -> int {\n    return x + 10\n}\n",
        &[(None, &a)],
    )
    .info;
    let c = ok(
        "/c",
        "pub fn h() -> int {\n    return x\n}\n",
        &[(None, &a)],
    )
    .info;
    (a, b, c)
}

#[test]
fn diamond_shares_variables_and_dominant_override_wins() {
    let (_a, b, c) = diamond();
    let d = ok(
        "/d",
        "pub fn use_all() -> int {\n    x = 5\n    return f() + g() + h()\n}\n",
        &[(Some("left"), &b), (Some("right"), &c)],
    );
    let lin: Vec<&str> = d.hir.linearization.iter().map(|s| &**s).collect();
    assert_eq!(
        lin,
        ["/a", "/b", "/c", "/d"],
        "A appears once: one copy of x"
    );
    assert_eq!(&*d.info.fns["f"].owner, "/b");
    // `x` resolves to A's single copy.
    let body = &d.hir.fns[0].body.stmts;
    match &body[0].kind {
        StmtKind::Assign {
            place: loom_compiler::hir::Place::Global(g),
            ..
        } => assert_eq!(&*g.owner, "/a"),
        other => panic!("{other:?}"),
    }
    assert_eq!(d.hir.inherits[0].label.as_deref(), Some("left"));
}

#[test]
fn unrelated_versions_must_be_overridden() {
    let p = ok(
        "/p",
        "pub fn name() -> string {\n    return \"p\"\n}\n",
        &[],
    )
    .info;
    let q = ok(
        "/q",
        "pub fn name() -> string {\n    return \"q\"\n}\n",
        &[],
    )
    .info;
    let err = compile("/r", "", &[(Some("p"), &p), (Some("q"), &q)])
        .err()
        .unwrap();
    assert_eq!(err, ["function `name` is inherited from both /p and /q"]);

    // Overriding resolves it; `super::name` is then ambiguous.
    let err = compile(
        "/r",
        "pub override fn name() -> string {\n    return super::name()\n}\n",
        &[(Some("p"), &p), (Some("q"), &q)],
    )
    .err()
    .unwrap();
    assert_eq!(
        err,
        ["`super::name` is ambiguous: it is inherited from /p and /q"]
    );

    let r = ok(
        "/r",
        "pub override fn name() -> string {\n    return \"r\"\n}\n",
        &[(Some("p"), &p), (Some("q"), &q)],
    );
    assert_eq!(&*r.info.fns["name"].owner, "/r");
}

#[test]
fn super_call_is_static_to_the_declaring_program() {
    let (_a, b, _c) = diamond();
    let e = ok(
        "/e",
        "pub override fn f() -> int {\n    return super::f() + super::g()\n}\n",
        &[(None, &b)],
    );
    let StmtKind::Return(Some(ret)) = &e.hir.fns[0].body.stmts[0].kind else {
        panic!()
    };
    let ExprKind::Binary { lhs, rhs, .. } = &ret.kind else {
        panic!()
    };
    let callee = |x: &loom_compiler::hir::Expr| match &x.kind {
        ExprKind::Call { callee, .. } => callee.clone(),
        k => panic!("{k:?}"),
    };
    assert_eq!(
        callee(lhs),
        Callee::Static {
            program: Rc::from("/b"),
            name: Rc::from("f")
        }
    );
    assert_eq!(
        callee(rhs),
        Callee::Static {
            program: Rc::from("/a"),
            name: Rc::from("g")
        },
        "g is declared in /a, reached through /b"
    );
}

#[test]
fn inherit_conflicts() {
    let v1 = ok("/v1", "var hp: int = 1\n", &[]).info;
    let v2 = ok("/v2", "var hp: int = 2\n", &[]).info;
    let err = compile("/w", "", &[(None, &v1), (None, &v2)])
        .err()
        .unwrap();
    assert_eq!(err, ["variable `hp` is inherited from both /v1 and /v2"]);

    let err = compile("/w", "", &[(Some("l"), &v1), (Some("l"), &v2)])
        .err()
        .unwrap();
    assert!(
        err.contains(&"inherit label `l` is used twice".to_string()),
        "{err:?}"
    );

    let err = compile("/w", "", &[(None, &v1), (None, &v1)])
        .err()
        .unwrap();
    assert_eq!(err, ["`/v1` is inherited twice"]);
}

#[test]
fn private_members_are_not_inherited() {
    let p = ok(
        "/p",
        "private var secret: int = 1\nprivate fn hidden() -> int {\n    return secret\n}\n",
        &[],
    )
    .info;
    let err = compile(
        "/c",
        "fn f() -> int {\n    return hidden() + secret\n}\n",
        &[(None, &p)],
    )
    .err()
    .unwrap();
    assert_eq!(
        err,
        ["unknown function `hidden`", "unknown variable `secret`"]
    );
    // A private function is called statically; others virtually.
    let c = ok(
        "/c",
        "private fn mine() -> int {\n    return 1\n}\nfn f() -> int {\n    return mine()\n}\n",
        &[],
    );
    let StmtKind::Return(Some(e)) = &c.hir.fns[1].body.stmts[0].kind else {
        panic!()
    };
    assert!(matches!(
        &e.kind,
        ExprKind::Call {
            callee: Callee::Static { .. },
            ..
        }
    ));
}
