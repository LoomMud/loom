// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests at the bytecode trust boundary (spec: "fuzz the trust
//! boundary"). `decode` sees bytes from anywhere a `Module` might one day
//! be read from at rest; `verify` sees anything `decode` accepts, including
//! a `Module` assembled directly (as these tests do), not just our own
//! codegen's output. Neither may panic, and `verify` must never accept a
//! `Module` with an out-of-bounds register or jump target.
//!
//! Same harness pattern as `loom-syntax`'s parser property tests (V0,
//! OBI-23): build a valid seed, mutate it, assert only "no panic" plus a
//! cheap, directly-recomputable soundness check on an `Ok` verdict.

use std::rc::Rc;

use loom_compiler::bytecode::{self, ConstValue, FunctionCode, Module, Op};
use loom_compiler::verify::verify;
use proptest::prelude::*;

fn seed_module() -> Module {
    // /std/room::exit_dest, taken from the Phase 0 mudlib fixture: enough
    // shape (locals, a map, a branch, a call, a loop) to be an interesting
    // mutation target.
    let src = r#"
        pub fn exits() -> {string: string} { return {"south": "/hall"} }
        pub fn exit_dest(dir: string) -> string? {
            let ex = exits()
            if dir in ex {
                return ex[dir]
            }
            return null
        }
        pub fn sum(xs: [int]) -> int {
            var total = 0
            for x in xs {
                total += x
            }
            return total
        }
    "#;
    let (ast, diags) = loom_syntax::parse(src);
    assert!(diags.is_empty(), "{diags:?}");
    let checked =
        loom_compiler::check_program("/std/room", &ast, Vec::new(), Vec::new()).expect("checks");
    let module = loom_compiler::codegen::compile(&checked.hir).expect("codegen");
    verify(&module).expect("seed must verify");
    module
}

/// Every register index, jump target and const/string index a *verified*
/// module claims to use is actually in bounds. A cheap, independent
/// recomputation of what `verify` is supposed to guarantee, so a mutation
/// that fools `verify` into accepting something unsound still gets caught.
fn assert_actually_in_bounds(m: &Module) {
    for f in &m.functions {
        assert!((f.name as usize) < m.strings.len());
        let n_regs = f.reg_types.len();
        let check_reg = |r: u32| assert!((r as usize) < n_regs, "register %{r} out of bounds");
        let check_pc = |t: u32| assert!((t as usize) < f.code.len(), "pc {t} out of bounds");
        for op in &f.code {
            match op {
                Op::LoadConst { dst, idx } => {
                    check_reg(*dst);
                    assert!((*idx as usize) < m.consts.len());
                }
                Op::Copy { dst, src } => {
                    check_reg(*dst);
                    check_reg(*src);
                }
                Op::LoadSelf { dst } => check_reg(*dst),
                Op::LoadGlobal {
                    dst, owner, name, ..
                } => {
                    check_reg(*dst);
                    assert!((*owner as usize) < m.strings.len());
                    assert!((*name as usize) < m.strings.len());
                }
                Op::StoreGlobal {
                    owner, name, src, ..
                } => {
                    check_reg(*src);
                    assert!((*owner as usize) < m.strings.len());
                    assert!((*name as usize) < m.strings.len());
                }
                Op::UnOp { dst, src, .. } => {
                    check_reg(*dst);
                    check_reg(*src);
                }
                Op::BinOp { dst, a, b, .. } => {
                    check_reg(*dst);
                    check_reg(*a);
                    check_reg(*b);
                }
                Op::NewArray { dst, elems, .. } => {
                    check_reg(*dst);
                    elems.iter().for_each(|&r| check_reg(r));
                }
                Op::NewMap { dst, entries, .. } => {
                    check_reg(*dst);
                    entries.iter().for_each(|(k, v)| {
                        check_reg(*k);
                        check_reg(*v);
                    });
                }
                Op::Index {
                    dst, base, index, ..
                } => {
                    check_reg(*dst);
                    check_reg(*base);
                    check_reg(*index);
                }
                Op::IndexSet {
                    base, index, src, ..
                } => {
                    check_reg(*base);
                    check_reg(*index);
                    check_reg(*src);
                }
                Op::IterElems { dst, src, .. } => {
                    check_reg(*dst);
                    check_reg(*src);
                }
                Op::ToStr { dst, src } => {
                    check_reg(*dst);
                    check_reg(*src);
                }
                Op::Call { dst, args, .. } => {
                    if let Some(d) = dst {
                        check_reg(*d);
                    }
                    args.iter().for_each(|&r| check_reg(r));
                }
                Op::CallOther {
                    dst, recv, args, ..
                } => {
                    check_reg(*dst);
                    check_reg(*recv);
                    args.iter().for_each(|&r| check_reg(r));
                }
                Op::CallEfun { dst, args, .. } => {
                    if let Some(d) = dst {
                        check_reg(*d);
                    }
                    args.iter().for_each(|&r| check_reg(r));
                }
                Op::Cast { dst, src, .. } => {
                    check_reg(*dst);
                    check_reg(*src);
                }
                Op::Jump { target } => check_pc(*target),
                Op::Branch {
                    cond,
                    then_target,
                    else_target,
                } => {
                    check_reg(*cond);
                    check_pc(*then_target);
                    check_pc(*else_target);
                }
                Op::Return { src } => {
                    if let Some(r) = src {
                        check_reg(*r);
                    }
                }
                Op::TickCheck => {}
                Op::Throw { src } => check_reg(*src),
                Op::PushHandler {
                    catch_pc,
                    catch_reg,
                } => {
                    check_pc(*catch_pc);
                    if let Some(r) = catch_reg {
                        check_reg(*r);
                    }
                }
                Op::PopHandler => {}
            }
        }
    }
}

#[test]
fn seed_encode_decode_roundtrips_and_verifies() {
    let m = seed_module();
    let bytes = bytecode::encode(&m);
    let back = bytecode::decode(&bytes).expect("decode");
    verify(&back).expect("verify");
    assert_actually_in_bounds(&back);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// A single-byte mutation anywhere in a valid encoded module: `decode`
    /// must not panic, and if it produces a `Module`, `verify` must not
    /// panic either. If `verify` says `Ok`, the module really must be in
    /// bounds (`verify` cannot be fooled into accepting nonsense).
    #[test]
    fn single_byte_mutation_never_panics(pos in 0usize..4096, new_byte: u8) {
        let m = seed_module();
        let mut bytes = bytecode::encode(&m);
        prop_assume!(!bytes.is_empty());
        let pos = pos % bytes.len();
        bytes[pos] = new_byte;
        if let Ok(mutated) = bytecode::decode(&bytes)
            && let Ok(()) = verify(&mutated)
        {
            assert_actually_in_bounds(&mutated);
        }
    }

    /// Same property for a handful of scattered mutations at once (closer
    /// to a genuinely corrupted blob than one flipped byte).
    #[test]
    fn multi_byte_mutation_never_panics(
        positions in prop::collection::vec(0usize..4096, 1..8),
        bytes_new in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let m = seed_module();
        let mut bytes = bytecode::encode(&m);
        prop_assume!(!bytes.is_empty());
        for (p, b) in positions.iter().zip(bytes_new.iter()) {
            let p = p % bytes.len();
            bytes[p] = *b;
        }
        if let Ok(mutated) = bytecode::decode(&bytes)
            && verify(&mutated).is_ok()
        {
            assert_actually_in_bounds(&mutated);
        }
    }

    /// Directly-constructed, structurally arbitrary (but decode-shaped)
    /// modules: registers, jump targets and string/const indices chosen
    /// independently of any real function, so most are nonsense. `verify`
    /// must reject them or prove them in bounds, never panic.
    #[test]
    fn arbitrary_hand_built_module_never_panics(
        n_regs in 0u32..8,
        params in 0u32..4,
        ops in prop::collection::vec(
            (0u8..6, 0u32..10, 0u32..10, 0u32..10),
            0..12,
        ),
    ) {
        let reg_types = vec![loom_compiler::Ty::Int; n_regs as usize];
        let mut code: Vec<Op> = ops
            .iter()
            .map(|&(tag, a, b, c)| match tag {
                0 => Op::Copy { dst: a, src: b },
                1 => Op::BinOp {
                    dst: a,
                    op: loom_compiler::ir::BinOp::Add,
                    kind: loom_compiler::ir::OpKind::Int,
                    a: b,
                    b: c,
                },
                2 => Op::Jump { target: a },
                3 => Op::Branch {
                    cond: a,
                    then_target: b,
                    else_target: c,
                },
                4 => Op::Return { src: Some(a) },
                _ => Op::TickCheck,
            })
            .collect();
        code.push(Op::Return { src: None });
        let m = Module {
            path: Rc::from("/p"),
            strings: vec![Rc::from("f")],
            consts: vec![ConstValue::Int(0)],
            functions: vec![FunctionCode {
                name: 0,
                params: params.min(n_regs),
                min_arity: params.min(n_regs),
                ret: loom_compiler::Ty::Void,
                reg_types,
                entry_points: vec![0],
                code,
            }],
        };
        if verify(&m).is_ok() {
            assert_actually_in_bounds(&m);
        }
    }
}
