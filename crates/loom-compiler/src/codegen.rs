// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Lowering: typed HIR → [`crate::ir`] → [`crate::bytecode`] (spec §5.8).
//!
//! Two passes: [`lower_function`] builds the SSA-lite IR (control flow as
//! blocks, no jump offsets yet), [`assemble`] flattens it into linear
//! bytecode (absolute instruction indices, an interned string/const pool).
//! Splitting them keeps each pass simple and gives `crate::verify` and
//! `crate::disasm` a single flat format to work over regardless of how the
//! IR's block graph looked.
//!
//! This is an internal-invariant boundary, not a trust boundary: its input
//! is our own checker's typed HIR (already proven well-typed), so a
//! malformed HIR is a compiler bug, not untrusted input, and this code may
//! panic on one (`unreachable!`/`assert!`) rather than thread a `Result`
//! through every call. The trust boundary is the bytecode this produces,
//! guarded by [`crate::verify`].

use std::collections::HashMap;
use std::rc::Rc;

use crate::bytecode::{CalleeOp, ConstValue, FunctionCode, Module, Op};
use crate::hir;
use crate::ir::{self, BlockId, Callee, ConstOperand, Inst, Reg, Terminator};
use crate::ty::Ty;

/// A HIR construct not yet lowered (tracked for a follow-up; not exercised
/// by any Phase 0 mudlib program). See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "codegen: {} is not lowered yet (V2 scope)", self.0)
    }
}
impl std::error::Error for Unsupported {}

pub fn compile(p: &hir::Program) -> Result<Module, Unsupported> {
    let ir = lower_program(p)?;
    Ok(assemble(&ir))
}

fn lower_program(p: &hir::Program) -> Result<ir::Program, Unsupported> {
    // Closures found anywhere in the program (including inside other
    // closures) are lowered as ordinary `ir::Function`s and appended after
    // every named function (spec r5 §5.2.2, OBI-79): `base` is the index
    // the first one gets, so an `Inst::MakeClosure` built while lowering
    // function `i` can already name a not-yet-appended closure by its
    // final index in the flattened list.
    let base = p.fns.len() as u32;
    let mut extra = Vec::new();
    let functions = p
        .fns
        .iter()
        .map(|f| lower_function(f, base, &mut extra))
        .collect::<Result<Vec<_>, _>>()?;
    let mut functions = functions;
    functions.extend(extra);
    Ok(ir::Program {
        path: p.path.clone(),
        functions,
    })
}

fn lower_function(
    f: &hir::Function,
    base: u32,
    extra: &mut Vec<ir::Function>,
) -> Result<ir::Function, Unsupported> {
    let mut b = FnLower {
        reg_types: f.locals.iter().map(|l| l.ty.clone()).collect(),
        blocks: vec![ir::Block::default()],
        cur: 0,
        unreachable: false,
        base,
        extra,
    };
    b.block(&f.body)?;
    // Falling off the end of the body is only well-typed for a `void`
    // function (the checker requires every other path to `return`); a
    // body that always returns leaves `cur` already sealed by the last
    // `return` statement (`b.unreachable`), nothing to patch.
    if !b.unreachable {
        assert_eq!(f.ret, Ty::Void, "{}: missing return", f.name);
        b.seal_cur(Terminator::Return(None));
    }

    // Trailing parameters may have a default (hir::Param doc: "filled
    // callee-side"); the checker enforces defaults are a contiguous suffix,
    // so `min_arity` is just the count of leading params without one.
    let min_arity = f.params.iter().take_while(|p| p.default.is_none()).count() as u32;
    let param_count = f.params.len() as u32;
    let mut default_entries = vec![0u32; (param_count - min_arity + 1) as usize];
    // entry_points[params - min_arity] is "every argument supplied": the
    // unmodified body entry, no default evaluation needed.
    default_entries[(param_count - min_arity) as usize] = 0;
    // Build one block per omittable trailing parameter, in reverse
    // declaration order, each evaluating that parameter's default into its
    // register then falling through to the next parameter's block (or, for
    // the last one, into the body's real entry, block 0).

    let mut next_blk: ir::BlockId = 0;
    for p_idx in (min_arity as usize..param_count as usize).rev() {
        let param = &f.params[p_idx];
        let default = param
            .default
            .as_ref()
            .expect("trailing parameter must have a default (checker invariant)");
        let blk = b.new_block();
        b.switch(blk);
        b.unreachable = false;
        let r = b.expr(default)?;
        b.emit(Inst::Copy {
            dst: param.local,
            src: r,
        });
        b.seal_cur(Terminator::Jump(next_blk));
        default_entries[p_idx - min_arity as usize] = blk;
        next_blk = blk;
    }

    Ok(ir::Function {
        name: f.name.clone(),
        atomic: f.atomic,
        param_count,
        min_arity,
        ret: f.ret.clone(),
        reg_types: b.reg_types,
        blocks: b.blocks,
        entry: 0,
        default_entries,
        capture_targets: Vec::new(),
    })
}

struct FnLower<'e> {
    reg_types: Vec<Ty>,
    blocks: Vec<ir::Block>,
    cur: BlockId,
    /// Set once the current block has been sealed by a `return` (or, once
    /// merged, once *every* predecessor of the current position returned):
    /// later statements in the same lexical block are dead code, and must
    /// not append to (or re-terminate) an already-terminated block.
    unreachable: bool,
    /// See `lower_program`'s doc: the index the first closure body in
    /// `extra` gets in the final flattened function list.
    base: u32,
    /// Closure bodies discovered while lowering this function (or, when
    /// this `FnLower` is itself lowering a closure body, discovered inside
    /// it), shared with every closure nested inside it too (OBI-79).
    extra: &'e mut Vec<ir::Function>,
}

impl FnLower<'_> {
    fn new_reg(&mut self, ty: Ty) -> Reg {
        self.reg_types.push(ty);
        (self.reg_types.len() - 1) as Reg
    }

    fn new_block(&mut self) -> BlockId {
        self.blocks.push(ir::Block::default());
        (self.blocks.len() - 1) as BlockId
    }

    fn emit(&mut self, inst: Inst) {
        self.blocks[self.cur as usize].insts.push(inst);
    }

    fn switch(&mut self, blk: BlockId) {
        self.cur = blk;
    }

    /// Set the terminator of the *currently open* block (not necessarily
    /// the block a caller last switched to: nested control flow may have
    /// moved `cur` on to its own join block first).
    fn seal_cur(&mut self, term: Terminator) {
        self.blocks[self.cur as usize].term = term;
    }

    fn const_reg(&mut self, ty: Ty, value: ConstOperand) -> Reg {
        let dst = self.new_reg(ty);
        self.emit(Inst::Const { dst, value });
        dst
    }

    fn block(&mut self, blk: &hir::Block) -> Result<(), Unsupported> {
        for s in &blk.stmts {
            if self.unreachable {
                break;
            }
            self.stmt(s)?;
        }
        Ok(())
    }

    fn stmt(&mut self, s: &hir::Stmt) -> Result<(), Unsupported> {
        match &s.kind {
            hir::StmtKind::Let { local, init } => {
                match init {
                    Some(e) => {
                        let r = self.expr(e)?;
                        self.emit(Inst::Copy {
                            dst: *local,
                            src: r,
                        });
                    }
                    None => {
                        let ty = self.reg_types[*local as usize].clone();
                        self.emit(Inst::Const {
                            dst: *local,
                            value: ConstOperand::Null,
                        });
                        let _ = ty; // documents: only valid because the type is nullable
                    }
                }
                Ok(())
            }
            hir::StmtKind::Assign {
                place,
                op,
                kind,
                value,
            } => self.assign(place, *op, *kind, value),
            hir::StmtKind::If { cond, then, els } => {
                let cond_r = self.expr(cond)?;
                let then_blk = self.new_block();
                let else_blk = self.new_block();
                let join_blk = self.new_block();
                self.seal_cur(Terminator::Branch {
                    cond: cond_r,
                    then_blk,
                    else_blk,
                });

                self.switch(then_blk);
                self.unreachable = false;
                self.block(then)?;
                let then_falls_through = !self.unreachable;
                if then_falls_through {
                    self.seal_cur(Terminator::Jump(join_blk));
                }

                self.switch(else_blk);
                self.unreachable = false;
                if let Some(e) = els {
                    self.block(e)?;
                }
                let else_falls_through = !self.unreachable;
                if else_falls_through {
                    self.seal_cur(Terminator::Jump(join_blk));
                }

                self.switch(join_blk);
                self.unreachable = !then_falls_through && !else_falls_through;
                Ok(())
            }
            hir::StmtKind::While { cond, body } => {
                let header = self.new_block();
                let body_blk = self.new_block();
                let exit_blk = self.new_block();
                self.seal_cur(Terminator::Jump(header));
                self.switch(header);
                self.emit(Inst::TickCheck); // back-edge target (§5.9)
                let cond_r = self.expr(cond)?;
                self.seal_cur(Terminator::Branch {
                    cond: cond_r,
                    then_blk: body_blk,
                    else_blk: exit_blk,
                });
                self.switch(body_blk);
                self.unreachable = false;
                self.block(body)?;
                if !self.unreachable {
                    self.seal_cur(Terminator::Jump(header));
                }
                self.switch(exit_blk);
                self.unreachable = false;
                Ok(())
            }
            hir::StmtKind::For {
                local,
                iter,
                kind,
                body,
            } => {
                let elem_ty = self.reg_types[*local as usize].clone();
                let src_r = self.expr(iter)?;
                let elems_r = self.new_reg(Ty::array(elem_ty.clone()));
                self.emit(Inst::IterElems {
                    dst: elems_r,
                    src: src_r,
                    kind: *kind,
                    elem_ty: elem_ty.clone(),
                });
                let len_r = self.new_reg(Ty::Int);
                self.emit(Inst::CallEfun {
                    dst: Some(len_r),
                    name: "len",
                    args: vec![elems_r],
                });
                let i_r = self.const_reg(Ty::Int, ConstOperand::Int(0));

                let header = self.new_block();
                let body_blk = self.new_block();
                let exit_blk = self.new_block();
                self.seal_cur(Terminator::Jump(header));

                self.switch(header);
                self.emit(Inst::TickCheck);
                let cond_r = self.new_reg(Ty::Bool);
                self.emit(Inst::BinOp {
                    dst: cond_r,
                    op: hir::BinOp::Lt,
                    kind: hir::OpKind::Int,
                    a: i_r,
                    b: len_r,
                });
                self.seal_cur(Terminator::Branch {
                    cond: cond_r,
                    then_blk: body_blk,
                    else_blk: exit_blk,
                });

                self.switch(body_blk);
                self.emit(Inst::Index {
                    dst: *local,
                    base: elems_r,
                    index: i_r,
                    kind: hir::IndexKind::Array,
                });
                self.unreachable = false;
                self.block(body)?;
                if !self.unreachable {
                    let one = self.const_reg(Ty::Int, ConstOperand::Int(1));
                    let next_r = self.new_reg(Ty::Int);
                    self.emit(Inst::BinOp {
                        dst: next_r,
                        op: hir::BinOp::Add,
                        kind: hir::OpKind::Int,
                        a: i_r,
                        b: one,
                    });
                    self.emit(Inst::Copy {
                        dst: i_r,
                        src: next_r,
                    });
                    self.seal_cur(Terminator::Jump(header));
                }

                self.switch(exit_blk);
                self.unreachable = false;
                Ok(())
            }
            hir::StmtKind::Return(e) => {
                let r = match e {
                    Some(e) => Some(self.expr(e)?),
                    None => None,
                };
                self.seal_cur(Terminator::Return(r));
                self.unreachable = true;
                Ok(())
            }
            hir::StmtKind::Try {
                body,
                catch_var,
                handler,
            } => {
                let handler_blk = self.new_block();
                let after_blk = self.new_block();
                self.emit(Inst::PushHandler {
                    catch_blk: handler_blk,
                    catch_reg: *catch_var,
                });
                self.unreachable = false;
                self.block(body)?;
                let body_falls_through = !self.unreachable;
                if body_falls_through {
                    self.emit(Inst::PopHandler);
                    self.seal_cur(Terminator::Jump(after_blk));
                }

                self.switch(handler_blk);
                self.unreachable = false;
                self.block(handler)?;
                let handler_falls_through = !self.unreachable;
                if handler_falls_through {
                    self.seal_cur(Terminator::Jump(after_blk));
                }

                self.switch(after_blk);
                self.unreachable = !body_falls_through && !handler_falls_through;
                Ok(())
            }
            hir::StmtKind::Throw(e) => {
                let r = self.expr(e)?;
                self.seal_cur(Terminator::Throw(r));
                self.unreachable = true;
                Ok(())
            }
            hir::StmtKind::Expr(e) => self.expr_stmt(e),
        }
    }

    fn assign(
        &mut self,
        place: &hir::Place,
        op: hir::AssignOp,
        kind: hir::OpKind,
        value: &hir::Expr,
    ) -> Result<(), Unsupported> {
        match place {
            hir::Place::Local(id) => {
                let v = self.expr(value)?;
                let final_r = self.combine(op, kind, *id, v)?;
                self.emit(Inst::Copy {
                    dst: *id,
                    src: final_r,
                });
                Ok(())
            }
            hir::Place::Global(g) => {
                let v = self.expr(value)?;
                // `Set` stores exactly `value`'s type; a compound op reads
                // the global back first, at the type `kind` operates on
                // (kind fully determines it: `+=`/`-=`/... only target
                // int/float/string). Each read/write site carries its own
                // type, independent of other sites for the same global
                // (HIR invariant 1: reads already carry their flow-narrowed
                // type, so there is no one canonical `Ty` to look up here).
                if matches!(op, hir::AssignOp::Set) {
                    self.emit(Inst::StoreGlobal {
                        global: g.clone(),
                        ty: value.ty.clone(),
                        src: v,
                    });
                    return Ok(());
                }
                let ty = op_kind_ty(kind, &value.ty);
                let cur = self.new_reg(ty.clone());
                self.emit(Inst::LoadGlobal {
                    dst: cur,
                    global: g.clone(),
                    ty: ty.clone(),
                });
                let dst = self.new_reg(ty.clone());
                self.emit(Inst::BinOp {
                    dst,
                    op: assign_binop(op),
                    kind,
                    a: cur,
                    b: v,
                });
                self.emit(Inst::StoreGlobal {
                    global: g.clone(),
                    ty,
                    src: dst,
                });
                Ok(())
            }
            hir::Place::Index {
                base,
                index,
                kind: ik,
            } => {
                let base_r = self.expr(base)?;
                let index_r = self.expr(index)?;
                let v = self.expr(value)?;
                let final_r = if matches!(op, hir::AssignOp::Set) {
                    v
                } else {
                    let elem_ty = elem_type_of(&self.reg_types[base_r as usize]);
                    let cur = self.new_reg(elem_ty.clone());
                    self.emit(Inst::Index {
                        dst: cur,
                        base: base_r,
                        index: index_r,
                        kind: *ik,
                    });
                    let dst = self.new_reg(elem_ty);
                    self.emit(Inst::BinOp {
                        dst,
                        op: assign_binop(op),
                        kind,
                        a: cur,
                        b: v,
                    });
                    dst
                };
                self.emit(Inst::IndexSet {
                    base: base_r,
                    index: index_r,
                    kind: *ik,
                    src: final_r,
                });
                // Value semantics (spec r5 D24): `IndexSet` mutates
                // `base_r`'s own register in place (copy-on-write), which
                // is *a copy* of whatever `base` read from, not a shared
                // reference back to it. If `base` is directly a program
                // global (`exits[dir] = dest`, not e.g. a local array),
                // the mutated container must be written back or the edit
                // is invisible outside this function. This only covers the
                // one-level case (`global[i] = v`); a chain rooted in a
                // global two or more levels down (`global[i][j] = v`) needs
                // the fuller place-write lowering tracked on OBI-53.
                if let hir::ExprKind::Global(g) = &base.kind {
                    self.emit(Inst::StoreGlobal {
                        global: g.clone(),
                        ty: base.ty.clone(),
                        src: base_r,
                    });
                }
                Ok(())
            }
        }
    }

    /// `local op= value`: read `local`'s current value (its register,
    /// already holding it), apply `op`; `Set` short-circuits to `value`.
    fn combine(
        &mut self,
        op: hir::AssignOp,
        kind: hir::OpKind,
        local: Reg,
        value: Reg,
    ) -> Result<Reg, Unsupported> {
        if matches!(op, hir::AssignOp::Set) {
            return Ok(value);
        }
        let ty = self.reg_types[local as usize].clone();
        let dst = self.new_reg(ty);
        self.emit(Inst::BinOp {
            dst,
            op: assign_binop(op),
            kind,
            a: local,
            b: value,
        });
        Ok(dst)
    }

    /// A void-typed expression can only be a statement (the checker never
    /// lets `void` flow into a larger expression), so it is the only place
    /// that may emit a call with no destination register.
    fn expr_stmt(&mut self, e: &hir::Expr) -> Result<(), Unsupported> {
        if e.ty != Ty::Void {
            self.expr(e)?;
            return Ok(());
        }
        match &e.kind {
            hir::ExprKind::Call { callee, args } => {
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                self.emit(Inst::Call {
                    dst: None,
                    callee: lower_callee(callee),
                    args: args_r,
                });
            }
            hir::ExprKind::CallEfun { name, args, .. } => {
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                self.emit(Inst::CallEfun {
                    dst: None,
                    name,
                    args: args_r,
                });
            }
            hir::ExprKind::CallValue { callee, args } => {
                let func_r = self.expr(callee)?;
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                self.emit(Inst::CallValue {
                    dst: None,
                    func: func_r,
                    args: args_r,
                });
            }
            _ => {
                self.expr(e)?;
            }
        }
        Ok(())
    }

    fn args(&mut self, args: &[hir::Expr]) -> Result<Vec<Reg>, Unsupported> {
        args.iter().map(|a| self.expr(a)).collect()
    }

    /// Lower a closure literal (spec r5 §5.2.2, OBI-79): its body becomes
    /// an ordinary [`ir::Function`] appended to this program's flattened
    /// function list (see `lower_program`); the captured-by-value
    /// snapshot is taken *here*, at the `Closure` expression, by reading
    /// `outer_ids` — registers of *this* function — right now.
    fn closure(
        &mut self,
        cf: &hir::ClosureFn,
        outer_ids: &[hir::LocalId],
        span: loom_syntax::Span,
    ) -> Result<Reg, Unsupported> {
        let synth = hir::Function {
            name: Rc::from("<closure>"),
            vis: hir::Visibility::Private,
            is_override: false,
            atomic: false,
            params: cf
                .params
                .iter()
                .map(|&local| hir::Param {
                    local,
                    default: None,
                })
                .collect(),
            ret: cf.ret.clone(),
            locals: cf.locals.clone(),
            body: cf.body.clone(),
            span,
        };
        let mut body_ir = lower_function(&synth, self.base, self.extra)?;
        body_ir.capture_targets = cf.captures.clone();
        let idx = self.base + self.extra.len() as u32;
        self.extra.push(body_ir);

        let captures = outer_ids.iter().map(|&id| self.expr_local(id)).collect();
        let ty = Ty::Fn(Rc::new(crate::ty::FnTy {
            params: cf
                .params
                .iter()
                .map(|&id| self.reg_types[id as usize].clone())
                .collect(),
            ret: cf.ret.clone(),
        }));
        let dst = self.new_reg(ty);
        self.emit(Inst::MakeClosure {
            dst,
            func: idx,
            captures,
        });
        Ok(dst)
    }

    /// A local read as a plain register (locals and registers share one
    /// numbering, see the module docs): used for reading an *outer*
    /// function's local at the point a closure captures it, where there is
    /// no `hir::Expr` to lower through `Self::expr`.
    fn expr_local(&self, id: hir::LocalId) -> Reg {
        id
    }

    fn expr(&mut self, e: &hir::Expr) -> Result<Reg, Unsupported> {
        assert_ne!(
            e.ty,
            Ty::Void,
            "a void expression must be lowered through expr_stmt"
        );
        Ok(match &e.kind {
            hir::ExprKind::Int(n) => self.const_reg(e.ty.clone(), ConstOperand::Int(*n)),
            hir::ExprKind::Float(x) => self.const_reg(e.ty.clone(), ConstOperand::Float(*x)),
            hir::ExprKind::Str(s) => self.const_reg(e.ty.clone(), ConstOperand::Str(s.clone())),
            hir::ExprKind::Bool(b) => self.const_reg(e.ty.clone(), ConstOperand::Bool(*b)),
            hir::ExprKind::Null => self.const_reg(e.ty.clone(), ConstOperand::Null),
            hir::ExprKind::Interp(parts) => self.interp(parts)?,
            hir::ExprKind::Array(es) => {
                let elem_ty = match &e.ty {
                    Ty::Array(t) => (**t).clone(),
                    _ => unreachable!("array literal has non-array type"),
                };
                let elems = es.iter().map(|x| self.expr(x)).collect::<Result<_, _>>()?;
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::NewArray {
                    dst,
                    elem_ty,
                    elems,
                });
                dst
            }
            hir::ExprKind::Map(kvs) => {
                let (key_ty, val_ty) = match &e.ty {
                    Ty::Map(k, v) => ((**k).clone(), (**v).clone()),
                    _ => unreachable!("map literal has non-map type"),
                };
                let mut entries = Vec::with_capacity(kvs.len());
                for (k, v) in kvs {
                    entries.push((self.expr(k)?, self.expr(v)?));
                }
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::NewMap {
                    dst,
                    key_ty,
                    val_ty,
                    entries,
                });
                dst
            }
            hir::ExprKind::Local(id) => {
                // Flow narrowing (spec §5.6, `hir::Expr::ty` doc: "a narrowed
                // *use* has the narrower type on its Expr") changes only the
                // *use*'s static type, never the local's own declared
                // register type (registers are fixed-type, spec §5.8), so a
                // narrowed read here can disagree with the register it comes
                // from (e.g. `object?` narrowed to `object` after `!= null`).
                // Emit the same runtime-checked `Cast` the checker already
                // uses at the `any` boundary (§5.6, `ExprKind::Cast` doc):
                // narrowing is always sound at runtime, so this cast can
                // never actually fail, it just lets the verifier see the
                // narrower type codegen already committed to everywhere
                // else this expression's value is used.
                if e.ty == self.reg_types[*id as usize] {
                    *id
                } else {
                    let dst = self.new_reg(e.ty.clone());
                    self.emit(Inst::Cast {
                        dst,
                        src: *id,
                        ty: e.ty.clone(),
                    });
                    dst
                }
            }
            hir::ExprKind::Global(g) => {
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::LoadGlobal {
                    dst,
                    global: g.clone(),
                    ty: e.ty.clone(),
                });
                dst
            }
            hir::ExprKind::SelfObj => {
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::LoadSelf { dst });
                dst
            }
            hir::ExprKind::FnRef(callee) => {
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::MakeFn {
                    dst,
                    callee: lower_callee(callee),
                });
                dst
            }
            hir::ExprKind::Closure(cf, outer_ids) => self.closure(cf, outer_ids, e.span)?,
            hir::ExprKind::Index { base, index, kind } => {
                let base_r = self.expr(base)?;
                let index_r = self.expr(index)?;
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::Index {
                    dst,
                    base: base_r,
                    index: index_r,
                    kind: *kind,
                });
                dst
            }
            hir::ExprKind::Unary { op, kind, expr } => {
                let src = self.expr(expr)?;
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::UnOp {
                    dst,
                    op: *op,
                    kind: *kind,
                    src,
                });
                dst
            }
            hir::ExprKind::Binary { op, kind, lhs, rhs } => {
                let a = self.expr(lhs)?;
                let b = self.expr(rhs)?;
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::BinOp {
                    dst,
                    op: *op,
                    kind: *kind,
                    a,
                    b,
                });
                dst
            }
            hir::ExprKind::And(a, b) => self.short_circuit(a, b, true)?,
            hir::ExprKind::Or(a, b) => self.short_circuit(a, b, false)?,
            hir::ExprKind::Coalesce(a, b) => self.coalesce(a, b, &e.ty)?,
            hir::ExprKind::Call { callee, args } => {
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::Call {
                    dst: Some(dst),
                    callee: lower_callee(callee),
                    args: args_r,
                });
                dst
            }
            hir::ExprKind::CallValue { callee, args } => {
                let func_r = self.expr(callee)?;
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::CallValue {
                    dst: Some(dst),
                    func: func_r,
                    args: args_r,
                });
                dst
            }
            hir::ExprKind::CallEfun { name, args, .. } => {
                let args_r = self.args(args)?;
                self.emit(Inst::TickCheck);
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::CallEfun {
                    dst: Some(dst),
                    name,
                    args: args_r,
                });
                dst
            }
            hir::ExprKind::CallOther {
                recv,
                name,
                args,
                safe,
            } => self.call_other(recv, name, args, *safe, &e.ty)?,
            hir::ExprKind::Cast(inner) => {
                let src = self.expr(inner)?;
                let dst = self.new_reg(e.ty.clone());
                self.emit(Inst::Cast {
                    dst,
                    src,
                    ty: e.ty.clone(),
                });
                dst
            }
        })
    }

    fn interp(&mut self, parts: &[hir::InterpPart]) -> Result<Reg, Unsupported> {
        let mut acc: Option<Reg> = None;
        for p in parts {
            let part_r = match p {
                hir::InterpPart::Lit(s) => self.const_reg(Ty::String, ConstOperand::Str(s.clone())),
                hir::InterpPart::Expr(e) => {
                    let v = self.expr(e)?;
                    let dst = self.new_reg(Ty::String);
                    self.emit(Inst::ToStr { dst, src: v });
                    dst
                }
            };
            acc = Some(match acc {
                None => part_r,
                Some(a) => {
                    let dst = self.new_reg(Ty::String);
                    self.emit(Inst::BinOp {
                        dst,
                        op: hir::BinOp::Add,
                        kind: hir::OpKind::Str,
                        a,
                        b: part_r,
                    });
                    dst
                }
            });
        }
        Ok(acc.unwrap_or_else(|| self.const_reg(Ty::String, ConstOperand::Str(Rc::from("")))))
    }

    /// `and`/`or`: evaluate `a`; only evaluate `b` if it can change the
    /// result (`and`: `a` true; `or`: `a` false).
    fn short_circuit(
        &mut self,
        a: &hir::Expr,
        b: &hir::Expr,
        is_and: bool,
    ) -> Result<Reg, Unsupported> {
        let dst = self.new_reg(Ty::Bool);
        let a_r = self.expr(a)?;
        let rhs_blk = self.new_block();
        let short_blk = self.new_block();
        let join_blk = self.new_block();
        if is_and {
            self.seal_cur(Terminator::Branch {
                cond: a_r,
                then_blk: rhs_blk,
                else_blk: short_blk,
            });
        } else {
            self.seal_cur(Terminator::Branch {
                cond: a_r,
                then_blk: short_blk,
                else_blk: rhs_blk,
            });
        }
        self.switch(rhs_blk);
        let b_r = self.expr(b)?;
        self.emit(Inst::Copy { dst, src: b_r });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(short_blk);
        self.emit(Inst::Copy { dst, src: a_r });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(join_blk);
        Ok(dst)
    }

    fn coalesce(&mut self, a: &hir::Expr, b: &hir::Expr, ty: &Ty) -> Result<Reg, Unsupported> {
        let dst = self.new_reg(ty.clone());
        let a_r = self.expr(a)?;
        let null_r = self.const_reg(Ty::Null, ConstOperand::Null);
        let is_null = self.new_reg(Ty::Bool);
        self.emit(Inst::BinOp {
            dst: is_null,
            op: hir::BinOp::Eq,
            kind: hir::OpKind::Generic,
            a: a_r,
            b: null_r,
        });
        let use_b_blk = self.new_block();
        let use_a_blk = self.new_block();
        let join_blk = self.new_block();
        self.seal_cur(Terminator::Branch {
            cond: is_null,
            then_blk: use_b_blk,
            else_blk: use_a_blk,
        });
        self.switch(use_b_blk);
        let b_r = self.expr(b)?;
        self.emit(Inst::Copy { dst, src: b_r });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(use_a_blk);
        self.emit(Inst::Cast {
            dst,
            src: a_r,
            ty: ty.clone(),
        });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(join_blk);
        Ok(dst)
    }

    fn call_other(
        &mut self,
        recv: &hir::Expr,
        name: &Rc<str>,
        args: &[hir::Expr],
        safe: bool,
        ty: &Ty,
    ) -> Result<Reg, Unsupported> {
        let recv_r = self.expr(recv)?;
        let dst = self.new_reg(ty.clone());
        if !safe {
            let args_r = self.args(args)?;
            self.emit(Inst::TickCheck);
            self.emit(Inst::CallOther {
                dst,
                recv: recv_r,
                name: name.clone(),
                args: args_r,
            });
            return Ok(dst);
        }
        let null_r = self.const_reg(Ty::Null, ConstOperand::Null);
        let is_null = self.new_reg(Ty::Bool);
        self.emit(Inst::BinOp {
            dst: is_null,
            op: hir::BinOp::Eq,
            kind: hir::OpKind::Generic,
            a: recv_r,
            b: null_r,
        });
        let null_blk = self.new_block();
        let call_blk = self.new_block();
        let join_blk = self.new_block();
        self.seal_cur(Terminator::Branch {
            cond: is_null,
            then_blk: null_blk,
            else_blk: call_blk,
        });
        self.switch(null_blk);
        self.emit(Inst::Const {
            dst,
            value: ConstOperand::Null,
        });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(call_blk);
        let args_r = self.args(args)?;
        self.emit(Inst::TickCheck);
        self.emit(Inst::CallOther {
            dst,
            recv: recv_r,
            name: name.clone(),
            args: args_r,
        });
        self.seal_cur(Terminator::Jump(join_blk));
        self.switch(join_blk);
        Ok(dst)
    }
}

fn assign_binop(op: hir::AssignOp) -> hir::BinOp {
    match op {
        hir::AssignOp::Set => unreachable!("Set has no operator"),
        hir::AssignOp::Add => hir::BinOp::Add,
        hir::AssignOp::Sub => hir::BinOp::Sub,
        hir::AssignOp::Mul => hir::BinOp::Mul,
        hir::AssignOp::Div => hir::BinOp::Div,
        hir::AssignOp::Rem => hir::BinOp::Rem,
    }
}

fn lower_callee(c: &hir::Callee) -> Callee {
    match c {
        hir::Callee::Virtual { name } => Callee::Virtual { name: name.clone() },
        hir::Callee::Static { program, name } => Callee::Static {
            program: program.clone(),
            name: name.clone(),
        },
    }
}

fn elem_type_of(container: &Ty) -> Ty {
    match container {
        Ty::Array(t) | Ty::Map(_, t) => (**t).clone(),
        _ => Ty::Any,
    }
}

/// The concrete `Ty` a compound-assignment operand kind implies (`kind` is
/// resolved from the checker's operator table, spec §5.3: only int, float
/// and string support `+=`/`-=`/...). Falls back to `fallback` (the RHS
/// expression's type) for kinds compound assignment does not apply to.
fn op_kind_ty(kind: hir::OpKind, fallback: &Ty) -> Ty {
    match kind {
        hir::OpKind::Int => Ty::Int,
        hir::OpKind::Float => Ty::Float,
        hir::OpKind::Str => Ty::String,
        hir::OpKind::Bool => Ty::Bool,
        _ => fallback.clone(),
    }
}

// ---------------------------------------------------------------------
// Assembly: IR (block graph) -> flat bytecode (absolute jump targets).
// ---------------------------------------------------------------------

struct Assembler {
    strings: Vec<Rc<str>>,
    str_index: HashMap<Rc<str>, u32>,
    consts: Vec<ConstValue>,
}

impl Assembler {
    fn intern(&mut self, s: &Rc<str>) -> u32 {
        if let Some(&id) = self.str_index.get(s) {
            return id;
        }
        let id = self.strings.len() as u32;
        self.strings.push(s.clone());
        self.str_index.insert(s.clone(), id);
        id
    }

    fn const_id(&mut self, v: ConstOperand) -> u32 {
        let cv = match v {
            ConstOperand::Int(n) => ConstValue::Int(n),
            ConstOperand::Float(x) => ConstValue::Float(x),
            ConstOperand::Str(s) => ConstValue::Str(self.intern(&s)),
            ConstOperand::Bool(b) => ConstValue::Bool(b),
            ConstOperand::Null => ConstValue::Null,
        };
        let id = self.consts.len() as u32;
        self.consts.push(cv);
        id
    }

    fn function(&mut self, f: &ir::Function) -> FunctionCode {
        // A join block that both incoming arms returned through (e.g. an
        // `if`/`else` where both branches `return`) is never jumped to and
        // never sealed; it has no instructions either (codegen never
        // populates a block before deciding whether it is reachable).
        // Dropping it keeps the invariant "every terminator in the
        // assembled code is well-typed" without a full reachability pass.
        let live: Vec<&ir::Block> = f
            .blocks
            .iter()
            .inspect(|b| {
                assert!(
                    !matches!(b.term, Terminator::Unset) || b.insts.is_empty(),
                    "a populated block must be sealed"
                );
            })
            .collect();
        let mut starts = vec![0u32; live.len()];
        let mut pc = 0u32;
        for (i, blk) in live.iter().enumerate() {
            starts[i] = pc;
            if !matches!(blk.term, Terminator::Unset) {
                pc += blk.insts.len() as u32 + 1; // +1 for the terminator
            }
        }
        let mut code = Vec::with_capacity(pc as usize);
        for blk in &live {
            if matches!(blk.term, Terminator::Unset) {
                continue;
            }
            for inst in &blk.insts {
                code.push(self.op(inst, &starts));
            }
            code.push(match &blk.term {
                Terminator::Jump(t) => Op::Jump {
                    target: starts[*t as usize],
                },
                Terminator::Branch {
                    cond,
                    then_blk,
                    else_blk,
                } => Op::Branch {
                    cond: *cond,
                    then_target: starts[*then_blk as usize],
                    else_target: starts[*else_blk as usize],
                },
                Terminator::Return(r) => Op::Return { src: *r },
                Terminator::Throw(r) => Op::Throw { src: *r },
                Terminator::Unset => unreachable!(),
            });
        }
        let entry_points: Vec<u32> = f
            .default_entries
            .iter()
            .map(|&blk| starts[blk as usize])
            .collect();
        let name = self.intern(&f.name);
        FunctionCode {
            name,
            atomic: f.atomic,
            params: f.param_count,
            min_arity: f.min_arity,
            ret: f.ret.clone(),
            reg_types: f.reg_types.clone(),
            entry_points,
            code,
            capture_targets: f.capture_targets.clone(),
        }
    }

    fn op(&mut self, inst: &Inst, starts: &[u32]) -> Op {
        match inst {
            Inst::Const { dst, value } => Op::LoadConst {
                dst: *dst,
                idx: self.const_id(value.clone()),
            },
            Inst::Copy { dst, src } => Op::Copy {
                dst: *dst,
                src: *src,
            },
            Inst::LoadSelf { dst } => Op::LoadSelf { dst: *dst },
            Inst::LoadGlobal { dst, global, ty } => Op::LoadGlobal {
                dst: *dst,
                owner: self.intern(&global.owner),
                name: self.intern(&global.name),
                ty: ty.clone(),
            },
            Inst::StoreGlobal { global, ty, src } => Op::StoreGlobal {
                owner: self.intern(&global.owner),
                name: self.intern(&global.name),
                ty: ty.clone(),
                src: *src,
            },
            Inst::UnOp { dst, op, kind, src } => Op::UnOp {
                dst: *dst,
                op: *op,
                kind: *kind,
                src: *src,
            },
            Inst::BinOp {
                dst,
                op,
                kind,
                a,
                b,
            } => Op::BinOp {
                dst: *dst,
                op: *op,
                kind: *kind,
                a: *a,
                b: *b,
            },
            Inst::NewArray {
                dst,
                elem_ty,
                elems,
            } => Op::NewArray {
                dst: *dst,
                elem_ty: elem_ty.clone(),
                elems: elems.clone(),
            },
            Inst::NewMap {
                dst,
                key_ty,
                val_ty,
                entries,
            } => Op::NewMap {
                dst: *dst,
                key_ty: key_ty.clone(),
                val_ty: val_ty.clone(),
                entries: entries.clone(),
            },
            Inst::Index {
                dst,
                base,
                index,
                kind,
            } => Op::Index {
                dst: *dst,
                base: *base,
                index: *index,
                kind: *kind,
            },
            Inst::IndexSet {
                base,
                index,
                kind,
                src,
            } => Op::IndexSet {
                base: *base,
                index: *index,
                kind: *kind,
                src: *src,
            },
            Inst::IterElems {
                dst,
                src,
                kind,
                elem_ty,
            } => Op::IterElems {
                dst: *dst,
                src: *src,
                kind: *kind,
                elem_ty: elem_ty.clone(),
            },
            Inst::ToStr { dst, src } => Op::ToStr {
                dst: *dst,
                src: *src,
            },
            Inst::Call { dst, callee, args } => Op::Call {
                dst: *dst,
                callee: match callee {
                    Callee::Virtual { name } => CalleeOp::Virtual {
                        name: self.intern(name),
                    },
                    Callee::Static { program, name } => CalleeOp::Static {
                        program: self.intern(program),
                        name: self.intern(name),
                    },
                },
                args: args.clone(),
            },
            Inst::CallOther {
                dst,
                recv,
                name,
                args,
            } => Op::CallOther {
                dst: *dst,
                recv: *recv,
                name: self.intern(name),
                args: args.clone(),
            },
            Inst::CallEfun { dst, name, args } => Op::CallEfun {
                dst: *dst,
                name: self.intern(&Rc::from(*name)),
                args: args.clone(),
            },
            Inst::Cast { dst, src, ty } => Op::Cast {
                dst: *dst,
                src: *src,
                ty: ty.clone(),
            },
            Inst::TickCheck => Op::TickCheck,
            Inst::PushHandler {
                catch_blk,
                catch_reg,
            } => Op::PushHandler {
                catch_pc: starts[*catch_blk as usize],
                catch_reg: *catch_reg,
            },
            Inst::PopHandler => Op::PopHandler,
            Inst::MakeFn { dst, callee } => Op::MakeFn {
                dst: *dst,
                callee: match callee {
                    Callee::Virtual { name } => CalleeOp::Virtual {
                        name: self.intern(name),
                    },
                    Callee::Static { program, name } => CalleeOp::Static {
                        program: self.intern(program),
                        name: self.intern(name),
                    },
                },
            },
            Inst::MakeClosure {
                dst,
                func,
                captures,
            } => Op::MakeClosure {
                dst: *dst,
                func: *func,
                captures: captures.clone(),
            },
            Inst::CallValue { dst, func, args } => Op::CallValue {
                dst: *dst,
                func: *func,
                args: args.clone(),
            },
        }
    }
}

fn assemble(p: &ir::Program) -> Module {
    let mut a = Assembler {
        strings: Vec::new(),
        str_index: HashMap::new(),
        consts: Vec::new(),
    };
    let functions = p.functions.iter().map(|f| a.function(f)).collect();
    Module {
        path: p.path.clone(),
        strings: a.strings,
        consts: a.consts,
        functions,
    }
}

#[cfg(test)]
#[path = "codegen_tests.rs"]
mod tests;
