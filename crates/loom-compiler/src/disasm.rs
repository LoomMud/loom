// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Bytecode disassembler: a stable text form of a [`Module`] for `loom
//! disasm` and golden tests. One instruction per line, `PC  op args : ty`
//! where `ty` is the destination register's static type — the same type
//! [`crate::verify`] checks the instruction against, so a verifier
//! rejection is easy to read side by side with this dump.

use std::fmt::Write as _;

use crate::bytecode::{CalleeOp, ConstValue, FunctionCode, Module, Op};

pub fn module(m: &Module) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "module {}", m.path);
    for (i, c) in m.consts.iter().enumerate() {
        let _ = writeln!(out, "  const {i} = {}", const_text(m, c));
    }
    for f in &m.functions {
        out.push_str(&function(m, f));
    }
    out
}

pub fn function(m: &Module, f: &FunctionCode) -> String {
    let mut out = String::new();
    let name = &m.strings[f.name as usize];
    let regs: Vec<String> = f
        .reg_types
        .iter()
        .enumerate()
        .map(|(i, t)| format!("%{i}: {t}"))
        .collect();
    let _ = writeln!(
        out,
        "  fn {name}({}) -> {}  [regs: {}]",
        (0..f.params)
            .map(|i| format!("%{i}"))
            .collect::<Vec<_>>()
            .join(", "),
        f.ret,
        regs.join(", "),
    );
    for (pc, op) in f.code.iter().enumerate() {
        let _ = writeln!(out, "    {pc:04}  {}", op_text(m, f, op));
    }
    out
}

fn const_text(m: &Module, c: &ConstValue) -> String {
    match c {
        ConstValue::Int(n) => format!("{n}"),
        ConstValue::Float(x) => format!("{x}"),
        ConstValue::Bool(b) => format!("{b}"),
        ConstValue::Str(s) => format!("{:?}", m.strings[*s as usize].as_ref()),
        ConstValue::Null => "null".to_string(),
    }
}

fn reg_ty(f: &FunctionCode, r: u32) -> String {
    f.reg_types
        .get(r as usize)
        .map(|t| t.to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn args_text(args: &[u32]) -> String {
    args.iter()
        .map(|r| format!("%{r}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn str_at(m: &Module, idx: u32) -> String {
    m.strings
        .get(idx as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("<bad str {idx}>"))
}

fn op_text(m: &Module, f: &FunctionCode, op: &Op) -> String {
    match op {
        Op::LoadConst { dst, idx } => {
            format!(
                "LoadConst %{dst}, #{idx} = {} : {}",
                m.consts
                    .get(*idx as usize)
                    .map(|c| const_text(m, c))
                    .unwrap_or_else(|| "<bad const>".to_string()),
                reg_ty(f, *dst)
            )
        }
        Op::Copy { dst, src } => format!("Copy %{dst}, %{src} : {}", reg_ty(f, *dst)),
        Op::LoadSelf { dst } => format!("LoadSelf %{dst} : {}", reg_ty(f, *dst)),
        Op::LoadGlobal {
            dst,
            owner,
            name,
            ty,
        } => format!(
            "LoadGlobal %{dst}, {}::{} : {ty}",
            str_at(m, *owner),
            str_at(m, *name)
        ),
        Op::StoreGlobal {
            owner,
            name,
            ty,
            src,
        } => format!(
            "StoreGlobal {}::{}, %{src} : {ty}",
            str_at(m, *owner),
            str_at(m, *name)
        ),
        Op::UnOp { dst, op, kind, src } => {
            format!("UnOp.{kind:?} {op:?} %{dst}, %{src} : {}", reg_ty(f, *dst))
        }
        Op::BinOp {
            dst,
            op,
            kind,
            a,
            b,
        } => format!(
            "BinOp.{kind:?} {op:?} %{dst}, %{a}, %{b} : {}",
            reg_ty(f, *dst)
        ),
        Op::NewArray {
            dst,
            elem_ty,
            elems,
        } => {
            format!("NewArray %{dst}, [{}] : [{elem_ty}]", args_text(elems))
        }
        Op::NewMap {
            dst,
            key_ty,
            val_ty,
            entries,
        } => {
            let items: Vec<String> = entries.iter().map(|(k, v)| format!("%{k}: %{v}")).collect();
            format!(
                "NewMap %{dst}, {{{}}} : {{{key_ty}: {val_ty}}}",
                items.join(", ")
            )
        }
        Op::Index {
            dst,
            base,
            index,
            kind,
        } => format!(
            "Index.{kind:?} %{dst}, %{base}[%{index}] : {}",
            reg_ty(f, *dst)
        ),
        Op::IndexSet {
            base,
            index,
            kind,
            src,
        } => format!("IndexSet.{kind:?} %{base}[%{index}], %{src}"),
        Op::IterElems {
            dst,
            src,
            kind,
            elem_ty,
        } => format!("IterElems.{kind:?} %{dst}, %{src} : [{elem_ty}]"),
        Op::ToStr { dst, src } => format!("ToStr %{dst}, %{src} : string"),
        Op::Call { dst, callee, args } => {
            let c = match callee {
                CalleeOp::Virtual { name } => format!("virtual {}", str_at(m, *name)),
                CalleeOp::Static { program, name } => {
                    format!("static {}::{}", str_at(m, *program), str_at(m, *name))
                }
            };
            match dst {
                Some(d) => format!("Call %{d}, {c}({}) : {}", args_text(args), reg_ty(f, *d)),
                None => format!("Call {c}({})", args_text(args)),
            }
        }
        Op::CallOther {
            dst,
            recv,
            name,
            args,
        } => format!(
            "CallOther %{dst}, %{recv}.{}({}) : {}",
            str_at(m, *name),
            args_text(args),
            reg_ty(f, *dst)
        ),
        Op::CallEfun { dst, name, args } => match dst {
            Some(d) => format!(
                "CallEfun %{d}, {}({}) : {}",
                str_at(m, *name),
                args_text(args),
                reg_ty(f, *d)
            ),
            None => format!("CallEfun {}({})", str_at(m, *name), args_text(args)),
        },
        Op::Cast { dst, src, ty } => format!("Cast %{dst}, %{src} : {ty}"),
        Op::Jump { target } => format!("Jump {target:04}"),
        Op::Branch {
            cond,
            then_target,
            else_target,
        } => format!("Branch %{cond}, {then_target:04}, {else_target:04}"),
        Op::Return { src } => match src {
            Some(r) => format!("Return %{r}"),
            None => "Return".to_string(),
        },
        Op::TickCheck => "TickCheck".to_string(),
        Op::Throw { src } => format!("Throw %{src}"),
        Op::PushHandler {
            catch_pc,
            catch_reg,
        } => match catch_reg {
            Some(r) => format!("PushHandler {catch_pc:04}, %{r}"),
            None => format!("PushHandler {catch_pc:04}"),
        },
        Op::PopHandler => "PopHandler".to_string(),
        Op::MakeFn { dst, callee } => {
            let c = match callee {
                CalleeOp::Virtual { name } => format!("virtual {}", str_at(m, *name)),
                CalleeOp::Static { program, name } => {
                    format!("static {}::{}", str_at(m, *program), str_at(m, *name))
                }
            };
            format!("MakeFn %{dst}, {c} : {}", reg_ty(f, *dst))
        }
        Op::MakeClosure {
            dst,
            func,
            captures,
        } => format!(
            "MakeClosure %{dst}, #{func}({}) : {}",
            args_text(captures),
            reg_ty(f, *dst)
        ),
        Op::CallValue { dst, func, args } => match dst {
            Some(d) => format!(
                "CallValue %{d}, %{func}({}) : {}",
                args_text(args),
                reg_ty(f, *d)
            ),
            None => format!("CallValue %{func}({})", args_text(args)),
        },
    }
}
