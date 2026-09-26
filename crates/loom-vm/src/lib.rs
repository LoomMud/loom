// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft values, object table, program registry and evaluator/VM (§3.4, §5.9, §7). Owner: Gimli.
//!
//! Phase 0: a tree-walking evaluator over the `loom-syntax` AST with live
//! recompile (`compile_object`). The world is driven by a single world
//! thread owned by `loom-cli serve`; it talks to the network only through
//! [`Host`]. See `docs/weft-grammar.md` (Part 2) for the supported subset;
//! everything else is rejected by [`subset::phase0_gate`].

pub mod efuns;
pub mod host;
pub mod interp;
pub mod object;
pub mod program;
pub mod subset;
pub mod value;
pub mod world;

use std::collections::HashMap;
use std::path::Path;

pub use host::{Host, NullHost};
pub use interp::RtError;
pub use object::ObjectId;
pub use value::Value;
pub use world::{BootError, Limits, WORLD_THREAD_STACK, World};

/// Parse and link every `.wf` file under `root` without running any code
/// (`loom check`). Returns one rendered report per failing file, sorted.
pub fn check_mudlib(root: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    collect_wf(root, root, &mut files)?;
    files.sort();
    let mut st = world::State {
        root: root.to_path_buf(),
        objects: object::ObjectTable::default(),
        programs: HashMap::new(),
        names: HashMap::new(),
        next_clone: 0,
        conns: HashMap::new(),
        master: None,
        limits: Limits::default(),
    };
    let mut host = NullHost;
    let mut x = interp::Exec {
        ticks_left: 0,
        st: &mut st,
        host: &mut host,
        depth: 0,
        this_player: None,
        conn: None,
        compiling: Vec::new(),
        stack_base: interp::stack_addr(),
    };
    let mut errors = Vec::new();
    for path in files {
        if let Err(e) = x.ensure_program(&path) {
            errors.push(e);
        }
    }
    Ok(errors)
}

fn collect_wf(root: &Path, dir: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            collect_wf(root, &p, out)?;
        } else if p.extension().is_some_and(|e| e == "wf")
            && let Ok(rel) = p.strip_prefix(root)
        {
            let rel = rel.with_extension("");
            let s: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push(format!("/{}", s.join("/")));
        }
    }
    Ok(())
}
