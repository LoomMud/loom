// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Weft values, object table, program registry and the bytecode VM (§3.4,
//! §5.9, §7). Owner: Gimli.
//!
//! `World` is driven by a single world thread owned by `loom-cli serve`;
//! it talks to the network only through [`Host`]. Every `.wf` file is
//! compiled through `loom-compiler`'s resolver/checker and run on
//! [`bcvm::registry`]'s register-bytecode VM (OBI-72); see
//! `docs/weft-grammar.md` for the supported grammar.

pub mod bcvm;
pub mod disk_usage;
pub mod efuns;
pub mod errors;
pub mod fileio;
pub mod host;
pub mod object;
pub mod profiler;
pub mod quota;
pub mod rng;
pub mod roles;
pub mod scheduler;
pub mod security;
pub mod snapshot;
pub mod world;

use std::path::Path;

pub use bcvm::Value;
pub use bcvm::registry::{ChangeSet, RecompileReport, UpgradeWarning};
pub use bcvm::vm::RtError;
pub use host::{Host, NullHost};
pub use object::ObjectId;
pub use roles::{DomainRole, Grant, RolesSnapshot};
pub use snapshot::{SnapshotError, SnapshotJob};
pub use world::{
    AccountAuth, AdminErrorGroup, AdminObjectSummary, AdminObjectVars, AdminVarEntry, AuditRow,
    BootError, Limits, NullAccountAuth, NullRolesMutations, RolesMutations, SessionSummary, World,
};

/// Parse and link every `.wf` file under `root` without running any code
/// (`loom check`). Returns one rendered report per failing file, sorted.
pub fn check_mudlib(root: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    collect_wf(root, root, &mut files)?;
    files.sort();
    let mut registry = bcvm::registry::Registry::default();
    let mut compiler = bcvm::registry::Compiler::new(root.to_path_buf());
    let mut errors = Vec::new();
    for path in files {
        if let Err(e) = compiler.ensure_program(&mut registry, &path) {
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
