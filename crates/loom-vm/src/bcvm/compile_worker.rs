// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Compile off the world thread, install on it (spec §7.2, D-P1.5, OBI-90).
//!
//! `Compiler::recompile`'s parse/check/codegen/verify runs a real disk read
//! and a full re-typecheck of every dependent, which can be slow for a
//! large program or a large dependent subtree (`/std/item`'s "10k live
//! clones" exit criterion, OBI-34's base AC). Doing that synchronously on
//! the world thread would stall every tick/heartbeat/`call_out` for as
//! long as it takes.
//!
//! **Why this can't just hand a `Vec<Rc<CompiledProgram>>` to another
//! thread:** `CompiledProgram`/`Module` are built entirely out of `Rc`
//! (`Rc<str>` for interned names, `Rc<CompiledProgram>` for the parent
//! link) — spec §3.3's single-threaded heap. `Rc<T>` is never `Send`,
//! regardless of `T` or of who else might be touching it: even a
//! freshly-built, not-yet-shared `Rc` fails to compile across a channel
//! or `thread::spawn` closure. Worse, `Compiler::recompile` reads
//! `registry.program(..)` to find already-registered ancestors to link
//! against — those `Rc<CompiledProgram>`s are *live*, shared with
//! whatever the world thread is doing in the very same instant (a running
//! call's dispatch, another object's destruction); cloning/dropping that
//! `Rc`'s non-atomic refcount from two threads at once is a data race
//! (UB), full stop, `unsafe impl Send` or not.
//!
//! So the background thread here never touches a live `Rc<CompiledProgram>`
//! at all. It:
//!
//! 1. gets a plain, `Send`, `Rc`-free [`ProgramSnapshot`] of the *shape* of
//!    the currently-registered programs (path → parent path → version) —
//!    enough to replicate `Compiler::recompile`'s "find every dependent,
//!    parents before children" logic without the actual `Rc`s;
//! 2. compiles `path` and its dependents from disk through its own private
//!    `mudlib::Session` (fresh reads, not `Compiler::session` — never
//!    shared with the world thread either);
//! 3. for each, calls the same [`super::registry::compile_hir_unit`]
//!    codegen+verify the synchronous path uses, then **encodes** the
//!    result ([`loom_compiler::bytecode::encode`]/[`encode_ty`]) into
//!    plain bytes instead of keeping the `Rc`-based `Module` around.
//!
//! `Vec<u8>`/`String`/`u32`/`bool` are `Send`, so [`WireProgram`] crosses
//! an `mpsc` channel with no `unsafe` anywhere in this file. The world
//! thread ([`super::registry::Compiler::finish_recompile`]) decodes and
//! **re-verifies** each one (the same trust boundary `Module::decode`
//! already exists for — see `loom_compiler::bytecode`'s module doc —
//! this is simply one more thing on the other side of it) before wiring
//! up real `Rc<CompiledProgram>` parent links and hashing them into a
//! `HashMap<String, Rc<CompiledProgram>>`, exactly what
//! `Compiler::recompile` returns and `RegistryHost::install` (registry
//! mutation + per-object migration) still runs on the world thread,
//! unchanged (spec §7.2 step 2/4).
//!
//! **Recorded threading-boundary shape (cross-seam, CTO sign-off
//! requested on OBI-90 before merge):** one `std::thread::spawn` per
//! `begin_recompile` call (not a persistent pool — recompiles are rare
//! enough that pool reuse isn't worth the complexity yet) plus a
//! `std::sync::mpsc` channel, polled non-blocking from `World::tick`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use loom_compiler::bytecode;
use loom_compiler::mudlib::{self, Outcome, Session};

use super::registry::{Registry, compile_hir_unit};

/// One compiled program, ready to cross a `Send` boundary (see the module
/// doc comment for why this can't just be a `Rc<CompiledProgram>`).
#[derive(Clone, Debug)]
pub struct WireProgram {
    pub path: String,
    pub version: u32,
    /// `loom_compiler::bytecode::encode` of the verified `Module`.
    pub module_bytes: Vec<u8>,
    pub var_specs: Vec<WireVarSpec>,
    pub non_public: Vec<String>,
    /// This program's single parent-chain link (same Phase 0 restriction
    /// as `Compiler::recompile`: only the first `inherit`).
    pub parent_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WireVarSpec {
    pub name: String,
    /// `loom_compiler::bytecode::encode_ty`.
    pub ty_bytes: Vec<u8>,
    pub has_init: bool,
}

/// What a background [`RecompileJob`] finishes with.
#[derive(Debug)]
pub enum CompileOutcome {
    /// Every program `path` and its dependents recompiled to, parent-first
    /// (so [`super::registry::Compiler::finish_recompile`] can link each
    /// one against an already-processed earlier entry in the same batch).
    Ready(Vec<WireProgram>),
    /// Rendered diagnostics / "file not found", exactly like
    /// `Compiler::recompile`'s `Err(String)`.
    Failed(String),
}

/// Send-safe snapshot of a [`Registry`]'s current program topology (OBI-90):
/// everything [`run_recompile`] needs to find `path`'s dependents and the
/// next version number for each, without a single live `Rc<CompiledProgram>`
/// crossing to the background thread. Cheap to build — one pass over
/// already-registered programs, no disk I/O, no recompilation.
#[derive(Clone, Debug, Default)]
pub struct ProgramSnapshot {
    /// path → (parent path, current version).
    entries: std::collections::HashMap<String, (Option<String>, u32)>,
}

impl ProgramSnapshot {
    pub fn capture(registry: &Registry) -> Self {
        let entries = registry
            .programs
            .values()
            .map(|p| {
                (
                    p.path.to_string(),
                    (p.parent.as_ref().map(|pp| pp.path.to_string()), p.version),
                )
            })
            .collect();
        ProgramSnapshot { entries }
    }

    fn parent_of(&self, path: &str) -> Option<String> {
        self.entries.get(path).and_then(|(p, _)| p.clone())
    }

    /// True if `ancestor` is a strict ancestor of `path` (mirrors
    /// `CompiledProgram::inherits`, walking parent paths instead of `Rc`s).
    fn inherits(&self, path: &str, ancestor: &str) -> bool {
        let mut cur = self.parent_of(path);
        while let Some(p) = cur {
            if p == ancestor {
                return true;
            }
            cur = self.parent_of(&p);
        }
        false
    }

    /// Chain length (self + every ancestor), for `Compiler::recompile`'s
    /// "parents before children" dependent ordering.
    fn chain_len(&self, path: &str) -> usize {
        let mut n = 1;
        let mut cur = self.parent_of(path);
        while let Some(p) = cur {
            n += 1;
            cur = self.parent_of(&p);
        }
        n
    }

    fn next_version(&self, path: &str) -> u32 {
        self.entries.get(path).map_or(1, |(_, v)| v + 1)
    }
}

/// A `begin_recompile` in flight: poll [`RecompileJob::poll`] (non-blocking)
/// from the world thread until it returns `Some`.
pub struct RecompileJob {
    rx: mpsc::Receiver<CompileOutcome>,
    path: String,
}

impl RecompileJob {
    /// The program path this job was recompiling (for logging/diagnostics;
    /// `World` also tracks its own opaque `RecompileToken` per call).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Non-blocking: `None` while the background thread is still running.
    pub fn poll(&self) -> Option<CompileOutcome> {
        match self.rx.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(CompileOutcome::Failed(
                "internal: compile worker thread exited without a result".to_string(),
            )),
        }
    }
}

/// Kick off `path`'s recompile (spec §7.2 steps 1–3: parse/check/codegen/
/// verify) on a new background OS thread. Returns immediately; nothing
/// about `root`/`path`/`snapshot` is shared with anything the world thread
/// touches afterwards (`root`/`path` are owned copies, `snapshot` is a
/// plain, `Rc`-free value).
pub fn spawn_recompile(root: PathBuf, path: String, snapshot: ProgramSnapshot) -> RecompileJob {
    spawn_recompile_after(root, path, snapshot, std::time::Duration::ZERO)
}

/// [`spawn_recompile`], but the background thread sleeps for `delay`
/// before it starts compiling. Lets a test stand in for "a large/slow
/// compile" (spec r5 amendment's own suggested alternative to an actually
/// huge dependent tree) without needing a real multi-second `.wf` file —
/// see `tests/async_compile.rs`'s `ticks_keep_advancing_during_a_slow_background_compile`.
pub fn spawn_recompile_after(
    root: PathBuf,
    path: String,
    snapshot: ProgramSnapshot,
    delay: std::time::Duration,
) -> RecompileJob {
    let (tx, rx) = mpsc::channel();
    let job_path = path.clone();
    thread::Builder::new()
        .name("loom-compile".to_string())
        .spawn(move || {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let outcome = run_recompile(&root, &path, &snapshot);
            // The world thread may have stopped polling (e.g. it's shutting
            // down); nothing to do if the receiver is gone.
            let _ = tx.send(outcome);
        })
        .expect("failed to spawn background compile thread");
    RecompileJob { rx, path: job_path }
}

/// The actual background work: `Compiler::recompile`'s logic, replicated
/// against a [`ProgramSnapshot`] instead of a live [`Registry`] (see the
/// module doc comment for why), with its own private `Session` (fresh
/// disk reads; never `Compiler::session`, which stays untouched until
/// `finish_recompile` invalidates exactly these paths on the world
/// thread).
fn run_recompile(root: &std::path::Path, path: &str, snapshot: &ProgramSnapshot) -> CompileOutcome {
    let path = match mudlib::normalize_path(path) {
        Ok(p) => p,
        Err(e) => return CompileOutcome::Failed(e),
    };
    let mut session = Session::new(mudlib::FsLoader {
        root: root.to_path_buf(),
    });

    let mut dependents: Vec<String> = snapshot
        .entries
        .keys()
        .filter(|p| snapshot.inherits(p, &path))
        .cloned()
        .collect();
    dependents.sort_by_key(|p| snapshot.chain_len(p));

    let mut to_compile: Vec<String> = vec![path.clone()];
    to_compile.extend(dependents);

    let mut out: Vec<WireProgram> = Vec::new();
    let mut done: HashSet<String> = HashSet::new();
    for p in &to_compile {
        if !done.insert(p.clone()) {
            continue;
        }
        match session.compile(p) {
            Outcome::Ok(_) => {}
            Outcome::Failed(msg) => return CompileOutcome::Failed(msg.clone()),
            Outcome::Missing(msg) => return CompileOutcome::Failed(msg.clone()),
        }
        let anc_hir = match session.outcomes().get(p) {
            Some(Outcome::Ok(c)) => c.hir.clone(),
            _ => {
                return CompileOutcome::Failed(format!(
                    "internal: {p} missing from the compile session"
                ));
            }
        };
        let parent_path = anc_hir.inherits.first().map(|inh| inh.path.to_string());
        let unit = match compile_hir_unit(&anc_hir) {
            Ok(u) => u,
            Err(e) => return CompileOutcome::Failed(format!("{p}: {e}")),
        };
        let var_specs = unit
            .var_specs
            .iter()
            .map(|v| WireVarSpec {
                name: v.name.to_string(),
                ty_bytes: bytecode::encode_ty(&v.ty),
                has_init: v.has_init,
            })
            .collect();
        out.push(WireProgram {
            path: p.clone(),
            version: snapshot.next_version(p),
            module_bytes: bytecode::encode(&unit.module),
            var_specs,
            non_public: unit.non_public.iter().map(|s| s.to_string()).collect(),
            parent_path,
        });
    }
    CompileOutcome::Ready(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_replicates_dependent_order_and_versions() {
        // A three-level chain root -> mid -> leaf; recompiling `root`
        // should find both dependents, parent-first, at version+1.
        let mut snapshot = ProgramSnapshot::default();
        snapshot.entries.insert("/root".to_string(), (None, 3));
        snapshot
            .entries
            .insert("/mid".to_string(), (Some("/root".to_string()), 1));
        snapshot
            .entries
            .insert("/leaf".to_string(), (Some("/mid".to_string()), 5));

        assert!(snapshot.inherits("/mid", "/root"));
        assert!(snapshot.inherits("/leaf", "/root"));
        assert!(!snapshot.inherits("/root", "/leaf"));

        let mut dependents: Vec<&str> = snapshot
            .entries
            .keys()
            .filter(|p| snapshot.inherits(p, "/root"))
            .map(|s| s.as_str())
            .collect();
        dependents.sort_by_key(|p| snapshot.chain_len(p));
        assert_eq!(dependents, vec!["/mid", "/leaf"]);

        assert_eq!(snapshot.next_version("/root"), 4);
        assert_eq!(snapshot.next_version("/mid"), 2);
        assert_eq!(snapshot.next_version("/unregistered"), 1);
    }
}
