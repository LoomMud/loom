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
//!    the currently-registered programs (path → parent path → version →
//!    source hash) — enough to replicate `Compiler::recompile`'s "find
//!    every dependent, parents before children" logic, and to later detect
//!    that the registry drifted while the background thread was running,
//!    without the actual `Rc`s;
//! 2. compiles `path` and its dependents from disk through its own private
//!    `mudlib::Session` (fresh reads, not `Compiler::session` — never
//!    shared with the world thread either);
//! 3. for each, calls the same [`super::registry::compile_hir_unit`]
//!    codegen+verify the synchronous path uses, then **encodes** the
//!    result ([`loom_compiler::bytecode::encode`]/[`encode_ty`]) into
//!    plain bytes instead of keeping the `Rc`-based `Module` around.
//!
//! `Vec<u8>`/`String`/`u32`/`u64`/`bool` are `Send`, so [`WireProgram`]
//! crosses an `mpsc` channel with no `unsafe` anywhere in this file. The
//! world thread ([`super::registry::Compiler::finish_recompile`]) decodes
//! and **re-verifies** each one (the same trust boundary `Module::decode`
//! already exists for — see `loom_compiler::bytecode`'s module doc — this
//! is simply one more thing on the other side of it), checks the batch and
//! every out-of-batch ancestor for drift against a fresh snapshot (see
//! [`RecompileDrift`]), and only then wires up real `Rc<CompiledProgram>`
//! parent links into a `HashMap<String, Rc<CompiledProgram>>`, exactly
//! what `Compiler::recompile` returns and `RegistryHost::install`
//! (registry mutation + per-object migration) still runs on the world
//! thread, unchanged (spec §7.2 step 2/4).
//!
//! **Recorded threading-boundary shape (cross-seam, CTO-approved on
//! OBI-93):** one `std::thread::spawn` per `begin_recompile` call (not a
//! persistent pool — recompiles are rare enough that pool reuse isn't
//! worth the complexity yet) plus a `std::sync::mpsc` channel, polled
//! non-blocking from `World::tick`.
//!
//! **CTO review follow-up (OBI-93 "requested changes"): staleness.** A
//! `ProgramSnapshot` taken at `begin_recompile` can be out of date by the
//! time [`super::registry::Compiler::finish_recompile`] applies it — a
//! second overlapping `update` of the same path, a synchronous
//! `compile_object`, or a brand-new dependent loaded via `ensure_program`
//! can all land in between. `finish_recompile` re-snapshots the registry
//! and refuses to install (returns `Err`, installs nothing) if:
//! - any program in this batch, or the dependent set of the recompiled
//!   path, no longer matches what `begin_recompile` saw (someone else
//!   already changed it), or
//! - any out-of-batch ancestor this compile actually consulted (see
//!   [`WireProgram::source_hash`]/[`RecompileResult::ancestor_hashes`])
//!   has a different on-disk source now than what is currently installed
//!   — otherwise a program could end up verified against one ancestor
//!   interface and linked (`parent_path` → `registry.program(..)`)
//!   against a different, already-stale one.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use loom_compiler::bytecode;
use loom_compiler::mudlib::{self, Outcome, Session};

use super::registry::{Registry, compile_hir_unit};

/// Hash of `<root>/<path[1..]>.wf`'s current bytes (OBI-93 review item 2):
/// lets a snapshot notice a program's on-disk source changed since it was
/// last compiled, without needing to retain (or re-diff) the source text
/// itself. `None` if the file can't be read (deleted, permissions) —
/// treated as "this hash cannot be confirmed", i.e. a mismatch, by every
/// caller.
pub(crate) fn source_hash(root: &Path, path: &str) -> Option<u64> {
    let file = root.join(format!("{}.wf", path.strip_prefix('/').unwrap_or(path)));
    let bytes = std::fs::read(file).ok()?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    Some(h.finish())
}

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
    /// [`source_hash`] of this program's own `.wf` file, at the moment the
    /// background thread read it. Stored on the resulting
    /// `CompiledProgram` so a *later* background compile that treats this
    /// program as an out-of-batch ancestor can detect drift against it.
    pub source_hash: u64,
}

#[derive(Clone, Debug)]
pub struct WireVarSpec {
    pub name: String,
    /// `loom_compiler::bytecode::encode_ty`.
    pub ty_bytes: Vec<u8>,
    pub has_init: bool,
}

/// A finished, not-yet-applied background recompile.
#[derive(Debug, Default)]
pub struct RecompileResult {
    /// `path` and its dependents, parent-first (so
    /// [`super::registry::Compiler::finish_recompile`] can link each one
    /// against an already-processed earlier entry in the same batch).
    pub programs: Vec<WireProgram>,
    /// Every out-of-batch ancestor/import this compile actually consulted
    /// while type-checking the batch, with a [`source_hash`] taken at the
    /// same time — see the module doc comment's "staleness" section.
    pub ancestor_hashes: Vec<(String, u64)>,
}

/// What a background [`RecompileJob`] finishes with.
#[derive(Debug)]
pub enum CompileOutcome {
    Ready(RecompileResult),
    /// Rendered diagnostics / "file not found", exactly like
    /// `Compiler::recompile`'s `Err(String)`. Also used when the OS
    /// refused to spawn the background thread at all.
    Failed(String),
}

/// Send-safe snapshot of a [`Registry`]'s current program topology
/// (OBI-90): everything [`run_recompile`]/`finish_recompile` need to find
/// `path`'s dependents, the next version number for each, and detect
/// staleness against a later snapshot — all without a single live
/// `Rc<CompiledProgram>` crossing to the background thread. Cheap to
/// build — one pass over already-registered programs, no disk I/O, no
/// recompilation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProgramSnapshot {
    /// path → (parent path, current version, current source hash).
    entries: std::collections::HashMap<String, (Option<String>, u32, u64)>,
}

impl ProgramSnapshot {
    pub fn capture(registry: &Registry) -> Self {
        let entries = registry
            .programs
            .values()
            .map(|p| {
                (
                    p.path.to_string(),
                    (
                        p.parent.as_ref().map(|pp| pp.path.to_string()),
                        p.version,
                        p.source_hash,
                    ),
                )
            })
            .collect();
        ProgramSnapshot { entries }
    }

    fn parent_of(&self, path: &str) -> Option<String> {
        self.entries.get(path).and_then(|(p, _, _)| p.clone())
    }

    /// True if `ancestor` is a strict ancestor of `path` (mirrors
    /// `CompiledProgram::inherits`, walking parent paths instead of `Rc`s).
    pub(crate) fn inherits(&self, path: &str, ancestor: &str) -> bool {
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
        self.entries.get(path).map_or(1, |(_, v, _)| v + 1)
    }

    /// `path`'s current `(parent path, version, source hash)`, for a
    /// staleness comparison between two snapshots taken at different
    /// times (`None` on either side just means "not registered then").
    pub(crate) fn entry(&self, path: &str) -> Option<&(Option<String>, u32, u64)> {
        self.entries.get(path)
    }

    pub(crate) fn source_hash_of(&self, path: &str) -> Option<u64> {
        self.entries.get(path).map(|(_, _, h)| *h)
    }

    /// Every currently-registered path that (directly or transitively)
    /// inherits `path`, unordered (callers that care about ordering sort
    /// separately — `run_recompile` by chain length, `finish_recompile`'s
    /// staleness check just needs set equality).
    pub(crate) fn dependents_of(&self, path: &str) -> Vec<&str> {
        self.entries
            .keys()
            .filter(|p| self.inherits(p, path))
            .map(String::as_str)
            .collect()
    }
}

/// A `begin_recompile` in flight: poll [`RecompileJob::poll`] (non-blocking)
/// from the world thread until it returns `Some`.
pub struct RecompileJob {
    rx: mpsc::Receiver<CompileOutcome>,
    root_path: String,
    /// The snapshot `begin_recompile` captured — `finish_recompile` needs
    /// this again to detect drift (see the module doc comment).
    begin_snapshot: ProgramSnapshot,
}

impl RecompileJob {
    /// The program path this job was recompiling (for logging/diagnostics;
    /// `World` also tracks its own opaque `RecompileToken` per call).
    pub fn path(&self) -> &str {
        &self.root_path
    }

    pub fn begin_snapshot(&self) -> &ProgramSnapshot {
        &self.begin_snapshot
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
/// plain, `Rc`-free value). If the OS refuses to spawn the thread, the
/// returned job's first `poll()` immediately yields
/// `CompileOutcome::Failed` instead of panicking the world thread.
pub fn spawn_recompile(root: PathBuf, path: String, snapshot: ProgramSnapshot) -> RecompileJob {
    spawn_recompile_after(root, path, snapshot, std::time::Duration::ZERO)
}

/// [`spawn_recompile`], but the background thread sleeps for `delay`
/// before it starts compiling. Test/tooling support for standing in for
/// "a large/slow compile" (spec r5 amendment's own suggested alternative
/// to an actually huge dependent tree) without needing a real
/// multi-second `.wf` file — see `tests/async_compile.rs`.
#[doc(hidden)]
pub fn spawn_recompile_after(
    root: PathBuf,
    path: String,
    snapshot: ProgramSnapshot,
    delay: std::time::Duration,
) -> RecompileJob {
    let (tx, rx) = mpsc::channel();
    let job_path = path.clone();
    let begin_snapshot = snapshot.clone();
    let tx_for_thread = tx.clone();
    let spawned = thread::Builder::new()
        .name("loom-compile".to_string())
        .spawn(move || {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let outcome = run_recompile(&root, &path, &snapshot);
            // The world thread may have stopped polling (e.g. it's shutting
            // down); nothing to do if the receiver is gone.
            let _ = tx_for_thread.send(outcome);
        });
    if let Err(e) = spawned {
        // Never panic the world thread over a thread-spawn failure (e.g.
        // the OS is out of resources) — report it the same way a compile
        // error would be reported, through the very channel the caller is
        // about to poll.
        let _ = tx.send(CompileOutcome::Failed(format!(
            "failed to spawn background compile thread: {e}"
        )));
    }
    RecompileJob {
        rx,
        root_path: job_path,
        begin_snapshot,
    }
}

/// The actual background work: `Compiler::recompile`'s logic, replicated
/// against a [`ProgramSnapshot`] instead of a live [`Registry`] (see the
/// module doc comment for why), with its own private `Session` (fresh
/// disk reads; never `Compiler::session`, which stays untouched until
/// `finish_recompile` invalidates exactly these paths on the world
/// thread).
fn run_recompile(root: &Path, path: &str, snapshot: &ProgramSnapshot) -> CompileOutcome {
    let path = match mudlib::normalize_path(path) {
        Ok(p) => p,
        Err(e) => return CompileOutcome::Failed(e),
    };
    let mut session = Session::new(mudlib::FsLoader {
        root: root.to_path_buf(),
    });

    let mut dependents: Vec<String> = snapshot
        .dependents_of(&path)
        .into_iter()
        .map(str::to_string)
        .collect();
    dependents.sort_by_key(|p| snapshot.chain_len(p));

    // OBI-156: same gap as `Compiler::recompile` (see its comment) --
    // `path` may inherit an ancestor the snapshot has never seen because
    // it was never loaded/registered at all. Compile `path` first (which
    // recursively compiles and checks every ancestor through this
    // session, same as `ensure_program`) and queue any linearization
    // member the snapshot doesn't know about, ancestor-first, so it gets
    // a real `WireProgram` (and thus a real parent link) in this batch
    // before `path` itself is built.
    let linearization: Vec<std::rc::Rc<str>> = match session.compile(&path) {
        Outcome::Ok(checked) => checked.info.linearization.clone(),
        Outcome::Failed(msg) => return CompileOutcome::Failed(msg.clone()),
        Outcome::Missing(msg) => return CompileOutcome::Failed(msg.clone()),
    };
    let mut to_compile: Vec<String> = Vec::new();
    for anc in &linearization {
        if **anc == *path {
            continue;
        }
        if snapshot.entry(anc).is_none() {
            to_compile.push(anc.to_string());
        }
    }
    to_compile.push(path.clone());
    to_compile.extend(dependents);
    let in_batch: HashSet<String> = to_compile.iter().cloned().collect();

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
            source_hash: source_hash(root, p).unwrap_or(0),
        });
    }

    // Every other program the session touched while resolving `to_compile`'s
    // inherits/imports (i.e. everything it compiled that isn't itself part
    // of this batch) is an out-of-batch ancestor `finish_recompile` will
    // link against whatever is *currently installed* for it — so it must
    // not have drifted since. Hash it now, while we're already on the
    // background thread (see the module doc comment's "staleness" section).
    let mut ancestor_hashes = Vec::new();
    for (p, outcome) in session.outcomes() {
        if in_batch.contains(p) {
            continue;
        }
        if matches!(outcome, Outcome::Ok(_))
            && let Some(h) = source_hash(root, p)
        {
            ancestor_hashes.push((p.clone(), h));
        }
    }

    CompileOutcome::Ready(RecompileResult {
        programs: out,
        ancestor_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(snapshot: &mut ProgramSnapshot, path: &str, parent: Option<&str>, version: u32) {
        snapshot
            .entries
            .insert(path.to_string(), (parent.map(str::to_string), version, 0));
    }

    #[test]
    fn snapshot_replicates_dependent_order_and_versions() {
        // A three-level chain root -> mid -> leaf; recompiling `root`
        // should find both dependents, parent-first, at version+1.
        let mut snapshot = ProgramSnapshot::default();
        insert(&mut snapshot, "/root", None, 3);
        insert(&mut snapshot, "/mid", Some("/root"), 1);
        insert(&mut snapshot, "/leaf", Some("/mid"), 5);

        assert!(snapshot.inherits("/mid", "/root"));
        assert!(snapshot.inherits("/leaf", "/root"));
        assert!(!snapshot.inherits("/root", "/leaf"));

        let mut dependents = snapshot.dependents_of("/root");
        dependents.sort_by_key(|p| snapshot.chain_len(p));
        assert_eq!(dependents, vec!["/mid", "/leaf"]);

        assert_eq!(snapshot.next_version("/root"), 4);
        assert_eq!(snapshot.next_version("/mid"), 2);
        assert_eq!(snapshot.next_version("/unregistered"), 1);
    }

    #[test]
    fn a_changed_entry_or_dependent_set_is_detected_as_drift() {
        let mut begin = ProgramSnapshot::default();
        insert(&mut begin, "/root", None, 1);
        insert(&mut begin, "/mid", Some("/root"), 1);

        // Unchanged: same entry, same dependent set.
        let mut same = begin.clone();
        assert_eq!(begin.entry("/root"), same.entry("/root"));
        assert_eq!(begin.dependents_of("/root"), same.dependents_of("/root"));

        // A concurrent install bumped `/root`'s version underneath us.
        insert(&mut same, "/root", None, 2);
        assert_ne!(begin.entry("/root"), same.entry("/root"));

        // A brand-new dependent appeared underneath us.
        let mut new_dependent = begin.clone();
        insert(&mut new_dependent, "/also_mid", Some("/root"), 1);
        assert_ne!(
            begin.dependents_of("/root"),
            new_dependent.dependents_of("/root")
        );
    }
}
