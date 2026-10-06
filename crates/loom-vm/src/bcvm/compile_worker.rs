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

use std::collections::{BTreeSet, HashSet};
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
    pub persistent: bool,
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

/// [`RecompileSetJob`]'s finished result (OBI-207, P2-B3.1b, D-B3.14): the
/// multi-root generalisation of [`RecompileResult`] -- `Compiler::
/// recompile_set`'s changed-set-plus-reverse-inherit-expansion logic,
/// replicated against a [`ProgramSnapshot`] on the background thread
/// exactly the way [`run_recompile`] already replicates `Compiler::
/// recompile` (see the module doc comment for why this can't be a live
/// `Rc<CompiledProgram>` instead).
#[derive(Debug, Default)]
pub struct RecompileSetResult {
    /// Every program actually compiled in this batch -- the reverse-
    /// inherit targets (`recompiled`, below) plus any never-loaded
    /// ancestor pulled in purely to resolve a target's parent link
    /// (OBI-156) -- ancestors first, so [`super::registry::Compiler::
    /// finish_recompile_set`] can link each one against an
    /// already-processed earlier entry in the same batch.
    pub programs: Vec<WireProgram>,
    /// Every changed, already-loaded path plus its reverse-inherit
    /// dependents, parents-first across the whole batch -- exactly
    /// [`super::registry::RecompileSetOutcome::recompiled`]'s contents,
    /// just not yet installed. A subset of `programs`' paths (an
    /// OBI-156 ancestor pulled in only for linking is never itself a
    /// target).
    pub recompiled: Vec<String>,
    /// Changed paths with no registered program at `begin_recompile_set`
    /// time -- nothing to do, the next `ensure_program` compiles them
    /// fresh.
    pub skipped_unloaded: Vec<String>,
    /// Deleted paths that were still registered -- kept running on their
    /// last-compiled program, not recompiled (nothing on disk to compile
    /// from).
    pub deleted_loaded: Vec<String>,
    /// Every out-of-batch ancestor/import this compile actually consulted
    /// while type-checking the batch, with a [`source_hash`] taken at the
    /// same time -- see the module doc comment's "staleness" section.
    pub ancestor_hashes: Vec<(String, u64)>,
}

/// What a background [`RecompileSetJob`] finishes with. Unlike
/// [`CompileOutcome`], `roots.is_empty()` (every changed path was unloaded,
/// a deleted path alone, or there was nothing to do) is not a failure --
/// it is a [`Ready`](CompileSetOutcome::Ready) outcome with empty
/// `programs`/`recompiled`, same as `Compiler::recompile_set`'s
/// synchronous "bail" path when there is nothing to compile. `Failed`
/// carries every diagnostic collected so far (a malformed changed-path
/// string, or a real compile error anywhere in the batch) -- all-or-
/// nothing, same contract as [`super::registry::RecompileSetOutcome::
/// failures`].
#[derive(Debug)]
pub enum CompileSetOutcome {
    Ready(RecompileSetResult),
    Failed(Vec<(String, String)>),
}

/// What a background [`RecompileJob`] finishes with.
#[derive(Debug)]
pub enum CompileOutcome {
    Ready(RecompileResult),
    /// Rendered diagnostics / "file not found", exactly like
    /// `Compiler::recompile`'s `Err(String)` used to be before OBI-296
    /// (T-FS-3): `path` is the specific program the diagnostic is about
    /// -- never folded into `message` -- so a caller with per-uid
    /// `valid_read` context (`World::poll_recompiles`) can redact it
    /// without having to re-parse a joined string. Also used when the
    /// OS refused to spawn the background thread at all, or the worker
    /// thread vanished without sending a result (`path` is then the
    /// root path this job was compiling, since that's the only path in
    /// scope).
    Failed {
        path: String,
        message: String,
    },
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
            Err(mpsc::TryRecvError::Disconnected) => Some(CompileOutcome::Failed {
                path: self.root_path.clone(),
                message: "internal: compile worker thread exited without a result".to_string(),
            }),
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
        let _ = tx.send(CompileOutcome::Failed {
            path: job_path.clone(),
            message: format!("failed to spawn background compile thread: {e}"),
        });
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
        Err(e) => {
            return CompileOutcome::Failed {
                path: path.to_string(),
                message: e,
            };
        }
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
        Outcome::Failed(msg) => {
            return CompileOutcome::Failed {
                path: path.clone(),
                message: msg.clone(),
            };
        }
        Outcome::Missing(msg) => {
            return CompileOutcome::Failed {
                path: path.clone(),
                message: msg.clone(),
            };
        }
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
            Outcome::Failed(msg) => {
                return CompileOutcome::Failed {
                    path: p.clone(),
                    message: msg.clone(),
                };
            }
            Outcome::Missing(msg) => {
                return CompileOutcome::Failed {
                    path: p.clone(),
                    message: msg.clone(),
                };
            }
        }
        let anc_hir = match session.outcomes().get(p) {
            Some(Outcome::Ok(c)) => c.hir.clone(),
            _ => {
                return CompileOutcome::Failed {
                    path: p.clone(),
                    message: "internal: missing from the compile session".to_string(),
                };
            }
        };
        let anc_src = match session.outcomes().get(p) {
            Some(Outcome::Ok(c)) => c.src.clone(),
            _ => {
                return CompileOutcome::Failed {
                    path: p.clone(),
                    message: "internal: missing from the compile session".to_string(),
                };
            }
        };
        let parent_path = anc_hir.inherits.first().map(|inh| inh.path.to_string());
        let unit = match compile_hir_unit(&anc_hir, &anc_src) {
            Ok(u) => u,
            Err(e) => {
                return CompileOutcome::Failed {
                    path: p.clone(),
                    message: e.to_string(),
                };
            }
        };
        let var_specs = unit
            .var_specs
            .iter()
            .map(|v| WireVarSpec {
                name: v.name.to_string(),
                ty_bytes: bytecode::encode_ty(&v.ty),
                has_init: v.has_init,
                persistent: v.persistent,
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

/// A [`Compiler::recompile_set`]-style classification of `changed`/`deleted`
/// against one [`ProgramSnapshot`] (OBI-207, D-B3.14): which changed paths
/// are already-registered roots vs. unloaded, which deleted paths are
/// still loaded, and the full reverse-inherit target set, parents-first.
/// Pure and snapshot-only (no disk I/O, no session) so it can run twice --
/// once against the snapshot [`spawn_recompile_set`] captured, once
/// against a fresh one at `finish_recompile_set` time -- and the two
/// results compared for equality as the multi-root staleness check (the
/// generalisation of [`finish_recompile`]'s single-root dependent-set
/// check). `Err` collects every malformed `changed`/`deleted` path
/// (`mudlib::normalize_path` failure) -- a batch-failing diagnostic, same
/// as a real compile error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Targets {
    /// Changed paths that are already registered -- the actual roots of
    /// the reverse-inherit expansion.
    pub(crate) roots: Vec<String>,
    pub(crate) skipped_unloaded: Vec<String>,
    pub(crate) deleted_loaded: Vec<String>,
    /// `roots` plus every currently-registered program that (directly or
    /// transitively) inherits one of them, parents-first across the whole
    /// batch -- [`super::registry::RecompileSetOutcome::recompiled`]'s
    /// contents.
    pub(crate) ordered: Vec<String>,
}

pub(crate) fn classify_targets(
    snapshot: &ProgramSnapshot,
    changed: &[String],
    deleted: &[String],
) -> Result<Targets, Vec<(String, String)>> {
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut roots: Vec<String> = Vec::new();
    let mut skipped_unloaded = Vec::new();
    for raw in changed {
        match mudlib::normalize_path(raw) {
            Ok(path) => {
                if snapshot.entry(&path).is_some() {
                    roots.push(path);
                } else {
                    skipped_unloaded.push(path);
                }
            }
            Err(e) => failures.push((raw.clone(), e)),
        }
    }
    let mut deleted_loaded = Vec::new();
    for raw in deleted {
        if let Ok(path) = mudlib::normalize_path(raw)
            && snapshot.entry(&path).is_some()
        {
            deleted_loaded.push(path);
        }
    }
    if !failures.is_empty() {
        return Err(failures);
    }
    if roots.is_empty() {
        return Ok(Targets {
            roots,
            skipped_unloaded,
            deleted_loaded,
            ordered: Vec::new(),
        });
    }

    let mut targets: BTreeSet<String> = roots.iter().cloned().collect();
    for p in snapshot.entries.keys() {
        if !deleted_loaded.iter().any(|d| d == p) && roots.iter().any(|r| snapshot.inherits(p, r)) {
            targets.insert(p.clone());
        }
    }
    let mut ordered: Vec<String> = targets.into_iter().collect();
    ordered.sort_by_key(|p| snapshot.chain_len(p));

    Ok(Targets {
        roots,
        skipped_unloaded,
        deleted_loaded,
        ordered,
    })
}

/// A `begin_recompile_set` in flight (OBI-207, D-B3.14): the multi-root
/// generalisation of [`RecompileJob`] -- poll [`RecompileSetJob::poll`]
/// (non-blocking) from the world thread until it returns `Some`.
pub struct RecompileSetJob {
    rx: mpsc::Receiver<CompileSetOutcome>,
    changed: Vec<String>,
    deleted: Vec<String>,
    begin_snapshot: ProgramSnapshot,
}

impl RecompileSetJob {
    pub fn changed(&self) -> &[String] {
        &self.changed
    }

    pub fn deleted(&self) -> &[String] {
        &self.deleted
    }

    pub fn begin_snapshot(&self) -> &ProgramSnapshot {
        &self.begin_snapshot
    }

    /// Non-blocking: `None` while the background thread is still running.
    pub fn poll(&self) -> Option<CompileSetOutcome> {
        match self.rx.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(CompileSetOutcome::Failed(vec![(
                "<batch>".to_string(),
                "internal: compile worker thread exited without a result".to_string(),
            )])),
        }
    }
}

/// Kick off `changed`/`deleted`'s batch recompile (D-B3.14's reverse-
/// inherit-expanded, dependency-ordered compile stage) on a new background
/// OS thread -- the multi-root generalisation of [`spawn_recompile`].
/// Returns immediately; nothing about `root`/`changed`/`deleted`/
/// `snapshot` is shared with anything the world thread touches afterwards.
pub fn spawn_recompile_set(
    root: PathBuf,
    changed: Vec<String>,
    deleted: Vec<String>,
    snapshot: ProgramSnapshot,
) -> RecompileSetJob {
    spawn_recompile_set_after(root, changed, deleted, snapshot, std::time::Duration::ZERO)
}

/// [`spawn_recompile_set`], but the background thread sleeps for `delay`
/// before it starts compiling -- test/tooling support, same as
/// [`spawn_recompile_after`].
#[doc(hidden)]
pub fn spawn_recompile_set_after(
    root: PathBuf,
    changed: Vec<String>,
    deleted: Vec<String>,
    snapshot: ProgramSnapshot,
    delay: std::time::Duration,
) -> RecompileSetJob {
    let (tx, rx) = mpsc::channel();
    let job_changed = changed.clone();
    let job_deleted = deleted.clone();
    let begin_snapshot = snapshot.clone();
    let tx_for_thread = tx.clone();
    let spawned = thread::Builder::new()
        .name("loom-compile-set".to_string())
        .spawn(move || {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let outcome = run_recompile_set(&root, &changed, &deleted, &snapshot);
            let _ = tx_for_thread.send(outcome);
        });
    if let Err(e) = spawned {
        let _ = tx.send(CompileSetOutcome::Failed(vec![(
            "<batch>".to_string(),
            format!("failed to spawn background compile thread: {e}"),
        )]));
    }
    RecompileSetJob {
        rx,
        changed: job_changed,
        deleted: job_deleted,
        begin_snapshot,
    }
}

/// The actual background work for a batch (D-B3.14, OBI-207): [`Compiler::
/// recompile_set`]'s reverse-inherit-expansion logic, replicated against a
/// [`ProgramSnapshot`] instead of a live [`Registry`] -- same reasoning and
/// same private per-thread [`Session`] as [`run_recompile`]. Compiles
/// "in topological waves" (D-B3.14's phrase): `ordered` -- the whole
/// batch's targets -- is already parents-before-children across every
/// root (same chain-length sort `Compiler::recompile_set` uses), and each
/// wave (one chain-length tier) is compiled before the next can need it,
/// through the one shared `Session` so a child's compile finds its
/// already-processed parent's checked HIR/linearization cached.
fn run_recompile_set(
    root: &Path,
    changed: &[String],
    deleted: &[String],
    snapshot: &ProgramSnapshot,
) -> CompileSetOutcome {
    let targets = match classify_targets(snapshot, changed, deleted) {
        Ok(t) => t,
        Err(failures) => return CompileSetOutcome::Failed(failures),
    };
    if targets.roots.is_empty() {
        return CompileSetOutcome::Ready(RecompileSetResult {
            programs: Vec::new(),
            recompiled: Vec::new(),
            skipped_unloaded: targets.skipped_unloaded,
            deleted_loaded: targets.deleted_loaded,
            ancestor_hashes: Vec::new(),
        });
    }

    let mut session = Session::new(mudlib::FsLoader {
        root: root.to_path_buf(),
    });
    for p in &targets.ordered {
        session.invalidate(p);
    }

    // OBI-156 (generalised to a batch, same as `Compiler::recompile_set`):
    // a root may inherit an ancestor that was never loaded/registered at
    // all. Compiling each root resolves its whole linearization; queue any
    // member the snapshot doesn't know about, ancestor-first, ahead of
    // every target below.
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut to_compile: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for root_path in &targets.roots {
        match session.compile(root_path) {
            Outcome::Ok(checked) => {
                for anc in &checked.info.linearization {
                    if **anc == *root_path.as_str() {
                        continue;
                    }
                    if snapshot.entry(anc).is_none() && seen.insert(anc.to_string()) {
                        to_compile.push(anc.to_string());
                    }
                }
            }
            Outcome::Failed(msg) | Outcome::Missing(msg) => {
                failures.push((root_path.clone(), msg.clone()))
            }
        }
    }
    for p in &targets.ordered {
        if seen.insert(p.clone()) {
            to_compile.push(p.clone());
        }
    }
    if !failures.is_empty() {
        return CompileSetOutcome::Failed(failures);
    }

    for p in &to_compile {
        match session.compile(p) {
            Outcome::Ok(_) => {}
            Outcome::Failed(msg) | Outcome::Missing(msg) => failures.push((p.clone(), msg.clone())),
        }
    }
    if !failures.is_empty() {
        return CompileSetOutcome::Failed(failures);
    }

    let in_batch: HashSet<String> = to_compile.iter().cloned().collect();
    let mut programs: Vec<WireProgram> = Vec::new();
    for p in &to_compile {
        let (anc_hir, anc_src) = match session.outcomes().get(p) {
            Some(Outcome::Ok(c)) => (c.hir.clone(), c.src.clone()),
            _ => {
                failures.push((
                    p.clone(),
                    format!("internal: {p} missing from the compile session"),
                ));
                continue;
            }
        };
        let parent_path = anc_hir.inherits.first().map(|inh| inh.path.to_string());
        let unit = match compile_hir_unit(&anc_hir, &anc_src) {
            Ok(u) => u,
            Err(e) => {
                failures.push((p.clone(), format!("{p}: {e}")));
                continue;
            }
        };
        let var_specs = unit
            .var_specs
            .iter()
            .map(|v| WireVarSpec {
                name: v.name.to_string(),
                ty_bytes: bytecode::encode_ty(&v.ty),
                has_init: v.has_init,
                persistent: v.persistent,
            })
            .collect();
        programs.push(WireProgram {
            path: p.clone(),
            version: snapshot.next_version(p),
            module_bytes: bytecode::encode(&unit.module),
            var_specs,
            non_public: unit.non_public.iter().map(|s| s.to_string()).collect(),
            parent_path,
            source_hash: source_hash(root, p).unwrap_or(0),
        });
    }
    if !failures.is_empty() {
        return CompileSetOutcome::Failed(failures);
    }

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

    CompileSetOutcome::Ready(RecompileSetResult {
        programs,
        recompiled: targets.ordered,
        skipped_unloaded: targets.skipped_unloaded,
        deleted_loaded: targets.deleted_loaded,
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

    #[test]
    fn classify_targets_unions_reverse_inherit_across_every_root() {
        // root1 -> mid -> leaf; root2 standalone. Both roots changed;
        // `mid`/`leaf` are pulled in purely through `root1`.
        let mut snapshot = ProgramSnapshot::default();
        insert(&mut snapshot, "/root1", None, 1);
        insert(&mut snapshot, "/mid", Some("/root1"), 1);
        insert(&mut snapshot, "/leaf", Some("/mid"), 1);
        insert(&mut snapshot, "/root2", None, 1);
        insert(&mut snapshot, "/unrelated", None, 1);

        let targets = classify_targets(
            &snapshot,
            &["/root1".to_string(), "/root2".to_string()],
            &[],
        )
        .expect("no malformed paths");
        assert_eq!(targets.roots, vec!["/root1", "/root2"]);
        assert!(targets.skipped_unloaded.is_empty());
        assert!(targets.deleted_loaded.is_empty());
        let mut ordered = targets.ordered.clone();
        ordered.sort_by_key(|p| snapshot.chain_len(p));
        assert_eq!(ordered, targets.ordered, "already parents-first");
        assert!(targets.ordered.contains(&"/root1".to_string()));
        assert!(targets.ordered.contains(&"/root2".to_string()));
        assert!(targets.ordered.contains(&"/mid".to_string()));
        assert!(targets.ordered.contains(&"/leaf".to_string()));
        assert!(!targets.ordered.contains(&"/unrelated".to_string()));
        // Parents before children: `/mid` before `/leaf`.
        let mid_pos = targets.ordered.iter().position(|p| p == "/mid").unwrap();
        let leaf_pos = targets.ordered.iter().position(|p| p == "/leaf").unwrap();
        assert!(mid_pos < leaf_pos);
    }

    #[test]
    fn classify_targets_skips_unloaded_and_reports_deleted_loaded() {
        let mut snapshot = ProgramSnapshot::default();
        insert(&mut snapshot, "/loaded", None, 1);

        let targets = classify_targets(
            &snapshot,
            &["/loaded".to_string(), "/never_loaded".to_string()],
            &["/loaded".to_string()],
        )
        .expect("no malformed paths");
        assert_eq!(targets.roots, vec!["/loaded"]);
        assert_eq!(targets.skipped_unloaded, vec!["/never_loaded"]);
        // `/loaded` is both changed and deleted: it stays a root (deleted
        // only excludes a *dependent* from the reverse-inherit expansion,
        // same as `Compiler::recompile_set`), but is also reported.
        assert_eq!(targets.deleted_loaded, vec!["/loaded"]);
    }

    #[test]
    fn classify_targets_agrees_before_and_after_an_unrelated_change() {
        // The multi-root staleness check (`finish_recompile_set`) compares
        // two `classify_targets` calls for equality -- confirm an
        // unrelated registry change (a brand-new, unrelated program) does
        // *not* trip it, while a new dependent of an actual root does.
        let mut begin = ProgramSnapshot::default();
        insert(&mut begin, "/root", None, 1);
        insert(&mut begin, "/mid", Some("/root"), 1);

        let mut unrelated_change = begin.clone();
        insert(&mut unrelated_change, "/elsewhere", None, 1);
        let changed = vec!["/root".to_string()];
        assert_eq!(
            classify_targets(&begin, &changed, &[]),
            classify_targets(&unrelated_change, &changed, &[])
        );

        let mut new_dependent = begin.clone();
        insert(&mut new_dependent, "/also_mid", Some("/root"), 1);
        assert_ne!(
            classify_targets(&begin, &changed, &[]),
            classify_targets(&new_dependent, &changed, &[])
        );
    }
}
