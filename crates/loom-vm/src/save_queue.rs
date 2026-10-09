// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Deferred durability for `save_object` writes (OBI-348, spec §8.1).
//!
//! ## Why this exists
//!
//! `World::disconnect` runs the mudlib's `autosave()` apply, which for a
//! player object is `save_character()` → `save_object()` →
//! [`crate::fileio::write_file_atomic`]: content write + `fsync`, `rename`,
//! then a second `fsync` on the **parent directory**. Two blocking `fsync`s
//! per save, on the thread that serves every connected player. The E1.1 CI
//! gate measured 150 simultaneous logouts producing world-loop iterations of
//! 304 ms and 562 ms (`loom_world_loop_stalls_total{kind="disconnect"}`,
//! `stall_ms_total 4905`) as soon as CI got a real save root (`ad489db`); the
//! same path cost 32 ms worst when the writes failed fast on `ENOENT`.
//!
//! What a save *is* -- the `sprint`/serialise, the §7.3 by-name keying -- is
//! mudlib code and must stay on the world thread. What a save *does to the
//! disk* (`fsync`, `rename`, dir `fsync`) need not. This module owns the
//! second half: the world thread renders and authorises a save, hands it to
//! one durability worker thread, and keeps serving.
//!
//! ## The durability contract this changes (spec §8.1 -- CTO decision)
//!
//! [`SaveDurability::Deferred`] (the default) makes `save_object()`
//! returning `true` mean "**the content is accepted, in order**"; it becomes
//! durable when the worker gets to it, or at the next
//! [`World::flush_pending_saves`] (which `World::begin_snapshot` and `Drop`
//! both call). Everything else about §8.1 holds:
//!
//! * **Atomicity unchanged.** The worker calls the same `write_file_atomic`,
//!   i.e. the `stage_write`/`commit_write` shape the OBI-171 PR #75 review
//!   fixed: a crash before the rename leaves the previous save byte-intact.
//! * **Validation and authorisation stay synchronous.** The suffix/size
//!   checks, symlink confinement, the master's `valid_write` apply and the
//!   `disk_quota_mb` projection all still run on the world thread inside
//!   `save_object()`, so a rejected save is rejected at the same call, with
//!   the same value, as before. Only the durable write moves.
//! * **Read-your-writes holds.** `restore_object()` on a path with queued
//!   saves waits for that path first ([`SaveQueue::flush_path`]), so
//!   `save_object(p); restore_object(p)` in one script reads back what it
//!   wrote, not the previous file.
//! * **Ordering holds.** One FIFO queue, one worker: saves for the same file
//!   commit in the order the world thread rendered them, so the newest
//!   content always wins. `World::disconnect` itself is untouched --
//!   unbind/`net_dead()` stay inline and in order.
//!
//! ## Backpressure: what a full queue does
//!
//! The queue is bounded by [`SaveQueueConfig::max_pending`] and
//! `max_pending_bytes`. A full queue **never takes a lock and never drops a
//! save**: [`SaveQueue::enqueue`] reaps what has already completed, and if
//! it still cannot fit an item it *waits for one slot* -- one commit's
//! latency, counted in [`SaveQueueStats::backpressure_waits`] -- instead of
//! committing inline beside a live worker. Only when there is no writer to
//! wait on (no worker, an item that can never fit even an empty queue, a
//! worker confirmed gone) does the save commit on the calling thread; that
//! is the one and only place the world thread pays for an `fsync` in
//! `save_object`, and [`SaveQueueStats::inline_commits`] counts it.
//!
//! `flush`/`flush_path` treat [`SaveQueueConfig::flush_deadline`] as a
//! *reporting* threshold, not a licence to start a second writer: past it the
//! flush keeps waiting, counts
//! [`SaveQueueStats::flush_deadline_exceeded`] (once per flush) and leaves a
//! one-line report for `World` to put in the error inbox
//! ([`SaveQueue::take_deadline_report`]). A wedged disk therefore stalls
//! `save_object`/`flush` instead of stalling *and* corrupting order. That is
//! deliberate, and no worse than the pre-OBI-348 driver, where every save
//! paid the wedge inline.
//!
//! ## The single-writer invariant (CTO review, OBI-348) -- non-negotiable
//!
//! **While the durability worker is alive, it is the only thread that ever
//! commits a save.** One writer per path is what makes "newest wins" true:
//! two threads committing the same path race on the temp file, and an older
//! queued save can be renamed *after* a newer one, so the newest content
//! loses. Committing inline to "make progress" on a wedged disk does not make
//! anything durable sooner -- it only adds the second writer. So an inline
//! commit happens **only** when there is provably nobody else writing: the
//! worker was never started, or it has been *confirmed* exited (its task
//! channel is closed and its buffered results drained), or `outstanding` is
//! empty -- which, because a task sits in `outstanding` from the moment it is
//! handed over until the moment its outcome is reaped, means the worker is
//! idle.
//!
//! CI proved why. `same_path_commits_in_order_so_the_newest_wins` failed on
//! run 37869788819 with `committed` 18 of 20: on a loaded runner the flush
//! deadline passed with two tasks still in flight, the old code committed
//! those two inline **while the worker still held them**, both writers used
//! `fileio`'s per-process temp name `.{leaf}.tmp-{pid}`, and one of the two
//! failed (`create_new` -> `EEXIST`, or the other writer's cleanup
//! `remove_file` unlinked its in-flight temp file). Both halves are now
//! regression-tested, and the temp name is unique per write.
//!
//! ## What an unclean shutdown costs
//!
//! A `SIGKILL`/power loss can lose only the saves still in the queue at that
//! instant. The worker commits eagerly (there is no batching timer to wait
//! for), so on a healthy disk that window is a millisecond or two of saves;
//! the E1.1 shape (an `fsync` taking hundreds of ms) is where the window
//! grows, which is why [`World::flush_pending_saves`] is called before every
//! snapshot/copyover capture and on `World` drop.
//!
//! ## Metrics
//!
//! Deliberately registers **no** `metrics` families: the counter family
//! names are `loom-obs`' owner's to expose (OBI-348 interface note).
//! [`World::save_queue_stats`] is the pull-side accessor for the runtime.
//!
//! [`World::flush_pending_saves`]: crate::world::World::flush_pending_saves

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How a `save_object` write reaches the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveDurability {
    /// Content is rendered and authorised on the world thread; the
    /// `fsync`/`rename`/dir-`fsync` half runs on the durability worker
    /// (OBI-348; what a `serve` world runs with).
    Deferred,
    /// The pre-OBI-348 behaviour: `save_object` performs the whole durable
    /// write inline on the calling (world) thread, and `true` means
    /// "durable". The fallback the queue degrades to when it cannot be
    /// served, and the mode tests/embedders can pin with
    /// [`crate::world::World::set_save_durability`].
    Sync,
}

/// One save waiting to be made durable. Owns everything the worker needs --
/// it never reads world state, the `Registry`, or `DiskUsage`.
#[derive(Clone, Debug)]
pub struct SaveTask {
    /// Monotonic per-queue sequence number; the FIFO ordering key, and the
    /// id outcomes are matched back with. Filled in by
    /// [`SaveQueue::enqueue`], so callers leave it at 0.
    pub seq: u64,
    /// The save root (`World::save_root`) captured at enqueue time, so a
    /// later `set_save_root` can't strand a queued save in the old tree.
    pub save_root: PathBuf,
    /// Mudlib-absolute save-file name, `.o` suffix included.
    pub path: String,
    /// The rendered save document.
    pub content: String,
    /// The writing object's uid, so the deferred `disk_quota_mb` charge can
    /// be applied against the right `DiskUsage` pool on completion.
    pub uid: String,
    /// The writing object's program path, for error-inbox attribution of a
    /// deferred failure (spec §8.3).
    pub program: String,
    /// The size this write replaces, as projected when the quota check ran
    /// (the queued predecessor's bytes if one exists, else the on-disk
    /// stat), so completion can charge `total - old + committed` exactly
    /// once per committed write.
    pub old_bytes: u64,
}

/// The durability worker's report on one [`SaveTask`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveOutcome {
    pub seq: u64,
    pub path: String,
    pub uid: String,
    pub program: String,
    pub old_bytes: u64,
    pub queued_bytes: u64,
    /// `Some(n)` -- the write landed and `n` is the file's size after the
    /// rename (a stat failure falls back to `queued_bytes`). `None` -- the
    /// durable write failed, so nothing was charged for it.
    pub committed_bytes: Option<u64>,
    /// `Some(reason)` on failure.
    pub error: Option<String>,
    /// The durable write **panicked** rather than returning `Err`: the worker
    /// caught it so the thread stayed alive, and this is what makes that
    /// visible in [`SaveQueueStats::panicked`]. A `false`/`Some(error)`
    /// outcome is a disk or policy failure; `true` is a bug.
    pub panicked: bool,
}

impl SaveOutcome {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Tuning for one durability queue.
///
/// Every wait here is a wait *on the worker*, never a second writer: see the
/// module doc's single-writer invariant.
#[derive(Clone, Debug)]
pub struct SaveQueueConfig {
    /// Maximum number of saves accepted before the queue counts as full. A
    /// full queue makes [`SaveQueue::enqueue`] wait for one slot (counted in
    /// [`SaveQueueStats::backpressure_waits`]) rather than commit beside the
    /// worker; the hand-off channel is bounded to exactly this, so the fit
    /// test itself is constant-time.
    pub max_pending: usize,
    /// Maximum total bytes of rendered-but-not-yet-durable saves. The count
    /// cap alone would let `max_pending` x `MAX_FILE_BYTES` (1 MiB) of save
    /// text sit in memory, so whichever bound trips first is "full".
    pub max_pending_bytes: u64,
    /// How many completed outcomes [`crate::world::World::tick`] reaps per
    /// tick. Reaping is what frees queue capacity, so this bounds how long
    /// a saturated queue takes to notice, not correctness (`enqueue` reaps
    /// too).
    pub poll_batch: usize,
    /// **Test-only** throttle: the worker sleeps this long before each
    /// commit. It exists so a *deterministic* local test can prove the world
    /// thread pays nothing for durability on a host whose real `fsync` is
    /// fast enough that "no stall" would prove nothing (OBI-344: the
    /// 150-session stall needs the loaded CI lane, and board directive
    /// OBI-306/307 forbids reproducing it here). Never set in production.
    pub commit_delay: Option<Duration>,
    /// **Test-only**: make [`Self::start_worker`] fail, exactly as a
    /// `thread::spawn` failure would, to exercise the inline fallback.
    pub worker_disabled: bool,
    /// How long one wait slice in `flush`/`flush_path` blocks before
    /// re-checking whether the worker is still alive.
    pub flush_wait_slice: Duration,
    /// Reporting threshold for one `flush`/`flush_path`/saturated-`enqueue`
    /// wait. Past it the wait *continues* -- a live worker is the only writer
    /// -- and the event is counted (`flush_deadline_exceeded`) plus left as a
    /// one-line report for `World` to put in the error inbox. It is how an
    /// operator learns the disk is behind, not a licence to start a second
    /// writer (CTO review, OBI-348).
    pub flush_deadline: Duration,
}

impl Default for SaveQueueConfig {
    fn default() -> Self {
        Self {
            // 512 covers a mass-teardown backlog with room (E1.1's shape is
            // 150 sessions at once) while the byte cap keeps memory honest.
            max_pending: 512,
            max_pending_bytes: 8 * 1024 * 1024,
            poll_batch: 64,
            commit_delay: None,
            worker_disabled: false,
            flush_wait_slice: Duration::from_millis(2),
            flush_deadline: Duration::from_secs(10),
        }
    }
}

/// Counters describing what the queue has done. Pull-side only, for the
/// runtime to scrape (see the module doc's `Metrics` section).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaveQueueStats {
    /// Saves handed to the worker.
    pub queued: u64,
    /// Saves the worker reported durable.
    pub committed: u64,
    /// Deferred durable writes that failed (each is also recorded in the
    /// world's error inbox against its own program).
    pub failed: u64,
    /// Durable writes performed on the **calling** thread: `Sync` mode, or a
    /// worker that could not be started / was confirmed gone. The number that
    /// answers "did the world thread just `fsync`?". With a live worker this
    /// stays flat: a full queue *waits* (see `backpressure_waits`) rather than
    /// starting a second writer (CTO review, OBI-348).
    pub inline_commits: u64,
    /// Tasks handed over and not yet reported on.
    pub pending: usize,
    /// Bytes of rendered save content held in the queue.
    pub pending_bytes: u64,
    /// High-water mark of `pending`.
    pub peak_pending: usize,
    /// Flushes that passed `flush_deadline` and were still waiting on the
    /// worker. Not an error in itself -- a slow disk -- but the number that
    /// says "durability is behind, and a world-thread call is waiting on it".
    /// It no longer means "a second writer was started" (CTO review, OBI-348).
    pub flush_deadline_exceeded: u64,
    /// Saturated `enqueue` calls that had to wait for one queue slot instead
    /// of committing inline. Each is roughly one commit's latency added to a
    /// `save_object` call, and it is the signal that the disk is behind the
    /// saves the world is producing.
    pub backpressure_waits: u64,
    /// Durable writes that panicked inside the worker (converted to a failed
    /// outcome rather than taking the thread down). Non-zero here means a bug
    /// in the durability path, not a disk problem.
    pub panicked: u64,
}

/// Where an enqueue landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// Handed to the durability worker; not on disk yet.
    Queued,
    /// Made durable on the calling thread, because there was provably no
    /// other writer to hand it to (`Sync` mode, no worker, a worker whose exit
    /// was confirmed) or because the item can never fit even an empty queue.
    /// Carries the write's own outcome, so the caller can bill
    /// `disk_quota_mb` off the real size.
    Inline(SaveOutcome),
}

/// The durability queue: a bounded FIFO hand-off to one worker thread, plus
/// the world-thread-side bookkeeping (an outstanding mirror for the inline
/// fallback, a per-path pending projection for quota math, stats).
///
/// Only ever touched through `&mut` from the world thread (`save_object`,
/// `restore_object`, `World::tick`, `begin_snapshot`, `Drop`). The worker
/// thread owns the other ends of the two channels and never touches this
/// struct, so **no lock is shared with the world thread**: `try_send`,
/// `try_recv` and `recv_timeout` are the only cross-thread primitives here,
/// and no other party can hold them.
pub struct SaveQueue {
    cfg: SaveQueueConfig,
    mode: SaveDurability,
    /// The worker's task sender. `None` before the first deferred save (the
    /// worker starts lazily) and after it has been detached.
    task_tx: Option<SyncSender<Arc<SaveTask>>>,
    /// The worker's completion receiver. Owned by the queue rather than by a
    /// worker handle, deliberately: the single-writer rule is decided by
    /// `thread_alive`, so losing the join handle must never be able to look
    /// like "the worker is gone, commit here" -- and with the receiver in the
    /// queue, the outcomes still arrive either way (CTO review, OBI-348).
    results: Option<Receiver<SaveOutcome>>,
    /// The worker's join handle. `None` means "not ours to wait for", never
    /// "the thread stopped writing".
    join: Option<JoinHandle<()>>,
    /// Every inline commit consults this first (the single-writer invariant):
    /// it is cleared by the worker thread itself as it exits, so a dropped
    /// handle can never be mistaken for a finished worker.
    thread_alive: Arc<AtomicBool>,
    next_seq: u64,
    /// Everything handed to the worker (or being committed inline) that has
    /// not been reported on yet, oldest first. `Arc` so the mirror costs a
    /// pointer, not a copy of the content: if the worker dies with a task in
    /// flight, the world thread still holds the bytes to commit it itself.
    outstanding: VecDeque<Arc<SaveTask>>,
    pending_bytes_total: u64,
    /// path -> the newest queued save for that path (ordering key, rendered
    /// size, and the uid it will be charged to), so a second save to a file
    /// that has not landed yet projects its quota delta against the queued
    /// content rather than the stale on-disk file, and so a uid's *other*
    /// queued saves still count against its `disk_quota_mb` (OBI-348: the
    /// charge must neither double-count nor escape).
    pending_by_path: HashMap<String, QueuedSave>,
    /// Outcomes reaped by some entry point that no caller has billed yet.
    /// Held rather than returned where the call has no way to return them:
    /// `enqueue` reaps to free capacity, and swallowing those outcomes would
    /// let the deferred `disk_quota_mb` charge escape (OBI-348: the charge
    /// must neither double-count nor escape). Drained by
    /// [`SaveQueue::poll`], [`SaveQueue::flush`], [`SaveQueue::flush_path`]
    /// and [`SaveQueue::take_reports`], each exactly once.
    reports: VecDeque<SaveOutcome>,
    stats: SaveQueueStats,

    /// Set once a flush has gone past `flush_deadline`, for
    /// [`SaveQueue::take_deadline_report`]; `World` turns it into one error
    /// inbox entry per event instead of one per wait slice.
    deadline_report: Option<String>,
}

impl Default for SaveQueue {
    fn default() -> Self {
        Self::new(SaveQueueConfig::default(), SaveDurability::Deferred)
    }
}

/// What one slice of a wait on the completion channel produced (OBI-348).
/// Deliberately has no "deadline passed" case: the deadline is the caller's
/// reporting concern, and conflating it with "the worker is gone" is what
/// used to let a second writer start (CTO review, OBI-348).
enum Slice {
    Got,
    Timeout,
    /// No completion channel any more -- the worker exited. Callers re-check
    /// [`SaveQueue::worker_may_commit`] and only commit inline once it is
    /// really gone.
    NoWriter,
}

/// What [`SaveQueue::drain`] waits for: everything, or just one path.
enum Drain {
    All,
    Path(String),
}

/// One queued save's quota-projection entry (see `SaveQueue::pending_by_path`).
struct QueuedSave {
    seq: u64,
    bytes: u64,
    uid: String,
}

impl QueuedSave {
    fn of(task: &SaveTask) -> Self {
        Self {
            seq: task.seq,
            bytes: task.content.len() as u64,
            uid: task.uid.clone(),
        }
    }
}

impl SaveQueue {
    pub fn new(cfg: SaveQueueConfig, mode: SaveDurability) -> Self {
        Self {
            cfg,
            mode,
            task_tx: None,
            results: None,
            join: None,
            thread_alive: Arc::new(AtomicBool::new(false)),
            next_seq: 0,
            outstanding: VecDeque::new(),
            pending_bytes_total: 0,
            pending_by_path: HashMap::new(),
            reports: VecDeque::new(),
            stats: SaveQueueStats::default(),
            deadline_report: None,
        }
    }

    pub fn config(&self) -> &SaveQueueConfig {
        &self.cfg
    }

    pub fn config_mut(&mut self) -> &mut SaveQueueConfig {
        &mut self.cfg
    }

    pub fn durability(&self) -> SaveDurability {
        self.mode
    }

    /// `Sync` makes every subsequent save an inline durable write; anything
    /// already queued is flushed first, so switching modes cannot leave a
    /// save in a queue nobody reaps.
    pub fn set_durability(&mut self, mode: SaveDurability) {
        if mode == self.mode {
            return;
        }
        if mode == SaveDurability::Sync {
            self.flush();
        }
        self.mode = mode;
    }

    pub fn stats(&self) -> SaveQueueStats {
        let mut s = self.stats;
        s.pending = self.outstanding.len();
        s.pending_bytes = self.pending_bytes_total;
        s
    }

    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes_total
    }

    /// The newest queued save for `path`, if any: `(seq, bytes)`. This is
    /// what `check_save_disk_quota` uses as its "size being replaced" term.
    pub fn pending_for_path(&self, path: &str) -> Option<(u64, u64)> {
        self.pending_by_path.get(path).map(|q| (q.seq, q.bytes))
    }

    /// Total bytes of everything queued for `uid` (newest save per path).
    ///
    /// OBI-348's quota projection needs this: a deferred save is not charged
    /// to `DiskUsage` until it lands, so without it a uid that has saves in
    /// flight could keep passing both the `save_object` and the `write_file`
    /// quota checks as if those bytes did not exist. Cost is O(pending) with
    /// `pending <= max_pending` (256 by default), per save/write check --
    /// not per file on disk.
    pub fn pending_bytes_for_uid(&self, uid: &str) -> u64 {
        self.pending_by_path
            .values()
            .filter(|q| q.uid == uid)
            .map(|q| q.bytes)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// Is there a queued (not yet durable) save for `path`?
    pub fn has_pending_for_path(&self, path: &str) -> bool {
        self.pending_by_path.contains_key(path)
    }

    /// Accept a rendered, authorised, quota-projected save.
    ///
    /// Never takes a lock, never drops the save, and -- while a worker is
    /// alive -- never commits on this thread. See the module doc's
    /// `Backpressure` and `single-writer invariant` sections for what happens
    /// when the queue is full.
    pub fn enqueue(&mut self, task: SaveTask) -> Enqueued {
        if self.mode == SaveDurability::Sync {
            return Enqueued::Inline(self.commit_inline(&task));
        }
        // Reap first: completed outcomes are what free queue capacity, and
        // this is also how queued memory gets released between ticks. The
        // outcomes themselves go to `reports` rather than being dropped here,
        // so the `disk_quota_mb` charge they carry cannot escape.
        self.reap_ready();
        let need_bytes = task.content.len() as u64;
        let start = Instant::now();
        let mut waited = false;
        let mut reported = false;
        loop {
            if self.fits(need_bytes) {
                return self.hand_off(task);
            }
            if self.outstanding.is_empty() {
                // The queue can never hold this item (it alone exceeds
                // `max_pending_bytes`), or there is no worker at all. An
                // empty `outstanding` means a live worker is between tasks
                // and a dead one is gone, so this thread is the only writer
                // and committing here cannot race with anything.
                return Enqueued::Inline(self.commit_inline(&task));
            }
            if !self.worker_may_commit() {
                // The worker died with a backlog. Confirm the exit (drain its
                // reported results, join it) and take the backlog over oldest
                // first -- committing the new save on top of an order the
                // world thread is now responsible for.
                self.detach_dead_worker();
                self.commit_remaining_inline();
                continue;
            }
            // Full, with a live worker holding work. Wait for *one* slot:
            // one commit's latency, and never a second writer (CTO review,
            // OBI-348). `inline_commits` deliberately does not move here.
            if !waited {
                self.stats.backpressure_waits += 1;
                waited = true;
            }
            match self.wait_slice() {
                Slice::Got => {}
                Slice::NoWriter => self.detach_dead_worker(),
                Slice::Timeout => {
                    if !reported && start.elapsed() >= self.cfg.flush_deadline {
                        reported = true;
                        self.stats.flush_deadline_exceeded += 1;
                        self.deadline_report = Some(format!(
                            "save_object waited {:?} for a queue slot ({} save(s) \
                             outstanding, durability worker alive): the disk is behind",
                            start.elapsed(),
                            self.outstanding.len()
                        ));
                    }
                }
            }
        }
    }

    /// Assign the ordering sequence, start the worker if this is the first
    /// deferred save, and hand the task over.
    fn hand_off(&mut self, task: SaveTask) -> Enqueued {
        let seq = self.next_seq;
        self.next_seq += 1;
        let task = Arc::new(SaveTask { seq, ..task });
        // Lazy start: a world that never saves never pays for a thread.
        if self.task_tx.is_none()
            && let Err(reason) = self.start_worker()
        {
            return Enqueued::Inline(self.commit_inline_with_reason(&task, &reason));
        }
        self.send_to_worker(task)
    }

    fn send_to_worker(&mut self, task: Arc<SaveTask>) -> Enqueued {
        let send = match self.task_tx.as_ref() {
            Some(tx) => tx.try_send(task.clone()),
            None => Err(mpsc::TrySendError::Disconnected(task.clone())),
        };
        match send {
            Ok(()) => {
                // Replace any older queued save for this path: it is what
                // will be on disk, and counting both would over-bill.
                if let Some(prev) = self
                    .pending_by_path
                    .insert(task.path.clone(), QueuedSave::of(&task))
                {
                    self.pending_bytes_total = self.pending_bytes_total.saturating_sub(prev.bytes);
                }
                self.pending_bytes_total += task.content.len() as u64;
                self.outstanding.push_back(task);
                self.stats.queued += 1;
                self.stats.peak_pending = self.stats.peak_pending.max(self.outstanding.len());
                Enqueued::Queued
            }
            Err(_) => {
                // `Disconnected`: the worker's task receiver is gone, which
                // happens only after its exit flag is cleared -- so the
                // thread has exited. `task` never reached it and is not in
                // `outstanding`/`pending_by_path`, so there is no projection
                // to undo. Confirm the exit (drain + join) before committing
                // anything here: that is what makes this thread the single
                // writer rather than a second one racing a dying worker.
                self.detach_dead_worker();
                self.commit_remaining_inline();
                Enqueued::Inline(self.commit_inline_with_reason(&task, "durability worker gone"))
            }
        }
    }

    fn fits(&self, need_bytes: u64) -> bool {
        self.outstanding.len() < self.cfg.max_pending
            && self.pending_bytes_total.saturating_add(need_bytes) <= self.cfg.max_pending_bytes
    }

    /// Non-blocking reap of up to `max` completed outcomes, oldest first.
    /// This is what `World::tick` calls; it does no filesystem work.
    pub fn poll(&mut self, max: usize) -> Vec<SaveOutcome> {
        self.reap_ready();
        self.take_reports(max)
    }

    /// Everything reaped and not yet billed to `DiskUsage`/the error inbox.
    /// Outcomes are handed out exactly once: whoever drains them applies them.
    pub fn take_reports(&mut self, max: usize) -> Vec<SaveOutcome> {
        let n = max.min(self.reports.len());
        self.reports.drain(..n).collect()
    }

    /// A one-line description of the last flush/wait that ran past
    /// [`SaveQueueConfig::flush_deadline`], or `None`. Taken (not peeked) so
    /// `World` records exactly one error inbox entry per event; the counter
    /// [`SaveQueueStats::flush_deadline_exceeded`] is the census.
    pub fn take_deadline_report(&mut self) -> Option<String> {
        self.deadline_report.take()
    }

    /// Block until every queued save has been made durable. Returns the
    /// outcomes -- including the ones this thread had to commit itself -- so
    /// the caller can apply the deferred `disk_quota_mb` charges.
    ///
    /// Past `flush_deadline` this keeps waiting on the worker and reports the
    /// event; it does not start a second writer.
    pub fn flush(&mut self) -> Vec<SaveOutcome> {
        self.drain(Drain::All)
    }

    /// Block until nothing is queued for `path`. `restore_object` uses this
    /// for read-your-writes: it costs a wait only when that exact file is
    /// still in flight, and because the worker is a single FIFO thread,
    /// waiting for `path` also lands everything queued before it.
    pub fn flush_path(&mut self, path: &str) -> Vec<SaveOutcome> {
        self.drain(Drain::Path(path.to_string()))
    }

    fn drain(&mut self, want: Drain) -> Vec<SaveOutcome> {
        self.reap_ready();
        let start = Instant::now();
        let mut reported = false;
        while self.drain_pending(&want) {
            if !self.worker_may_commit() {
                // Confirmed exited, so nobody else can commit these. Oldest
                // first, which is also the order the worker would have used.
                self.detach_dead_worker();
                self.commit_remaining_inline();
                break;
            }
            match self.wait_slice() {
                Slice::Got => {}
                Slice::NoWriter => self.detach_dead_worker(),
                Slice::Timeout => {
                    if !reported && start.elapsed() >= self.cfg.flush_deadline {
                        reported = true;
                        self.stats.flush_deadline_exceeded += 1;
                        self.deadline_report = Some(format!(
                            "flush_pending_saves waited {:?} for {} queued save(s) \
                             (durability worker alive, disk behind)",
                            start.elapsed(),
                            self.outstanding.len()
                        ));
                    }
                }
            }
        }
        self.take_reports(usize::MAX)
    }

    fn drain_pending(&self, want: &Drain) -> bool {
        match want {
            Drain::All => !self.outstanding.is_empty(),
            Drain::Path(p) => self.outstanding.iter().any(|t| &t.path == p),
        }
    }

    /// One bounded wait for the next completed outcome. Past the deadline is
    /// the caller's business (`drain` reports it); this only distinguishes
    /// "nothing yet" from "there never will be, the worker is gone".
    fn wait_slice(&mut self) -> Slice {
        let next = match self.results.as_mut() {
            Some(r) => r.recv_timeout(self.cfg.flush_wait_slice),
            None => return Slice::NoWriter,
        };
        match next {
            Ok(o) => {
                self.accept(o);
                Slice::Got
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Slice::Timeout,
            Err(mpsc::RecvTimeoutError::Disconnected) => Slice::NoWriter,
        }
    }

    /// Drain everything the worker has already reported, without waiting.
    fn reap_ready(&mut self) {
        loop {
            let next = match self.results.as_mut() {
                Some(r) => r.try_recv().ok(),
                None => None,
            };
            match next {
                Some(o) => self.accept(o),
                None => break,
            };
        }
    }

    /// Bookkeep one outcome: drop the queue's mirror/projection for it, count
    /// it, and hold it until someone bills it. The *charges* stay with the
    /// caller (they need `DiskUsage`).
    fn accept(&mut self, o: SaveOutcome) {
        self.bookkeep(&o);
        self.reports.push_back(o);
    }

    /// The bookkeeping half of [`SaveQueue::accept`], for outcomes this thread
    /// produced itself and hands straight back to the caller: those must not
    /// also sit in `reports`, or the charge would be applied twice.
    fn bookkeep(&mut self, o: &SaveOutcome) {
        // The worker commits and reports strictly in order, so everything up
        // to `o.seq` is finished. Anything newer stays.
        while let Some(front) = self.outstanding.front().cloned() {
            if front.seq > o.seq {
                break;
            }
            self.outstanding.pop_front();
            self.release(&front);
            if front.seq == o.seq {
                break;
            }
        }
        match &o.error {
            Some(_) => self.stats.failed += 1,
            None => self.stats.committed += 1,
        }
        if o.panicked {
            self.stats.panicked += 1;
        }
    }

    fn release(&mut self, task: &SaveTask) {
        self.pending_bytes_total = self
            .pending_bytes_total
            .saturating_sub(task.content.len() as u64);
        self.drop_projection(task);
    }

    fn drop_projection(&mut self, task: &SaveTask) {
        if self
            .pending_by_path
            .get(&task.path)
            .is_some_and(|q| q.seq == task.seq)
        {
            self.pending_by_path.remove(&task.path);
        }
    }

    /// Commit every remaining task, in order, on the calling thread. Only
    /// ever reached once the worker is *confirmed* gone -- a live worker is
    /// the only writer (CTO review, OBI-348). Outcomes go to `reports`, so
    /// whoever is flushing bills them.
    fn commit_remaining_inline(&mut self) {
        let rest: Vec<Arc<SaveTask>> = self.outstanding.iter().cloned().collect();
        for task in rest {
            let outcome = self.commit_inline_with_reason(&task, "durability worker gone");
            self.accept(outcome);
        }
    }

    fn commit_inline(&mut self, task: &SaveTask) -> SaveOutcome {
        self.commit_inline_with_reason(task, "")
    }

    /// Commit on the calling thread. `reason` is non-empty only when the
    /// queue could not serve the save (no worker / a lost worker), and it
    /// rides along in the failure text so `errors` says *why* a save went
    /// through the slow path. The caller applies the returned outcome: this
    /// write is durable **now**, so `disk_quota_mb` must see it on this call,
    /// exactly as it did before OBI-348.
    fn commit_inline_with_reason(&mut self, task: &SaveTask, reason: &str) -> SaveOutcome {
        self.stats.inline_commits += 1;
        let outcome = match commit_task(task, self.cfg.commit_delay) {
            Ok(()) => outcome_for(task, Ok(())),
            Err(e) if reason.is_empty() => outcome_for(task, Err(e)),
            Err(e) => outcome_for(task, Err(format!("{e}; [committed inline: {reason}]"))),
        };
        self.bookkeep(&outcome);
        outcome
    }

    /// Is there a durability worker thread that might be committing right
    /// now? Cleared by the thread itself as it exits, and independent of
    /// whether we still hold its handle, because "we lost the handle" is not
    /// evidence that the write finished.
    fn worker_may_commit(&self) -> bool {
        self.thread_alive.load(Ordering::Acquire)
    }

    /// Spawn the durability worker. Lazy (first deferred save), so a `World`
    /// that never saves anything never pays for a thread, and so a test
    /// harness that builds worlds in the hundreds doesn't leak them.
    fn start_worker(&mut self) -> Result<(), String> {
        debug_assert!(self.task_tx.is_none(), "one worker at a time");
        if self.cfg.worker_disabled {
            return Err("durability worker disabled by config".to_string());
        }
        let (task_tx, task_rx): (SyncSender<Arc<SaveTask>>, Receiver<Arc<SaveTask>>) =
            mpsc::sync_channel(self.cfg.max_pending.max(1));
        let (out_tx, out_rx): (mpsc::Sender<SaveOutcome>, Receiver<SaveOutcome>) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let alive_flag = alive.clone();
        // Replace the previous flag *before* spawning: a fresh worker means
        // the old thread is confirmed gone (`start_worker` is only reached
        // with no handle), and `thread_alive` must never describe a thread
        // that no longer exists.
        self.thread_alive = alive.clone();
        let delay = self.cfg.commit_delay;
        let join = std::thread::Builder::new()
            .name("loom-save-worker".to_string())
            .spawn(move || {
                // Clears `alive` on every exit path, panic included, so the
                // world thread can tell "idle" from "gone".
                struct Flag(Arc<AtomicBool>);
                impl Drop for Flag {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _flag = Flag(alive_flag);
                while let Ok(task) = task_rx.recv() {
                    let outcome = commit_task_capturing_panic(&task, delay);
                    if out_tx.send(outcome).is_err() {
                        return; // the World is gone; nobody to report to
                    }
                }
            })
            .map_err(|e| format!("spawn durability worker: {e}"))?;
        self.task_tx = Some(task_tx);
        self.results = Some(out_rx);
        self.join = Some(join);
        Ok(())
    }

    /// Test hook: the worker thread is gone *for certain* and its handle is
    /// gone with it -- the state `detach_dead_worker` leaves behind, and the
    /// only state in which an inline commit of a non-empty backlog is legal.
    #[cfg(test)]
    fn abandon_worker(&mut self) {
        self.thread_alive.store(false, Ordering::Release);
        self.task_tx = None;
        self.results = None;
        self.join = None;
    }

    /// Test hook: the join handle is gone but the thread is alive and its
    /// channels still work. Nothing may commit inline in this state, and the
    /// outcomes must still come back.
    #[cfg(test)]
    fn abandon_handle_only(&mut self) {
        self.join = None;
    }

    /// The worker has exited: drain the outcomes it reported, join it so we
    /// *know* no write is in flight, and drop the handle. Afterwards this
    /// thread is the only writer again, which is exactly what makes an inline
    /// commit legal. Only reached once `thread_alive` is false or a channel
    /// closed, so the join cannot block on a live worker.
    fn detach_dead_worker(&mut self) {
        self.reap_ready();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.thread_alive.store(false, Ordering::Release);
    }

    /// Flush everything still queued, then stop the worker and join it.
    /// Called by `Drop`, and available to an embedder that wants durability
    /// drained at a known point instead of at drop.
    pub fn shutdown(&mut self) {
        self.flush();
        // Dropping the sender is what tells the worker there is no more work.
        self.task_tx = None;
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.results = None;
        self.thread_alive.store(false, Ordering::Release);
    }
}

impl Drop for SaveQueue {
    fn drop(&mut self) {
        // Never leave a rendered save behind. A blocking `Drop` is unusual,
        // and it is deliberate: the alternative is "the process exited and a
        // character is gone". Outcomes are dropped here -- the `World`
        // (and so its `DiskUsage`) is going away with us, and a
        // soon-to-be-free counter does not need its final delta.
        self.shutdown();
    }
}

fn outcome_for(task: &SaveTask, result: Result<(), String>) -> SaveOutcome {
    let queued_bytes = task.content.len() as u64;
    match result {
        Ok(()) => SaveOutcome {
            seq: task.seq,
            path: task.path.clone(),
            uid: task.uid.clone(),
            program: task.program.clone(),
            old_bytes: task.old_bytes,
            queued_bytes,
            committed_bytes: Some(
                // The real post-rename size, so the deferred `disk_quota_mb`
                // charge is billed off the disk, not off the rendered text
                // (`file_size_bytes` is one `metadata()`, never a read).
                // A stat failure falls back to the rendered size -- same
                // `unwrap_or(0)`-tolerant shape `check_save_disk_quota`
                // already uses for a missing old file.
                crate::fileio::file_size_bytes(&task.save_root, &task.path).unwrap_or(queued_bytes),
            ),
            error: None,
            panicked: false,
        },
        Err(error) => SaveOutcome {
            seq: task.seq,
            path: task.path.clone(),
            uid: task.uid.clone(),
            program: task.program.clone(),
            old_bytes: task.old_bytes,
            queued_bytes,
            committed_bytes: None,
            error: Some(error),
            panicked: false,
        },
    }
}

/// The durable half of a save: `stage_write` + `commit_write`, i.e. the
/// content `fsync`, the `rename`, and the parent-directory `fsync`. Runs on
/// whichever thread is *not* serving players -- unless the queue has
/// degraded, in which case it runs on the world thread, for one save.
fn commit_task(task: &SaveTask, delay: Option<Duration>) -> Result<(), String> {
    if let Some(d) = delay
        && !d.is_zero()
    {
        std::thread::sleep(d);
    }
    // `write_file_atomic` re-checks the suffix, the size cap and symlink
    // confinement on *this* thread, so a path that was confined when it was
    // rendered is still confined when it lands.
    crate::fileio::write_file_atomic(&task.save_root, &task.path, &task.content)
        .map(|_| ())
        .map_err(|e| format!("save_object({:?}) durable write failed: {e}", task.path))
}

fn commit_task_capturing_panic(task: &SaveTask, delay: Option<Duration>) -> SaveOutcome {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| commit_task(task, delay)));
    match r {
        Ok(res) => outcome_for(task, res),
        Err(p) => {
            let mut o = outcome_for(
                task,
                Err(format!(
                    "save_object({:?}) durable write panicked: {}",
                    task.path,
                    panic_message(&p)
                )),
            );
            o.panicked = true;
            o
        }
    }
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Apply reaped outcomes to the two pieces of world state they are billed
/// against:
///
/// * `disk_quota_mb` -- charged **once per committed write**, from the real
///   post-rename size, never at render time (OBI-348: "the charge must not
///   double-count or escape"). A write that fails charges nothing, and an
///   over-quota save is still rejected before it is ever queued (that check
///   stays synchronous in `check_save_disk_quota`).
/// * the error inbox (spec §8.3) -- a deferred failure is recorded against
///   the program of the object that asked for the save, with the save path
///   in the message, so `errors`/`/api/v1/admin/errors` show it like any
///   other runtime error.
pub(crate) fn apply_outcomes(
    outcomes: &[SaveOutcome],
    disk_usage: &mut crate::disk_usage::DiskUsage,
    errors: &mut crate::errors::ErrorInbox,
    now_unix_ms: u64,
) {
    for o in outcomes {
        match o.committed_bytes {
            Some(committed) => disk_usage.note_save_write(&o.uid, o.old_bytes, committed),
            None => {
                let message = o
                    .error
                    .clone()
                    .unwrap_or_else(|| "durability write failed".to_string());
                errors.record(
                    if o.program.is_empty() {
                        "driver"
                    } else {
                        &o.program
                    },
                    "save_object",
                    0,
                    &message,
                    &[],
                    now_unix_ms,
                    false,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "loom-save-queue-{tag}-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn task(root: &Path, path: &str, content: &str) -> SaveTask {
        SaveTask {
            seq: 0,
            save_root: root.to_path_buf(),
            path: path.to_string(),
            content: content.to_string(),
            uid: "tester".to_string(),
            program: "/std/player".to_string(),
            old_bytes: 0,
        }
    }

    fn queue(cfg: SaveQueueConfig) -> SaveQueue {
        SaveQueue::new(cfg, SaveDurability::Deferred)
    }

    #[test]
    fn deferred_save_lands_and_flush_reports_it() {
        let root = scratch("deferred");
        let mut q = queue(SaveQueueConfig::default());
        assert_eq!(q.enqueue(task(&root, "/a.o", "one")), Enqueued::Queued);
        let out = q.flush();
        assert_eq!(out.len(), 1);
        assert!(out[0].ok(), "{:?}", out[0].error);
        assert_eq!(std::fs::read_to_string(root.join("a.o")).unwrap(), "one");
        assert_eq!(q.stats().committed, 1);
        assert_eq!(q.stats().inline_commits, 0);
        assert_eq!(q.stats().queued, 1);
    }

    #[test]
    fn sync_mode_commits_on_the_calling_thread() {
        let root = scratch("sync");
        let mut q = SaveQueue::new(SaveQueueConfig::default(), SaveDurability::Sync);
        let e = q.enqueue(task(&root, "/b.o", "two"));
        assert!(matches!(e, Enqueued::Inline(ref o) if o.ok()), "{e:?}");
        assert_eq!(std::fs::read_to_string(root.join("b.o")).unwrap(), "two");
        assert_eq!(q.stats().inline_commits, 1);
        assert_eq!(q.stats().queued, 0);
        assert!(q.is_empty());
    }

    /// The CTO's regression bar for run 37869788819, where 2 of these 20
    /// same-path saves came back `failed` because the flush deadline let the
    /// world thread commit inline *while the worker still held those tasks*:
    /// both writers used `fileio`'s then-per-process temp name, so one lost
    /// `create_new` to `EEXIST` or had its in-flight temp file unlinked.
    /// `committed == 20` / `failed == 0` / `inline_commits == 0` is what
    /// "one writer, newest wins" looks like from the outside.
    #[test]
    fn same_path_commits_in_order_so_the_newest_wins() {
        let root = scratch("order");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(1)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..20 {
            assert_eq!(
                q.enqueue(task(&root, "/c.o", &format!("v{i}"))),
                Enqueued::Queued
            );
        }
        q.flush();
        assert_eq!(std::fs::read_to_string(root.join("c.o")).unwrap(), "v19");
        let s = q.stats();
        assert_eq!(s.committed, 20, "{s:?}");
        assert_eq!(s.failed, 0, "{s:?}");
        assert_eq!(s.inline_commits, 0, "the worker was the only writer");
        assert!(q.is_empty());
    }

    /// CTO review item 5(a): a saturated queue on **one path** must still
    /// produce exactly one writer. `max_pending: 2` forces every enqueue after
    /// the second to wait for a slot; the newest content must win and nothing
    /// may fail. Deterministic: 10 saves x 20 ms of simulated disk, no load.
    #[test]
    fn a_saturated_queue_on_one_path_still_has_one_writer() {
        let root = scratch("saturation-order");
        let cfg = SaveQueueConfig {
            max_pending: 2,
            commit_delay: Some(Duration::from_millis(20)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..10 {
            q.enqueue(task(&root, "/c.o", &format!("v{i}")));
        }
        q.flush();
        let s = q.stats();
        assert_eq!(std::fs::read_to_string(root.join("c.o")).unwrap(), "v9");
        assert_eq!(s.committed, 10, "{s:?}");
        assert_eq!(s.failed, 0, "{s:?}");
        assert_eq!(s.inline_commits, 0, "a live worker means no inline commit");
        assert!(s.backpressure_waits > 0, "{s:?}");
    }

    /// CTO review item 5(b): the same shape with `flush_deadline` far shorter
    /// than the backlog, so the deadline branch is forced on every wait. Past
    /// the deadline the queue reports and keeps waiting -- it must not start a
    /// second writer, which is precisely what used to lose two saves.
    #[test]
    fn a_flush_deadline_does_not_start_a_second_writer() {
        let root = scratch("deadline-order");
        let cfg = SaveQueueConfig {
            max_pending: 2,
            commit_delay: Some(Duration::from_millis(20)),
            flush_deadline: Duration::from_millis(5),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..10 {
            q.enqueue(task(&root, "/c.o", &format!("v{i}")));
        }
        q.flush();
        let s = q.stats();
        assert_eq!(std::fs::read_to_string(root.join("c.o")).unwrap(), "v9");
        assert_eq!(s.committed, 10, "{s:?}");
        assert_eq!(s.failed, 0, "{s:?}");
        assert_eq!(s.inline_commits, 0, "a wedged disk is not a second writer");
        assert!(
            s.flush_deadline_exceeded > 0,
            "the deadline was crossed and had to be reported: {s:?}"
        );
        assert!(
            q.take_deadline_report().is_some() || s.flush_deadline_exceeded > 1,
            "the report is handed to the caller at least once"
        );
    }

    /// The other half of the single-writer invariant: losing the *handle* is
    /// not losing the thread. With a worker still alive, `flush` must wait for
    /// it rather than commit the same files a second time.
    #[test]
    fn a_live_worker_without_a_handle_is_still_the_only_writer() {
        let root = scratch("handle-gone");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(5)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..4 {
            q.enqueue(task(&root, &format!("/h{i}.o"), "H"));
        }
        // The handle disappears; the thread and its tasks do not.
        q.abandon_handle_only();
        let before = q.stats().inline_commits;
        q.flush();
        assert_eq!(
            q.stats().inline_commits,
            before,
            "the worker is alive: nothing may commit on this thread"
        );
        for i in 0..4 {
            assert_eq!(
                std::fs::read_to_string(root.join(format!("h{i}.o"))).unwrap(),
                "H",
                "save {i} landed exactly once"
            );
        }
        assert_eq!(q.stats().committed, 4, "{:?}", q.stats());
        q.shutdown();
    }

    #[test]
    fn a_saturated_queue_never_loses_a_save() {
        let root = scratch("saturation");
        let cfg = SaveQueueConfig {
            max_pending: 2,
            commit_delay: Some(Duration::from_millis(1)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..10 {
            q.enqueue(task(&root, &format!("/p{i}.o"), "x"));
        }
        q.flush();
        for i in 0..10 {
            assert_eq!(
                std::fs::read_to_string(root.join(format!("p{i}.o"))).unwrap(),
                "x",
                "save {i} survived queue saturation"
            );
        }
        let s = q.stats();
        // Saturation costs a *wait*, not a second writer and not a save.
        assert_eq!(s.queued, 10, "{s:?}");
        assert_eq!(s.committed, 10, "{s:?}");
        assert_eq!(s.failed, 0, "{s:?}");
        assert_eq!(s.inline_commits, 0, "{s:?}");
        assert!(s.backpressure_waits > 0, "saturation waited for slots");
        assert!(s.peak_pending <= 3, "the cap held: {s:?}");
    }

    /// Two ways a queue is "full": waiting helps with the first and can never
    /// help with the second. A save that alone exceeds `max_pending_bytes`
    /// cannot be queued at all, so it is the calling thread's -- with the
    /// queue empty, so there is nobody to race.
    #[test]
    fn byte_budget_waits_then_falls_back_only_for_an_unqueueable_save() {
        let root = scratch("bytes");
        let cfg = SaveQueueConfig {
            max_pending: 1000,
            max_pending_bytes: 16,
            commit_delay: Some(Duration::from_millis(2)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        let mut inline = 0;
        for i in 0..6 {
            if matches!(
                q.enqueue(task(&root, &format!("/q{i}.o"), &"z".repeat(10))),
                Enqueued::Inline(_)
            ) {
                inline += 1;
            }
        }
        let s = q.stats();
        assert_eq!(inline, 0, "a slow queue is waited on, not bypassed");
        assert_eq!(s.queued, 6, "{s:?}");
        assert!(
            s.backpressure_waits > 0,
            "the byte budget made enqueue wait: {s:?}"
        );
        assert!(q.stats().pending_bytes <= 16, "{:?}", q.stats());
        q.flush();
        for i in 0..6 {
            assert_eq!(
                std::fs::read_to_string(root.join(format!("q{i}.o"))).unwrap(),
                "z".repeat(10)
            );
        }
        // Now a save no queue slot could ever hold: inline, and it lands.
        let big = "B".repeat(40);
        assert!(matches!(
            q.enqueue(task(&root, "/too-big.o", &big)),
            Enqueued::Inline(ref o) if o.ok()
        ));
        assert_eq!(
            std::fs::read_to_string(root.join("too-big.o")).unwrap(),
            big
        );
        assert_eq!(q.stats().inline_commits, 1);
    }

    #[test]
    fn flush_path_waits_for_that_path() {
        let root = scratch("flush-path");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(3)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        q.enqueue(task(&root, "/x.o", "X"));
        q.enqueue(task(&root, "/y.o", "Y"));
        assert!(q.has_pending_for_path("/x.o"));
        let out = q.flush_path("/x.o");
        assert!(!out.is_empty());
        assert_eq!(std::fs::read_to_string(root.join("x.o")).unwrap(), "X");
        assert!(
            !q.has_pending_for_path("/x.o"),
            "x is durable, so a restore of it reads the new file"
        );
        q.shutdown();
    }

    #[test]
    fn drop_flushes_everything_queued() {
        let root = scratch("drop");
        {
            let mut q = queue(SaveQueueConfig::default());
            for i in 0..25 {
                q.enqueue(task(&root, &format!("/d{i}.o"), "d"));
            }
        }
        for i in 0..25 {
            assert!(
                root.join(format!("d{i}.o")).exists(),
                "dropping the queue must not lose save {i}"
            );
        }
    }

    #[test]
    fn a_bad_write_is_reported_not_panicked() {
        let root = scratch("bad");
        let mut q = queue(SaveQueueConfig::default());
        // A save name whose suffix `stage_write` refuses: reported as a
        // failed outcome, and the queue keeps working afterwards.
        q.enqueue(task(&root, "/not-a-save.txt", "x"));
        let out = q.flush();
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok(), "{:?}", out[0]);
        assert!(
            !out[0].panicked,
            "a refused suffix is an ordinary error, not a caught panic"
        );
        assert_eq!(q.stats().failed, 1);
        assert_eq!(q.stats().committed, 0);
        assert_eq!(q.stats().panicked, 0);
        q.enqueue(task(&root, "/still-works.o", "y"));
        q.flush();
        assert_eq!(
            std::fs::read_to_string(root.join("still-works.o")).unwrap(),
            "y"
        );
    }

    #[test]
    fn pending_projection_sees_queued_bytes_not_the_stale_file() {
        let root = scratch("projection");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(30)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        q.enqueue(task(&root, "/e.o", &"a".repeat(5)));
        assert_eq!(q.pending_for_path("/e.o"), Some((0, 5)));
        q.enqueue(task(&root, "/e.o", &"b".repeat(9)));
        assert_eq!(
            q.pending_for_path("/e.o"),
            Some((1, 9)),
            "the second save projects against the first queued one, so the \
             quota delta is neither applied twice nor skipped"
        );
        q.flush();
        assert_eq!(q.pending_for_path("/e.o"), None);
        assert_eq!(
            std::fs::read_to_string(root.join("e.o")).unwrap(),
            "b".repeat(9)
        );
    }

    #[test]
    fn no_worker_available_falls_back_to_inline_and_loses_nothing() {
        let root = scratch("no-worker");
        let cfg = SaveQueueConfig {
            worker_disabled: true,
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..5 {
            let e = q.enqueue(task(&root, &format!("/w{i}.o"), "W"));
            assert!(
                matches!(e, Enqueued::Inline(ref o) if o.ok()),
                "a world with no worker must still durably save: {e:?}"
            );
        }
        for i in 0..5 {
            assert_eq!(
                std::fs::read_to_string(root.join(format!("w{i}.o"))).unwrap(),
                "W"
            );
        }
        assert_eq!(q.stats().queued, 0);
        assert_eq!(q.stats().inline_commits, 5);
    }

    #[test]
    fn a_lost_worker_commits_its_backlog_inline() {
        let root = scratch("lost-worker");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(2)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..8 {
            q.enqueue(task(&root, &format!("/l{i}.o"), "L"));
        }
        // The worker handle disappears (panic, aborted process, whatever).
        q.abandon_worker();
        let out = q.flush();
        assert!(
            q.stats().inline_commits > 0,
            "the backlog had to be committed by the caller: {:?}",
            q.stats()
        );
        for i in 0..8 {
            assert!(
                root.join(format!("l{i}.o")).exists(),
                "a lost worker must not lose save {i}"
            );
        }
        assert!(!out.is_empty());
    }

    #[test]
    fn set_durability_sync_flushes_first() {
        let root = scratch("switch");
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(2)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        for i in 0..5 {
            q.enqueue(task(&root, &format!("/s{i}.o"), "s"));
        }
        q.set_durability(SaveDurability::Sync);
        for i in 0..5 {
            assert!(root.join(format!("s{i}.o")).exists());
        }
        assert_eq!(q.durability(), SaveDurability::Sync);
        assert!(q.is_empty());
    }

    #[test]
    fn outcomes_are_reported_exactly_once() {
        let root = scratch("once");
        let mut q = queue(SaveQueueConfig::default());
        for i in 0..6 {
            q.enqueue(task(&root, &format!("/o{i}.o"), "o"));
        }
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !q.is_empty() && Instant::now() < deadline {
            seen.extend(q.poll(64));
            if !q.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        seen.extend(q.poll(64));
        assert_eq!(seen.len(), 6, "no outcome reported twice");
        let mut seqs: Vec<u64> = seen.iter().map(|o| o.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(q.stats().committed, 6);
    }

    /// Disk failures stay per-save: one path the save root cannot write (a
    /// plain file where a directory would have to be -- `stage_write` creates
    /// missing parents, so that is the deterministic "the disk said no") must
    /// not fail its neighbours, and the queue must keep working afterwards.
    /// `save_object`'s error contract, and the `errors` inbox entry, depend
    /// on that granularity.
    #[test]
    fn a_commit_failure_reports_one_save_not_the_batch() {
        let root = scratch("failure");
        std::fs::write(root.join("blocker"), "not a directory").unwrap();
        let cfg = SaveQueueConfig {
            commit_delay: Some(Duration::from_millis(1)),
            ..SaveQueueConfig::default()
        };
        let mut q = queue(cfg);
        q.enqueue(task(&root, "/ok1.o", "one"));
        q.enqueue(task(&root, "/blocker/deeper.o", "doomed"));
        q.enqueue(task(&root, "/ok2.o", "two"));
        let out = q.flush();
        assert_eq!(out.len(), 3, "one outcome per save");
        let doomed = out
            .iter()
            .find(|o| o.path.contains("blocker"))
            .expect("the failing save is reported");
        assert!(
            !doomed.ok(),
            "a path the root cannot write fails: {doomed:?}"
        );
        assert!(doomed.committed_bytes.is_none(), "nothing to bill");
        let err = doomed.error.as_deref().unwrap();
        assert!(err.contains("blocker"), "names the path: {err}");
        assert!(
            !err.contains("committed inline"),
            "not a fallback case: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("ok1.o")).unwrap(),
            "one",
            "the neighbour before it landed"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("ok2.o")).unwrap(),
            "two",
            "the neighbour after it landed too"
        );
        let s = q.stats();
        assert_eq!((s.committed, s.failed, s.panicked), (2, 1, 0), "{s:?}");
        assert!(q.is_empty());
        // ...and the queue still accepts work afterwards.
        q.enqueue(task(&root, "/ok3.o", "three"));
        assert_eq!(q.flush().len(), 1);
        assert_eq!(
            std::fs::read_to_string(root.join("ok3.o")).unwrap(),
            "three"
        );
    }

    /// Defence in depth for the single-writer invariant (CTO review item 4):
    /// even if a second thread ever does stage a save for the same path,
    /// `fileio`'s per-write temp name means they cannot unlink each other's
    /// in-flight file or lose `create_new` to `EEXIST` -- which is what
    /// CI run 37869788819 actually hit.
    #[test]
    fn temp_files_do_not_collide_across_threads() {
        use crate::fileio::write_file_atomic as loom_write_file_atomic;
        let root = scratch("temp-race");
        std::fs::create_dir_all(&root).unwrap();
        let writes = 100;
        std::thread::scope(|s| {
            for t in 0..2 {
                let root = root.clone();
                s.spawn(move || {
                    for i in 0..writes {
                        let path = "/shared.o".to_string();
                        let content = format!("thread{t}-save{i}");
                        let out = loom_write_file_atomic(&root, &path, &content);
                        assert!(out.is_ok(), "{out:?}");
                    }
                });
            }
        });
        // Every write either completed or was replaced by a later one; the
        // file exists and no temp litter is left behind.
        let contents = std::fs::read_to_string(root.join("shared.o")).unwrap();
        assert!(contents.starts_with("thread"), "{contents}");
        let litter: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(litter.is_empty(), "temp files left behind: {litter:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
