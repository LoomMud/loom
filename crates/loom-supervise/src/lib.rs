// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom supervise`: the in-pod supervisor that owns the listening
//! sockets and performs copyover (design §7.5, §9.2, §9.9; tracked as
//! P2-O1 / OBI-184).
//!
//! This crate is being built incrementally; see OBI-184 for the slice
//! plan. What's here so far:
//!
//! - [`fdpass`]: `SCM_RIGHTS` file-descriptor passing over a `UnixStream`
//!   control socket -- the primitive step 2 of §7.5 needs ("Pass
//!   listening & client sockets to the new process via Unix-domain socket
//!   FD passing"). Fully unit-tested (real socket pairs, real pipe fds).
//! - [`version_source`]: the `VersionSource` seam between "what version
//!   should run" (a file today, written by the Docker-staging reconciler;
//!   a `loom-release` ConfigMap key once K1/OBI-187 lands) and the
//!   supervisor's reconcile loop, which never looks at either source
//!   directly, plus [`VersionWatcher`] (change detection on top of any
//!   `VersionSource`: reports a version only the first time it differs
//!   from what's currently tracked). `loom-cli`'s `supervise` polls one
//!   on a timer, when `LOOM_DESIRED_VERSION_FILE` is set, and logs a
//!   detected change -- *detection* is wired in; actually driving a
//!   copyover off it is not (see below).
//! - [`listener`]: turning a received fd back into a `TcpListener`
//!   (`adopt_tcp_listener`) or an inherited control fd into a
//!   `UnixStream` (`control_stream_from_raw_fd`), plus the `fcntl`
//!   helpers (`clear_cloexec`) the handoff protocol needs.
//! - [`signal`]: `SIGTERM`/`SIGINT` forwarding from the supervisor to its
//!   child, and `PR_SET_PDEATHSIG` so an unexpected supervisor exit
//!   doesn't orphan the child -- required before `supervise` can become
//!   the container entrypoint without regressing `serve`'s graceful-
//!   shutdown path (CTO review, OBI-225). Wired into `loom-cli`'s
//!   `supervise`/`spawn_and_handoff`.
//! - `loom-cli`'s `supervise` subcommand and `serve --adopt-control-fd`
//!   wire the above into a real, end-to-end supervisor: one standby
//!   child at a time, signal-forwarded shutdown, and respawn-on-crash
//!   (any exit the supervisor didn't itself request is treated as
//!   transient and retried against the same already-bound listeners,
//!   bounded by a consecutive-crash limit) -- but still no replace-an-
//!   already-running-process copyover (see `loom-cli`'s own doc comments
//!   on `supervise`/`run_one_child_attempt` for exactly what's built and
//!   what isn't).
//!
//! - [`copyover`]: the two-child, two-phase copyover state machine
//!   (design doc "OBI-184: copyover standby hand-off design", rev 2,
//!   CTO-approved incl. amendments A1-A6). [`copyover::Phase`] and
//!   [`copyover::CopyoverState`] encode amendment A3's explicit
//!   `active`/`Option<standby>`/phase representation and amendment A1's
//!   no-split-brain ordering (a standby that never received `Go` cannot
//!   be aborted-around unsafely, because reaching the decision point is
//!   the only way to leave the last abortable phase) -- unit-tested, not
//!   yet wired into `loom-cli`'s real supervise loop or given real
//!   `Child`/`UnixStream` handles (next slice).
//!
//! Not yet implemented (each is its own follow-up slice/issue, not
//! silently deferred -- see OBI-184's tracking comments):
//! - Staging a cosign-verified driver artifact + `abi.json` from GHCR.
//! - Actually wiring [`copyover::CopyoverState`] into `loom-cli`'s real
//!   supervise loop: spawning a genuine standby for `Preparing`, routing
//!   the new `HandoffOffer`/`HandoffReady`/`HandoffGo`/`HandoffCommit`/
//!   `HandoffAbort`/`HandoffRunning` control messages ([`control::
//!   ControlMessage`]) to/from the right process at the right phase, and
//!   the full quiesce -> drain -> reclaim -> snapshot -> send -> (await
//!   Ready) -> (Go+Commit | Abort) -> accept sequence the design doc's
//!   §3/§5 lay out. The snapshot save/load and `reconnect()` apply
//!   themselves are OBI-221/Gimli's piece, merged; this crate's
//!   remaining job is driving that interface from a live copyover.
//! - Relaying the snapshot file and reclaimed-connection fds through the
//!   supervisor process itself (design doc §4: "relay through the
//!   supervisor... don't open a direct old<->new channel") -- today's
//!   `fdpass` calls are all single-hop (supervisor<->one child); a real
//!   hand-off needs the supervisor to receive from the old process and
//!   re-send to the standby.
//! - Abort/fallback paths specific to a *copyover* failing partway
//!   through (old driver keeps running; a re-exec fallback if the *new*
//!   process fails after takeover) -- distinct from the already-built
//!   respawn-on-crash, which only ever starts a fresh standby from
//!   scratch, never attempts a live hand-off.
//! - Cross-version compatibility of the control protocol itself (N2, CTO
//!   re-review OBI-273): the old side of a hand-off runs the *previous*
//!   binary by definition, so the very first deploy that introduces a
//!   new control-message tag can't hand off *from* a binary that
//!   predates it -- that binary's [`control::read_message`] reads the
//!   new tag as "unknown message tag" (`io::ErrorKind::InvalidData`),
//!   not as the new variant. The wiring slice above must treat an
//!   unknown-tag error (or a `CopyoverNack`) from the old process the
//!   same as any other abort-the-hand-off condition, and fall back to a
//!   cold restart (the existing respawn-on-crash path) rather than retry
//!   the same hand-off against a peer that cannot speak it. Tags stay
//!   append-only (see [`control`]'s `TAG_*` block) specifically so this
//!   fallback is the only cross-version case to handle -- a tag never
//!   changes meaning out from under an old binary that already shipped.

pub mod control;
pub mod copyover;
pub mod fdpass;
pub mod listener;
pub mod signal;
pub mod version_source;

pub use copyover::{CopyoverState, Phase};
pub use version_source::{FileVersionSource, VersionSource, VersionWatcher};

// Loom only ever runs on Linux (the runtime image is debian/distroless,
// design §9.2), and this crate leans on Linux-specific ancillary-data
// behaviour `libc` doesn't even expose identically elsewhere (e.g.
// `MSG_CMSG_CLOEXEC`, `SCM_MAX_FD`'s value). Fail the build with a clear
// message rather than a wall of missing-constant errors from `libc` if
// someone ever points this crate at another target (CTO re-review nit,
// OBI-226).
#[cfg(not(target_os = "linux"))]
compile_error!(
    "loom-supervise is Linux-only (SCM_RIGHTS/MSG_CMSG_CLOEXEC semantics are not portable)"
);
