// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom-lsp`: the Weft language server (spec \u00a712.1 E2.1, OBI-168).
//!
//! The protocol core ([`server::run`]) is transport-agnostic: it drives an
//! [`lsp_server::Connection`], which is just a pair of crossbeam channels.
//! `main.rs` wires that up to stdio directly, or to a WebSocket via
//! [`lsp_server::Connection::memory`] plus [`ws::serve`]'s bridge thread --
//! the web IDE (P2-B2) and a local editor get exactly the same server
//! logic and exactly the same test coverage.

pub mod completion;
pub mod definition;
pub mod diagnostics;
pub mod env_guard;
pub mod file_provider;
pub mod hover;
pub mod position;
pub mod server;
pub mod workspace;
pub mod ws;
