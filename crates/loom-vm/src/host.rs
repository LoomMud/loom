// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Output side of the driver ↔ VM seam.

/// The world thread asks the host to write to or close a connection.
/// Connection ids are plain `u64` (assigned by `loom-net`).
pub trait Host {
    /// Queue `text` for connection `conn`. Unknown ids are ignored.
    fn send(&mut self, conn: u64, text: &str);
    /// Close connection `conn`. Unknown ids are ignored.
    fn close(&mut self, conn: u64);
}

/// A host that discards everything (boot, tools).
pub struct NullHost;

impl Host for NullHost {
    fn send(&mut self, _conn: u64, _text: &str) {}
    fn close(&mut self, _conn: u64) {}
}
