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
    /// Turn local client echo on (`enabled = true`) or off (`enabled =
    /// false`) for connection `conn` around a no-echo input, e.g. a
    /// password prompt (spec §9, OBI-176). Telnet gets `IAC WILL/WONT
    /// ECHO`; WebSocket gets an equivalent JSON flag the client uses to
    /// mask the field. Unknown ids are ignored.
    fn set_echo(&mut self, conn: u64, enabled: bool);
}

/// A host that discards everything (boot, tools).
pub struct NullHost;

impl Host for NullHost {
    fn send(&mut self, _conn: u64, _text: &str) {}
    fn close(&mut self, _conn: u64) {}
    fn set_echo(&mut self, _conn: u64, _enabled: bool) {}
}
