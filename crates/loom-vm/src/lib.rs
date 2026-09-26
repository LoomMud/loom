// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Weft values, object table, program registry and evaluator/VM (§3.4, §5.9, §7). Owner: Gimli.
//!
//! Phase 0: the driver ↔ VM seam (`World` / `Host`). The world is driven by a
//! single world thread owned by `loom-cli serve`; it never blocks on I/O and
//! talks to the network only through [`Host`].

use std::fmt;
use std::path::{Path, PathBuf};

/// Output side of the seam: the world thread asks the host to write to or
/// close a connection. Connection ids are plain `u64` (assigned by `loom-net`).
pub trait Host {
    /// Queue `text` for connection `conn`. Unknown ids are ignored.
    fn send(&mut self, conn: u64, text: &str);
    /// Close connection `conn`. Unknown ids are ignored.
    fn close(&mut self, conn: u64);
}

/// Failure to boot a world from a mudlib root.
#[derive(Debug)]
pub enum BootError {
    /// The mudlib root does not exist or is not a directory.
    NoMudlib(PathBuf),
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::NoMudlib(p) => write!(f, "mudlib root {} is not a directory", p.display()),
        }
    }
}

impl std::error::Error for BootError {}

/// The game world. Stub: echoes input until the evaluator lands (OBI-10).
pub struct World {
    root: PathBuf,
}

impl World {
    /// Boot a world from `mudlib_root` (loads `/secure/master.wf`).
    pub fn boot(mudlib_root: &Path) -> Result<World, BootError> {
        if !mudlib_root.is_dir() {
            return Err(BootError::NoMudlib(mudlib_root.to_path_buf()));
        }
        Ok(World {
            root: mudlib_root.to_path_buf(),
        })
    }

    /// The mudlib root this world was booted from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A new connection arrived: master `connect()`, bind, then `logon()`.
    pub fn connect(&mut self, conn: u64, host: &mut dyn Host) {
        host.send(conn, "Welcome to Loom (stub world).\n");
    }

    /// A line of input from `conn`: `process_input(line)` on the bound object.
    pub fn input(&mut self, conn: u64, line: &str, host: &mut dyn Host) {
        host.send(conn, &format!("You said: {line}\n"));
    }

    /// The connection went away: `net_dead()` on the bound object.
    pub fn disconnect(&mut self, _conn: u64, _host: &mut dyn Host) {}
}
