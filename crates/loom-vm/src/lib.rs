// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Weft values, object table, program registry and evaluator/VM (§3.4, §5.9, §7). Owner: Gimli.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Host callbacks used by the world thread to emit network effects.
pub trait Host {
    fn send(&mut self, conn: u64, text: &str);
    fn close(&mut self, conn: u64);
}

/// Minimal Phase 0 world implementation.
pub struct World {
    _mudlib_root: PathBuf,
}

#[derive(Debug, Error)]
pub enum BootError {
    #[error("mudlib path does not exist: {0}")]
    MissingMudlib(PathBuf),
}

impl World {
    pub fn boot(mudlib_root: &Path) -> Result<Self, BootError> {
        if !mudlib_root.exists() {
            return Err(BootError::MissingMudlib(mudlib_root.to_path_buf()));
        }

        Ok(Self {
            _mudlib_root: mudlib_root.to_path_buf(),
        })
    }

    pub fn connect(&mut self, _conn: u64, _host: &mut dyn Host) {}

    pub fn input(&mut self, conn: u64, line: &str, host: &mut dyn Host) {
        host.send(conn, line);
    }

    pub fn disconnect(&mut self, _conn: u64, _host: &mut dyn Host) {}
}
