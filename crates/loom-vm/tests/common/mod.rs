// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use loom_vm::Host;

/// Records everything the world sends, per connection.
#[derive(Default)]
pub struct FakeHost {
    pub out: HashMap<u64, String>,
    pub closed: Vec<u64>,
}

impl FakeHost {
    /// Take and clear the output sent to `conn`.
    pub fn take(&mut self, conn: u64) -> String {
        self.out.remove(&conn).unwrap_or_default()
    }
}

impl Host for FakeHost {
    fn send(&mut self, conn: u64, text: &str) {
        self.out.entry(conn).or_default().push_str(text);
    }
    fn close(&mut self, conn: u64) {
        self.closed.push(conn);
    }
}

static N: AtomicU32 = AtomicU32::new(0);

/// A fresh scratch directory under the target tmpdir.
pub fn scratch(tag: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for e in std::fs::read_dir(from).expect("readdir") {
        let p = e.expect("entry").path();
        let dest = to.join(p.file_name().expect("name"));
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).expect("copy");
        }
    }
}

/// Copy `tests/fixtures/<name>` into a scratch dir (tests rewrite files).
pub fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = scratch(name);
    copy_dir(&src, &dir);
    dir
}

/// Run `f` on a plain spawned thread. The bytecode VM keeps its call
/// stack on the heap (D-P1.3), not the native stack, so unlike the old
/// tree-walker the world thread no longer needs an oversized stack; this
/// helper is kept only so callers don't need to care where `f` runs.
pub fn on_world_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(f).join().expect("world thread panicked")
}
