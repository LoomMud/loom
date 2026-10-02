// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `file://` URI <-> mudlib program path conversion, and the open-buffer
//! overlay a running session compiles against.
//!
//! A mudlib program path (`/std/room`) maps to `<root>/std/room.wf` on
//! disk and to `file://<root>/std/room.wf` as an LSP URI. An open buffer's
//! *unsaved* text overlays the on-disk file so diagnostics/hover/definition
//! reflect what the builder is looking at, not what `loom check` would see
//! (spec `docs/hir.md`'s [`loom_compiler::mudlib::SourceLoader`] was built
//! exactly for this: the in-memory `HashMap<String, String>` impl already
//! doubles as "LSP buffers" per its own doc comment).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use loom_compiler::mudlib::{SourceLoader, normalize_path};
use lsp_types::Uri;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

/// Characters a `file://` path segment must percent-encode (RFC 3986
/// `pchar` complement, restricted to the handful of bytes that actually
/// show up in filesystem paths we care about).
const PATH_ESCAPE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'%');

/// Build a `file://` URI for an absolute filesystem path.
pub fn fs_path_to_uri(path: &Path) -> Uri {
    let s = path.to_string_lossy();
    // Encode each segment but keep `/` as a separator.
    let encoded: String = s
        .split('/')
        .map(|seg| utf8_percent_encode(seg, PATH_ESCAPE).to_string())
        .collect::<Vec<_>>()
        .join("/");
    let raw = format!("file://{encoded}");
    raw.parse()
        .unwrap_or_else(|e| panic!("built an invalid file URI from {path:?}: {e}"))
}

/// The absolute filesystem path a `file://` URI names, if it is one.
pub fn uri_to_fs_path(uri: &Uri) -> Option<PathBuf> {
    let s = uri.as_str();
    let rest = s.strip_prefix("file://")?;
    let decoded = percent_decode_str(rest).decode_utf8_lossy();
    Some(PathBuf::from(decoded.into_owned()))
}

/// Open buffers, keyed by normalised mudlib program path (`/std/room`, no
/// `.wf`), holding whatever the client last sent (not necessarily saved).
#[derive(Default)]
pub struct Workspace {
    pub root: PathBuf,
    overlays: HashMap<String, String>,
}

impl Workspace {
    pub fn new(root: PathBuf) -> Workspace {
        Workspace {
            root,
            overlays: HashMap::new(),
        }
    }

    /// Program path (`/std/room`) for a `file://` URI under `self.root`,
    /// if it names a `.wf` file inside the root.
    pub fn program_path(&self, uri: &Uri) -> Option<String> {
        let fs = uri_to_fs_path(uri)?;
        let rel = fs.strip_prefix(&self.root).ok()?;
        if rel.extension().is_none_or(|e| e != "wf") {
            return None;
        }
        let rel = rel.with_extension("");
        let s = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
        normalize_path(&s).ok()
    }

    /// The `file://` URI a program path maps to, whether or not it is open
    /// or exists on disk (go-to-definition targets a file that may not be
    /// loaded yet).
    pub fn uri_for_path(&self, path: &str) -> Uri {
        let rel = &path[1..]; // path is always absolute, checked by normalize_path
        fs_path_to_uri(&self.root.join(format!("{rel}.wf")))
    }

    pub fn open(&mut self, path: String, text: String) {
        self.overlays.insert(path, text);
    }

    pub fn change(&mut self, path: &str, text: String) {
        self.overlays.insert(path.to_string(), text);
    }

    pub fn close(&mut self, path: &str) {
        self.overlays.remove(path);
    }

    /// The text a compile of `path` would currently use: the open buffer
    /// if there is one, else whatever is on disk.
    pub fn text(&self, path: &str) -> Result<String, String> {
        OverlayLoader(self).load(path)
    }

    pub fn is_open(&self, path: &str) -> bool {
        self.overlays.contains_key(path)
    }

    /// A [`SourceLoader`] over this workspace's open buffers, falling back
    /// to disk: hand this to a fresh [`loom_compiler::mudlib::Session`] to
    /// compile `path` and its whole inherit/import closure the way the
    /// builder currently sees it (unsaved edits included).
    pub fn loader(&self) -> OverlayLoader<'_> {
        OverlayLoader(self)
    }
}

pub struct OverlayLoader<'a>(&'a Workspace);

impl SourceLoader for OverlayLoader<'_> {
    fn load(&self, path: &str) -> Result<String, String> {
        if let Some(s) = self.0.overlays.get(path) {
            return Ok(s.clone());
        }
        let file = self.0.root.join(format!("{}.wf", &path[1..]));
        std::fs::read_to_string(&file).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_round_trips_a_plain_path() {
        let p = PathBuf::from("/srv/warp/std/room.wf");
        let uri = fs_path_to_uri(&p);
        assert_eq!(uri.as_str(), "file:///srv/warp/std/room.wf");
        assert_eq!(uri_to_fs_path(&uri).unwrap(), p);
    }

    #[test]
    fn uri_round_trips_a_path_with_spaces() {
        let p = PathBuf::from("/srv/my warp/std/room.wf");
        let uri = fs_path_to_uri(&p);
        assert!(uri.as_str().contains("%20"));
        assert_eq!(uri_to_fs_path(&uri).unwrap(), p);
    }

    #[test]
    fn program_path_maps_file_under_root() {
        let ws = Workspace::new(PathBuf::from("/srv/warp"));
        let uri = fs_path_to_uri(&PathBuf::from("/srv/warp/std/room.wf"));
        assert_eq!(ws.program_path(&uri).as_deref(), Some("/std/room"));
    }

    #[test]
    fn program_path_rejects_files_outside_root_or_non_wf() {
        let ws = Workspace::new(PathBuf::from("/srv/warp"));
        let outside = fs_path_to_uri(&PathBuf::from("/etc/passwd"));
        assert_eq!(ws.program_path(&outside), None);
        let non_wf = fs_path_to_uri(&PathBuf::from("/srv/warp/README.md"));
        assert_eq!(ws.program_path(&non_wf), None);
    }

    #[test]
    fn uri_for_path_round_trips_program_path() {
        let ws = Workspace::new(PathBuf::from("/srv/warp"));
        let uri = ws.uri_for_path("/std/room");
        assert_eq!(ws.program_path(&uri).as_deref(), Some("/std/room"));
    }
}
