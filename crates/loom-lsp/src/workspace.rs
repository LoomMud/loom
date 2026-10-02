// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! URI <-> mudlib program path conversion, and the open-buffer overlay a
//! running session compiles against.
//!
//! Two URI schemes, matched to the two [`FileProvider`] implementations
//! (spec `docs/threat-model-phase2.md` \u00a76.3 **M-LSP-2**, **M-LSP-3**):
//!
//! - **Local** (`UriMode::Local`, `--stdio`/`--root`): `file://<root>/...`
//!   URIs map onto a filesystem root, same as any local editor LSP.
//! - **Vfs** (`UriMode::Vfs`, the per-session/WS case): `loom-vfs:///path`
//!   URIs map directly onto the program path -- no filesystem root, and
//!   no `file:` URI is ever accepted or emitted, so a host path can never
//!   reach a response (T-LSP-3). Resolution still goes through
//!   [`normalize_path`], the same percent-decode-once /
//!   reject-`.`-`..`-NUL rules `loom_compiler::mudlib` already enforces
//!   for `inherit`/`import` (the "shared VFS resolver", M-FS-2's
//!   counterpart for path *syntax*; M-FS-2's filesystem-escape half --
//!   symlinks, `O_NOFOLLOW`, the VFS root -- is the [`FileProvider`]'s
//!   job, specifically whatever OBI-180 plugs in for the real `/data`-
//!   backed VFS).
//!
//! An open buffer's *unsaved* text overlays whatever the [`FileProvider`]
//! would otherwise return, so diagnostics/hover/definition reflect what
//! the builder is looking at (spec `docs/hir.md`'s
//! [`loom_compiler::mudlib::SourceLoader`] was built exactly for this).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use loom_compiler::mudlib::{SourceLoader, normalize_path};
use lsp_types::Uri;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

use crate::file_provider::{FileProvider, LocalDirectoryProvider};

/// Spec M-LSP-4: "max document 1 MiB".
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// Spec M-LSP-4: "\u2264 64 open documents per session".
pub const MAX_OPEN_DOCUMENTS: usize = 64;

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

/// Build a `loom-vfs:///path` URI for an already-normalised program path.
pub fn program_path_to_vfs_uri(path: &str) -> Uri {
    let encoded: String = path
        .split('/')
        .map(|seg| utf8_percent_encode(seg, PATH_ESCAPE).to_string())
        .collect::<Vec<_>>()
        .join("/");
    let raw = format!("loom-vfs://{encoded}.wf");
    raw.parse()
        .unwrap_or_else(|e| panic!("built an invalid loom-vfs URI from {path:?}: {e}"))
}

/// The program path a `loom-vfs:///path` URI names, if it is one.
pub fn vfs_uri_to_program_path(uri: &Uri) -> Option<String> {
    let s = uri.as_str();
    let rest = s.strip_prefix("loom-vfs://")?;
    let decoded = percent_decode_str(rest).decode_utf8_lossy();
    let decoded = decoded.strip_suffix(".wf")?;
    normalize_path(decoded).ok()
}

/// Which URI scheme this workspace accepts/emits (see module docs).
#[derive(Clone)]
pub enum UriMode {
    Local { root: PathBuf },
    Vfs,
}

/// Open buffers, keyed by normalised mudlib program path (`/std/room`, no
/// `.wf`), holding whatever the client last sent (not necessarily saved).
/// Cheaply [`Clone`] (an `Arc`'d provider plus a `HashMap` of open docs,
/// bounded by [`MAX_OPEN_DOCUMENTS`]/[`MAX_DOCUMENT_BYTES`]): each request
/// (spec M-LSP-4) runs against its own snapshot on its own worker thread,
/// so a slow compile never blocks the main loop from reading the next
/// message (in particular, `$/cancelRequest`).
#[derive(Clone)]
pub struct Workspace {
    mode: UriMode,
    provider: Arc<dyn FileProvider>,
    overlays: HashMap<String, String>,
}

/// Why [`Workspace::open`]/[`Workspace::change`] refused a buffer (spec
/// M-LSP-4): the caller should publish one diagnostic explaining this
/// instead of silently dropping the edit.
#[derive(Debug, PartialEq, Eq)]
pub enum LimitExceeded {
    DocumentTooLarge { bytes: usize },
    TooManyOpenDocuments,
}

impl Workspace {
    /// stdio/local mode: every path under `root` is readable (spec
    /// M-LSP-2's "directory impl for stdio/local").
    pub fn new(root: PathBuf) -> Workspace {
        Workspace {
            provider: Arc::new(LocalDirectoryProvider { root: root.clone() }),
            mode: UriMode::Local { root },
            overlays: HashMap::new(),
        }
    }

    /// Per-session/WS mode (spec M-LSP-2/M-LSP-3): `loom-vfs://` URIs
    /// only, reads gated by `provider` (a [`crate::file_provider::GatedProvider`]
    /// in the real deployment).
    pub fn new_vfs(provider: Arc<dyn FileProvider>) -> Workspace {
        Workspace {
            provider,
            mode: UriMode::Vfs,
            overlays: HashMap::new(),
        }
    }

    /// Program path (`/std/room`) for a URI in this workspace's scheme, if
    /// it is one (a `file://` URI in `Vfs` mode, or vice versa, is
    /// rejected outright -- spec M-LSP-3: "others rejected").
    pub fn program_path(&self, uri: &Uri) -> Option<String> {
        match &self.mode {
            UriMode::Local { root } => {
                let fs = uri_to_fs_path(uri)?;
                let rel = fs.strip_prefix(root).ok()?;
                if rel.extension().is_none_or(|e| e != "wf") {
                    return None;
                }
                let rel = rel.with_extension("");
                let s = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                normalize_path(&s).ok()
            }
            UriMode::Vfs => vfs_uri_to_program_path(uri),
        }
    }

    /// The URI a program path maps to in this workspace's scheme, whether
    /// or not it is open, exists, or is readable (go-to-definition targets
    /// a file that may be none of those).
    pub fn uri_for_path(&self, path: &str) -> Uri {
        match &self.mode {
            UriMode::Local { root } => {
                let rel = &path[1..]; // path is always absolute (normalize_path)
                fs_path_to_uri(&root.join(format!("{rel}.wf")))
            }
            UriMode::Vfs => program_path_to_vfs_uri(path),
        }
    }

    /// Spec M-LSP-2: may `path` be read at all? A denial must look
    /// identical to "does not exist" to every caller (see
    /// `crate::file_provider`'s module docs).
    pub fn can_read(&self, path: &str) -> bool {
        self.provider.can_read(path)
    }

    /// Accept `path`'s buffer, refusing it (spec M-LSP-4) if it is over
    /// [`MAX_DOCUMENT_BYTES`] or would exceed [`MAX_OPEN_DOCUMENTS`].
    pub fn open(&mut self, path: String, text: String) -> Result<(), LimitExceeded> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(LimitExceeded::DocumentTooLarge { bytes: text.len() });
        }
        if !self.overlays.contains_key(&path) && self.overlays.len() >= MAX_OPEN_DOCUMENTS {
            return Err(LimitExceeded::TooManyOpenDocuments);
        }
        self.overlays.insert(path, text);
        Ok(())
    }

    pub fn change(&mut self, path: &str, text: String) -> Result<(), LimitExceeded> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(LimitExceeded::DocumentTooLarge { bytes: text.len() });
        }
        self.overlays.insert(path.to_string(), text);
        Ok(())
    }

    pub fn close(&mut self, path: &str) {
        self.overlays.remove(path);
    }

    /// The text a compile of `path` would currently use: the open buffer
    /// if there is one (always allowed -- the client already has it, and
    /// whatever let it open the buffer already answered the read-access
    /// question), else whatever [`FileProvider::read`] returns, gated.
    pub fn text(&self, path: &str) -> Result<String, String> {
        OverlayLoader(self).load(path)
    }

    pub fn is_open(&self, path: &str) -> bool {
        self.overlays.contains_key(path)
    }

    pub fn open_document_count(&self) -> usize {
        self.overlays.len()
    }

    /// A [`SourceLoader`] over this workspace's open buffers, falling back
    /// to the gated [`FileProvider`]: hand this to a fresh
    /// [`loom_compiler::mudlib::Session`] to compile `path` and its whole
    /// inherit/import closure the way the builder currently sees it
    /// (unsaved edits included, unreadable ancestors reported the same
    /// way a missing file is -- `W0114`, spec M-LSP-2).
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
        self.0.provider.read(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_provider::GatedProvider;
    use crate::file_provider::tests::AllowList;
    use std::collections::HashSet;

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

    #[test]
    fn vfs_mode_round_trips_and_rejects_file_uris() {
        let provider: Arc<dyn crate::file_provider::FileProvider> = Arc::new(GatedProvider {
            inner: LocalDirectoryProvider {
                root: PathBuf::from("/srv/warp"),
            },
            authz: AllowList(HashSet::from(["/std/room".to_string()])),
        });
        let ws = Workspace::new_vfs(provider);
        let uri = ws.uri_for_path("/std/room");
        assert_eq!(uri.as_str(), "loom-vfs:///std/room.wf");
        assert_eq!(ws.program_path(&uri).as_deref(), Some("/std/room"));

        // A `file://` URI (host path) is rejected outright in Vfs mode.
        let file_uri = fs_path_to_uri(&PathBuf::from("/srv/warp/std/room.wf"));
        assert_eq!(ws.program_path(&file_uri), None);
    }

    #[test]
    fn vfs_mode_gates_reads_through_the_authorizer() {
        let provider: Arc<dyn crate::file_provider::FileProvider> = Arc::new(GatedProvider {
            inner: LocalDirectoryProvider {
                root: PathBuf::from("/srv/warp"),
            },
            authz: AllowList(HashSet::from(["/domains/start/yard".to_string()])),
        });
        let ws = Workspace::new_vfs(provider);
        assert!(ws.can_read("/domains/start/yard"));
        assert!(!ws.can_read("/secure/master"));
    }

    #[test]
    fn open_refuses_a_document_over_the_size_cap() {
        let mut ws = Workspace::new(PathBuf::from("/srv/warp"));
        let big = "x".repeat(MAX_DOCUMENT_BYTES + 1);
        let err = ws.open("/std/room".to_string(), big).unwrap_err();
        assert!(matches!(err, LimitExceeded::DocumentTooLarge { .. }));
        assert!(!ws.is_open("/std/room"));
    }

    #[test]
    fn open_refuses_past_the_open_document_cap() {
        let mut ws = Workspace::new(PathBuf::from("/srv/warp"));
        for i in 0..MAX_OPEN_DOCUMENTS {
            ws.open(format!("/d{i}"), "x".to_string()).unwrap();
        }
        let err = ws
            .open("/one/too/many".to_string(), "x".to_string())
            .unwrap_err();
        assert_eq!(err, LimitExceeded::TooManyOpenDocuments);
        // Re-opening (or changing) an already-open document never counts
        // as "one more" against the cap.
        ws.open("/d0".to_string(), "y".to_string()).unwrap();
    }
}
