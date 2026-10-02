// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `FileProvider`: the only way `loom-lsp` ever touches source text (spec
//! `docs/threat-model-phase2.md` \u00a76.3 **M-LSP-2**, OBI-179/OBI-168).
//!
//! T-LSP-2 (H\u00d7M): "LSP reads beyond the tier ... because the server reads
//! the filesystem directly". The mitigation is that the server *never*
//! does: every read goes through this trait, which has two
//! implementations --
//!
//! - [`LocalDirectoryProvider`]: every path under a root directory is
//!   readable. This is the **stdio/local** case (`--stdio`/`--root`): a
//!   trusted human runs `loom-lsp` against their own checkout, the same
//!   trust level as opening the files in any editor.
//! - [`GatedProvider`]: wraps a [`ReadAuthorizer`] (answering, per spec,
//!   "may the session's uid `valid_read` this path?") and refuses a read
//!   exactly the way a missing file refuses one -- same error, no
//!   distinguishing "exists but denied" from "does not exist" (T-FS-3's
//!   sibling threat for LSP: a denial must not leak existence). This is
//!   the seam the **per-session** case (M-LSP-2's other half, the web IDE
//!   bridge, OBI-180) plugs a real `valid_read`-backed [`ReadAuthorizer`]
//!   into; `loom-lsp` itself has no session/uid/Postgres concept, so it
//!   cannot (and must not pretend to) implement the real policy -- that
//!   authority lives in the master `valid_*` applies on the world thread
//!   (spec \u00a75.11, D-TM5: "an HTTP-side ACL mirroring the master" is an
//!   explicitly rejected design). `tests::` below exercises the contract
//!   with a mock authorizer standing in for that real one (the T1/T4 test
//!   cases \u00a76.3 names), so the policy shape is proven even though the
//!   real authorization backend is OBI-180's to wire in.

/// Decides whether a path may be read at all, for a given (unspecified
/// here -- it's whatever the embedding session is) principal. A `false`
/// must look exactly like "this program does not exist" to every caller.
pub trait ReadAuthorizer: Send + Sync {
    fn can_read(&self, path: &str) -> bool;
}

/// One source of program text.
pub trait FileProvider: Send + Sync {
    /// `path` is a normalised program path (`/std/room`, no `.wf`, no
    /// scheme). `Err` covers both "does not exist" and "exists but
    /// denied" -- see the module docs' T-FS-3 note.
    fn read(&self, path: &str) -> Result<String, String>;
    /// Whether `path` may be read at all (existence included).
    fn can_read(&self, path: &str) -> bool;
}

/// stdio/local mode (spec M-LSP-2): a trusted checkout, every path under
/// `root` is readable.
pub struct LocalDirectoryProvider {
    pub root: std::path::PathBuf,
}

impl FileProvider for LocalDirectoryProvider {
    fn read(&self, path: &str) -> Result<String, String> {
        // N1 (CTO review of OBI-168): `path` is documented as normalised,
        // but this is a `pub` trait impl a future caller could hand an
        // un-normalised string to (an empty string, or one with a
        // non-ASCII first byte would panic on a raw `&path[1..]` slice).
        // Re-validate here so the provider is safe on its own, not only
        // because today's callers happen to normalise first.
        let Ok(normalized) = loom_compiler::mudlib::normalize_path(path) else {
            return Err("No such file or directory".to_string());
        };
        let file = self.root.join(format!("{}.wf", &normalized[1..]));
        std::fs::read_to_string(&file).map_err(|e| e.to_string())
    }

    fn can_read(&self, _path: &str) -> bool {
        true
    }
}

/// Per-session mode (spec M-LSP-2): every read is gated by `authz`, and a
/// denial is indistinguishable from a missing file.
pub struct GatedProvider<P: FileProvider, A: ReadAuthorizer> {
    pub inner: P,
    pub authz: A,
}

impl<P: FileProvider, A: ReadAuthorizer> FileProvider for GatedProvider<P, A> {
    fn read(&self, path: &str) -> Result<String, String> {
        if !self.authz.can_read(path) {
            return Err("No such file or directory".to_string());
        }
        self.inner.read(path)
    }

    fn can_read(&self, path: &str) -> bool {
        self.authz.can_read(path)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A mock authorizer standing in for the real `valid_read`-backed one
    /// (OBI-180 wires that in; this crate only proves the policy shape).
    pub struct AllowList(pub HashSet<String>);

    impl ReadAuthorizer for AllowList {
        fn can_read(&self, path: &str) -> bool {
            self.0.contains(path)
        }
    }

    #[test]
    fn gated_provider_read_fails_the_same_way_for_denied_and_missing() {
        let provider = GatedProvider {
            inner: LocalDirectoryProvider {
                root: std::env::temp_dir(),
            },
            authz: AllowList(HashSet::from(["/domains/start/yard".to_string()])),
        };
        assert!(!provider.can_read("/secure/master"));
        let denied = provider.read("/secure/master").unwrap_err();
        let missing = provider.read("/does/not/exist").unwrap_err();
        assert_eq!(
            denied, missing,
            "a denial must look exactly like a missing file"
        );
    }

    #[test]
    fn local_directory_provider_read_does_not_panic_on_bad_paths() {
        // N1: an empty string or a path missing its leading `/` used to
        // panic on a raw `&path[1..]` slice.
        let provider = LocalDirectoryProvider {
            root: std::env::temp_dir(),
        };
        assert!(provider.read("").is_err());
        assert!(provider.read("no-leading-slash").is_err());
        assert!(provider.read("/../escape").is_err());
    }
}
