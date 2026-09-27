// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Mudlib-confined file I/O for the `read_file`/`write_file` efuns (spec
//! §5.5, OBI-85): the `ed`-lite builder command's storage. Paths are
//! mudlib-absolute (`/domains/x/y.wf`), normalised and confined to the
//! mudlib root -- `..` and NUL are rejected outright, and both directions
//! are capped at [`MAX_FILE_BYTES`].

use std::path::{Path, PathBuf};

/// Read/write size cap (spec: "cap it at 1 MiB").
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Resolve a mudlib-absolute path to a filesystem path confined under
/// `root`, purely lexically (no `..`, no NUL, no empty/`.` segments kept).
/// Does not touch the filesystem, so it also confines a path that does
/// not exist yet (`write_file` creating a new file).
fn resolve(root: &Path, path: &str) -> Result<PathBuf, String> {
    if path.as_bytes().contains(&0) {
        return Err("path must not contain a NUL byte".to_string());
    }
    let trimmed = path.trim();
    if !trimmed.starts_with('/') {
        return Err("path must be mudlib-absolute (start with `/`)".to_string());
    }
    let mut out = root.to_path_buf();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err("path must not contain `..`".to_string());
        }
        out.push(seg);
    }
    Ok(out)
}

/// `read_file()`: `Ok(None)` if the file does not exist, `Err` for a bad
/// path, an oversized file, or any other I/O failure.
pub fn read_file(root: &Path, path: &str) -> Result<Option<String>, String> {
    let resolved = resolve(root, path)?;
    match std::fs::metadata(&resolved) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => {
            return Err(format!(
                "{path}: {} bytes exceeds the {MAX_FILE_BYTES}-byte cap",
                meta.len()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{path}: {e}")),
    }
    match std::fs::read_to_string(&resolved) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

/// `write_file()`: only `.wf`/`.txt` suffixes are allowed; parent
/// directories are created under the root as needed.
pub fn write_file(root: &Path, path: &str, text: &str) -> Result<bool, String> {
    if !(path.ends_with(".wf") || path.ends_with(".txt")) {
        return Err(format!("{path}: write_file only allows .wf or .txt files"));
    }
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{path}: {} bytes exceeds the {MAX_FILE_BYTES}-byte cap",
            text.len()
        ));
    }
    let resolved = resolve(root, path)?;
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
    }
    // S2: `valid_write` policy hook goes here (per-tier/per-domain write
    // confinement beyond the mudlib-root confinement `resolve` already
    // enforces).
    std::fs::write(&resolved, text).map_err(|e| format!("{path}: {e}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("loom-fileio-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn read_missing_is_none() {
        let root = tmp_root("missing");
        assert_eq!(read_file(&root, "/domains/x/nope.wf").unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_then_read_round_trips() {
        let root = tmp_root("roundtrip");
        assert!(write_file(&root, "/domains/x/y.wf", "hello").unwrap());
        assert_eq!(
            read_file(&root, "/domains/x/y.wf").unwrap(),
            Some("hello".to_string())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dotdot_is_rejected() {
        let root = tmp_root("dotdot");
        assert!(read_file(&root, "/domains/../../etc/passwd").is_err());
        assert!(write_file(&root, "/domains/../../etc/passwd.txt", "x").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nul_is_rejected() {
        let root = tmp_root("nul");
        assert!(read_file(&root, "/domains/x\0y.wf").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absolute_path_outside_root_stays_confined() {
        let root = tmp_root("confine");
        // Not `..`, but an absolute-looking mudlib path is always resolved
        // *under* root, never as a real absolute filesystem path.
        assert!(write_file(&root, "/etc/passwd.txt", "pwned").unwrap());
        assert!(root.join("etc/passwd.txt").exists());
        assert!(
            !Path::new("/etc/passwd.txt").exists() || {
                // Extremely defensive: never true in CI, but never trust a
                // real /etc/passwd.txt existing because of this test.
                std::fs::read_to_string("/etc/passwd.txt").unwrap_or_default() != "pwned"
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_suffix_is_rejected() {
        let root = tmp_root("suffix");
        assert!(write_file(&root, "/domains/x/y.exe", "no").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_write_is_rejected() {
        let root = tmp_root("oversize-write");
        let big = "a".repeat(MAX_FILE_BYTES as usize + 1);
        assert!(write_file(&root, "/domains/x/big.txt", &big).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_read_is_rejected() {
        let root = tmp_root("oversize-read");
        let path = root.join("big.txt");
        std::fs::write(&path, vec![b'a'; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_file(&root, "/big.txt").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
