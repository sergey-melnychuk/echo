//! Path confinement (CRD-7, SEC-4). A vault key is a relative path with `/`
//! separators. Keys that are absolute, contain `..` or `.`, or point into
//! `.vault/` are rejected before any file operation.

use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Result};

use crate::config::DOT_DIR;

/// Check that `key` may name a file inside the vault.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("empty key");
    }
    if key.starts_with('/') {
        bail!("absolute key {key:?}");
    }
    if key.ends_with('/') {
        bail!("key {key:?} names a directory");
    }
    if key.contains('\\') || key.contains('\0') {
        bail!("key {key:?} contains a forbidden character");
    }
    let mut components = key.split('/');
    match components.next() {
        Some(first) if first == DOT_DIR => bail!("key {key:?} is inside {DOT_DIR}/"),
        _ => {}
    }
    for component in key.split('/') {
        if component.is_empty() {
            bail!("key {key:?} has an empty component");
        }
        if component == "." || component == ".." {
            bail!("key {key:?} has a relative component");
        }
    }
    Ok(())
}

/// The key for a file under `root`, or `None` when the path is outside the
/// vault, inside `.vault/`, or not representable as a key.
pub fn key_from_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            _ => return None,
        }
    }
    let key = parts.join("/");
    validate_key(&key).ok()?;
    Some(key)
}

/// The on-disk path for a validated key.
pub fn path_for_key(root: &Path, key: &str) -> Result<PathBuf> {
    validate_key(key)?;
    let mut path = root.to_path_buf();
    for component in key.split('/') {
        path.push(component);
    }
    Ok(path)
}

/// A key as bytes from a docs entry, if it is valid UTF-8 and passes
/// [`validate_key`].
pub fn key_from_bytes(bytes: &[u8]) -> Result<String> {
    let key = std::str::from_utf8(bytes)?;
    validate_key(key)?;
    Ok(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_keys_are_rejected() {
        for key in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../b",
            "a/./b",
            ".",
            "..",
            "a//b",
            "a/",
            ".vault",
            ".vault/config.json",
            ".vault/../x",
            "a\\b",
            "a\0b",
        ] {
            assert!(validate_key(key).is_err(), "{key:?} must be rejected");
        }
    }

    #[test]
    fn ordinary_keys_pass() {
        for key in [
            "a.txt",
            "dir/sub/file.md",
            ".hidden",
            ".vaultx/ok",
            "notes/.vault/inner",
            "weird name with spaces.txt",
            "ünïcödé/ファイル.txt",
        ] {
            assert!(validate_key(key).is_ok(), "{key:?} must pass");
        }
    }

    #[test]
    fn paths_and_keys_round_trip() {
        let root = Path::new("/vault");
        assert_eq!(
            key_from_path(root, Path::new("/vault/a/b.txt")),
            Some("a/b.txt".into())
        );
        assert_eq!(
            key_from_path(root, Path::new("/vault/.vault/state.json")),
            None
        );
        assert_eq!(key_from_path(root, Path::new("/vault/.vault")), None);
        assert_eq!(key_from_path(root, Path::new("/elsewhere/x")), None);
        assert_eq!(key_from_path(root, Path::new("/vault")), None);
        assert_eq!(key_from_path(root, Path::new("/vault/a/../b")), None);
        assert_eq!(
            path_for_key(root, "a/b.txt").unwrap(),
            PathBuf::from("/vault/a/b.txt")
        );
        assert!(path_for_key(root, "../b").is_err());
        assert_eq!(key_from_bytes(b"ok/file").unwrap(), "ok/file");
        assert!(key_from_bytes(b"\xff\xfe").is_err());
        assert!(key_from_bytes(b".vault/x").is_err());
    }
}
