//! [`ChunkRef`], [`FileManifest`], manifest ID computation, [`FileManifest::validate`]
//! and the path confinement rules (SEC-9).
//!
//! A manifest lists the chunks of one file version in order. Its ID is
//! derived and never trusted from the wire: receivers recompute it.

use crate::crypto::MANIFEST_CONTEXT;
use crate::Hash;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Smallest chunk FastCDC may emit, except for the final remainder.
pub const MIN_CHUNK: u32 = 8_192;
/// Target average chunk size.
pub const AVG_CHUNK: u32 = 16_384;
/// Largest chunk FastCDC may emit, and the largest `ChunkRef::length`.
pub const MAX_CHUNK: u32 = 32_768;
/// Largest file the PoC syncs (files are chunked in memory).
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
/// Most chunks in one manifest.
pub const MAX_CHUNKS: usize = 32_768;
/// Longest `file_name` in bytes.
pub const MAX_FILE_NAME_LEN: usize = 1_024;
/// The tool's own directory inside a document; manifests may not name it.
pub const INTERNAL_DIR: &str = ".p2p-sync";

/// One chunk of a file: its content hash and its length. Offsets are the
/// running sum of lengths.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkRef {
    /// `blake3::hash` of the chunk bytes.
    pub hash: Hash,
    /// `1..=MAX_CHUNK`.
    pub length: u32,
}

/// The ordered chunk list of one file version.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FileManifest {
    /// Relative path with `/` separators and normal components only (SEC-9).
    pub file_name: String,
    /// Sum of chunk lengths; at most [`MAX_FILE_SIZE`].
    pub total_size: u64,
    /// Chunks in file order.
    pub chunks: Vec<ChunkRef>,
}

/// Why a manifest or file name was refused.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// `total_size` exceeds [`MAX_FILE_SIZE`].
    #[error("file size {0} exceeds the {MAX_FILE_SIZE} byte limit")]
    TooLarge(u64),
    /// `total_size` is not the sum of chunk lengths.
    #[error("total_size {total_size} does not equal the chunk sum {chunk_sum}")]
    SizeMismatch {
        /// Declared size.
        total_size: u64,
        /// Sum of `ChunkRef::length`.
        chunk_sum: u64,
    },
    /// A chunk length is 0 or above [`MAX_CHUNK`].
    #[error("chunk {index} has invalid length {length}")]
    BadChunkLength {
        /// Position in `chunks`.
        index: usize,
        /// The offending length.
        length: u32,
    },
    /// More than [`MAX_CHUNKS`] chunks.
    #[error("manifest has {0} chunks, more than {MAX_CHUNKS}")]
    TooManyChunks(usize),
    /// `file_name` is empty.
    #[error("file name is empty")]
    EmptyName,
    /// `file_name` is longer than [`MAX_FILE_NAME_LEN`] bytes.
    #[error("file name is {0} bytes, longer than {MAX_FILE_NAME_LEN}")]
    NameTooLong(usize),
    /// `file_name` violates a path rule (SEC-9). The string says which.
    #[error("file name is not a safe relative path: {0}")]
    BadPath(&'static str),
    /// `file_name` is inside the tool's own directory.
    #[error("file name is inside the reserved {INTERNAL_DIR} directory")]
    ReservedPath,
    /// The path resolved outside the document directory (SEC-9).
    #[error("path resolves outside the document directory")]
    OutsideDocument,
    /// Filesystem error while resolving a path.
    #[error("io error while resolving path: {0}")]
    Io(String),
}

impl FileManifest {
    /// The manifest ID: BLAKE3 in key-derivation mode over the name (length
    /// prefixed), size, chunk count and every chunk's hash and length. This is
    /// the root of a depth-1 Merkle tree whose leaves are the chunk hashes.
    pub fn id(&self) -> Hash {
        let mut h = blake3::Hasher::new_derive_key(MANIFEST_CONTEXT);
        h.update(&(self.file_name.len() as u64).to_le_bytes());
        h.update(self.file_name.as_bytes());
        h.update(&self.total_size.to_le_bytes());
        h.update(&(self.chunks.len() as u64).to_le_bytes());
        for c in &self.chunks {
            h.update(&c.hash);
            h.update(&c.length.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// Reject a manifest unless its size, chunk lengths, chunk count and
    /// file name all satisfy section 5, including the SEC-9 path rules.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_file_name(&self.file_name)?;
        if self.total_size > MAX_FILE_SIZE {
            return Err(ManifestError::TooLarge(self.total_size));
        }
        if self.chunks.len() > MAX_CHUNKS {
            return Err(ManifestError::TooManyChunks(self.chunks.len()));
        }
        let mut sum: u64 = 0;
        for (index, c) in self.chunks.iter().enumerate() {
            if c.length == 0 || c.length > MAX_CHUNK {
                return Err(ManifestError::BadChunkLength {
                    index,
                    length: c.length,
                });
            }
            sum += u64::from(c.length);
        }
        if sum != self.total_size {
            return Err(ManifestError::SizeMismatch {
                total_size: self.total_size,
                chunk_sum: sum,
            });
        }
        Ok(())
    }
}

/// SEC-9: `name` must be a non-empty relative path of at most
/// [`MAX_FILE_NAME_LEN`] bytes, using `/` separators, with no NUL, backslash,
/// colon (drive prefix), empty component, `.` or `..`, not starting with `/`,
/// and not inside [`INTERNAL_DIR`].
pub fn validate_file_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty() {
        return Err(ManifestError::EmptyName);
    }
    if name.len() > MAX_FILE_NAME_LEN {
        return Err(ManifestError::NameTooLong(name.len()));
    }
    if name.contains('\0') {
        return Err(ManifestError::BadPath("contains NUL"));
    }
    if name.contains('\\') {
        return Err(ManifestError::BadPath("contains backslash"));
    }
    if name.contains(':') {
        return Err(ManifestError::BadPath("contains a drive prefix or colon"));
    }
    if name.starts_with('/') {
        return Err(ManifestError::BadPath("is absolute"));
    }
    for component in name.split('/') {
        match component {
            "" => return Err(ManifestError::BadPath("has an empty component")),
            "." => return Err(ManifestError::BadPath("has a '.' component")),
            ".." => return Err(ManifestError::BadPath("has a '..' component")),
            _ => {}
        }
    }
    if name.split('/').next() == Some(INTERNAL_DIR) {
        return Err(ManifestError::ReservedPath);
    }
    Ok(())
}

/// Join a validated `file_name` onto `doc_dir` and confirm the result stays
/// inside it (SEC-9), following symlinks in any existing ancestor.
///
/// `doc_dir` must exist. Returns the non-canonical joined path for use in
/// writes, after confirming that its deepest existing ancestor canonicalizes
/// to a location under the canonical `doc_dir`.
pub fn confined_path(doc_dir: &Path, file_name: &str) -> Result<PathBuf, ManifestError> {
    validate_file_name(file_name)?;
    let root = doc_dir
        .canonicalize()
        .map_err(|e| ManifestError::Io(e.to_string()))?;
    let mut target = root.clone();
    for component in file_name.split('/') {
        // Belt and braces: the component was validated above, but make sure
        // the OS agrees it is a plain normal component.
        let mut parts = Path::new(component).components();
        match (parts.next(), parts.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err(ManifestError::BadPath("component is not a normal name")),
        }
        target.push(component);
    }
    // Find the deepest existing ancestor (the target itself may not exist yet)
    // and check where it really lives.
    let mut probe = target.clone();
    loop {
        match probe.canonicalize() {
            Ok(real) => {
                if real == root || real.starts_with(&root) {
                    return Ok(target);
                }
                return Err(ManifestError::OutsideDocument);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match probe.parent() {
                Some(p) if p.starts_with(&root) => probe = p.to_path_buf(),
                _ => return Err(ManifestError::OutsideDocument),
            },
            Err(e) => return Err(ManifestError::Io(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(byte: u8, length: u32) -> ChunkRef {
        ChunkRef {
            hash: [byte; 32],
            length,
        }
    }

    fn good() -> FileManifest {
        FileManifest {
            file_name: "dir/file.bin".into(),
            total_size: 10_000 + 32_768,
            chunks: vec![chunk(1, 10_000), chunk(2, 32_768)],
        }
    }

    #[test]
    fn valid_manifest_passes() {
        good().validate().unwrap();
        FileManifest {
            file_name: "empty".into(),
            total_size: 0,
            chunks: vec![],
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn id_changes_with_name_size_and_any_chunk() {
        let base = good();
        let id = base.id();
        assert_eq!(id, good().id());

        let mut m = good();
        m.file_name = "dir/file.bin2".into();
        assert_ne!(m.id(), id);

        let mut m = good();
        m.total_size += 1;
        assert_ne!(m.id(), id);

        let mut m = good();
        m.chunks[0].hash[0] ^= 1;
        assert_ne!(m.id(), id);

        let mut m = good();
        m.chunks[1].length -= 1;
        assert_ne!(m.id(), id);

        let mut m = good();
        m.chunks.swap(0, 1);
        assert_ne!(m.id(), id);

        let mut m = good();
        m.chunks.push(chunk(3, 1));
        assert_ne!(m.id(), id);
    }

    #[test]
    fn id_is_not_a_plain_hash_and_length_prefix_prevents_name_shift() {
        // Moving bytes between the name and the rest changes the ID because
        // the name is length prefixed.
        let a = FileManifest {
            file_name: "ab".into(),
            total_size: 0,
            chunks: vec![],
        };
        let b = FileManifest {
            file_name: "a".into(),
            total_size: 0,
            chunks: vec![],
        };
        assert_ne!(a.id(), b.id());
        assert_ne!(a.id(), crate::crypto::chunk_hash(b"ab"));
    }

    #[test]
    fn validate_rejects_size_and_chunk_problems() {
        let mut m = good();
        m.total_size = MAX_FILE_SIZE + 1;
        assert_eq!(
            m.validate(),
            Err(ManifestError::TooLarge(MAX_FILE_SIZE + 1))
        );

        let mut m = good();
        m.total_size += 1;
        assert!(matches!(
            m.validate(),
            Err(ManifestError::SizeMismatch { .. })
        ));

        let mut m = good();
        m.chunks[0].length = 0;
        assert_eq!(
            m.validate(),
            Err(ManifestError::BadChunkLength {
                index: 0,
                length: 0
            })
        );

        let mut m = good();
        m.chunks[1].length = MAX_CHUNK + 1;
        m.total_size = 10_000 + u64::from(MAX_CHUNK) + 1;
        assert_eq!(
            m.validate(),
            Err(ManifestError::BadChunkLength {
                index: 1,
                length: MAX_CHUNK + 1
            })
        );

        let m = FileManifest {
            file_name: "x".into(),
            total_size: (MAX_CHUNKS as u64) + 1,
            chunks: vec![chunk(1, 1); MAX_CHUNKS + 1],
        };
        assert_eq!(
            m.validate(),
            Err(ManifestError::TooManyChunks(MAX_CHUNKS + 1))
        );

        // Exactly MAX_CHUNKS is fine.
        let m = FileManifest {
            file_name: "x".into(),
            total_size: MAX_CHUNKS as u64,
            chunks: vec![chunk(1, 1); MAX_CHUNKS],
        };
        m.validate().unwrap();
    }

    /// SEC-9: the table of bad paths from section 12, stage 3.
    #[test]
    fn sec9_bad_paths_are_rejected() {
        let long = "a".repeat(MAX_FILE_NAME_LEN + 1);
        let cases: Vec<(&str, ManifestError)> = vec![
            ("..", ManifestError::BadPath("has a '..' component")),
            ("../x", ManifestError::BadPath("has a '..' component")),
            ("a/../b", ManifestError::BadPath("has a '..' component")),
            ("a/..", ManifestError::BadPath("has a '..' component")),
            ("/etc/x", ManifestError::BadPath("is absolute")),
            ("a//b", ManifestError::BadPath("has an empty component")),
            ("a/", ManifestError::BadPath("has an empty component")),
            ("a\\b", ManifestError::BadPath("contains backslash")),
            ("a\0b", ManifestError::BadPath("contains NUL")),
            (
                "C:x",
                ManifestError::BadPath("contains a drive prefix or colon"),
            ),
            ("C:\\x", ManifestError::BadPath("contains backslash")),
            (".", ManifestError::BadPath("has a '.' component")),
            ("./a", ManifestError::BadPath("has a '.' component")),
            ("", ManifestError::EmptyName),
            (&long, ManifestError::NameTooLong(MAX_FILE_NAME_LEN + 1)),
            (".p2p-sync/config.toml", ManifestError::ReservedPath),
            (".p2p-sync", ManifestError::ReservedPath),
        ];
        for (name, err) in cases {
            assert_eq!(validate_file_name(name), Err(err.clone()), "{name:?}");
            let m = FileManifest {
                file_name: name.to_string(),
                total_size: 0,
                chunks: vec![],
            };
            assert_eq!(m.validate(), Err(err), "{name:?}");
        }
        for name in [
            "a",
            "a/b",
            "a.b/c.d",
            ".hidden",
            "a b",
            "ünïcode/文件",
            ".p2p-sync-not/x",
        ] {
            validate_file_name(name).unwrap_or_else(|e| panic!("{name:?}: {e}"));
        }
        validate_file_name(&"a".repeat(MAX_FILE_NAME_LEN)).unwrap();
    }

    #[test]
    fn confined_path_stays_inside_and_rejects_escapes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();

        let p = confined_path(root, "sub/new/file.txt").unwrap();
        assert!(p.starts_with(root.canonicalize().unwrap()));
        assert!(p.ends_with("sub/new/file.txt"));

        assert_eq!(
            confined_path(root, "../x"),
            Err(ManifestError::BadPath("has a '..' component"))
        );
        assert_eq!(
            confined_path(root, "/etc/passwd"),
            Err(ManifestError::BadPath("is absolute"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn confined_path_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        assert_eq!(
            confined_path(root, "link/file.txt"),
            Err(ManifestError::OutsideDocument)
        );
        // A symlink that stays inside is fine.
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("inner")).unwrap();
        confined_path(root, "inner/file.txt").unwrap();
    }
}
