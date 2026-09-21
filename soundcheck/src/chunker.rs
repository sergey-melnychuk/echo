//! FastCDC content-defined chunking. Returns a manifest plus chunk bytes.
//!
//! Parameters are fixed by section 5: 8 KiB minimum, 16 KiB average, 32 KiB
//! maximum, `fastcdc::v2020::FastCDC`. Files are chunked whole in memory and
//! capped at [`MAX_FILE_SIZE`].

use crate::crypto::chunk_hash;
use crate::manifest::{
    validate_file_name, ChunkRef, FileManifest, ManifestError, AVG_CHUNK, MAX_CHUNK, MAX_CHUNKS,
    MAX_FILE_SIZE, MIN_CHUNK,
};
use fastcdc::v2020::FastCDC;

/// The result of chunking one file: its manifest and the bytes of every
/// chunk, in the same order as `manifest.chunks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedPayload {
    /// Validated manifest for the data.
    pub manifest: FileManifest,
    /// `chunks[i]` holds the bytes of `manifest.chunks[i]`.
    pub chunks: Vec<Vec<u8>>,
}

impl ChunkedPayload {
    /// Chunk bytes paired with their hashes, in file order. A chunk that
    /// repeats within the file appears once per occurrence.
    pub fn iter(&self) -> impl Iterator<Item = (&ChunkRef, &Vec<u8>)> {
        self.manifest.chunks.iter().zip(self.chunks.iter())
    }
}

/// Chunk `data` for the file called `file_name`.
///
/// Returns a manifest that passes [`FileManifest::validate`]. An empty file
/// yields zero chunks; a file smaller than the minimum chunk yields one.
pub fn chunk_bytes(file_name: &str, data: &[u8]) -> Result<ChunkedPayload, ManifestError> {
    validate_file_name(file_name)?;
    let total_size = data.len() as u64;
    if total_size > MAX_FILE_SIZE {
        return Err(ManifestError::TooLarge(total_size));
    }
    let mut refs = Vec::new();
    let mut chunks = Vec::new();
    if !data.is_empty() {
        for c in FastCDC::new(
            data,
            MIN_CHUNK as usize,
            AVG_CHUNK as usize,
            MAX_CHUNK as usize,
        ) {
            let bytes = &data[c.offset..c.offset + c.length];
            let length = u32::try_from(bytes.len())
                .ok()
                .filter(|l| *l >= 1 && *l <= MAX_CHUNK)
                .ok_or(ManifestError::BadChunkLength {
                    index: refs.len(),
                    length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                })?;
            refs.push(ChunkRef {
                hash: chunk_hash(bytes),
                length,
            });
            chunks.push(bytes.to_vec());
            if refs.len() > MAX_CHUNKS {
                return Err(ManifestError::TooManyChunks(refs.len()));
            }
        }
    }
    let manifest = FileManifest {
        file_name: file_name.to_string(),
        total_size,
        chunks: refs,
    };
    manifest.validate()?;
    Ok(ChunkedPayload { manifest, chunks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::{Rng, SeedableRng};

    fn seeded(seed: u64, len: usize) -> Vec<u8> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut v = vec![0u8; len];
        rng.fill_bytes(&mut v);
        v
    }

    fn concat(p: &ChunkedPayload) -> Vec<u8> {
        p.chunks.iter().flatten().copied().collect()
    }

    #[test]
    fn chunks_concatenate_to_input_and_are_deterministic() {
        let data = seeded(1, 300_000);
        let a = chunk_bytes("f", &data).unwrap();
        let b = chunk_bytes("f", &data).unwrap();
        assert_eq!(a, b);
        assert_eq!(concat(&a), data);
        assert_eq!(a.manifest.total_size, data.len() as u64);
        assert!(a.manifest.chunks.len() > 1);
        for (r, bytes) in a.iter() {
            assert_eq!(r.length as usize, bytes.len());
            assert_eq!(r.hash, chunk_hash(bytes));
            assert!(r.length >= 1 && r.length <= MAX_CHUNK);
        }
        // All but the last chunk respect the minimum.
        for r in &a.manifest.chunks[..a.manifest.chunks.len() - 1] {
            assert!(r.length >= MIN_CHUNK, "{}", r.length);
        }
    }

    #[test]
    fn empty_file_has_zero_chunks() {
        let p = chunk_bytes("empty", &[]).unwrap();
        assert!(p.chunks.is_empty());
        assert!(p.manifest.chunks.is_empty());
        assert_eq!(p.manifest.total_size, 0);
        p.manifest.validate().unwrap();
    }

    #[test]
    fn small_file_is_one_chunk() {
        let data = seeded(2, 8_191);
        let p = chunk_bytes("small", &data).unwrap();
        assert_eq!(p.chunks.len(), 1);
        assert_eq!(p.chunks[0], data);
        let p = chunk_bytes("one", &[42]).unwrap();
        assert_eq!(p.chunks.len(), 1);
    }

    #[test]
    fn rejects_bad_name_and_oversize() {
        assert!(matches!(
            chunk_bytes("../x", b"data"),
            Err(ManifestError::BadPath(_))
        ));
        // Not allocating 256 MiB in a unit test: the size check runs before
        // chunking, so exercise it through validate on a synthetic manifest.
        let m = FileManifest {
            file_name: "x".into(),
            total_size: MAX_FILE_SIZE + 1,
            chunks: vec![],
        };
        assert_eq!(
            m.validate(),
            Err(ManifestError::TooLarge(MAX_FILE_SIZE + 1))
        );
    }

    /// Boundary stability: a one-byte change near the 1 MiB mark of a 4 MiB
    /// file leaves every chunk before it identical, and the chunks after the
    /// boundaries resynchronize identical too. No claim is made that no
    /// boundary moves.
    #[test]
    fn one_byte_change_only_affects_nearby_chunks() {
        let mut data = seeded(3, 4 << 20);
        let a = chunk_bytes("big", &data).unwrap();
        let pos = 1 << 20;
        data[pos] ^= 0xff;
        let b = chunk_bytes("big", &data).unwrap();

        // Prefix: every chunk that ends before the change is identical.
        let mut offset = 0usize;
        let mut prefix = 0;
        for (ra, rb) in a.manifest.chunks.iter().zip(b.manifest.chunks.iter()) {
            if offset + ra.length as usize > pos {
                break;
            }
            assert_eq!(ra, rb, "chunk {prefix} before the change differs");
            offset += ra.length as usize;
            prefix += 1;
        }
        assert!(
            prefix >= 20,
            "expected many unchanged prefix chunks, got {prefix}"
        );

        // Suffix: walk back from the end while chunks match, and require the
        // matching suffix to start within a few maximum chunks of the change.
        let mut ia = a.manifest.chunks.len();
        let mut ib = b.manifest.chunks.len();
        let mut suffix_start = a.manifest.total_size as usize;
        while ia > 0 && ib > 0 && a.manifest.chunks[ia - 1] == b.manifest.chunks[ib - 1] {
            ia -= 1;
            ib -= 1;
            suffix_start -= a.manifest.chunks[ia].length as usize;
        }
        assert!(
            suffix_start <= pos + 4 * MAX_CHUNK as usize,
            "boundaries did not resynchronize: suffix starts at {suffix_start}, change at {pos}"
        );
        assert!(
            suffix_start > pos - (MAX_CHUNK as usize),
            "suffix cannot start before the change"
        );

        // Differing middle: bounded on both sides.
        assert!(
            ia - prefix <= 4,
            "too many changed chunks in a: {}",
            ia - prefix
        );
        assert!(
            ib - prefix <= 5,
            "too many changed chunks in b: {}",
            ib - prefix
        );
    }

    #[test]
    fn repeated_content_yields_repeated_chunk_refs() {
        // Two copies of the same 200 KiB block: the interior chunks of the
        // second copy repeat hashes from the first.
        let block = seeded(4, 200_000);
        let mut data = block.clone();
        data.extend_from_slice(&block);
        let p = chunk_bytes("rep", &data).unwrap();
        let hashes: std::collections::HashSet<_> =
            p.manifest.chunks.iter().map(|c| c.hash).collect();
        assert!(hashes.len() < p.manifest.chunks.len());
    }

    fn arbitrary_data() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // Small, fully arbitrary data (shrinks well).
            proptest::collection::vec(any::<u8>(), 0..4096),
            // Larger seeded data up to 1 MiB, driven by an arbitrary seed and
            // length so proptest still controls both.
            (any::<u64>(), 0usize..=(1 << 20)).prop_map(|(seed, len)| seeded(seed, len)),
            // Low-entropy data, which stresses the maximum chunk size.
            (any::<u8>(), 0usize..=(1 << 18)).prop_map(|(b, len)| vec![b; len]),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn chunks_concat_to_input_and_manifest_validates(data in arbitrary_data()) {
            let p = chunk_bytes("prop/file", &data).unwrap();
            prop_assert_eq!(concat(&p), data.clone());
            prop_assert_eq!(p.manifest.total_size, data.len() as u64);
            p.manifest.validate().unwrap();
            for (r, bytes) in p.iter() {
                prop_assert_eq!(r.length as usize, bytes.len());
                prop_assert_eq!(r.hash, chunk_hash(bytes));
            }
        }
    }
}
