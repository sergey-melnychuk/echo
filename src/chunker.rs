//! Chunker and assembler (SPEC.md section 5.2).
//!
//! A file that is not text is split with FastCDC into content-defined chunks,
//! each stored as its own blob; the manifest is a `HashSeq` blob of the chunk
//! hashes in order. A changed file therefore transfers only its new chunks.
//!
//! Export is two-step (NOTES.md, stage 0): fetch the manifest as a raw blob
//! first, then let the downloader fetch the children that are missing. The
//! missing set cannot be computed while the root is absent, and a one-step
//! download of the hash sequence transfers every chunk again.

use std::io::{BufReader, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use fastcdc::v2020::StreamCDC;
use iroh::EndpointId;
use iroh_blobs::api::downloader::Downloader;
use iroh_blobs::api::Store as BlobStore;
use iroh_blobs::hashseq::HashSeq;
use iroh_blobs::{BlobFormat, Hash, HashAndFormat};
use tokio::sync::mpsc;

/// FastCDC parameters (SPEC.md section 4): min 16 KiB, average 64 KiB, max
/// 256 KiB. The maximum bounds how many chunks one edit can touch.
pub const MIN_CHUNK: usize = 16 << 10;
pub const AVG_CHUNK: usize = 64 << 10;
pub const MAX_CHUNK: usize = 256 << 10;

/// The named tag that protects a manifest and, through it, its chunks.
pub fn manifest_tag(manifest: &Hash) -> String {
    format!("manifest/{}", manifest.to_hex())
}

/// Stream a file through FastCDC, add each chunk and the `HashSeq` to the
/// blob store, and return the manifest hash and the total size.
///
/// Chunking runs on a blocking thread and hands chunks over a small channel,
/// so memory stays bounded and the runtime is never blocked on file reads.
pub async fn import_blob_file(store: &BlobStore, path: &Path) -> Result<(Hash, u64)> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let (tx, mut rx) = mpsc::channel::<std::io::Result<Vec<u8>>>(4);
    let producer = tokio::task::spawn_blocking(move || {
        let chunker = StreamCDC::new(BufReader::new(file), MIN_CHUNK, AVG_CHUNK, MAX_CHUNK);
        for chunk in chunker {
            let item = chunk
                .map(|c| c.data)
                .map_err(|err| std::io::Error::other(err.to_string()));
            if tx.blocking_send(item).is_err() {
                break;
            }
        }
    });
    let mut hashes = Vec::new();
    let mut temp_tags = Vec::new();
    let mut size = 0u64;
    while let Some(chunk) = rx.recv().await {
        let data = chunk.with_context(|| format!("chunking {}", path.display()))?;
        size += data.len() as u64;
        let tag = store.add_bytes(data).temp_tag().await?;
        hashes.push(tag.hash());
        temp_tags.push(tag);
    }
    producer.await.context("chunker thread")?;
    let seq: HashSeq = hashes.iter().copied().collect();
    let manifest = store
        .add_bytes_with_opts((seq.into_inner(), BlobFormat::HashSeq))
        .temp_tag()
        .await?;
    let hash = manifest.hash();
    store
        .tags()
        .set(manifest_tag(&hash), HashAndFormat::hash_seq(hash))
        .await?;
    drop(temp_tags);
    drop(manifest);
    Ok((hash, size))
}

/// Make the manifest and every chunk present locally, downloading what is
/// missing from `peers`.
pub async fn ensure_blob_local(
    store: &BlobStore,
    downloader: &Downloader,
    manifest: Hash,
    peers: &[EndpointId],
) -> Result<()> {
    if !store.has(manifest).await? {
        if peers.is_empty() {
            bail!(
                "manifest {} is not local and no peer is known to fetch it from",
                manifest.fmt_short()
            );
        }
        downloader
            .download(manifest, peers.to_vec())
            .await
            .map_err(|err| anyhow!("downloading manifest {}: {err}", manifest.fmt_short()))?;
    }
    let local = store
        .remote()
        .local(HashAndFormat::hash_seq(manifest))
        .await?;
    if !local.is_complete() {
        if peers.is_empty() {
            bail!(
                "chunks of {} are missing and no peer is known to fetch them from",
                manifest.fmt_short()
            );
        }
        downloader
            .download(HashAndFormat::hash_seq(manifest), peers.to_vec())
            .await
            .map_err(|err| anyhow!("downloading chunks of {}: {err}", manifest.fmt_short()))?;
    }
    Ok(())
}

/// The chunk hashes of a manifest that is present locally.
pub async fn chunk_hashes(store: &BlobStore, manifest: Hash) -> Result<Vec<Hash>> {
    let bytes = store
        .get_bytes(manifest)
        .await
        .with_context(|| format!("reading manifest {}", manifest.fmt_short()))?;
    let seq = HashSeq::new(bytes)
        .ok_or_else(|| anyhow!("manifest {} is not a hash sequence", manifest.fmt_short()))?;
    Ok(seq.iter().collect())
}

/// Write the blob's bytes to `tmp`, then rename it to `dest`. Returns the
/// blake3 hash of the written bytes and their count.
pub async fn assemble_to(
    store: &BlobStore,
    manifest: Hash,
    tmp: &Path,
    dest: &Path,
) -> Result<(String, u64)> {
    let chunks = chunk_hashes(store, manifest).await?;
    let mut file =
        std::fs::File::create(tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    for chunk in chunks {
        let bytes = store
            .get_bytes(chunk)
            .await
            .with_context(|| format!("reading chunk {}", chunk.fmt_short()))?;
        hasher.update(&bytes);
        size += bytes.len() as u64;
        file.write_all(&bytes)?;
    }
    file.sync_all()?;
    drop(file);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::rename(tmp, dest).with_context(|| format!("renaming into {}", dest.display()))?;
    Ok((
        data_encoding::HEXLOWER.encode(hasher.finalize().as_bytes()),
        size,
    ))
}

/// Ensure the manifest and all chunks are present (downloading from `peers`),
/// then write the file to `tmp` and rename it into `dest`.
pub async fn export_blob_file(
    store: &BlobStore,
    downloader: &Downloader,
    manifest: Hash,
    peers: &[EndpointId],
    tmp: &Path,
    dest: &Path,
) -> Result<(String, u64)> {
    ensure_blob_local(store, downloader, manifest, peers).await?;
    assemble_to(store, manifest, tmp, dest).await
}

/// The whole blob in memory, for tests and small files.
pub async fn blob_bytes(store: &BlobStore, manifest: Hash) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in chunk_hashes(store, manifest).await? {
        out.extend_from_slice(&store.get_bytes(chunk).await?);
    }
    Ok(out)
}

/// Read `path` in full through the chunker without storing anything; the
/// chunk count, for tests and diagnostics.
pub fn count_chunks(path: &Path) -> Result<usize> {
    let file = std::fs::File::open(path)?;
    let mut n = 0;
    for chunk in StreamCDC::new(BufReader::new(file), MIN_CHUNK, AVG_CHUNK, MAX_CHUNK) {
        chunk.map_err(|err| anyhow!("{err}"))?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_blobs::store::mem::MemStore;

    fn random_bytes(size: usize, mut seed: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(size + 8);
        while data.len() < size {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            data.extend_from_slice(&seed.to_le_bytes());
        }
        data.truncate(size);
        data
    }

    #[tokio::test]
    async fn import_and_assemble_round_trip_and_delta() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemStore::new();
        let data = random_bytes(3 << 20, 7);
        let path = dir.path().join("f.bin");
        std::fs::write(&path, &data).unwrap();
        let (manifest, size) = import_blob_file(&store, &path).await.unwrap();
        assert_eq!(size, data.len() as u64);
        let chunks = chunk_hashes(&store, manifest).await.unwrap();
        assert!(chunks.len() >= 8, "{} chunks", chunks.len());
        assert_eq!(blob_bytes(&store, manifest).await.unwrap(), data);
        let tmp = dir.path().join("tmp");
        let dest = dir.path().join("out/f.bin");
        let (hash, written) = assemble_to(&store, manifest, &tmp, &dest).await.unwrap();
        assert_eq!(written, size);
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(
            hash,
            data_encoding::HEXLOWER.encode(blake3::hash(&data).as_bytes())
        );
        assert!(!tmp.exists());

        // One byte changes one chunk.
        let mut edited = data.clone();
        edited[data.len() / 2] ^= 0xff;
        std::fs::write(&path, &edited).unwrap();
        let (manifest2, _) = import_blob_file(&store, &path).await.unwrap();
        assert_ne!(manifest2, manifest);
        let chunks2 = chunk_hashes(&store, manifest2).await.unwrap();
        let new: Vec<_> = chunks2.iter().filter(|c| !chunks.contains(c)).collect();
        assert_eq!(new.len(), 1);
        assert_eq!(chunks2.len(), chunks.len());
        assert_eq!(count_chunks(&path).unwrap(), chunks2.len());
        // Both manifests are tagged.
        assert!(store
            .tags()
            .get(manifest_tag(&manifest))
            .await
            .unwrap()
            .is_some());
        assert!(store
            .tags()
            .get(manifest_tag(&manifest2))
            .await
            .unwrap()
            .is_some());
        // An empty file is a manifest with no chunks.
        std::fs::write(&path, b"").unwrap();
        let (empty, size) = import_blob_file(&store, &path).await.unwrap();
        assert_eq!(size, 0);
        assert!(chunk_hashes(&store, empty).await.unwrap().is_empty());
        assert_eq!(blob_bytes(&store, empty).await.unwrap(), b"");
    }
}
