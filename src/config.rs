//! Everything that lives under `<vault>/.vault/`: the directory layout, the
//! config file, the key files and the list of known peers.
//!
//! Key files and the config are written with mode 0600 (SEC-5) through a
//! temporary file and a rename, so a crash never leaves a half-written file.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use iroh::{EndpointAddr, SecretKey};
use iroh_docs::{Capability, NamespaceId};
use serde::{Deserialize, Serialize};

/// Name of the directory that holds vault state inside the synced folder.
pub const DOT_DIR: &str = ".vault";

/// Paths inside a vault directory.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// The synced folder.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<vault>/.vault`.
    pub fn dot(&self) -> PathBuf {
        self.root.join(DOT_DIR)
    }

    pub fn config(&self) -> PathBuf {
        self.dot().join("config.json")
    }

    /// This device's iroh endpoint secret key (hex, 0600).
    pub fn endpoint_key(&self) -> PathBuf {
        self.dot().join("endpoint.key")
    }

    /// The vault capability: namespace secret (write) or id (read), hex, 0600.
    pub fn vault_key(&self) -> PathBuf {
        self.dot().join("vault.key")
    }

    /// Known peers with their last known addresses (JSON).
    pub fn peers(&self) -> PathBuf {
        self.dot().join("peers.json")
    }

    /// This device's last bound addresses, written by `run` for `invite`.
    pub fn own_addr(&self) -> PathBuf {
        self.dot().join("addr.json")
    }

    /// Advisory lock held by the process that has the stores open.
    pub fn lock(&self) -> PathBuf {
        self.dot().join("lock")
    }

    pub fn blobs(&self) -> PathBuf {
        self.dot().join("blobs")
    }

    pub fn docs(&self) -> PathBuf {
        self.dot().join("docs")
    }

    /// Path to content hash of what this device last wrote to or read from disk.
    pub fn state(&self) -> PathBuf {
        self.dot().join("state.json")
    }

    pub fn conflicts(&self) -> PathBuf {
        self.dot().join("conflicts")
    }

    pub fn tmp(&self) -> PathBuf {
        self.dot().join("tmp")
    }

    /// True once `init` or `join` has written the config.
    pub fn is_initialized(&self) -> bool {
        self.config().is_file()
    }

    /// Create every directory the stores and the engine need.
    pub fn create_dirs(&self) -> Result<()> {
        for dir in [
            self.dot(),
            self.blobs(),
            self.docs(),
            self.conflicts(),
            self.tmp(),
        ] {
            fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }
}

/// `config.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// The vault id: the docs namespace id, hex.
    pub vault_id: String,
    /// Whether this device holds the namespace secret and may publish.
    pub write: bool,
}

impl Config {
    pub fn new(id: NamespaceId, write: bool) -> Self {
        Self {
            vault_id: id.to_string(),
            write,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        write_private(path, text.as_bytes())
    }

    pub fn namespace_id(&self) -> Result<NamespaceId> {
        Ok(NamespaceId::from(&parse_hex32(&self.vault_id)?))
    }
}

/// Load the endpoint secret key, generating and storing a new one if the file
/// does not exist yet (`whoami` on a fresh device).
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
    if path.is_file() {
        return load_secret_key(path);
    }
    let key = SecretKey::generate();
    write_private(path, hex(&key.to_bytes()).as_bytes())?;
    Ok(key)
}

pub fn load_secret_key(path: &Path) -> Result<SecretKey> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(SecretKey::from_bytes(&parse_hex32(text.trim())?))
}

/// Store the vault capability as `<kind byte><32 bytes>` in hex.
pub fn save_capability(path: &Path, capability: &Capability) -> Result<()> {
    let (kind, bytes) = capability.raw();
    let mut raw = Vec::with_capacity(33);
    raw.push(kind);
    raw.extend_from_slice(&bytes);
    write_private(path, hex(&raw).as_bytes())
}

pub fn load_capability(path: &Path) -> Result<Capability> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.trim().as_bytes())
        .context("vault key is not hex")?;
    if raw.len() != 33 {
        bail!("vault key has {} bytes, expected 33", raw.len());
    }
    let bytes: [u8; 32] = raw[1..].try_into().expect("length checked");
    Capability::from_raw(raw[0], &bytes)
}

/// Known peers. A missing file means no peers.
pub fn load_peers(path: &Path) -> Result<Vec<EndpointAddr>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn save_peers(path: &Path, peers: &[EndpointAddr]) -> Result<()> {
    write_private(path, serde_json::to_string_pretty(peers)?.as_bytes())
}

/// Merge `addr` into `peers`: one entry per endpoint id, addresses unioned.
/// Returns true if anything changed.
pub fn merge_peer(peers: &mut Vec<EndpointAddr>, addr: EndpointAddr) -> bool {
    match peers.iter_mut().find(|p| p.id == addr.id) {
        Some(existing) => {
            let before = existing.addrs.len();
            existing.addrs.extend(addr.addrs);
            existing.addrs.len() != before
        }
        None => {
            peers.push(addr);
            true
        }
    }
}

pub fn save_own_addr(path: &Path, addr: &EndpointAddr) -> Result<()> {
    write_private(path, serde_json::to_string_pretty(addr)?.as_bytes())
}

pub fn load_own_addr(path: &Path) -> Result<Option<EndpointAddr>> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(serde_json::from_str(&text)?))
}

/// Write `contents` to `path` with mode 0600, atomically.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("private")
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

pub fn parse_hex32(text: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.trim().as_bytes())
        .context("not hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_round_trip_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.key");
        let key = load_or_create_secret_key(&path).unwrap();
        let again = load_or_create_secret_key(&path).unwrap();
        assert_eq!(key.to_bytes(), again.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn capability_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        let write = Capability::from_raw(1, &[9u8; 32]).unwrap();
        let id = write.id();
        save_capability(&path, &write).unwrap();
        let loaded = load_capability(&path).unwrap();
        assert_eq!(loaded.id(), id);
        assert!(matches!(loaded, Capability::Write(_)));
        let read = Capability::Read(id);
        save_capability(&path, &read).unwrap();
        let loaded = load_capability(&path).unwrap();
        assert!(matches!(loaded, Capability::Read(_)));
        assert_eq!(loaded.id(), id);
    }

    #[test]
    fn config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let id = NamespaceId::from(&[7u8; 32]);
        let config = Config::new(id, true);
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded, config);
        assert_eq!(loaded.namespace_id().unwrap(), id);
    }

    #[test]
    fn peers_merge_by_id() {
        let a = SecretKey::from_bytes(&[1u8; 32]).public();
        let b = SecretKey::from_bytes(&[2u8; 32]).public();
        let mut peers = Vec::new();
        assert!(merge_peer(
            &mut peers,
            EndpointAddr::new(a).with_ip_addr("127.0.0.1:1000".parse().unwrap())
        ));
        assert!(!merge_peer(
            &mut peers,
            EndpointAddr::new(a).with_ip_addr("127.0.0.1:1000".parse().unwrap())
        ));
        assert!(merge_peer(
            &mut peers,
            EndpointAddr::new(a).with_ip_addr("127.0.0.1:1001".parse().unwrap())
        ));
        assert!(merge_peer(&mut peers, EndpointAddr::new(b)));
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].addrs.len(), 2);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        assert!(load_peers(&path).unwrap().is_empty());
        save_peers(&path, &peers).unwrap();
        assert_eq!(load_peers(&path).unwrap(), peers);
    }
}
