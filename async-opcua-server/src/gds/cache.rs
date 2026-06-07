//! Filesystem cache for GDS certificate credentials.

use std::{
    fs,
    path::{Path, PathBuf},
};

const CACHE_DIR: &str = "cache";
const GDS_DIR: &str = "gds";
const CERTIFICATE_FILE: &str = "certificate.der";
const PRIVATE_KEY_FILE: &str = "private_key.der";
const TRUST_LIST_FILE: &str = "trust_list.der";

/// DER-encoded GDS credential material cached after renewal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsCachedCredentials {
    /// DER-encoded application certificate.
    pub certificate_der: Vec<u8>,
    /// DER-encoded private key.
    pub private_key_der: Vec<u8>,
    /// DER-encoded trust list.
    pub trust_list_der: Vec<u8>,
}

/// Saves GDS credential material under the supplied PKI directory.
///
/// # Errors
///
/// Returns an error if the cache directory cannot be created, or if any cache
/// file cannot be written.
pub fn save_cached_credentials(
    pki_dir: &Path,
    cert_der: &[u8],
    pkey_der: &[u8],
    trust_list_der: &[u8],
) -> Result<(), String> {
    let paths = CachePaths::new(pki_dir);

    fs::create_dir_all(&paths.dir).map_err(|e| {
        format!(
            "failed to create GDS credential cache directory {}: {e}",
            paths.dir.display()
        )
    })?;

    write_cached_file(&paths.certificate, "certificate DER", cert_der)?;
    write_cached_private_key(&paths.private_key, pkey_der)?;
    write_cached_file(&paths.trust_list, "trust list DER", trust_list_der)
}

/// Loads cached GDS credential material from the supplied PKI directory.
///
/// Returns `Ok(None)` when no cache files exist.
///
/// # Errors
///
/// Returns an error if only part of the cache exists, or if any cache file
/// cannot be read.
pub fn load_cached_credentials(pki_dir: &Path) -> Result<Option<GdsCachedCredentials>, String> {
    let paths = CachePaths::new(pki_dir);
    let files = [
        (CERTIFICATE_FILE, &paths.certificate),
        (PRIVATE_KEY_FILE, &paths.private_key),
        (TRUST_LIST_FILE, &paths.trust_list),
    ];

    if files.iter().all(|(_, path)| !path.exists()) {
        return Ok(None);
    }

    let missing = files
        .iter()
        .filter_map(|(name, path)| (!path.exists()).then_some(*name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "cached GDS credentials are incomplete; missing {}",
            missing.join(", ")
        ));
    }

    Ok(Some(GdsCachedCredentials {
        certificate_der: read_cached_file(&paths.certificate, "certificate DER")?,
        private_key_der: read_cached_file(&paths.private_key, "private key DER")?,
        trust_list_der: read_cached_file(&paths.trust_list, "trust list DER")?,
    }))
}

struct CachePaths {
    dir: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
    trust_list: PathBuf,
}

impl CachePaths {
    fn new(pki_dir: &Path) -> Self {
        let dir = pki_dir.join(GDS_DIR).join(CACHE_DIR);
        Self {
            certificate: dir.join(CERTIFICATE_FILE),
            private_key: dir.join(PRIVATE_KEY_FILE),
            trust_list: dir.join(TRUST_LIST_FILE),
            dir,
        }
    }
}

fn write_cached_file(path: &Path, label: &str, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| {
        format!(
            "failed to write cached {label} file {}: {e}",
            path.display()
        )
    })
}

fn write_cached_private_key(path: &Path, pkey_der: &[u8]) -> Result<(), String> {
    write_cached_file(path, "private key DER", pkey_der)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            format!(
                "failed to set private key cache permissions {}: {e}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn read_cached_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path)
        .map_err(|e| format!("failed to read cached {label} file {}: {e}", path.display()))
}
