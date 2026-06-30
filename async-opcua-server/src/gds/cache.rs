//! Filesystem cache for GDS certificate credentials.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const CACHE_DIR: &str = "cache";
const GDS_DIR: &str = "gds";
const CERTIFICATE_FILE: &str = "certificate.der";
const PRIVATE_KEY_FILE: &str = "private_key.der";
const TRUST_LIST_FILE: &str = "trust_list.der";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    let file_specs = [
        CacheFileSpec {
            path: &paths.certificate,
            label: "certificate DER",
            bytes: cert_der,
            private: false,
        },
        CacheFileSpec {
            path: &paths.private_key,
            label: "private key DER",
            bytes: pkey_der,
            private: true,
        },
        CacheFileSpec {
            path: &paths.trust_list,
            label: "trust list DER",
            bytes: trust_list_der,
            private: false,
        },
    ];

    for spec in &file_specs {
        ensure_cached_file_replaceable(spec.path, spec.label)?;
    }

    let staged_files = prepare_cached_files(&file_specs)?;
    replace_cached_files(staged_files)
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

struct CacheFileSpec<'a> {
    path: &'a Path,
    label: &'static str,
    bytes: &'a [u8],
    private: bool,
}

struct StagedCachedFile {
    target_path: PathBuf,
    temp_path: PathBuf,
    label: &'static str,
}

struct CachedFileBackup {
    target_path: PathBuf,
    backup_path: PathBuf,
    label: &'static str,
}

fn ensure_cached_file_replaceable(path: &Path, label: &str) -> Result<(), String> {
    match OpenOptions::new().write(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "failed to open cached {label} file {} for replacement: {e}",
            path.display()
        )),
    }
}

fn prepare_cached_files(specs: &[CacheFileSpec<'_>]) -> Result<Vec<StagedCachedFile>, String> {
    let mut staged_files = Vec::with_capacity(specs.len());

    for spec in specs {
        match write_staged_cached_file(spec) {
            Ok(staged_file) => staged_files.push(staged_file),
            Err(e) => {
                cleanup_staged_files(&staged_files);
                return Err(e);
            }
        }
    }

    Ok(staged_files)
}

fn write_staged_cached_file(spec: &CacheFileSpec<'_>) -> Result<StagedCachedFile, String> {
    let temp_path = unique_sidecar_path(spec.path, "tmp");

    let result = (|| {
        let mut file = create_staged_file(&temp_path, spec.label, spec.private)?;
        file.write_all(spec.bytes).map_err(|e| {
            format!(
                "failed to write temporary cached {} file {}: {e}",
                spec.label,
                temp_path.display()
            )
        })?;
        file.sync_all().map_err(|e| {
            format!(
                "failed to sync temporary cached {} file {}: {e}",
                spec.label,
                temp_path.display()
            )
        })?;

        #[cfg(unix)]
        if spec.private {
            set_private_key_permissions(&temp_path)?;
        }

        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    Ok(StagedCachedFile {
        target_path: spec.path.to_path_buf(),
        temp_path,
        label: spec.label,
    })
}

fn create_staged_file(path: &Path, label: &str, private: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        if private {
            options.mode(0o600);
        }
    }

    options.open(path).map_err(|e| {
        format!(
            "failed to create temporary cached {label} file {}: {e}",
            path.display()
        )
    })
}

fn replace_cached_files(staged_files: Vec<StagedCachedFile>) -> Result<(), String> {
    let mut backups = Vec::with_capacity(staged_files.len());

    for staged_file in &staged_files {
        if !staged_file.target_path.exists() {
            continue;
        }

        let backup_path = unique_sidecar_path(&staged_file.target_path, "bak");
        if let Err(e) = fs::rename(&staged_file.target_path, &backup_path) {
            let error = format!(
                "failed to prepare cached {} file {} for replacement: {e}",
                staged_file.label,
                staged_file.target_path.display()
            );
            let rollback_errors = restore_cached_file_backups(&backups);
            cleanup_staged_files(&staged_files);
            return Err(with_rollback_errors(error, rollback_errors));
        }

        backups.push(CachedFileBackup {
            target_path: staged_file.target_path.clone(),
            backup_path,
            label: staged_file.label,
        });
    }

    for (installed_count, staged_file) in staged_files.iter().enumerate() {
        if let Err(e) = fs::rename(&staged_file.temp_path, &staged_file.target_path) {
            let error = format!(
                "failed to replace cached {} file {}: {e}",
                staged_file.label,
                staged_file.target_path.display()
            );
            let rollback_errors =
                rollback_cached_file_replacement(&staged_files, installed_count, &backups);
            return Err(with_rollback_errors(error, rollback_errors));
        }
    }

    for backup in backups {
        let _ = fs::remove_file(backup.backup_path);
    }

    Ok(())
}

fn rollback_cached_file_replacement(
    staged_files: &[StagedCachedFile],
    installed_count: usize,
    backups: &[CachedFileBackup],
) -> Vec<String> {
    let mut errors = Vec::new();

    for staged_file in staged_files.iter().take(installed_count) {
        if let Err(e) = remove_file_if_exists(&staged_file.target_path) {
            errors.push(format!(
                "failed to remove partially replaced cached {} file {}: {e}",
                staged_file.label,
                staged_file.target_path.display()
            ));
        }
    }

    errors.extend(restore_cached_file_backups(backups));

    for staged_file in staged_files.iter().skip(installed_count) {
        if let Err(e) = remove_file_if_exists(&staged_file.temp_path) {
            errors.push(format!(
                "failed to remove staged cached {} file {}: {e}",
                staged_file.label,
                staged_file.temp_path.display()
            ));
        }
    }

    errors
}

fn restore_cached_file_backups(backups: &[CachedFileBackup]) -> Vec<String> {
    let mut errors = Vec::new();

    for backup in backups.iter().rev() {
        if let Err(e) = fs::rename(&backup.backup_path, &backup.target_path) {
            errors.push(format!(
                "failed to restore cached {} file {}: {e}",
                backup.label,
                backup.target_path.display()
            ));
        }
    }

    errors
}

fn remove_file_if_exists(path: &Path) -> Result<(), io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn cleanup_staged_files(staged_files: &[StagedCachedFile]) {
    for staged_file in staged_files {
        let _ = fs::remove_file(&staged_file.temp_path);
    }
}

fn with_rollback_errors(mut error: String, rollback_errors: Vec<String>) -> String {
    if !rollback_errors.is_empty() {
        error.push_str("; additionally failed to restore previous cache state: ");
        error.push_str(&rollback_errors.join("; "));
    }
    error
}

fn unique_sidecar_path(path: &Path, tag: &str) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cache-file");

    path.with_file_name(format!(
        "{file_name}.{tag}.{}.{}",
        std::process::id(),
        counter
    ))
}

#[cfg(unix)]
fn set_private_key_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        format!(
            "failed to set private key cache permissions {}: {e}",
            path.display()
        )
    })
}

fn read_cached_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path)
        .map_err(|e| format!("failed to read cached {label} file {}: {e}", path.display()))
}
