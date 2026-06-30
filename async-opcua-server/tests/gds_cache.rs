//! Integration tests for GDS cached credential storage.

use std::{
    fs,
    path::{Path, PathBuf},
};

use opcua_server::gds::cache::{
    load_cached_credentials, save_cached_credentials, GdsCachedCredentials,
};

struct TempPki {
    path: PathBuf,
}

impl TempPki {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("async-opcua-server-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temporary pki dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn cached_file_path(pki_dir: &Path, file_name: &str) -> PathBuf {
    pki_dir.join("gds").join("cache").join(file_name)
}

fn make_private_key_read_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .expect("private key cache file should be made read-only");
    }

    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .expect("private key cache file metadata should be readable")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
            .expect("private key cache file should be made read-only");
    }
}

fn make_private_key_writable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("private key cache file should be made writable");
    }

    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .expect("private key cache file metadata should be readable")
            .permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)
            .expect("private key cache file should be made writable");
    }
}

#[test]
fn save_and_load_cached_credentials_preserves_der_blobs() {
    let temp_pki = TempPki::new("gds-cache-round-trip");

    save_cached_credentials(
        temp_pki.path(),
        b"certificate-der",
        b"private-key-der",
        b"trust-list-der",
    )
    .expect("cached credentials should be saved");

    let cached = load_cached_credentials(temp_pki.path())
        .expect("cached credentials should load")
        .expect("cache should exist");

    assert_eq!(
        cached,
        GdsCachedCredentials {
            certificate_der: b"certificate-der".to_vec(),
            private_key_der: b"private-key-der".to_vec(),
            trust_list_der: b"trust-list-der".to_vec(),
        }
    );
}

#[test]
fn load_cached_credentials_returns_none_when_cache_is_absent() {
    let temp_pki = TempPki::new("gds-cache-missing");

    let cached = load_cached_credentials(temp_pki.path()).expect("missing cache should not error");

    assert_eq!(cached, None);
}

#[test]
fn load_cached_credentials_errors_when_cache_is_partial() {
    let temp_pki = TempPki::new("gds-cache-partial");
    let cache_dir = temp_pki.path().join("gds").join("cache");
    fs::create_dir_all(&cache_dir).expect("cache dir should be created");
    fs::write(cache_dir.join("certificate.der"), b"certificate-der")
        .expect("certificate cache file should be written");

    let err = load_cached_credentials(temp_pki.path())
        .expect_err("partial cache should be reported as corrupt");

    assert!(err.contains("private_key.der"), "{err}");
}

#[test]
fn failed_private_key_replacement_preserves_previous_cached_credential_pair() {
    let temp_pki = TempPki::new("gds-cache-atomic-private-key-failure");
    let previous = GdsCachedCredentials {
        certificate_der: b"previous-certificate-der".to_vec(),
        private_key_der: b"previous-private-key-der".to_vec(),
        trust_list_der: b"previous-trust-list-der".to_vec(),
    };

    save_cached_credentials(
        temp_pki.path(),
        &previous.certificate_der,
        &previous.private_key_der,
        &previous.trust_list_der,
    )
    .expect("previous cached credentials should be saved");

    let private_key_path = cached_file_path(temp_pki.path(), "private_key.der");
    make_private_key_read_only(&private_key_path);

    let err = save_cached_credentials(
        temp_pki.path(),
        b"replacement-certificate-der",
        b"replacement-private-key-der",
        b"replacement-trust-list-der",
    )
    .expect_err("private key replacement write should fail");

    make_private_key_writable(&private_key_path);

    assert!(err.contains("private key DER"), "{err}");

    let cached = load_cached_credentials(temp_pki.path())
        .expect("cached credentials should remain readable")
        .expect("previous cached credentials should still exist");

    assert_eq!(cached, previous);
}
