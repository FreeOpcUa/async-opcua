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
