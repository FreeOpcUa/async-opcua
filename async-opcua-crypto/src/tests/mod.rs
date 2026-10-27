use tempdir::TempDir;

use crate::CertificateStore;

use crate::{
    x509::{AlternateNames, X509Data, X509},
    PrivateKey,
};

const APPLICATION_URI: &str = "urn:testapplication";
const APPLICATION_HOSTNAME: &str = "testhost";

fn make_certificate_store() -> (TempDir, CertificateStore) {
    let tmp_dir = TempDir::new("pki").unwrap();
    let cert_store = CertificateStore::new(tmp_dir.path());
    assert!(cert_store.ensure_pki_path().is_ok());
    (tmp_dir, cert_store)
}

fn make_test_cert(key_size: u32) -> (X509, PrivateKey) {
    let mut alt_host_names = AlternateNames::new();
    alt_host_names.add_uri(APPLICATION_URI);
    alt_host_names.add_dns("foo");
    alt_host_names.add_dns("foo2");
    alt_host_names.add_dns(APPLICATION_HOSTNAME);
    alt_host_names.add_dns("foo3");
    let args = X509Data {
        key_size,
        common_name: "x".to_string(),
        organization: "x.org".to_string(),
        organizational_unit: "x.org ops".to_string(),
        country: "EN".to_string(),
        state: "London".to_string(),
        alt_host_names,
        certificate_duration_days: 60,
    };
    let cert = X509::cert_and_pkey(&args);
    cert.unwrap()
}

fn make_test_cert_1024() -> (X509, PrivateKey) {
    make_test_cert(1024)
}

fn make_test_cert_2048() -> (X509, PrivateKey) {
    make_test_cert(2048)
}

mod authentication;
mod crypto;
mod security_policy;
