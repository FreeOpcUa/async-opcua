// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! Dynamic TLS/X.509 context reloading utilities.
//! Allows saving renewed certificate and key pairs, and reloading them into active memory.

use crate::{CertificateStore, PrivateKey, X509};
use std::fs;

/// Reloads the certificate and private key from the store's configured paths on disk.
pub fn reload_store_from_disk(store: &CertificateStore) -> Result<(X509, PrivateKey), String> {
    let cert = store.read_own_cert()?;
    let pkey = store.read_own_pkey()?;
    Ok((cert, pkey))
}

/// Helper to write new certificate (DER format) and private key (PEM format) to the store's paths on disk.
pub fn save_new_credentials(
    store: &CertificateStore,
    cert_der: &[u8],
    pkey_pem: &[u8],
) -> Result<(), String> {
    let cert_path = store.own_certificate_path();
    let pkey_path = store.own_private_key_path();

    // Ensure parent directories exist
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create cert parent dir: {e}"))?;
    }
    if let Some(parent) = pkey_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create pkey parent dir: {e}"))?;
    }

    // Write certificate
    fs::write(&cert_path, cert_der).map_err(|e| format!("Failed to write cert file: {e}"))?;

    // Write private key
    fs::write(&pkey_path, pkey_pem).map_err(|e| format!("Failed to write pkey file: {e}"))?;

    Ok(())
}
