// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! Unified Global Discovery Server client helpers.

use super::{csr::GdsCsrClient, registration::GdsRegistrationClient};
use crate::Session;
use opcua_core::sync::RwLock;
use opcua_crypto::{gds_reload, CertificateStore};
use opcua_types::{ApplicationDescription, NodeId, StatusCode};
use std::fs;

/// Facade over the GDS registration and certificate signing helpers.
pub struct GdsClient {
    registration: GdsRegistrationClient,
    csr: GdsCsrClient,
}

impl Default for GdsClient {
    fn default() -> Self {
        Self {
            registration: GdsRegistrationClient::new(),
            csr: GdsCsrClient::new(),
        }
    }
}

impl GdsClient {
    /// Creates a GDS client using the standard GDS NodeIds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a GDS client from explicit helper clients.
    pub fn from_parts(registration: GdsRegistrationClient, csr: GdsCsrClient) -> Self {
        Self { registration, csr }
    }

    /// Returns the wrapped registration helper.
    pub fn registration(&self) -> &GdsRegistrationClient {
        &self.registration
    }

    /// Returns the wrapped CSR helper.
    pub fn csr(&self) -> &GdsCsrClient {
        &self.csr
    }

    /// Registers an application with the GDS directory service.
    pub async fn register_application(
        &self,
        session: &Session,
        application_description: ApplicationDescription,
    ) -> Result<NodeId, StatusCode> {
        self.registration
            .register_application(session, application_description)
            .await
    }

    /// Submits a DER-encoded CSR to the GDS and returns the signing request id.
    pub async fn request_signing_csr(
        &self,
        session: &Session,
        application_id: NodeId,
        certificate_group_id: NodeId,
        certificate_type_id: NodeId,
        csr_der: &[u8],
        regenerate_private_key: bool,
    ) -> Result<NodeId, StatusCode> {
        self.csr
            .start_signing_request(
                session,
                application_id,
                certificate_group_id,
                certificate_type_id,
                csr_der,
                regenerate_private_key,
            )
            .await
    }

    /// Polls the GDS for a completed signing request.
    pub async fn poll_signing_request(
        &self,
        session: &Session,
        application_id: NodeId,
        request_id: NodeId,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), StatusCode> {
        self.csr
            .finish_signing_request(session, application_id, request_id)
            .await
    }

    /// Persists renewed certificate material and verifies the store can reload it.
    pub fn apply_renewed_certificate(
        &self,
        certificate_store: &RwLock<CertificateStore>,
        certificate_der: &[u8],
        private_key_pem: Option<&[u8]>,
    ) -> Result<(), StatusCode> {
        let store = certificate_store.read();

        match private_key_pem {
            Some(private_key_pem) => {
                gds_reload::save_new_credentials(&store, certificate_der, private_key_pem)
            }
            None => write_certificate(&store, certificate_der),
        }
        .map_err(|_| StatusCode::BadSecurityChecksFailed)?;

        gds_reload::reload_store_from_disk(&store)
            .map(|_| ())
            .map_err(|_| StatusCode::BadSecurityChecksFailed)
    }
}

fn write_certificate(store: &CertificateStore, certificate_der: &[u8]) -> Result<(), String> {
    let cert_path = store.own_certificate_path();
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create certificate parent dir: {e}"))?;
    }
    fs::write(&cert_path, certificate_der).map_err(|e| format!("failed to write certificate: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::NodeId;
    use std::path::{Path, PathBuf};

    struct TempPki {
        path: PathBuf,
    }

    impl TempPki {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("async-opcua-client-{name}-{}", std::process::id()));
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
    fn default_client_uses_standard_gds_helpers() {
        let client = GdsClient::new();

        assert_eq!(
            client.registration().directory_object_id,
            NodeId::new(0, 22384)
        );
        assert_eq!(
            client.registration().register_method_id,
            NodeId::new(0, 22385)
        );
        assert_eq!(client.csr().certificate_manager_id, NodeId::new(0, 22388));
        assert_eq!(client.csr().start_signing_request_id, NodeId::new(0, 22400));
        assert_eq!(
            client.csr().finish_signing_request_id,
            NodeId::new(0, 22402)
        );
    }

    #[test]
    fn apply_renewed_certificate_rejects_invalid_security_material() {
        let temp_pki = TempPki::new("gds-client-invalid-material");
        let store = RwLock::new(CertificateStore::new(temp_pki.path()));
        let client = GdsClient::new();

        let result = client.apply_renewed_certificate(&store, b"not-a-certificate", None);

        assert_eq!(
            result,
            Err(opcua_types::StatusCode::BadSecurityChecksFailed)
        );
    }
}
