// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

//! Certificate Signing Request (CSR) GDS exchange client implementation.
//! Provides mechanisms to initiate and finalize dynamic certificate signing requests.

use crate::Session;
use opcua_types::{ByteString, CallMethodRequest, NodeId, StatusCode, Variant};
use tracing::error;

/// Client helper for dynamic certificate signing request exchange with GDS Certificate Managers.
pub struct GdsCsrClient {
    /// NodeId of the CertificateManager object (standard ns=0;i=22388)
    pub certificate_manager_id: NodeId,
    /// NodeId of the StartSigningRequest method (standard ns=0;i=22400)
    pub start_signing_request_id: NodeId,
    /// NodeId of the FinishSigningRequest method (standard ns=0;i=22402)
    pub finish_signing_request_id: NodeId,
}

impl Default for GdsCsrClient {
    fn default() -> Self {
        Self {
            certificate_manager_id: NodeId::new(0, 22388),
            start_signing_request_id: NodeId::new(0, 22400),
            finish_signing_request_id: NodeId::new(0, 22402),
        }
    }
}

impl GdsCsrClient {
    /// Creates a new `GdsCsrClient` with default standard GDS NodeIds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submits a CSR to the GDS CertificateManager to start the signing process.
    /// Returns the GDS-allocated `NodeId` representing the request ID.
    pub async fn start_signing_request(
        &self,
        session: &Session,
        application_id: NodeId,
        certificate_group_id: NodeId,
        certificate_type_id: NodeId,
        csr_der: &[u8],
        regenerate_private_key: bool,
    ) -> Result<NodeId, StatusCode> {
        let request = CallMethodRequest {
            object_id: self.certificate_manager_id.clone(),
            method_id: self.start_signing_request_id.clone(),
            input_arguments: Some(vec![
                Variant::from(application_id),
                Variant::from(certificate_group_id),
                Variant::from(certificate_type_id),
                Variant::from(ByteString::from(csr_der)),
                Variant::from(regenerate_private_key),
            ]),
        };

        match session.call_one(request).await {
            Ok(result) => {
                if result.status_code.is_good() {
                    if let Some(args) = result.output_arguments {
                        if !args.is_empty() {
                            match &args[0] {
                                Variant::NodeId(node_id) => {
                                    return Ok(*node_id.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Err(result.status_code)
                }
            }
            Err(err) => {
                error!("Failed to start signing request: {}", err);
                Err(err.status())
            }
        }
    }

    /// Polls or calls FinishSigningRequest to fetch the signed certificate (and optional private key).
    /// Returns a tuple containing the signed DER certificate bytes, and optionally the PEM private key if regenerated.
    pub async fn finish_signing_request(
        &self,
        session: &Session,
        application_id: NodeId,
        request_id: NodeId,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), StatusCode> {
        let request = CallMethodRequest {
            object_id: self.certificate_manager_id.clone(),
            method_id: self.finish_signing_request_id.clone(),
            input_arguments: Some(vec![
                Variant::from(application_id),
                Variant::from(request_id),
            ]),
        };

        match session.call_one(request).await {
            Ok(result) => {
                if result.status_code.is_good() {
                    if let Some(args) = result.output_arguments {
                        if args.len() >= 2 {
                            let signed_cert = match &args[0] {
                                Variant::ByteString(bs) => bs.as_ref().to_vec(),
                                _ => return Err(StatusCode::BadUnexpectedError),
                            };
                            let private_key = match &args[1] {
                                Variant::ByteString(bs) if !bs.is_null() => {
                                    Some(bs.as_ref().to_vec())
                                }
                                _ => None,
                            };
                            return Ok((signed_cert, private_key));
                        }
                    }
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Err(result.status_code)
                }
            }
            Err(err) => {
                error!("Failed to finish signing request: {}", err);
                Err(err.status())
            }
        }
    }
}
