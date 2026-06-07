// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2026 Adam Lock

use opcua_types::NodeId;

/// DER-encoded certificate material cached for GDS-managed applications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedCredentials {
    /// Application instance certificate in DER encoding.
    pub certificate_der: Vec<u8>,
    /// Application private key in DER encoding.
    pub private_key_der: Vec<u8>,
    /// Trust list received from the GDS in DER encoding.
    pub trust_list_der: Vec<u8>,
}

/// Registration lifecycle state for an application enrolled with a GDS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationState {
    /// Application has not been registered with the GDS.
    Unregistered,
    /// Application registration completed successfully.
    Registered,
    /// Certificate renewal has been requested and is awaiting completion.
    RenewalPending {
        /// GDS request identifier for the pending renewal.
        request_id: NodeId,
    },
    /// Registration or renewal failed.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// Client-side GDS enrollment configuration and cached state.
#[derive(Debug, Clone)]
pub struct GdsEnrollment {
    /// Endpoint URL of the Global Discovery Server.
    pub gds_endpoint_url: String,
    /// OPC UA application URI registered with the GDS.
    pub application_uri: String,
    /// Current registration lifecycle state.
    pub registration_state: RegistrationState,
    /// Cached credentials used for reconnect or startup recovery.
    pub cached_credentials: Option<CachedCredentials>,
}
