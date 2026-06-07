//! Global Discovery Server (GDS) support.

use std::sync::Arc;

use crate::node_manager::memory::SimpleNodeManager;

use self::{
    pull_methods::{register_gds_pull_methods, GdsPullMethodRegistry},
    push_methods::{register_gds_push_methods, GdsSigningRequestRegistry},
};

/// Filesystem cache for GDS certificate credentials.
pub mod cache;
/// Pull model method callbacks for certificate management.
pub mod pull_methods;
/// Push model method callbacks for certificate signing requests.
pub mod push_methods;

/// Registries backing the standard GDS method callbacks.
pub struct GdsMethodRegistries {
    /// Signing request registry used by push-model callbacks.
    pub signing_requests: Arc<GdsSigningRequestRegistry>,
    /// Pull certificate registry used by pull-model callbacks.
    pub pull_methods: GdsPullMethodRegistry,
}

/// Registers the standard GDS certificate management callbacks.
pub fn register_gds_certificate_management_methods(
    node_manager: &SimpleNodeManager,
) -> GdsMethodRegistries {
    GdsMethodRegistries {
        signing_requests: register_gds_push_methods(node_manager),
        pull_methods: register_gds_pull_methods(node_manager),
    }
}
